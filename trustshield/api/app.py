"""FastAPI URL scanning API.

The API performs local validation and static URL analysis only. It never
requests the destination URL or redirects a client to it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from trustshield.engine.risk import assess
from trustshield.gateway import SecureURLGateway, URLValidationError
from trustshield.models import AnalysisContext, AnalysisResult, MessageInput
from trustshield.stages.base import run_stage
from trustshield.stages.url_analysis import URLAnalysisStage
from trustshield.storage.db import Base, create_store
from trustshield.correlation import CorrelationEngine
from trustshield.explainability import build_explanation
from trustshield.fusion import fuse
from trustshield.correlation.campaigns import correlate_messages
from trustshield.models import Indicator


class URLAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=4096)


class URLScanResponse(BaseModel):
    scan_id: str
    destination_url: str
    scan_url: str
    status: str
    analysis: AnalysisResult
    warnings: list[str]


class URLScanRecord(Base):
    __tablename__ = "url_scans"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    destination_url: Mapped[str] = mapped_column(Text)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def create_app(database_path: str | Path = "trustshield.db") -> FastAPI:
    """Create an API instance with an isolated SQLite store."""
    engine, _ = create_store(database_path)
    gateway = SecureURLGateway()
    app = FastAPI(title="TrustShield API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
    app.state.engine = engine
    app.state.gateway = gateway

    @app.post("/api/analyze/url", response_model=URLScanResponse)
    def analyze_url(request: URLAnalyzeRequest) -> URLScanResponse:
        try:
            decision = gateway.validate(request.url)
        except URLValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        message = MessageInput(
            sender="url-gateway@trustshield.local",
            text=decision.destination_url,
            urls=[decision.destination_url],
            source="secure_url_gateway",
            consent=True,
        )
        context = AnalysisContext(message=message)
        context.masked_text = decision.destination_url
        run_stage(URLAnalysisStage(), context)
        graph = CorrelationEngine().build(context)
        context.data["trust_graph"] = graph.model_dump(mode="json")
        context.data["fusion"] = fuse(context)
        result = assess(context)
        result.trust_graph = graph.model_dump(mode="json")
        result.explanation_data = build_explanation(context.indicators)
        scan_id = f"scan-{uuid4().hex}"
        with Session(engine) as session:
            existing = session.scalars(select(URLScanRecord)).all()
            related = [{
                "id": item.scan_id,
                "sender": "url-gateway@trustshield.local",
                "text": item.destination_url,
                "urls": [item.destination_url],
                "attachments": [],
                "timestamp": item.created_at,
            } for item in existing]
            related.append({
                "id": scan_id,
                "sender": "url-gateway@trustshield.local",
                "text": decision.destination_url,
                "urls": [decision.destination_url],
                "attachments": [],
                "timestamp": datetime.now(timezone.utc),
            })
            report = correlate_messages(related)
            if report.campaigns:
                campaign = report.campaigns[-1]
                indicator = Indicator(
                    name="correlated_campaign", severity="medium",
                    description="This scan shares infrastructure or content with other analyzed messages.",
                    evidence=campaign.model_dump(mode="json"), stage="correlation",
                )
                result.indicators.append(indicator)
                result.trust_graph.setdefault("nodes", []).append({
                    "id": f"campaign:{campaign.campaign_id}", "type": "campaign",
                    "label": "Related campaign", "metadata": campaign.model_dump(mode="json"),
                })
                result.trust_graph.setdefault("edges", []).append({
                    "source": f"message:{result.message_id}",
                    "target": f"campaign:{campaign.campaign_id}",
                    "relationship": "belongs_to_campaign",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "evidence_ids": [indicator.id], "confidence": campaign.confidence,
                })
                result.explanation_data.setdefault("reasons", []).append({
                    "text": indicator.description, "indicator_ids": [indicator.id],
                })
                result.conflicting_evidence = result.conflicting_evidence
            session.add(URLScanRecord(
                scan_id=scan_id,
                destination_url=decision.destination_url,
                payload=result.model_dump_json(),
                created_at=datetime.now(timezone.utc),
            ))
            session.commit()
        return URLScanResponse(
            scan_id=scan_id,
            destination_url=decision.destination_url,
            scan_url=decision.scan_url,
            status="complete",
            analysis=result,
            warnings=decision.warnings,
        )

    @app.get("/api/scan/{scan_id}", response_model=URLScanResponse)
    def get_scan(scan_id: str) -> URLScanResponse:
        with Session(engine) as session:
            record = session.scalar(select(URLScanRecord).where(URLScanRecord.scan_id == scan_id))
        if record is None:
            raise HTTPException(status_code=404, detail="scan not found")
        result = AnalysisResult.model_validate_json(record.payload)
        decision = gateway.validate(record.destination_url)
        return URLScanResponse(
            scan_id=scan_id,
            destination_url=record.destination_url,
            scan_url=decision.scan_url,
            status="complete",
            analysis=result,
            warnings=decision.warnings,
        )

    @app.get("/api/scan/{scan_id}/evidence")
    def get_scan_evidence(scan_id: str) -> dict:
        response = get_scan(scan_id)
        return {
            "scan_id": scan_id,
            "indicators": [indicator.model_dump(mode="json") for indicator in response.analysis.indicators],
            "explanation": response.analysis.explanation,
            "risk_level": response.analysis.risk_level,
            "score": response.analysis.score,
            "confidence": response.analysis.confidence,
        }

    @app.get("/messages/{message_id}/trustgraph")
    def get_trustgraph(message_id: str) -> dict:
        with Session(engine) as session:
            record = session.scalar(select(URLScanRecord).where(
                URLScanRecord.scan_id == message_id
            ))
        if record is None:
            raise HTTPException(status_code=404, detail="message or scan not found")
        return AnalysisResult.model_validate_json(record.payload).trust_graph

    @app.get("/messages/{message_id}", response_model=AnalysisResult)
    def get_message(message_id: str) -> AnalysisResult:
        with Session(engine) as session:
            record = session.scalar(select(URLScanRecord).where(URLScanRecord.scan_id == message_id))
        if record is None:
            raise HTTPException(status_code=404, detail="message or scan not found")
        return AnalysisResult.model_validate_json(record.payload)

    @app.get("/messages/{message_id}/timeline")
    def get_timeline(message_id: str) -> dict:
        graph = get_trustgraph(message_id)
        return {"message_id": message_id, "timeline": graph.get("timeline", [])}

    @app.get("/messages/{message_id}/explanation")
    def get_explanation(message_id: str) -> dict:
        with Session(engine) as session:
            record = session.scalar(select(URLScanRecord).where(URLScanRecord.scan_id == message_id))
        if record is None:
            raise HTTPException(status_code=404, detail="message or scan not found")
        result = AnalysisResult.model_validate_json(record.payload)
        return result.explanation_data

    return app


app = create_app()
