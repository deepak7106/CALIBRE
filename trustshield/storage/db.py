"""SQLite persistence for Phase 2 analysis records."""

import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, Float, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from trustshield.models import AnalysisResult


class Base(DeclarativeBase):
    pass


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    message_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(String(40))
    risk_level: Mapped[str] = mapped_column(String(10))
    score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def create_store(path: str | Path = "trustshield.db") -> tuple[object, type[Base]]:
    """Create a SQLite engine and schema without requiring a running service."""
    engine = create_engine(f"sqlite:///{Path(path)}", future=True)
    Base.metadata.create_all(engine)
    return engine, Base


def save_result(engine: object, result: AnalysisResult) -> None:
    with Session(engine) as session:
        session.merge(AnalysisRecord(
            message_id=result.message_id,
            category=result.category,
            risk_level=result.risk_level,
            score=result.score,
            confidence=result.confidence,
            payload=json.dumps(result.model_dump(mode="json")),
            created_at=datetime.now(timezone.utc),
        ))
        session.commit()


def get_result(engine: object, message_id: str) -> AnalysisResult | None:
    with Session(engine) as session:
        record = session.scalar(select(AnalysisRecord).where(
            AnalysisRecord.message_id == message_id
        ))
        return AnalysisResult.model_validate(json.loads(record.payload)) if record else None
