"""Evidence-backed timeline and TrustGraph generation."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from trustshield.models import AnalysisContext, Indicator
from .models import CorrelationEvent


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = 1.0


class TrustGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)


class CorrelationEngine:
    """Builds only relationships represented by the current context."""

    def build(self, context: AnalysisContext) -> TrustGraph:
        graph = TrustGraph()
        message_id = f"message:{context.message_id}"
        sender_id = f"sender:{context.message.sender.lower()}"
        graph.nodes.extend([
            GraphNode(id=sender_id, type="sender", label="Sender", metadata={"address": context.message.sender}),
            GraphNode(id=message_id, type="message", label="Message", metadata={"message_id": context.message_id}),
        ])
        received = next((i for i in context.indicators if i.name == "message_received"), None)
        graph.edges.append(GraphEdge(source=sender_id, target=message_id, relationship="sent",
                                     evidence_ids=[received.id] if received else []))
        for url in context.data.get("url_evidence", []):
            domain = url["domain"]
            url_id = f"url:{url['url']}"
            domain_id = f"domain:{domain}"
            graph.nodes.extend([
                GraphNode(id=url_id, type="url", label="URL", metadata={"url": url["url"]}),
                GraphNode(id=domain_id, type="domain", label=domain, metadata={"domain": domain}),
            ])
            graph.edges.extend([
                GraphEdge(source=message_id, target=url_id, relationship="links_to"),
                GraphEdge(source=url_id, target=domain_id, relationship="associated_with"),
            ])
        browser = context.data.get("browser_inspection", {})
        original_url = browser.get("url")
        final_url = browser.get("final_url")
        if original_url and final_url and final_url != original_url:
            graph.nodes.append(GraphNode(
                id=f"url:{final_url}", type="url", label="Final URL",
                metadata={"url": final_url},
            ))
            graph.edges.append(GraphEdge(
                source=f"url:{original_url}", target=f"url:{final_url}",
                relationship="redirects_to",
            ))
        for file in browser.get("files", []):
            sha256 = file.get("sha256")
            file_id = f"file:{sha256 or file.get('filename', 'download')}"
            graph.nodes.append(GraphNode(
                id=file_id, type="file", label=file.get("filename", "Downloaded file"),
                metadata={"sha256": sha256, "detected_type": file.get("detected_type")},
            ))
            if final_url:
                graph.edges.append(GraphEdge(
                    source=f"url:{final_url}", target=file_id,
                    relationship="downloads",
                ))
            if sha256:
                hash_id = f"sha256:{sha256}"
                graph.nodes.append(GraphNode(id=hash_id, type="sha256", label=sha256))
                graph.edges.append(GraphEdge(
                    source=file_id, target=hash_id, relationship="identified_by",
                ))
        for indicator in context.indicators:
            indicator_id = f"indicator:{indicator.id}"
            graph.nodes.append(GraphNode(id=indicator_id, type="indicator",
                                         label=indicator.name, metadata={"severity": indicator.severity}))
            graph.edges.append(GraphEdge(source=message_id, target=indicator_id,
                                         relationship="triggered", evidence_ids=[indicator.id]))
        graph.timeline.append({
            "timestamp": context.message.timestamp.isoformat(),
            "event": "message_received",
            "event_type": "message_received",
            "entity_id": message_id,
            "description": "Message received for analysis.",
            "evidence_ids": [received.id] if received else [],
            "message_id": context.message_id,
        })
        for item in context.data.get("url_evidence", []):
            graph.timeline.append({
                "timestamp": context.message.timestamp.isoformat(),
                "event": "url_extracted",
                "event_type": "url_extracted",
                "entity_id": f"url:{item['url']}",
                "description": "URL extracted from the message.",
                "evidence_ids": [],
            })
        if browser:
            graph.timeline.append({
                "timestamp": context.message.timestamp.isoformat(),
                "event": "browser_inspection_completed",
                "event_type": "browser_inspection_completed",
                "entity_id": message_id,
                "description": "Browser inspection completed with safe metadata capture.",
                "evidence_ids": [],
            })
            for file in browser.get("files", []):
                graph.timeline.append({
                    "timestamp": context.message.timestamp.isoformat(),
                    "event": "file_static_analysis_completed",
                    "event_type": "file_static_analysis_completed",
                    "entity_id": f"file:{file.get('sha256', file.get('filename', 'download'))}",
                    "description": "Downloaded content was analyzed statically and not executed.",
                    "evidence_ids": [],
                })
        graph.timeline.sort(key=lambda item: item["timestamp"])
        return graph
