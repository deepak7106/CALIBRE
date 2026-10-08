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
        graph.timeline.sort(key=lambda item: item["timestamp"])
        return graph
