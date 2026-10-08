"""Serializable campaign and event-correlation models."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class CorrelationEvent(BaseModel):
    event_type: str
    source: str | None = None
    target: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Campaign(BaseModel):
    campaign_id: str
    message_ids: list[str]
    confidence: float = Field(ge=0, le=1)
    signals: list[str]
    threat_type: str = "Suspicious"


class CorrelationReport(BaseModel):
    campaigns: list[Campaign] = Field(default_factory=list)
    events: list[CorrelationEvent] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
