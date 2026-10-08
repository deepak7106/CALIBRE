"""Typed schemas shared by every pipeline stage."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["info", "low", "medium", "high", "critical"]
ThreatCategory = Literal[
    "Legitimate", "Spam", "Suspicious", "Scam", "Phishing",
    "Impersonation", "Malware", "Coordinated Cyberattack",
]
RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Indicator(BaseModel):
    """A citable piece of evidence emitted by a pipeline stage."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: f"ind-{uuid4().hex[:12]}")
    name: str
    severity: Severity
    description: str
    evidence: Any = None
    stage: str


class MessageInput(BaseModel):
    """Safe, normalized input contract for an incoming message."""

    model_config = ConfigDict(extra="allow")

    sender: str = Field(min_length=1, max_length=320)
    text: str = Field(default="", max_length=100_000)
    urls: list[str] = Field(default_factory=list, max_length=100)
    attachments: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(default="demo", max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)
    consent: bool = False

    @field_validator("timestamp")
    @classmethod
    def ensure_timezone(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class StageResult(BaseModel):
    """Result returned by one stage and appended to the context."""

    stage: str
    status: Literal["ok", "rejected", "unknown"] = "ok"
    indicators: list[Indicator] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class AnalysisContext(BaseModel):
    """Mutable-by-replacement state passed through the analysis pipeline."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    message: MessageInput
    message_id: str = Field(default_factory=lambda: f"msg-{uuid4().hex}")
    masked_text: str = ""
    stages: list[StageResult] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)

    def append(self, result: StageResult) -> "AnalysisContext":
        self.stages.append(result)
        self.data.update(result.data)
        return self

    @property
    def indicators(self) -> list[Indicator]:
        return [indicator for stage in self.stages for indicator in stage.indicators]


class AnalysisResult(BaseModel):
    """Phase 1 response shape, suitable for the later API layer."""

    message_id: str
    category: ThreatCategory
    risk_level: RiskLevel
    score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=100)
    explanation: str
    indicators: list[Indicator]
    action: str
    stages: list[StageResult]
    uncertainty: bool = False
    conflicting_evidence: bool = False
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    explanation_data: dict[str, Any] = Field(default_factory=dict)
    trust_graph: dict[str, Any] = Field(default_factory=dict)
