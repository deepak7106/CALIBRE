"""Reasoner contracts and safe local fallback."""

from typing import Protocol

from pydantic import BaseModel, Field


class LLMReasoning(BaseModel):
    """Strict, bounded response schema accepted from a reasoner."""

    intent: str = Field(min_length=1, max_length=200)
    tactics: list[str] = Field(default_factory=list, max_length=20)
    rationale: str = Field(min_length=1, max_length=2_000)
    cited_indicator_ids: list[str] = Field(default_factory=list, max_length=50)
    confidence_adjustment: float = Field(default=0, ge=-20, le=20)


class LLMReasoner(Protocol):
    def reason(self, masked_text: str, indicators: list[dict]) -> tuple[LLMReasoning, str]:
        """Return validated reasoning and the answering model ID."""


def templated_reasoning(indicators: list[dict]) -> tuple[LLMReasoning, str]:
    cited = [str(item["id"]) for item in indicators]
    return LLMReasoning(
        intent="potentially harmful or unsolicited communication",
        tactics=[str(item["name"]) for item in indicators if item.get("severity") in {"high", "critical"}],
        rationale="Deterministic indicators were used because remote reasoning was unavailable or disabled.",
        cited_indicator_ids=cited,
    ), "template"
