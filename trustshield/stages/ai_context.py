"""Advisory AI context stage; deterministic findings remain authoritative."""

from trustshield.models import AnalysisContext, Indicator, StageResult
from trustshield.reasoners import OpenRouterReasoner
from trustshield.reasoners.base import templated_reasoning


class AIContextStage:
    name = "ai_context_intent"

    def __init__(self, reasoner: OpenRouterReasoner | None = None):
        self.reasoner = reasoner or OpenRouterReasoner()

    def run(self, context: AnalysisContext) -> StageResult:
        # Evidence can contain sender/contact data; only safe, non-PII fields cross
        # the remote-reasoner boundary. Raw attachments and URLs are never sent.
        indicators = [
            {
                "id": indicator.id,
                "name": indicator.name,
                "severity": indicator.severity,
                "description": indicator.description,
            }
            for indicator in context.indicators
        ]
        try:
            reasoning, model_id = self.reasoner.reason(context.masked_text, indicators)
            return StageResult(
                stage=self.name,
                data={"llm_reasoning": reasoning.model_dump(), "llm_model": model_id},
                indicators=[Indicator(
                    name="ai_intent_context", severity="info",
                    description="Advisory intent reasoning was validated against the supplied indicators.",
                    evidence={"model": model_id, "cited_indicator_ids": reasoning.cited_indicator_ids},
                    stage=self.name,
                )],
            )
        except Exception as exc:
            fallback, model_id = templated_reasoning(indicators)
            return StageResult(
                stage=self.name, status="unknown", error=str(exc),
                data={"llm_reasoning": fallback.model_dump(), "llm_model": model_id},
            )
