"""Stage protocol and resilient execution helper."""

from typing import Protocol

from trustshield.models import AnalysisContext, StageResult


class Stage(Protocol):
    name: str

    def run(self, context: AnalysisContext) -> StageResult:
        ...


def run_stage(stage: Stage, context: AnalysisContext) -> AnalysisContext:
    """Run a stage and preserve an explicit unknown result on unexpected failure."""
    try:
        result = stage.run(context)
    except Exception as exc:  # a stage must not crash the complete analysis
        result = StageResult(stage=stage.name, status="unknown", error=str(exc))
    return context.append(result)
