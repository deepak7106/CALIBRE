"""Phase 1 pipeline composition."""

from trustshield.engine.risk import assess
from trustshield.models import AnalysisContext, AnalysisResult, MessageInput, StageResult
from trustshield.stages.base import run_stage
from trustshield.stages.ingestion import MessageIngestionStage
from trustshield.stages.preprocessing import ContentPreprocessingStage
from trustshield.stages.text_analysis import TextAnalysisStage
from trustshield.stages.file_analysis import FileAnalysisStage
from trustshield.stages.sender_trust import SenderTrustStage
from trustshield.stages.url_analysis import URLAnalysisStage
from trustshield.stages.ai_context import AIContextStage
from trustshield.identity import IdentityBehaviorStage
from trustshield.correlation import CorrelationEngine
from trustshield.fusion import fuse
from trustshield.explainability import build_explanation


def analyze(message: MessageInput) -> AnalysisResult:
    context = AnalysisContext(message=message)
    if not message.consent:
        context.append(StageResult(
            stage="consent_safety_gate", status="rejected",
            error="Explicit consent is required before analysis.",
        ))
        return assess(context)
    stages = [MessageIngestionStage(), ContentPreprocessingStage(), SenderTrustStage(),
              IdentityBehaviorStage(), TextAnalysisStage(), AIContextStage()]
    if message.urls:
        stages.append(URLAnalysisStage())
    if message.attachments:
        stages.append(FileAnalysisStage())
    for stage in stages:
        run_stage(stage, context)
    graph = CorrelationEngine().build(context)
    context.data["trust_graph"] = graph.model_dump(mode="json")
    context.data["fusion"] = fuse(context)
    result = assess(context)
    result.explanation_data = build_explanation(
        context.indicators, any(stage.status == "unknown" for stage in context.stages)
    )
    result.trust_graph = graph.model_dump(mode="json")
    result.uncertainty = any(stage.status == "unknown" for stage in context.stages)
    result.conflicting_evidence = any(
        indicator.name in {"identity_untrusted_sender", "local_threat_intel_match"}
        for indicator in context.indicators
    )
    result.conflicts = ([{
        "sources": ["identity", "threat_intelligence"],
        "description": "Sender trust context conflicts with URL threat evidence.",
    }] if result.conflicting_evidence else [])
    return result
