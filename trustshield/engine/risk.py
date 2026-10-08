"""Evidence fusion, classification, explanation, and protection action."""

from trustshield.engine.classifier import classify
from trustshield.models import AnalysisContext, AnalysisResult, Indicator
from trustshield.risk.hybrid import hybrid_components


def assess(context: AnalysisContext) -> AnalysisResult:
    indicators = context.indicators
    browser_unknown = any(
        stage.stage == "browser_inspection" and stage.status == "unknown"
        for stage in context.stages
    )
    final_destination_verified = any(
        stage.stage == "final_destination_analysis" and stage.status == "ok"
        for stage in context.stages
    )
    explicit_safe_destination = any(
        indicator.name in {"verified_safe_destination", "trusted_destination_verified"}
        for indicator in indicators
    )
    weights = {"info": 0, "low": 8, "medium": 18, "high": 30, "critical": 45}
    rule_score = min(100.0, sum(weights[i.severity] for i in indicators))
    predicted, ml_confidence = classify(context.masked_text or context.message.text)
    identity_score = min(1.0, sum(
        {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}.get(item.severity, 0)
        for item in indicators if item.stage == "identity_behavior"
    ))
    correlation_score = float(context.data.get("fusion", {}).get(
        "feature_vector", {}
    ).get("correlated_attack", 0))
    hybrid_score, missing_component = hybrid_components({
        "rules": rule_score / 100,
        "ml": (100 - ml_confidence) / 100 if predicted != "Legitimate" else 0.0,
        "identity": identity_score,
        "correlation": correlation_score,
    })
    score = round(hybrid_score * 100, 2)
    if any(indicator.severity == "critical" for indicator in indicators):
        score = 100.0
        risk, action = "CRITICAL", "safe hold and block interaction"
    elif score >= 75:
        risk, action = "CRITICAL", "safe hold and block interaction"
    elif score >= 50:
        risk, action = "HIGH", "quarantine and require approval"
    elif score >= 25:
        risk, action = "MEDIUM", "warn and require user review"
    else:
        risk, action = "LOW", "allow"
    if (
        browser_unknown and not final_destination_verified
        and not explicit_safe_destination and risk == "LOW"
    ):
        risk, action = "MEDIUM", "warn and require user review"
    category = predicted
    if any(i.name in {"credential_request", "browser_credential_collection"} for i in indicators):
        category = "Phishing"
    elif any(i.name == "financial_request" for i in indicators) and any(
        i.name == "authority_impersonation" for i in indicators
    ):
        category = "Impersonation"
    elif browser_unknown and not final_destination_verified and not explicit_safe_destination:
        category = "Suspicious"
    cited = "; ".join(f"{i.id}: {i.description}" for i in indicators)
    if not cited:
        cited = "No threat indicators were observed."
    explanation = f"Classified as {category}. Evidence: {cited}"
    confidence = min(99.0, max(10.0, (ml_confidence + min(100.0, len(indicators) * 20)) / 2))
    if missing_component:
        confidence = max(10.0, confidence - 10)
    return AnalysisResult(
        message_id=context.message_id, category=category, risk_level=risk,
        score=round(score, 2), confidence=round(confidence, 2),
        explanation=explanation, indicators=indicators, action=action, stages=context.stages,
    )
