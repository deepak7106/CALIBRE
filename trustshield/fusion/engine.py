"""Interpretable feature vector and evidence normalization."""

from trustshield.models import AnalysisContext


def fuse(context: AnalysisContext) -> dict:
    indicators = context.indicators
    names = {item.name for item in indicators}
    feature_vector = {
        "credential_request": int("credential_request" in names),
        "financial_request": int("financial_request" in names),
        "urgency": int("urgency_pressure" in names),
        "sender_untrusted": int(any("untrusted_sender" in name for name in names)),
        "lookalike_domain": int("lookalike_domain" in names),
        "known_blocklist_match": int("local_threat_intel_match" in names),
        "style_change": int("writing_style_change" in names),
        "identity_mismatch": int("sudden_request_type_change" in names),
        "correlated_attack": int("correlated_attack_escalation" in names),
    }
    return {
        "feature_vector": feature_vector,
        "evidence": [item.model_dump(mode="json") for item in indicators],
    }
