"""Generate explanations whose claims cite actual indicator IDs."""

def build_explanation(indicators, uncertainty: bool = False) -> dict:
    reasons = [
        {"text": indicator.description, "indicator_ids": [indicator.id]}
        for indicator in indicators if indicator.severity in {"medium", "high", "critical"}
    ]
    uncertainties = []
    if uncertainty:
        uncertainties.append({"text": "Some contextual evidence was unavailable.", "indicator_ids": []})
    return {
        "summary": "TrustShield found supporting evidence for this assessment." if reasons
        else "TrustShield found no significant threat indicators.",
        "reasons": reasons,
        "uncertainties": uncertainties,
        "recommended_verification": [
            "Verify the sender or destination through a trusted channel."
        ] if reasons else [],
    }
