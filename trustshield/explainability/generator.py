"""Generate explanations whose claims cite actual indicator IDs."""

def build_explanation(indicators, uncertainty: bool = False) -> dict:
    reasons = [
        {"text": indicator.description, "indicator_ids": [indicator.id]}
        for indicator in indicators if indicator.severity in {"medium", "high", "critical"}
    ]
    uncertainties = []
    if uncertainty:
        incomplete = [
            indicator for indicator in indicators
            if indicator.name == "destination_inspection_incomplete"
        ]
        shortener = any(
            indicator.name == "url_shortener_detected" for indicator in indicators
        )
        if incomplete:
            text = (
                "The destination initiated a download before a document "
                "destination could be verified. TrustShield captured the "
                "content inertly without executing it, so the destination "
                "could not be fully classified as safe."
            )
            if shortener:
                text += " The original URL uses a shortening service."
            uncertainties.append({
                "text": text,
                "indicator_ids": [indicator.id for indicator in incomplete],
            })
        else:
            uncertainties.append({
                "text": "Some analysis evidence was unavailable; the result is not verified safe.",
                "indicator_ids": [],
            })
    return {
        "summary": "TrustShield found supporting evidence for this assessment." if reasons
        else "TrustShield found no significant threat indicators.",
        "reasons": reasons,
        "uncertainties": uncertainties,
        "recommended_verification": [
            "Verify the sender or destination through a trusted channel."
        ] if reasons else [],
    }
