"""Rule-based text threat detectors."""

import re

from trustshield.models import AnalysisContext, Indicator, StageResult

PATTERNS = {
    "credential_request": (r"\b(password|passcode|login|sign in|verify your account)\b", "high"),
    "financial_request": (r"\b(pay|payment|wire|transfer|gift card|invoice)\b", "high"),
    "urgency_pressure": (r"\b(urgent|immediately|within \d+ minutes|act now|last chance)\b", "medium"),
    "authority_impersonation": (r"\b(ceo|chief executive|bank security|it helpdesk|administrator)\b", "medium"),
    "reward_lure": (r"\b(prize|winner|bonus|reward|free money)\b", "medium"),
}


class TextAnalysisStage:
    name = "text_analysis"

    def run(self, context: AnalysisContext) -> StageResult:
        text = context.data.get("normalized_text", context.message.text).casefold()
        indicators = [
            Indicator(
                name=name, severity=severity,
                description=f"Message contains a {name.replace('_', ' ')} pattern.",
                evidence={"matched": re.findall(pattern, text, re.IGNORECASE)},
                stage=self.name,
            )
            for name, (pattern, severity) in PATTERNS.items()
            if re.search(pattern, text, re.IGNORECASE)
        ]
        return StageResult(stage=self.name, indicators=indicators,
                           data={"text_indicator_count": len(indicators)})
