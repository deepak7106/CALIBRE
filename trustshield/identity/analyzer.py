"""Conservative sender/content mismatch and behavior checks."""

import re
from statistics import mean

from trustshield.models import AnalysisContext, Indicator, StageResult


def _features(text: str) -> dict[str, float]:
    words = re.findall(r"\b\w+\b", text)
    return {
        "length": float(len(text)),
        "sentence_length": float(len(words) / max(1, len(re.findall(r"[.!?]", text)))),
        "punctuation": float(sum(char in "!?$" for char in text) / max(1, len(text))),
        "urgency": float(bool(re.search(r"\burgent|immediately|act now\b", text, re.I))),
    }


class IdentityBehaviorStage:
    name = "identity_behavior"

    def run(self, context: AnalysisContext) -> StageResult:
        message = context.message
        history = message.metadata.get("sender_history")
        indicators: list[Indicator] = []
        text = message.text
        if not history:
            return StageResult(stage=self.name, status="unknown", data={
                "identity_status": "unknown",
                "identity_reason": "sender history was not supplied",
            })
        known = bool(history.get("known_contact", False))
        if not known:
            indicators.append(Indicator(
                name="identity_untrusted_sender", severity="medium",
                description="Sender is not marked as a known contact in supplied history.",
                evidence={"sender": message.sender}, stage=self.name,
            ))
        requests = set(history.get("request_types", []))
        current_request = (
            "credential" if re.search(r"password|login|verify.*account", text, re.I)
            else "financial" if re.search(r"wire|transfer|payment|gift card", text, re.I)
            else "other"
        )
        if requests and current_request not in requests and current_request != "other":
            indicators.append(Indicator(
                name="sudden_request_type_change", severity="high",
                description="Current request type differs from the sender's recorded history.",
                evidence={"current": current_request, "historical": sorted(requests)},
                stage=self.name,
            ))
        current = _features(text)
        historical = history.get("style_features")
        if historical:
            distance = mean(abs(current[key] - float(historical.get(key, current[key])))
                            for key in current)
            if distance > float(history.get("style_threshold", 20)):
                indicators.append(Indicator(
                    name="writing_style_change", severity="medium",
                    description="Writing-style features differ materially from sender history.",
                    evidence={"distance": round(distance, 3), "current": current, "historical": historical},
                    stage=self.name,
                ))
        return StageResult(stage=self.name, indicators=indicators, data={
            "identity_status": "ok", "identity_features": current,
        })
