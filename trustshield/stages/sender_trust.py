"""Mock known-contact and communication-history trust context."""

from datetime import datetime, timezone

from trustshield.models import AnalysisContext, Indicator, StageResult

KNOWN_CONTACTS = {"colleague@example.com", "manager@example.com"}
HISTORY = {"colleague@example.com": 12, "manager@example.com": 5}


class SenderTrustStage:
    name = "sender_trust"

    def run(self, context: AnalysisContext) -> StageResult:
        sender = context.message.sender.lower()
        indicators: list[Indicator] = []
        known = sender in KNOWN_CONTACTS
        if not known:
            indicators.append(Indicator(
                name="untrusted_sender", severity="medium",
                description="Sender is not present in the mock known-contacts table.",
                evidence={"sender": sender}, stage=self.name,
            ))
        if context.message.timestamp.hour < 6 or context.message.timestamp.hour >= 22:
            indicators.append(Indicator(
                name="unusual_time", severity="low",
                description="Message arrived outside the normal 06:00-22:00 window.",
                evidence={"hour": context.message.timestamp.hour}, stage=self.name,
            ))
        return StageResult(stage=self.name, indicators=indicators, data={
            "sender_trust": {"known_contact": known, "history_count": HISTORY.get(sender, 0)}
        })
