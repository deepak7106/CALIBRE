from datetime import datetime, timedelta, timezone

from trustshield.correlation.campaigns import correlate_messages, detect_escalation
from trustshield.correlation.models import CorrelationEvent
from trustshield.risk.hybrid import hybrid_components


def _message(identifier, sender, text, minutes=0, urls=None, attachments=None):
    return {
        "id": identifier,
        "sender": sender,
        "text": text,
        "timestamp": datetime.now(timezone.utc) + timedelta(minutes=minutes),
        "urls": urls or [],
        "attachments": attachments or [],
    }


def test_campaign_correlates_sender_domain_url_and_content():
    report = correlate_messages([
        _message("m1", "a@example.com", "urgent verify your account", urls=["https://evil.test/login"]),
        _message("m2", "a@example.com", "urgent verify your account now", minutes=2, urls=["https://evil.test/login"]),
    ])
    assert len(report.campaigns) == 1
    assert {"same_sender", "same_domain", "same_url", "similar_content"} <= set(report.campaigns[0].signals)


def test_campaign_respects_time_window():
    report = correlate_messages([
        _message("m1", "a@example.com", "same content", minutes=-100, urls=["https://evil.test"]),
        _message("m2", "a@example.com", "same content", urls=["https://evil.test"]),
    ])
    assert not report.campaigns


def test_escalation_detects_ordered_events():
    now = datetime.now(timezone.utc)
    events = [
        CorrelationEvent(event_type="message_received", timestamp=now),
        CorrelationEvent(event_type="url_extracted", timestamp=now + timedelta(seconds=1)),
        CorrelationEvent(event_type="redirect", timestamp=now + timedelta(seconds=2)),
        CorrelationEvent(event_type="download_started", timestamp=now + timedelta(seconds=3)),
    ]
    assert detect_escalation(events)


def test_hybrid_renormalizes_missing_components():
    score, uncertain = hybrid_components({"rules": 0.9, "ml": None, "identity": 0.7, "correlation": None})
    assert 0.7 < score < 0.9
    assert uncertain is True
