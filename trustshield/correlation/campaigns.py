"""Deterministic multi-message correlation helpers."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from trustshield.correlation.models import Campaign, CorrelationEvent, CorrelationReport


def _config() -> dict[str, Any]:
    path = Path("config/risk.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]{3,}", text.lower())
            if token not in {"the", "and", "for", "your", "this", "with"}}


def _similarity(left: str, right: str) -> float:
    a, b = _tokens(left), _tokens(right)
    return len(a & b) / max(1, len(a | b))


def _message_data(item: Any) -> dict[str, Any]:
    if hasattr(item, "message"):
        message = item.message
        return {
            "id": item.message_id, "sender": message.sender.lower(), "text": message.text,
            "timestamp": message.timestamp, "urls": message.urls,
            "attachments": message.attachments,
        }
    return item


def correlate_messages(items: list[Any]) -> CorrelationReport:
    """Correlate contexts or plain message dictionaries within a time window."""
    cfg = _config().get("correlation", {})
    window = timedelta(minutes=int(cfg.get("time_window_minutes", 60)))
    threshold = float(cfg.get("content_similarity_threshold", 0.75))
    messages = [_message_data(item) for item in items]
    for message in messages:
        timestamp = message["timestamp"]
        if timestamp.tzinfo is None:
            message["timestamp"] = timestamp.replace(tzinfo=timezone.utc)
    campaigns: list[Campaign] = []
    events: list[CorrelationEvent] = []
    for index, current in enumerate(messages):
        related = [current]
        signals: set[str] = set()
        for other in messages[index + 1:]:
            if abs(current["timestamp"] - other["timestamp"]) > window:
                continue
            same_sender = current["sender"] == other["sender"]
            current_domains = {url.split("/")[2].lower() for url in current.get("urls", []) if "//" in url}
            other_domains = {url.split("/")[2].lower() for url in other.get("urls", []) if "//" in url}
            same_domain = bool(current_domains & other_domains)
            same_url = bool(set(current.get("urls", [])) & set(other.get("urls", [])))
            similar = _similarity(current["text"], other["text"]) >= threshold
            current_hashes = {str(a.get("sha256")) for a in current.get("attachments", []) if a.get("sha256")}
            other_hashes = {str(a.get("sha256")) for a in other.get("attachments", []) if a.get("sha256")}
            same_file = bool(current_hashes & other_hashes)
            if any((same_sender, same_domain, same_url, similar, same_file)):
                related.append(other)
                if same_sender: signals.add("same_sender")
                if same_domain: signals.add("same_domain")
                if same_url: signals.add("same_url")
                if similar: signals.add("similar_content")
                if same_file: signals.add("same_attachment_hash")
        if len(related) >= int(cfg.get("campaign_min_messages", 2)):
            ids = sorted({item["id"] for item in related})
            campaign_id = "camp-" + hashlib.sha256("|".join(ids).encode()).hexdigest()[:12]
            confidence = min(0.99, 0.55 + 0.1 * len(signals))
            campaigns.append(Campaign(
                campaign_id=campaign_id, message_ids=ids, confidence=confidence,
                signals=sorted(signals), threat_type="Phishing" if "same_domain" in signals else "Suspicious",
            ))
            evidence_ids = []
            events.append(CorrelationEvent(
                event_type="campaign_detected", source=campaign_id,
                timestamp=min(item["timestamp"] for item in related),
                evidence_ids=evidence_ids, metadata={"message_ids": ids, "signals": sorted(signals)},
            ))
    return CorrelationReport(campaigns=campaigns, events=events)


def detect_escalation(events: list[CorrelationEvent]) -> bool:
    order = ["message_received", "url_extracted", "redirect", "download_started", "file_analyzed"]
    observed = [event.event_type for event in sorted(events, key=lambda event: event.timestamp)]
    positions = [observed.index(event) for event in order if event in observed]
    return len(positions) >= 3 and positions == sorted(positions)
