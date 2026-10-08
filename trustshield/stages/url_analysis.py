"""Offline-safe URL safety and reputation checks."""

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

import yaml
from trustshield.models import AnalysisContext, Indicator, StageResult

BRANDS = {"microsoft.com", "paypal.com", "google.com", "apple.com", "bank.example"}
BLOCKLIST = {"malware.test", "phishing.test", "credential-harvest.test"}


def _shortener_hosts() -> set[str]:
    path = Path("config/risk.yaml")
    if not path.exists():
        return {"tinyurl.com", "bit.ly", "t.co", "is.gd", "cutt.ly", "shorturl.at"}
    config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return set(config.get("url", {}).get("shortener_hosts", []))


def _private_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in {"localhost", "metadata.google.internal"} or host.endswith(".internal")


class URLAnalysisStage:
    name = "url_analysis"

    def run(self, context: AnalysisContext) -> StageResult:
        urls = context.message.urls + re.findall(r"https?://[^\s<>()]+", context.message.text)
        indicators: list[Indicator] = []
        evidence = []
        for raw_url in dict.fromkeys(urls):
            parsed = urlparse(raw_url)
            host = (parsed.hostname or "").lower()
            item = {"url": raw_url, "domain": host, "protocol": parsed.scheme}
            evidence.append(item)
            if parsed.scheme not in {"http", "https"}:
                indicators.append(Indicator(
                    name="unsafe_url_protocol", severity="high",
                    description="URL uses a protocol outside the HTTP(S) allow-list.",
                    evidence=item, stage=self.name,
                ))
            if _private_host(host):
                indicators.append(Indicator(
                    name="private_or_internal_target", severity="critical",
                    description="URL targets a private, loopback, or internal host.",
                    evidence=item, stage=self.name,
                ))
            if host in BLOCKLIST:
                indicators.append(Indicator(
                    name="local_threat_intel_match", severity="critical",
                    description="Domain matches the local threat-intelligence blocklist.",
                    evidence=item, stage=self.name,
                ))
            if host in _shortener_hosts():
                indicators.append(Indicator(
                    name="url_shortener_detected", severity="low",
                    description="URL uses a shortening service and requires destination inspection.",
                    evidence=item, stage=self.name,
                ))
            if any(host.endswith(f".{brand}") and host != brand for brand in BRANDS):
                indicators.append(Indicator(
                    name="lookalike_domain", severity="high",
                    description="Domain is a subdomain/lookalike of a monitored brand.",
                    evidence=item, stage=self.name,
                ))
            if "@" in parsed.netloc or any(char in host for char in "аеоі"):
                indicators.append(Indicator(
                    name="suspicious_url_characters", severity="high",
                    description="URL contains a suspicious authority or homograph character.",
                    evidence=item, stage=self.name,
                ))
        return StageResult(stage=self.name, indicators=indicators,
                           data={"url_evidence": evidence, "url_count": len(evidence)})
