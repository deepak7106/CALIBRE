"""Validate and encode URLs before they can enter the TrustShield scan flow.

This module deliberately does not perform network requests or issue HTTP
redirects. Callers must analyze the returned destination before navigation.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
SUPPORTED_SCHEMES = frozenset({"https"})
SUSPICIOUS_PORTS = frozenset({21, 22, 23, 25, 110, 139, 445, 3389})
MAX_URL_LENGTH = 4096


class URLValidationError(ValueError):
    """Raised when a destination is not safe to enter the scan flow."""


class GatewayDecision(BaseModel):
    """Safe gateway output; the destination is not opened by this service."""

    model_config = ConfigDict(extra="forbid")

    destination_url: str
    scan_url: str
    scheme: str
    host: str
    port: int | None = None
    path: str
    status: str = "awaiting_analysis"
    network_access_performed: bool = False
    warnings: list[str] = Field(default_factory=list)


class SecureURLGateway:
    """Fail-closed URL validator and scan-route builder."""

    def __init__(self, scan_path: str = "/scan"):
        if not scan_path.startswith("/") or scan_path.startswith("//"):
            raise ValueError("scan_path must be an absolute application path")
        self.scan_path = scan_path

    @staticmethod
    def _is_forbidden_host(host: str) -> bool:
        normalized = host.rstrip(".").lower()
        if normalized in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
            return True
        if normalized.endswith(".internal") or normalized.endswith(".localhost"):
            return True
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return False
        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        )

    @staticmethod
    def _normalize_host(host: str) -> str:
        try:
            return host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise URLValidationError("destination host is not valid IDNA") from exc

    def validate(self, destination_url: str) -> GatewayDecision:
        """Validate a URL without DNS resolution, HTTP requests, or redirects."""
        if not isinstance(destination_url, str) or not destination_url.strip():
            raise URLValidationError("destination URL is required")
        if len(destination_url) > MAX_URL_LENGTH:
            raise URLValidationError("destination URL exceeds the size limit")
        if destination_url != destination_url.strip() or CONTROL_CHARS.search(destination_url):
            raise URLValidationError("destination URL contains invalid whitespace or control characters")

        parsed = urlsplit(destination_url)
        if parsed.scheme.lower() not in SUPPORTED_SCHEMES:
            raise URLValidationError("only HTTPS destinations are supported")
        if parsed.username is not None or parsed.password is not None:
            raise URLValidationError("URLs containing embedded credentials are not allowed")
        if not parsed.hostname:
            raise URLValidationError("destination URL must include a hostname")
        try:
            port = parsed.port
        except ValueError as exc:
            raise URLValidationError("destination URL has an invalid port") from exc

        host = self._normalize_host(parsed.hostname)
        if self._is_forbidden_host(host):
            raise URLValidationError("private, loopback, reserved, or internal destinations are blocked")

        warnings = []
        if port in SUSPICIOUS_PORTS:
            warnings.append(f"suspicious destination port: {port}")
        if host.startswith("xn--") or ".xn--" in host:
            warnings.append("destination uses an IDN/punycode label")
        if "@" in parsed.netloc:
            raise URLValidationError("destination authority is invalid")

        canonical = parsed._replace(scheme="https", netloc=parsed.netloc).geturl()
        return GatewayDecision(
            destination_url=canonical,
            scan_url=f"{self.scan_path}?url={quote(canonical, safe='')}",
            scheme="https",
            host=host,
            port=port,
            path=parsed.path or "/",
            warnings=warnings,
        )

    def create_scan_url(self, destination_url: str) -> str:
        """Return only the TrustShield scan route; never a direct redirect."""
        return self.validate(destination_url).scan_url
