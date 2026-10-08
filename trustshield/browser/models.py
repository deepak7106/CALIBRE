"""Pydantic models for browser observations; no Playwright objects escape."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class RedirectObservation(BaseModel):
    source: str
    target: str
    status_code: int | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    depth: int


class BrowserIndicator(BaseModel):
    id: str
    name: str
    severity: str
    description: str
    evidence: dict = Field(default_factory=dict)


class BrowserInspection(BaseModel):
    scan_id: str
    url: str
    final_url: str | None = None
    page_title: str | None = None
    status_code: int | None = None
    inspection_status: str = "complete"
    redirects: list[RedirectObservation] = Field(default_factory=list)
    login_forms: list[dict] = Field(default_factory=list)
    credential_requests: list[dict] = Field(default_factory=list)
    downloads: list[dict] = Field(default_factory=list)
    suspicious_scripts: list[dict] = Field(default_factory=list)
    network_events: list[dict] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)
    indicators: list[BrowserIndicator] = Field(default_factory=list)
    duration_ms: int = 0
    error: str | None = None
