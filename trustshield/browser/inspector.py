"""Disposable Playwright inspection with a deterministic offline simulation.

Live inspection is opt-in. The default ``simulate=True`` path reads no network
and is suitable for tests and demos. Live mode requires the optional Playwright
dependency and still validates every initial destination through the gateway.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel

from trustshield.gateway import SecureURLGateway, URLValidationError

from .models import BrowserIndicator, BrowserInspection, RedirectObservation


class BrowserInspectionError(RuntimeError):
    """Raised when browser inspection cannot be safely started."""


class BrowserConfig(BaseModel):
    timeout_seconds: float = 15
    max_redirects: int = 5
    screenshot: bool = False
    max_download_size_mb: int = 10


class BrowserInspector:
    def __init__(self, gateway: SecureURLGateway | None = None,
                 config: BrowserConfig | None = None):
        self.gateway = gateway or SecureURLGateway()
        self.config = config or BrowserConfig()

    @staticmethod
    def _indicator(name: str, severity: str, description: str, evidence: dict) -> BrowserIndicator:
        digest = hashlib.sha256(f"{name}:{evidence}".encode()).hexdigest()[:12]
        return BrowserIndicator(
            id=f"ind-browser-{digest}", name=name, severity=severity,
            description=description, evidence=evidence,
        )

    def inspect_fixture(self, scan_id: str, url: str, fixture: dict) -> BrowserInspection:
        """Analyze a supplied page fixture without any network or browser."""
        decision = self.gateway.validate(url)
        started = time.monotonic()
        redirects = [
            RedirectObservation(
                source=item["source"], target=item["target"],
                status_code=item.get("status_code"), depth=index + 1,
            )
            for index, item in enumerate(fixture.get("redirects", []))
        ]
        indicators = [
            BrowserIndicator.model_validate(item)
            for item in fixture.get("indicators", [])
        ]
        login_forms = fixture.get("login_forms", [])
        credential_requests = fixture.get("credential_requests", [])
        downloads = fixture.get("downloads", [])
        if login_forms or credential_requests:
            indicators.append(self._indicator(
                "browser_credential_collection", "high",
                "The inspected page contains a login form or requests credentials.",
                {"login_forms": len(login_forms), "credential_requests": len(credential_requests)},
            ))
        if downloads:
            indicators.append(self._indicator(
                "browser_download_detected", "high",
                "The inspected page attempted a download; the file was captured inertly.",
                {"count": len(downloads), "executed": False},
            ))
        if len(redirects) > 1:
            indicators.append(self._indicator(
                "multiple_redirects", "medium",
                "The page used multiple redirects before reaching its final location.",
                {"count": len(redirects)},
            ))
        final_url = fixture.get("final_url", redirects[-1].target if redirects else decision.destination_url)
        return BrowserInspection(
            scan_id=scan_id, url=decision.destination_url, final_url=final_url,
            page_title=fixture.get("page_title"), status_code=fixture.get("status_code", 200),
            redirects=redirects, login_forms=login_forms,
            credential_requests=credential_requests, downloads=downloads,
            suspicious_scripts=fixture.get("suspicious_scripts", []),
            network_events=fixture.get("network_events", []),
            screenshots=fixture.get("screenshots", []),
            indicators=indicators,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    async def _inspect_live(self, scan_id: str, url: str) -> BrowserInspection:
        decision = self.gateway.validate(url)
        try:
            from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
        except ImportError as exc:
            raise BrowserInspectionError(
                "Playwright is not installed; use browser extras or simulate mode"
            ) from exc

        started = time.monotonic()
        redirects: list[RedirectObservation] = []
        downloads: list[dict] = []
        network_events: list[dict] = []
        indicators: list[BrowserIndicator] = []
        with tempfile.TemporaryDirectory(prefix="trustshield-browser-") as artifact_dir:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True, downloads_path=artifact_dir,
                )
                context = await browser.new_context(
                    accept_downloads=True, service_workers="block",
                )
                page = await context.new_page()
                page.set_default_timeout(self.config.timeout_seconds * 1000)

                async def request_listener(request):
                    network_events.append({"url": request.url, "method": request.method})

                async def download_listener(download):
                    size_bytes = None
                    try:
                        path = await download.path()
                        size_bytes = Path(path).stat().st_size if path else None
                    except Exception:
                        size_bytes = None
                    downloads.append({
                        "suggested_filename": download.suggested_filename,
                        "path_captured": True, "size_bytes": size_bytes, "executed": False,
                        "within_limit": size_bytes is None or size_bytes <= self.config.max_download_size_mb * 1024 * 1024,
                    })

                async def route_handler(route):
                    try:
                        self.gateway.validate(route.request.url)
                    except URLValidationError:
                        await route.abort()
                        return
                    await route.continue_()

                async def response_listener(response):
                    if response.request.is_navigation_request() and 300 <= response.status < 400:
                        target = response.headers.get("location")
                        if target and len(redirects) < self.config.max_redirects:
                            redirects.append(RedirectObservation(
                                source=response.url, target=target, status_code=response.status,
                                depth=len(redirects) + 1,
                            ))

                page.on("request", request_listener)
                page.on("download", download_listener)
                page.on("response", response_listener)
                await page.route("**/*", route_handler)
                try:
                    response = await page.goto(
                        decision.destination_url, wait_until="domcontentloaded",
                        timeout=self.config.timeout_seconds * 1000,
                    )
                    final_url = page.url
                    title = await page.title()
                    login_forms = await page.locator("form").evaluate_all(
                        "(forms) => forms.filter(f => f.querySelector('input[type=password]')).map(f => ({action: f.action}))"
                    )
                    credential_requests = await page.locator("input[type=password]").count()
                    if login_forms or credential_requests:
                        indicators.append(self._indicator(
                            "browser_credential_collection", "high",
                            "The inspected page contains a password field or login form.",
                            {"login_forms": len(login_forms), "password_fields": credential_requests},
                        ))
                    if self.config.screenshot:
                        screenshot_path = str(Path(artifact_dir) / "page.png")
                        await page.screenshot(path=screenshot_path, full_page=False)
                        # Return an opaque artifact name, never a host path.
                        screenshots = ["page.png"]
                    else:
                        screenshots = []
                    if downloads:
                        indicators.append(self._indicator(
                            "browser_download_detected", "high",
                            "The page attempted a download; content was not executed.",
                            {"count": len(downloads), "executed": False},
                        ))
                    return BrowserInspection(
                        scan_id=scan_id, url=decision.destination_url, final_url=final_url,
                        page_title=title, status_code=response.status if response else None,
                        redirects=redirects, login_forms=login_forms,
                        credential_requests=[{"count": credential_requests}],
                        downloads=downloads, network_events=network_events,
                        screenshots=screenshots, indicators=indicators,
                        duration_ms=int((time.monotonic() - started) * 1000),
                    )
                except PlaywrightTimeout:
                    return BrowserInspection(
                        scan_id=scan_id, url=decision.destination_url,
                        inspection_status="timeout", network_events=network_events,
                        downloads=downloads, duration_ms=int((time.monotonic() - started) * 1000),
                        error="browser inspection timed out",
                    )
                finally:
                    await context.close()
                    await browser.close()

    def inspect(self, scan_id: str, url: str, *, simulate: bool = True,
                fixture: dict | None = None) -> BrowserInspection:
        """Inspect a validated URL; simulation is the safe default."""
        if simulate:
            return self.inspect_fixture(scan_id, url, fixture or {})
        self.gateway.validate(url)
        try:
            return asyncio.run(self._inspect_live(scan_id, url))
        except URLValidationError:
            raise
        except Exception as exc:
            raise BrowserInspectionError(str(exc)) from exc
