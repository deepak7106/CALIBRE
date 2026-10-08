from fastapi.testclient import TestClient

from trustshield.api.app import create_app
from trustshield.browser import BrowserInspection, BrowserInspector
from trustshield.browser.inspector import BrowserInspectionError


def test_simulated_browser_detects_login_redirect_and_download():
    inspection = BrowserInspector().inspect(
        "scan-test", "https://example.com/start", simulate=True, fixture={
            "final_url": "https://login.example.com/",
            "page_title": "Verify account",
            "redirects": [{
                "source": "https://example.com/start",
                "target": "https://login.example.com/",
                "status_code": 302,
            }],
            "login_forms": [{"action": "/login"}],
            "credential_requests": [{"field": "password"}],
            "downloads": [{"suggested_filename": "invoice.txt", "executed": False}],
        },
    )
    assert inspection.final_url == "https://login.example.com/"
    assert inspection.login_forms
    assert inspection.downloads[0]["executed"] is False
    assert {item.name for item in inspection.indicators} >= {
        "browser_credential_collection", "browser_download_detected",
    }


def test_browser_api_uses_offline_simulation(tmp_path):
    client = TestClient(create_app(tmp_path / "browser.db"))
    created = client.post("/api/analyze/url", json={"url": "https://example.com"}).json()
    scan_id = created["scan_id"]
    response = client.post(f"/api/scan/{scan_id}/inspect", json={
        "simulate": True,
        "fixture": {"page_title": "Safe fixture", "status_code": 200},
    })
    assert response.status_code == 200
    assert response.json()["page_title"] == "Safe fixture"
    assert client.get(f"/api/scan/{scan_id}/inspection").status_code == 200


def test_browser_fixture_final_destination_is_analyzed_before_verdict(tmp_path):
    client = TestClient(create_app(tmp_path / "browser-final.db"))
    response = client.post("/api/analyze/url", json={
        "url": "https://tinyurl.com/demo",
        "browser_fixture": {
            "final_url": "https://phishing.test/login",
            "login_forms": [{"action": "/login"}],
        },
    })
    assert response.status_code == 200
    body = response.json()
    assert body["analysis"]["risk_level"] == "CRITICAL"
    assert any(item["name"] == "browser_credential_collection" for item in body["analysis"]["indicators"])
    assert any(stage["stage"] == "final_destination_analysis" for stage in body["analysis"]["stages"])


def test_browser_inspection_failure_is_explicit_and_uncertain(tmp_path, monkeypatch):
    client = TestClient(create_app(tmp_path / "browser-failure.db"))

    def fail(*args, **kwargs):
        raise BrowserInspectionError("browser unavailable")

    monkeypatch.setattr(BrowserInspector, "inspect", fail)
    response = client.post("/api/analyze/url", json={
        "url": "https://tinyurl.com/unavailable",
    })

    assert response.status_code == 200
    body = response.json()
    browser_stage = next(
        stage for stage in body["analysis"]["stages"]
        if stage["stage"] == "browser_inspection"
    )
    assert browser_stage["status"] == "unknown"
    assert browser_stage["error"] == "browser unavailable"
    assert "destination_inspection_incomplete" in {
        item["name"] for item in body["analysis"]["indicators"]
    }
    assert body["analysis"]["uncertainty"] is True
    assert body["analysis"]["category"] == "Suspicious"
    assert body["analysis"]["risk_level"] == "MEDIUM"
    assert "final destination could not be verified" in body["analysis"]["explanation"]


def test_tinyurl_download_fixture_returns_complete_scan(tmp_path):
    client = TestClient(create_app(tmp_path / "tinyurl-regression.db"))
    response = client.post("/api/analyze/url", json={
        "url": "https://tinyurl.com/Stack-0610-EX",
        "browser_fixture": {
            "downloads": [{
                "suggested_filename": "assessment_6102.seb",
                "executed": False,
            }],
            "indicators": [{
                "id": "fixture-download",
                "name": "browser_download_detected",
                "severity": "high",
                "description": "A download was intercepted.",
                "evidence": {"executed": False},
            }],
        },
    })
    assert response.status_code == 200
    body = response.json()
    assert body["analysis"]["stages"][0]["status"] == "ok"
    assert any(
        stage["stage"] == "browser_inspection"
        for stage in body["analysis"]["stages"]
    )
    assert "browser_download_detected" in {
        item["name"] for item in body["analysis"]["indicators"]
    }


def test_download_analysis_failure_is_structured(monkeypatch):
    from trustshield.browser import inspector as inspector_module

    original = inspector_module.analyze_download

    def fail(*args, **kwargs):
        raise ValueError("malformed fixture")

    monkeypatch.setattr(inspector_module, "analyze_download", fail)
    try:
        inspection = BrowserInspector().inspect(
            "scan-failure", "https://example.com/file", simulate=True,
            fixture={"downloads": [{"suggested_filename": "file.bin"}]},
        )
        assert inspection.inspection_status == "complete"
    finally:
        monkeypatch.setattr(inspector_module, "analyze_download", original)


def test_browser_timeout_is_normalized_to_unknown(tmp_path, monkeypatch):
    client = TestClient(create_app(tmp_path / "browser-timeout.db"))

    def timeout(*args, **kwargs):
        return BrowserInspection(
            scan_id="timeout",
            url="https://example.com",
            inspection_status="unknown",
            error="browser inspection timed out",
        )

    monkeypatch.setattr(BrowserInspector, "inspect", timeout)
    response = client.post("/api/analyze/url", json={"url": "https://example.com"})

    assert response.status_code == 200
    body = response.json()
    stage = next(item for item in body["analysis"]["stages"] if item["stage"] == "browser_inspection")
    assert stage["status"] == "unknown"
    assert stage["error"] == "browser inspection timed out"
    assert body["analysis"]["uncertainty"] is True
    assert body["analysis"]["category"] == "Suspicious"


def test_cancelled_download_preserves_capture_diagnostic(tmp_path):
    client = TestClient(create_app(tmp_path / "cancelled-download.db"))
    response = client.post("/api/analyze/url", json={
        "url": "https://example.com",
        "browser_fixture": {
            "downloads": [{
                "suggested_filename": "cancelled.bin",
                "path_captured": False,
                "executed": False,
                "analysis_error": "download capture/static analysis failed: Error",
            }],
            "indicators": [{
                "id": "fixture-download-cancelled",
                "name": "browser_download_detected",
                "severity": "high",
                "description": "A download was observed.",
                "evidence": {"executed": False},
            }, {
                "id": "fixture-capture-incomplete",
                "name": "download_capture_incomplete",
                "severity": "medium",
                "description": "The download artifact was unavailable.",
                "evidence": {},
            }],
        },
    })

    assert response.status_code == 200
    names = {item["name"] for item in response.json()["analysis"]["indicators"]}
    assert {"browser_download_detected", "download_capture_incomplete"} <= names


def test_unverified_download_is_suspicious_not_malware(tmp_path):
    client = TestClient(create_app(tmp_path / "unverified-download.db"))
    response = client.post("/api/analyze/url", json={
        "url": "https://amtso.eicar.org/eicar.com",
        "browser_fixture": {
            "downloads": [{"suggested_filename": "eicar.com"}],
            "indicators": [{
                "id": "fixture-download",
                "name": "browser_download_detected",
                "severity": "high",
                "description": "A download was intercepted.",
                "evidence": {"executed": False},
            }, {
                "id": "fixture-incomplete",
                "name": "destination_inspection_incomplete",
                "severity": "medium",
                "description": "The document destination was not verified.",
                "evidence": {},
            }],
        },
    })
    body = response.json()
    assert body["analysis"]["category"] == "Suspicious"
    assert body["analysis"]["risk_level"] != "CRITICAL"
    assert body["analysis"]["uncertainty"] is True


def test_explanation_does_not_claim_shortener_without_current_indicator(tmp_path):
    client = TestClient(create_app(tmp_path / "fresh-explanation.db"))
    response = client.post("/api/analyze/url", json={
        "url": "https://amtso.eicar.org/eicar.com",
        "browser_fixture": {
            "indicators": [{
                "id": "fixture-incomplete",
                "name": "destination_inspection_incomplete",
                "severity": "medium",
                "description": "The document destination was not verified.",
                "evidence": {},
            }],
        },
    })
    body = response.json()
    assert "shortening service" not in body["analysis"]["explanation_data"]["uncertainties"][0]["text"]
