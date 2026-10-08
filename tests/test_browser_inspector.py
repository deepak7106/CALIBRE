from fastapi.testclient import TestClient

from trustshield.api.app import create_app
from trustshield.browser import BrowserInspector


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
