from fastapi.testclient import TestClient

from trustshield.api.app import create_app


def test_url_api_scans_without_opening_destination(tmp_path):
    client = TestClient(create_app(tmp_path / "api.db"))
    response = client.post("/api/analyze/url", json={"url": "https://example.com/login"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "complete"
    assert body["analysis"]["risk_level"] == "LOW"
    assert body["analysis"]["stages"][0]["stage"] == "url_analysis"
    assert body["analysis"]["stages"][0]["data"]["url_evidence"][0]["domain"] == "example.com"
    assert body["analysis"]["stages"][0]["data"]["url_evidence"][0]["url"].startswith("https://")
    assert any(stage["stage"] == "browser_inspection" for stage in body["analysis"]["stages"])


def test_shortener_is_inspected_but_not_marked_malicious_by_itself(tmp_path):
    client = TestClient(create_app(tmp_path / "api.db"))
    response = client.post("/api/analyze/url", json={"url": "https://tinyurl.com/Stack-0610-EX"})

    assert response.status_code == 200
    body = response.json()
    names = {item["name"] for item in body["analysis"]["indicators"]}
    assert "url_shortener_detected" in names
    assert body["analysis"]["risk_level"] != "CRITICAL"


def test_url_api_returns_blocklist_evidence(tmp_path):
    client = TestClient(create_app(tmp_path / "api.db"))
    response = client.post("/api/analyze/url", json={"url": "https://phishing.test/login"})

    assert response.status_code == 200
    body = response.json()
    assert body["analysis"]["risk_level"] == "CRITICAL"
    assert any(item["name"] == "local_threat_intel_match" for item in body["analysis"]["indicators"])


def test_url_api_rejects_private_destinations(tmp_path):
    client = TestClient(create_app(tmp_path / "api.db"))
    response = client.post("/api/analyze/url", json={"url": "https://127.0.0.1/admin"})
    assert response.status_code == 422


def test_url_api_retrieves_persisted_scan_and_evidence(tmp_path):
    client = TestClient(create_app(tmp_path / "api.db"))
    created = client.post("/api/analyze/url", json={"url": "https://example.com"}).json()

    scan = client.get(f"/api/scan/{created['scan_id']}")
    evidence = client.get(f"/api/scan/{created['scan_id']}/evidence")

    assert scan.status_code == 200
    assert evidence.status_code == 200
    assert evidence.json()["scan_id"] == created["scan_id"]


def test_url_api_returns_not_found(tmp_path):
    client = TestClient(create_app(tmp_path / "api.db"))
    assert client.get("/api/scan/scan-missing").status_code == 404
