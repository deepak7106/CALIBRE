from fastapi.testclient import TestClient

from trustshield.api.app import create_app


def test_url_api_correlates_repeated_domain_into_campaign(tmp_path):
    client = TestClient(create_app(tmp_path / "campaign.db"))
    first = client.post("/api/analyze/url", json={"url": "https://campaign.test/login"}).json()
    second = client.post("/api/analyze/url", json={"url": "https://campaign.test/login?step=2"}).json()

    graph = client.get(f"/messages/{second['scan_id']}/trustgraph").json()
    campaign_nodes = [node for node in graph["nodes"] if node["type"] == "campaign"]
    assert campaign_nodes
    assert any(edge["relationship"] == "belongs_to_campaign" for edge in graph["edges"])
