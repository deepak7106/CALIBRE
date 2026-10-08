from fastapi.testclient import TestClient

from trustshield.api.app import create_app
from trustshield.engine.pipeline import analyze
from trustshield.models import MessageInput


def test_identity_detects_new_financial_request():
    result = analyze(MessageInput(
        sender="manager@example.com",
        text="Urgent, send a wire transfer immediately.",
        metadata={"sender_history": {
            "known_contact": True,
            "request_types": ["other"],
            "style_features": {"length": 20, "sentence_length": 4, "punctuation": 0, "urgency": 0},
        }},
        consent=True,
    ))
    names = {item.name for item in result.indicators}
    assert "sudden_request_type_change" in names
    assert result.explanation_data["reasons"]


def test_missing_identity_history_sets_uncertainty():
    result = analyze(MessageInput(sender="unknown@example.com", text="hello", consent=True))
    assert result.uncertainty is True
    assert any(stage.stage == "identity_behavior" and stage.status == "unknown" for stage in result.stages)


def test_pipeline_builds_evidence_backed_trustgraph():
    result = analyze(MessageInput(
        sender="unknown@example.com",
        text="open https://phishing.test/login",
        urls=["https://phishing.test/login"],
        consent=True,
    ))
    assert result.trust_graph["nodes"]
    assert any(edge["relationship"] == "links_to" for edge in result.trust_graph["edges"])
    assert any(edge["relationship"] == "triggered" for edge in result.trust_graph["edges"])


def test_trustgraph_timeline_and_explanation_endpoints(tmp_path):
    client = TestClient(create_app(tmp_path / "phase4.db"))
    created = client.post("/api/analyze/url", json={"url": "https://phishing.test/login"}).json()
    scan_id = created["scan_id"]

    graph = client.get(f"/messages/{scan_id}/trustgraph")
    timeline = client.get(f"/messages/{scan_id}/timeline")
    explanation = client.get(f"/messages/{scan_id}/explanation")

    assert graph.status_code == 200
    assert any(node["type"] == "domain" for node in graph.json()["nodes"])
    assert timeline.json()["timeline"]
    assert explanation.json()["reasons"]
