from trustshield.engine.pipeline import analyze
from trustshield.models import MessageInput
from trustshield.stages.preprocessing import mask_pii
from trustshield.stages.file_analysis import FileAnalysisStage
from trustshield.stages.url_analysis import URLAnalysisStage
from trustshield.stages.sender_trust import SenderTrustStage
from trustshield.models import AnalysisContext
from trustshield.reasoners.openrouter import OpenRouterReasoner


def test_pii_is_masked():
    assert mask_pii("email a@example.com and card 4111 1111 1111 1111") == (
        "email [EMAIL] and card [CARD]"
    )


def test_consent_gate_rejects_without_analysis():
    result = analyze(MessageInput(sender="a@example.com", text="hello"))
    assert result.stages[0].status == "rejected"
    assert result.risk_level == "LOW"


def test_phishing_end_to_end():
    result = analyze(MessageInput(
        sender="alerts@example.com",
        text="Urgent: verify your bank password immediately by signing in.",
        consent=True,
    ))
    assert result.category == "Phishing"
    assert result.risk_level in {"MEDIUM", "HIGH", "CRITICAL"}
    assert result.indicators
    assert result.indicators[0].id.startswith("ind-")
    assert result.indicators[0].id in result.explanation


def test_legitimate_end_to_end():
    result = analyze(MessageInput(
        sender="colleague@example.com",
        text="Please review the meeting agenda before lunch.",
        consent=True,
    ))
    assert result.category == "Legitimate"
    assert result.risk_level == "LOW"


def test_url_blocklist_and_private_target():
    result = analyze(MessageInput(
        sender="unknown@example.com", text="open http://phishing.test/login",
        urls=["http://phishing.test/login", "http://127.0.0.1/admin"], consent=True,
    ))
    names = {indicator.name for indicator in result.indicators}
    assert "local_threat_intel_match" in names
    assert "private_or_internal_target" in names


def test_file_static_analysis_never_executes():
    result = analyze(MessageInput(
        sender="unknown@example.com", text="see attached file",
        attachments=[{"name": "invoice.docm", "content": "vbaProject AutoOpen", "content_type": "application/octet-stream"}],
        consent=True,
    ))
    names = {indicator.name for indicator in result.indicators}
    assert "embedded_macro_or_script" in names
    assert "unapproved_attachment_type" in names


def test_remote_reasoner_uses_free_models_and_masked_prompt():
    reasoner = OpenRouterReasoner()
    assert all(model.endswith(":free") or model == "openrouter/free" for model in reasoner.models)
    prompt = reasoner._prompt("[EMAIL]", [{"id": "ind-1", "name": "credential_request"}])
    assert "[EMAIL]" in prompt
    assert "credential_request" in prompt
