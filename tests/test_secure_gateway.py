import pytest

from trustshield.gateway import SecureURLGateway, URLValidationError


def test_gateway_encodes_destination_and_does_not_open_it():
    decision = SecureURLGateway().validate("https://example.com/login?next=%2Faccount")

    assert decision.scan_url.startswith("/scan?url=https%3A%2F%2Fexample.com")
    assert "%2Flogin%3Fnext%3D%252Faccount" in decision.scan_url
    assert decision.status == "awaiting_analysis"
    assert decision.network_access_performed is False


@pytest.mark.parametrize("url", [
    "javascript:alert(1)",
    "data:text/html,unsafe",
    "file:///C:/secret.txt",
    "vbscript:msgbox(1)",
    "http://example.com",
    "https://user:password@example.com/",
])
def test_gateway_rejects_unsafe_protocols_and_authority(url):
    with pytest.raises(URLValidationError):
        SecureURLGateway().validate(url)


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/admin",
    "https://10.0.0.5/",
    "https://[::1]/",
    "https://localhost/",
    "https://service.internal/",
])
def test_gateway_blocks_ssrf_targets(url):
    with pytest.raises(URLValidationError):
        SecureURLGateway().validate(url)


def test_gateway_flags_suspicious_port_without_fetching():
    decision = SecureURLGateway().validate("https://example.com:22/")
    assert decision.warnings == ["suspicious destination port: 22"]
