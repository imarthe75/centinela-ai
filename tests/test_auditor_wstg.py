"""
Centinela-AI — Unit and Integration Tests for OWASP WSTG v4.2 / ASVS v4.0 Perimeter Auditor
"""
import pytest
from unittest.mock import MagicMock, patch
import requests

from auditors import auditor_wstg, compliance_mapper
import centinela


class MockResponse:
    def __init__(self, status_code=200, text="", headers=None, url="http://192.0.2.23/login/"):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.request = MagicMock()
        self.request.method = "GET"
        self.request.url = url


def test_wstg_cleartext_login_and_unencrypted_cookie():
    """Validates detection of plain HTTP login and unencrypted session cookies (WSTG-ATHN-02 & WSTG-CRYP-03)."""
    mock_resp = MockResponse(
        status_code=200,
        text="<html><body><form method='POST' action='/login/'><input name='username'></form></body></html>",
        headers={
            "Set-Cookie": "session=eyJhbGciOi...; Path=/; HttpOnly",  # Missing Secure & SameSite
            "Server": "nginx/1.27.5",
        },
        url="http://192.0.2.23/login/",
    )

    with patch.object(requests.Session, "get", return_value=mock_resp), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)), \
         patch.object(requests.Session, "post", return_value=MockResponse(status_code=401)):

        findings = auditor_wstg.audit_url_wstg("http://192.0.2.23/login/")
        cves = [f["cve_id"] for f in findings]

        assert "WSTG-ATHN-02-CLEARTEXT-LOGIN" in cves
        assert "WSTG-CRYP-03-UNENCRYPTED-CHANNEL" in cves
        assert "WSTG-SESS-02-COOKIE-SAMESITE" in cves
        assert "WSTG-INFO-02-SERVER-BANNER-LEAK" in cves


def test_wstg_host_header_injection_reflected():
    """Validates detection of Host Header Injection in Location redirect (WSTG-INPV-17)."""
    def mock_get(url, *args, **kwargs):
        headers = kwargs.get("headers", {})
        if "canary-centinela-eval.internal" in headers.get("Host", ""):
            return MockResponse(
                status_code=302,
                headers={"Location": "/login/?next=http://canary-centinela-eval.internal/superset/log/"},
            )
        return MockResponse(status_code=200, headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})

    with patch.object(requests.Session, "get", side_effect=mock_get), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)), \
         patch.object(requests.Session, "post", return_value=MockResponse(status_code=401)):

        findings = auditor_wstg.audit_url_wstg("https://192.0.2.23/login/")
        cves = [f["cve_id"] for f in findings]

        assert "WSTG-INPV-17-HOST-HEADER-INJECTION" in cves


def test_wstg_dangerous_connect_method():
    """Validates detection of unrejected HTTP CONNECT method (WSTG-CONF-06)."""
    # 200 OK or 502 means CONNECT was accepted or attempted by proxy rather than rejected with 405
    connect_resp = MockResponse(status_code=200)

    with patch.object(requests.Session, "get", return_value=MockResponse(status_code=200, headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})), \
         patch.object(requests.Session, "send", return_value=connect_resp), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)), \
         patch.object(requests.Session, "post", return_value=MockResponse(status_code=401)):

        findings = auditor_wstg.audit_url_wstg("https://192.0.2.23/")
        cves = [f["cve_id"] for f in findings]

        assert "WSTG-CONF-06-DANGEROUS-HTTP-METHOD" in cves


def test_wstg_open_redirect_detection():
    """Validates detection of Client Side URL Redirect (WSTG-CLNT-04)."""
    def mock_get(url, *args, **kwargs):
        if "next=http://canary-centinela-eval.internal" in url or "next=//canary-centinela-eval.internal" in url:
            return MockResponse(
                status_code=302,
                headers={"Location": "http://canary-centinela-eval.internal/auth/callback"},
            )
        return MockResponse(status_code=200, headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})

    with patch.object(requests.Session, "get", side_effect=mock_get), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)), \
         patch.object(requests.Session, "post", return_value=MockResponse(status_code=401)):

        findings = auditor_wstg.audit_url_wstg("https://192.0.2.23/login/")
        cves = [f["cve_id"] for f in findings]

        assert "WSTG-CLNT-04-OPEN-REDIRECT" in cves


def test_wstg_improper_error_handling_superset_json():
    """Validates detection of Superset / Flask internal error codes in 405 response (WSTG-ERRH-01)."""
    superset_err_body = (
        '{"errors": [{"message": "405 Method Not Allowed: The method is not allowed for the requested URL.", '
        '"error_type": "GENERIC_BACKEND_ERROR", "level": "error", "extra": {"issue_codes": [{"code": 1011, '
        '"message": "Issue 1011 - Superset ha encontrado un error inesperado."}]}}]}'
    )
    err_resp = MockResponse(status_code=405, text=superset_err_body, url="https://192.0.2.23/superset/log/?explode=events")
    err_resp.request.method = "PATCH"

    with patch.object(requests.Session, "get", return_value=MockResponse(status_code=200, headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=err_resp), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)), \
         patch.object(requests.Session, "post", return_value=MockResponse(status_code=401)):

        findings = auditor_wstg.audit_url_wstg("https://192.0.2.23/")
        cves = [f["cve_id"] for f in findings]

        assert "WSTG-ERRH-01-VERBOSE-BACKEND-ERROR" in cves


def test_wstg_insecure_cors_reflection():
    """Validates detection of insecure CORS origin reflection (WSTG-CLNT-07)."""
    cors_resp = MockResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "https://canary-evil.internal",
            "Access-Control-Allow-Credentials": "true",
        },
    )

    with patch.object(requests.Session, "get", return_value=MockResponse(status_code=200, headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=cors_resp), \
         patch.object(requests.Session, "post", return_value=MockResponse(status_code=401)):

        findings = auditor_wstg.audit_url_wstg("https://192.0.2.23/")
        cves = [f["cve_id"] for f in findings]

        assert "WSTG-CLNT-07-INSECURE-CORS" in cves


def test_wstg_sensitive_files_exposure():
    """Validates detection of exposed .env or .git/HEAD files (WSTG-CONF-04)."""
    def mock_get(url, *args, **kwargs):
        if url.endswith("/.env"):
            return MockResponse(status_code=200, text="SECRET_KEY=supersecretkey\nDB_PASSWORD=adminpass", url=url)
        return MockResponse(status_code=404, url=url)

    with patch.object(requests.Session, "get", side_effect=mock_get), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)), \
         patch.object(requests.Session, "post", return_value=MockResponse(status_code=401)):

        findings = auditor_wstg.audit_url_wstg("https://192.0.2.23/")
        cves = [f["cve_id"] for f in findings]

        assert "WSTG-CONF-04-SENSITIVE-FILES" in cves


def test_wstg_debug_endpoints_exposure():
    """Validates detection of exposed /metrics or actuator (WSTG-CONF-05)."""
    def mock_get(url, *args, **kwargs):
        if url.endswith("/metrics"):
            return MockResponse(status_code=200, text="# HELP http_requests_total\n# TYPE http_requests_total counter", url=url)
        return MockResponse(status_code=404, url=url)

    with patch.object(requests.Session, "get", side_effect=mock_get), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)), \
         patch.object(requests.Session, "post", return_value=MockResponse(status_code=401)):

        findings = auditor_wstg.audit_url_wstg("https://192.0.2.23/")
        cves = [f["cve_id"] for f in findings]

        assert "WSTG-CONF-05-DEBUG-ENDPOINTS" in cves


def test_wstg_default_credentials_check(monkeypatch):
    """Validates single check for factory admin:admin credentials (WSTG-AUTH-02) -- opt-in only."""
    monkeypatch.setenv("WSTG_DEFAULT_CRED_PROBE", "1")
    mock_login_resp = MockResponse(
        status_code=302,
        headers={"Location": "/superset/welcome/", "Set-Cookie": "session=authenticated_cookie"},
        url="https://192.0.2.23/login/",
    )

    with patch.object(requests.Session, "get", return_value=MockResponse(status_code=200, headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)), \
         patch.object(requests.Session, "post", return_value=mock_login_resp):

        findings = auditor_wstg.audit_url_wstg("https://192.0.2.23/")
        cves = [f["cve_id"] for f in findings]

        assert "WSTG-AUTH-02-DEFAULT-CREDENTIALS" in cves


def test_wstg_default_credentials_probe_is_off_by_default(monkeypatch):
    monkeypatch.delenv("WSTG_DEFAULT_CRED_PROBE", raising=False)
    with patch.object(requests.Session, "get", return_value=MockResponse(status_code=200, headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)), \
         patch.object(requests.Session, "post") as post:
        findings = auditor_wstg.audit_url_wstg("https://192.0.2.23/")
        post.assert_not_called()
        assert "WSTG-AUTH-02-DEFAULT-CREDENTIALS" not in [f["cve_id"] for f in findings]


def test_centinela_remediation_generation_for_wstg():
    """Validates that centinela generates idempotent bash scripts and analyses for WSTG findings."""
    vuln_cve = {
        "cve_id": "WSTG-ATHN-02-CLEARTEXT-LOGIN",
        "asset_name": "proyecto-k-Conciliacion",
        "endpoint": "192.0.2.23",
        "severity": "High",
        "description": "Formulario transmitido por HTTP sin TLS",
    }
    script = centinela.generate_heuristic_script(vuln_cve)
    assert "return 301 https://$host$request_uri;" in script
    assert "Strict-Transport-Security" in script
    assert centinela.heuristic_can_automate(vuln_cve) is True

    riesgo, impacto, accion = centinela.generate_heuristic_analysis(vuln_cve)
    assert "WSTG-ATHN-02" in riesgo
    assert "redirección obligatoria 301" in accion


def test_compliance_matrix_wstg_mappings():
    """Validates that all WSTG rules are correctly mapped in COMPLIANCE_MAPPING_MATRIX."""
    wstg_rules = [
        "WSTG-ATHN-02-CLEARTEXT-LOGIN",
        "WSTG-CRYP-03-UNENCRYPTED-CHANNEL",
        "WSTG-INPV-17-HOST-HEADER-INJECTION",
        "WSTG-CONF-06-DANGEROUS-HTTP-METHOD",
        "WSTG-CLNT-04-OPEN-REDIRECT",
        "WSTG-INFO-02-SERVER-BANNER-LEAK",
        "WSTG-INFO-08-FRAMEWORK-FINGERPRINT",
        "WSTG-ERRH-01-VERBOSE-BACKEND-ERROR",
        "WSTG-CLNT-07-INSECURE-CORS",
        "WSTG-CONF-04-SENSITIVE-FILES",
        "WSTG-CONF-05-DEBUG-ENDPOINTS",
        "WSTG-SESS-02-COOKIE-SAMESITE",
        "WSTG-CONF-07-INCOMPLETE-HSTS",
        "WSTG-CLNT-09-DUPLICATE-OR-WEAK-FRAME-OPTIONS",
        "WSTG-AUTH-02-DEFAULT-CREDENTIALS",
    ]
    for rule in wstg_rules:
        assert rule in compliance_mapper.COMPLIANCE_MAPPING_MATRIX, f"Missing {rule} in COMPLIANCE_MAPPING_MATRIX"
        entry = compliance_mapper.COMPLIANCE_MAPPING_MATRIX[rule]
        assert "ISO_27001" in entry
        assert "NIST_800_53" in entry
        assert "OWASP_ASVS" in entry
        assert "OWASP_WSTG" in entry


def test_wstg_open_redirect_not_flagged_when_query_string_is_merely_echoed():
    """http->https redirects that keep the query string contain the canary text but redirect to the same host."""
    echo = MockResponse(status_code=301, headers={"Location": "https://192.0.2.23/login/?next=http://canary-centinela-eval.internal/auth/callback",
                                                   "Strict-Transport-Security": "max-age=31536000"})
    with patch.object(requests.Session, "get", return_value=echo), \
         patch.object(requests.Session, "send", return_value=MockResponse(status_code=405)), \
         patch.object(requests.Session, "request", return_value=MockResponse(status_code=404)), \
         patch.object(requests.Session, "options", return_value=MockResponse(status_code=200)):
        cves = [f["cve_id"] for f in auditor_wstg.audit_url_wstg("https://192.0.2.23/")]
    assert "WSTG-CLNT-04-OPEN-REDIRECT" not in cves
