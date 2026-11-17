"""core.asset_types: shared host-type groups, the URL target of URL assets and the public-target guard (2026-11-13)."""
from unittest import mock

from core import asset_types


def test_form_server_types_are_scanned():
    assert "SERVER_LINUX" in asset_types.NETWORK_HOST_TYPES and "SERVER_WINDOWS" in asset_types.NETWORK_HOST_TYPES
    assert "SERVER_LINUX" in asset_types.LINUX_HOST_TYPES and "SERVER_WINDOWS" not in asset_types.LINUX_HOST_TYPES
    from auditors import auditor_ext
    assert "SERVER_LINUX" in auditor_ext._SCANNABLE_TYPES and "SERVER_WINDOWS" in auditor_ext._SCANNABLE_TYPES


def test_url_target_uses_the_name_when_the_endpoint_is_only_the_host():
    name = "http://192.0.2.12/fe-app/auth/login"
    assert asset_types.url_scan_target(name, "192.0.2.12") == name
    assert asset_types.url_scan_target(name, "https://192.0.2.12/x") == "https://192.0.2.12/x"   # endpoint already a URL
    assert asset_types.url_scan_target("http://other.host/app", "192.0.2.12") == "http://192.0.2.12"  # different host
    assert asset_types.url_scan_target("portal", "192.0.2.12:8080") == "http://192.0.2.12:8080"


def _resolves_to(ip):
    return mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", (ip, 0))])


def test_public_targets_need_explicit_authorization(monkeypatch):
    monkeypatch.delenv("SCAN_ALLOWED_PUBLIC_TARGETS", raising=False)
    with _resolves_to("103.103.103.100"):
        ok, reason = asset_types.scan_target_allowed("103.103.103.100")
    assert ok is False and "SCAN_ALLOWED_PUBLIC_TARGETS" in reason
    monkeypatch.setenv("SCAN_ALLOWED_PUBLIC_TARGETS", "portal.example.org, 103.103.103.100")
    with _resolves_to("103.103.103.100"):
        assert asset_types.scan_target_allowed("https://103.103.103.100/x")[0] is True


def test_internal_and_non_network_targets_pass(monkeypatch):
    monkeypatch.delenv("SCAN_ALLOWED_PUBLIC_TARGETS", raising=False)
    with _resolves_to("192.0.2.16"):
        assert asset_types.scan_target_allowed("192.0.2.16")[0] is True
    assert asset_types.scan_target_allowed("remote-agent")[0] is True
    with _resolves_to("127.0.0.1"):
        assert asset_types.scan_target_allowed("localhost")[0] is False


def test_dispatcher_skips_a_public_target_without_scanning(monkeypatch):
    from auditors import auditor_ext
    monkeypatch.delenv("SCAN_ALLOWED_PUBLIC_TARGETS", raising=False)
    called, logged = [], []
    monkeypatch.setattr(auditor_ext, "scan_appserver", lambda *a: called.append(a))
    monkeypatch.setattr(auditor_ext.auditor_api_fuzz, "run_for_asset", lambda *a: called.append(a))
    monkeypatch.setattr(auditor_ext, "log_audit", lambda aid, msg: logged.append(msg))
    with _resolves_to("103.103.103.100"):
        auditor_ext._dispatch_asset_scan({"id": "a1", "type": "SERVER_LINUX", "endpoint": "103.103.103.100"})
    assert called == [] and "NO ejecutado" in logged[0]


def test_dispatcher_scans_the_url_asset_by_its_full_url(monkeypatch):
    from auditors import auditor_ext
    seen = []
    monkeypatch.setattr(auditor_ext, "scan_url", lambda aid, url: seen.append(url))
    for fn in ("_run_authz_dast", "_run_runtime_session"):
        monkeypatch.setattr(auditor_ext, fn, lambda *a: None)
    monkeypatch.setattr(auditor_ext.auditor_api_fuzz, "run_for_asset", lambda *a: None)
    monkeypatch.setattr(auditor_ext.auditor_nuclei_dast, "run_for_asset", lambda *a: None)
    with _resolves_to("192.0.2.12"):
        auditor_ext._dispatch_asset_scan({"id": "a2", "type": "URL", "endpoint": "192.0.2.12",
                                          "name": "http://192.0.2.12/fe-app/auth/login"})
    assert seen == ["http://192.0.2.12/fe-app/auth/login"]
