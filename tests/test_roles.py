"""Role-based permissions by function (core/roles.py) and their enforcement in the API middleware."""
import pytest
from fastapi.testclient import TestClient

from core import auth, roles


def claims(*groups):
    return {"sub": "u1", "preferred_username": "u1", "groups": list(groups)}


def test_role_of_takes_the_highest_group_and_service_token_is_admin():
    assert roles.role_of(claims("Centinela Viewer", "Centinela Analyst", "Superset Admin")) == "Analyst"
    assert roles.role_of(claims("org", "proyecto-g")) is None
    assert roles.role_of({"sub": "service-token"}) == "Admin"


@pytest.mark.parametrize("method,path,need", [
    ("GET", "/api/remediation", "Viewer"),
    ("POST", "/api/reports/group/bundle", "Viewer"),
    ("POST", "/api/remediation/approve/x", "Analyst"),
    ("POST", "/api/suppression-proposals/x/approve", "Analyst"),
    ("POST", "/api/gitlab/scan", "Analyst"),
    ("POST", "/api/inventory/web-1/ping", "Analyst"),
    ("POST", "/api/users/role", "Admin"),
    ("GET", "/api/users", "Admin"),
    ("GET", "/api/users/me", "Viewer"),
    ("GET", "/api/access-scopes/me", "Viewer"),
    ("POST", "/api/inventory", "Admin"),
    ("DELETE", "/api/inventory", "Admin"),
    ("POST", "/api/inventory/web-1/vault-secret", "Admin"),
    ("PUT", "/api/test-credentials/role", "Admin"),
    ("POST", "/api/host-containment/web-1", "Admin"),
    ("POST", "/api/some-new-write-endpoint", "Admin"),     # fail-closed for unlisted writes
])
def test_required_role(method, path, need):
    assert roles.required_role(method, path) == need


def test_check_denies_lower_role_and_disabled():
    assert roles.check("POST", "/api/users/role", claims("Centinela Viewer"))[0] is False
    assert roles.check("GET", "/api/stats", claims("org"))[0] is False          # no Centinela group = Disabled
    assert roles.check("POST", "/api/remediation/approve/x", claims("Centinela Analyst"))[0] is True


@pytest.fixture()
def enforced_client(monkeypatch):
    import main
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    monkeypatch.setenv("API_ROLE_MODE", "enforce")
    tokens = {"viewer-token-xxxx": claims("Centinela Viewer"), "admin-token-xxxxx": claims("Centinela Admin")}
    monkeypatch.setattr(auth, "verify_token", lambda t: tokens.get(t))
    return TestClient(main.app)


def test_viewer_cannot_change_roles_but_reads_its_own_role(enforced_client):
    h = {"Authorization": "Bearer viewer-token-xxxx"}
    r = enforced_client.post("/api/users/role", json={"username": "someone", "role": "Admin"}, headers=h)
    assert r.status_code == 403 and r.json()["required_role"] == "Admin" and r.json()["your_role"] == "Viewer"
    me = enforced_client.get("/api/users/me", headers=h)
    assert me.status_code == 200 and me.json()["role"] == "Viewer"
    assert enforced_client.get("/api/users", headers=h).status_code == 403


def test_log_mode_does_not_block(monkeypatch, enforced_client):
    monkeypatch.setenv("API_ROLE_MODE", "log")
    h = {"Authorization": "Bearer viewer-token-xxxx"}
    r = enforced_client.post("/api/users/role", json={"username": "", "role": "Nope"}, headers=h)
    assert r.status_code != 403          # reaches the handler (which rejects the bad body itself)


def test_ssh_credentials_are_not_stored_under_a_url_asset_name(monkeypatch):
    """2026-11-13: a URL asset's '/' became nested OpenBao folders holding a duplicate of the host's SSH credentials."""
    from api.routers import inventory
    called = []
    monkeypatch.setattr(inventory, "get_vault_client", lambda: called.append(1))
    assert inventory.store_vault_secret("http://192.0.2.2/app/login", sudo_password="x", ansible_user="u") is False
    assert called == []                                    # never reached OpenBao
