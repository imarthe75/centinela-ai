"""ADR-0008 #8: API authentication middleware (core/auth.py)."""
import pytest
from fastapi.testclient import TestClient

import main
from core import auth

PATH = "/api/coverage"          # cheap, static, not exempt
client = TestClient(main.app)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("API_SERVICE_TOKEN", raising=False)
    auth._cache.clear()
    auth._grace.clear()
    auth._reasons.clear()
    for k in auth._counters:
        auth._counters[k] = 0
    auth._recent_would_reject.clear()


def _bearer(t="x" * 30):
    return {"Authorization": f"Bearer {t}"}


def test_off_mode_does_nothing(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "off")
    assert client.get(PATH).status_code == 200
    assert set(auth._counters.values()) == {0}


def test_log_mode_allows_but_records_what_would_be_rejected(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "log")
    assert client.get(PATH).status_code == 200
    assert auth._counters["would_reject"] == 1
    assert auth._recent_would_reject[-1]["path"] == PATH and auth._recent_would_reject[-1]["reason"] == "no bearer token"
    st = client.get("/api/auth/status").json()
    assert st["mode"] == "log" and st["counters"]["would_reject"] == 1


def test_default_mode_is_log(monkeypatch):
    monkeypatch.delenv("API_AUTH_MODE", raising=False)
    assert auth.mode() == "log"
    monkeypatch.setenv("API_AUTH_MODE", "garbage")
    assert auth.mode() == "log"          # unknown value never silently disables or hard-enforces


def test_enforce_rejects_missing_and_invalid_tokens(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    r = client.get(PATH)
    assert r.status_code == 401 and r.json()["reason"] == "no bearer token"
    monkeypatch.setattr(auth, "verify_token", lambda t: None)
    r = client.get(PATH, headers=_bearer())
    assert r.status_code == 401 and "rejected" in r.json()["reason"]


def test_enforce_accepts_a_valid_token(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    monkeypatch.setattr(auth, "verify_token", lambda t: {"sub": "u1", "email": "u@example.com", "groups": ["Centinela Viewer"]})
    assert client.get(PATH, headers=_bearer()).status_code == 200
    assert auth._counters["allowed"] == 1


def test_enforce_fails_closed_when_authentik_is_unreachable(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    def boom(t): raise ConnectionError("authentik down")
    monkeypatch.setattr(auth, "verify_token", boom)
    r = client.get(PATH, headers=_bearer())
    assert r.status_code == 401 and r.json()["reason"] == "authentik unreachable"


def test_exempt_paths_are_not_blocked_by_this_layer(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    assert client.get("/api/health").status_code != 401
    # the webhook keeps ITS OWN fail-closed token check (503/401 from the handler), never our "Authentication required"
    r = client.post("/api/gitlab/push-webhook", json={})
    assert "Authentication required" not in r.text


def test_service_token_for_scripts(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    monkeypatch.setenv("API_SERVICE_TOKEN", "s3cret-service-token-value")
    assert client.get(PATH, headers=_bearer("s3cret-service-token-value")).status_code == 200
    monkeypatch.setattr(auth, "verify_token", lambda t: None)
    assert client.get(PATH, headers=_bearer("wrong-service-token-value-x")).status_code == 401


def test_verify_token_caches_and_uses_userinfo(monkeypatch):
    calls = []
    class R:
        status_code = 200
        def json(self): return {"sub": "abc"}
    monkeypatch.setattr(auth.requests, "get", lambda url, **kw: (calls.append((url, kw["headers"])) or R()))
    assert auth.verify_token("tok-1" * 6) == {"sub": "abc"}
    assert auth.verify_token("tok-1" * 6) == {"sub": "abc"}
    assert len(calls) == 1 and calls[0][1]["Authorization"].startswith("Bearer ")


# ---- WebSocket (token travels as subprotocol ['centinela.bearer', token]) ----
from starlette.websockets import WebSocketDisconnect

WS = "/api/ws/alerts"


def test_ws_enforce_rejects_without_token(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    with pytest.raises(WebSocketDisconnect) as e:
        with client.websocket_connect(WS):
            pass
    assert e.value.code == 1008
    assert auth._counters["rejected"] == 1


def test_ws_enforce_rejects_invalid_token(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    monkeypatch.setattr(auth, "verify_token", lambda t: None)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(WS, subprotocols=["centinela.bearer", "bad" * 10]):
            pass


def test_ws_enforce_accepts_valid_token_and_echoes_the_subprotocol(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    monkeypatch.setattr(auth, "verify_token", lambda t: {"sub": "u1", "groups": ["Centinela Viewer"]})
    with client.websocket_connect(WS, subprotocols=["centinela.bearer", "good" * 10]) as ws:
        assert ws.accepted_subprotocol == "centinela.bearer"      # without the echo the browser aborts the handshake


def test_ws_log_mode_connects_but_records(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "log")
    with client.websocket_connect(WS):
        pass
    assert auth._counters["would_reject"] == 1 and auth._recent_would_reject[-1]["method"] == "WS"


def _jwt(exp):
    import base64, json
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b({'alg': 'HS256'})}.{b({'exp': exp})}.sig"


def test_expired_session_is_told_apart_from_a_token_authentik_rejects(monkeypatch):
    """The access token lives 1 h and the app has no silent renew: the log must say 'expired', not just 'rejected'."""
    import time as _t
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    monkeypatch.setattr(auth, "verify_token", lambda t: None)
    r = client.get(PATH, headers=_bearer(_jwt(int(_t.time()) - 60)))
    assert r.status_code == 401 and r.json()["reason"] == "token expired"
    r = client.get(PATH, headers=_bearer(_jwt(int(_t.time()) + 3600)))
    assert r.json()["reason"] == "token rejected by Authentik"       # not expired -> genuinely unknown to Authentik
    assert auth._jwt_expired("not-a-jwt") is False                   # opaque/garbage never counts as expired


def test_docs_routes_serve_the_right_documents():
    """/api/manual is the usage manual, /api/glosario the glossary (formerly the 'Manual Técnico'); old paths keep working; all public."""
    from fastapi.testclient import TestClient
    import main
    c = TestClient(main.app)
    expect = {"/api/manual": "Manual de Uso", "/api/manual/user": "Manual de Uso", "/api/glosario": "Glosario y Definición de Términos",
              "/api/manual/technical": "Glosario y Definición de Términos", "/api/manual/developer": "Manual de Desarrollador"}
    for path, title in expect.items():
        r = c.get(path)
        assert r.status_code == 200, path
        assert title in r.text, path


# ---- Authentik outage: a token Authentik already accepted keeps working until its own expiry ----
import base64 as _b64
import json as _json
import time as _time

import requests as _requests


def _jwt(exp):
    enc = lambda d: _b64.urlsafe_b64encode(_json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256'})}.{enc({'exp': exp, 'sub': 'u1'})}.sig"


class _Ok:
    status_code = 200
    def json(self): return {"sub": "u1", "groups": ["Centinela Viewer"]}


def _down(*a, **kw):
    raise _requests.ConnectionError("authentik down")


def test_validated_token_survives_an_authentik_outage(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    tok = _jwt(_time.time() + 600)
    monkeypatch.setattr(auth.requests, "get", lambda url, **kw: _Ok())
    assert client.get(PATH, headers=_bearer(tok)).status_code == 200
    auth._cache.clear()                                    # force a fresh userinfo call
    monkeypatch.setattr(auth.requests, "get", _down)
    assert client.get(PATH, headers=_bearer(tok)).status_code == 200
    assert auth._counters["allowed_authentik_down"] == 1


def test_outage_never_admits_an_unknown_or_expired_token(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "enforce")
    monkeypatch.setattr(auth.requests, "get", _down)
    r = client.get(PATH, headers=_bearer(_jwt(_time.time() + 600)))   # never validated before
    assert r.status_code == 401 and r.json()["reason"] == "authentik unreachable"
    old = _jwt(_time.time() - 5)                                        # validated once, now past its exp
    monkeypatch.setattr(auth.requests, "get", lambda url, **kw: _Ok())
    auth.verify_token(old)
    auth._cache.clear()
    monkeypatch.setattr(auth.requests, "get", _down)
    assert client.get(PATH, headers=_bearer(old)).status_code == 401


def test_a_token_authentik_rejects_is_dropped_from_the_grace_store(monkeypatch):
    tok = _jwt(_time.time() + 600)
    monkeypatch.setattr(auth.requests, "get", lambda url, **kw: _Ok())
    auth.verify_token(tok)
    class _No:
        status_code = 401
        def json(self): return {}
    auth._cache.clear()
    monkeypatch.setattr(auth.requests, "get", lambda url, **kw: _No())
    assert auth.verify_token(tok) is None                              # revoked
    auth._cache.clear()
    monkeypatch.setattr(auth.requests, "get", _down)
    with pytest.raises(_requests.RequestException):
        auth.verify_token(tok)


def test_status_reports_reasons(monkeypatch):
    monkeypatch.setenv("API_AUTH_MODE", "log")
    client.get(PATH)
    assert client.get("/api/auth/status").json()["by_reason"] == {"no bearer token": 1}
