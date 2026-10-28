"""API authentication (ADR-0008 #8).

Until now the API trusted anyone who could reach nginx: the OIDC login lived only in the React app. This middleware requires a valid Authentik
access token (Authorization: Bearer ...) on /api/*.

Why userinfo and not local JWT verification: the Authentik provider signs with HS256 and publishes an EMPTY JWKS, so the signature cannot be
checked locally. The token is validated by Authentik itself (GET .../userinfo/ with the bearer token) and the result cached for a short time.

Modes (env API_AUTH_MODE):
  off      -> middleware does nothing
  log      -> (default) every request is allowed, but those that WOULD be rejected are logged and counted (GET /api/auth/status):
              lets the owner see exactly what enforcing would break before turning it on
  enforce  -> missing/invalid token -> 401
Exempt: health, the public manual and glossary, the two GitLab webhooks and the SOAR evaluate hook (each has its own token), the auth status endpoint, CORS preflight.
Non-browser callers (report scripts, cron) may use API_SERVICE_TOKEN as the bearer value (constant-time compare).
WebSockets: browsers cannot set headers, so the token is sent as a subprotocol pair ['centinela.bearer', <token>] and checked by ws_authorize() with the same modes.
"""
import hashlib
import hmac
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

import requests
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger("centinela.auth")

EXEMPT_PREFIXES = ("/api/health", "/api/manual", "/api/glosario", "/api/gitlab/push-webhook", "/api/gitlab/mr-webhook", "/api/xdr/soar/evaluate", "/api/auth/status",
                   "/api/ingest/smart-tests")   # own service token, fail-closed (api/routers/ingest.py)
USERINFO_URL = os.getenv("AUTH_USERINFO_URL", os.getenv("AUTHENTIK_URL", "https://auth.example.internal").rstrip("/") + "/application/o/userinfo/")
CACHE_TTL = int(os.getenv("AUTH_CACHE_SECONDS", "60"))

_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()
_counters = {"allowed": 0, "would_reject": 0, "rejected": 0}
_recent_would_reject: list = []


def mode() -> str:
    m = os.getenv("API_AUTH_MODE", "log").strip().lower()
    return m if m in ("off", "log", "enforce") else "log"


def _tls_verify():
    ca = os.getenv("AUTH_CA_BUNDLE")
    if ca:
        return ca
    return os.getenv("AUTH_TLS_VERIFY", "false").lower() in ("1", "true", "yes")   # internal CA: unverified unless a bundle is given


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Return the Authentik claims for a valid access token, None when Authentik rejects it. Raises on transport errors (callers fail closed)."""
    key = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    r = requests.get(USERINFO_URL, headers={"Authorization": f"Bearer {token}"}, timeout=8, verify=_tls_verify())
    claims = r.json() if r.status_code == 200 else None
    with _cache_lock:
        if len(_cache) > 2000:
            _cache.clear()
        _cache[key] = (now + (CACHE_TTL if claims else 10), claims)   # negative results are cached briefly too (cheap brute-force damper)
    return claims


def _jwt_expired(token: str) -> bool:
    """Diagnostics only (never used to ACCEPT anything): True when the token is a JWT whose `exp` is in the past. Lets the log tell an
    expired session (the access token lives 1 h and the app has no silent renew) apart from a token Authentik really does not know."""
    import base64
    import json
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return float(claims.get("exp", 0)) < time.time()
    except Exception:
        return False


def _rejection_reason(token: str) -> str:
    return "token expired" if _jwt_expired(token) else "token rejected by Authentik"


def _service_token_ok(token: str) -> bool:
    expected = os.getenv("API_SERVICE_TOKEN", "")
    return bool(expected) and hmac.compare_digest(token.encode(), expected.encode())


def is_admin(claims: Optional[Dict[str, Any]]) -> bool:
    """True when the token's groups include a Centinela Admin group. Only used to gate sensitive writes (e.g. test credentials) in `enforce` mode."""
    groups = (claims or {}).get("groups") or []
    return any(isinstance(g, str) and g.strip().lower() in ("centinela admin", "centinela admins") for g in groups)


def status() -> Dict[str, Any]:
    return {"mode": mode(), "counters": dict(_counters), "recent_would_reject": list(_recent_would_reject[-20:]),
            "service_token_configured": bool(os.getenv("API_SERVICE_TOKEN"))}


class ApiAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path
        m = mode()
        if m == "off" or not path.startswith("/api/") or request.method == "OPTIONS" or path.startswith(EXEMPT_PREFIXES):
            return await call_next(request)

        reason = None
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer ") or len(auth) < 15:
            reason = "no bearer token"
        else:
            token = auth[7:].strip()
            if _service_token_ok(token):
                request.state.user = {"sub": "service-token"}
            else:
                try:
                    from starlette.concurrency import run_in_threadpool
                    claims = await run_in_threadpool(verify_token, token)
                    if claims:
                        request.state.user = claims
                    else:
                        reason = _rejection_reason(token)
                except Exception:
                    logger.error("Authentik userinfo unreachable while validating a token", exc_info=True)
                    reason = "authentik unreachable"      # fail closed in enforce mode

        if reason is None:
            _counters["allowed"] += 1
            return await call_next(request)
        if m == "log":
            _counters["would_reject"] += 1
            _recent_would_reject.append({"t": int(time.time()), "method": request.method, "path": path, "reason": reason})
            del _recent_would_reject[:-100]
            logger.warning("[API-AUTH log-mode] would reject %s %s: %s", request.method, path, reason)
            return await call_next(request)
        _counters["rejected"] += 1
        return JSONResponse({"detail": "Authentication required", "reason": reason}, status_code=401)


WS_SUBPROTOCOL = "centinela.bearer"


def _ws_token(websocket) -> Optional[str]:
    protos = [p.strip() for p in websocket.headers.get("sec-websocket-protocol", "").split(",") if p.strip()]
    return protos[1] if len(protos) >= 2 and protos[0] == WS_SUBPROTOCOL else None


async def ws_authorize(websocket) -> bool:
    """Same modes as the HTTP middleware. True = accept the connection. In log mode everything is accepted but a missing/invalid token is recorded."""
    m = mode()
    if m == "off":
        return True
    reason = None
    token = _ws_token(websocket)
    if not token:
        reason = "no bearer token"
    elif _service_token_ok(token):
        pass
    else:
        try:
            from starlette.concurrency import run_in_threadpool
            if not await run_in_threadpool(verify_token, token):
                reason = _rejection_reason(token)
        except Exception:
            logger.error("Authentik userinfo unreachable while validating a websocket token", exc_info=True)
            reason = "authentik unreachable"
    if reason is None:
        _counters["allowed"] += 1
        return True
    path = websocket.url.path
    if m == "log":
        _counters["would_reject"] += 1
        _recent_would_reject.append({"t": int(time.time()), "method": "WS", "path": path, "reason": reason})
        del _recent_would_reject[:-100]
        logger.warning("[API-AUTH log-mode] would reject WS %s: %s", path, reason)
        return True
    _counters["rejected"] += 1
    return False
