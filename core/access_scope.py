"""Per-project / per-group data access (ADR-0019, phase 1).

Who is restricted: every authenticated user except Admins (group "Centinela Admin") and the service token. A restricted user sees only the
assets granted in public.access_scopes to their username/email or to one of their Authentik groups. A user with no rows falls back to
ACCESS_SCOPE_DEFAULT: "all" (unrestricted, the rollout default so nobody loses access before scopes are assigned) or "none".

How it is enforced:
  * the auth middleware stores the caller's scope in a context variable (current());
  * enforce_request_scope() — a dependency on every router — answers 403 when a request names an asset (path `asset_name`, query
    `asset`/`asset_name`/`assets`/`prefix`) outside the scope, and closes every data route not listed as scope-aware for restricted users
    (fail-closed: a fleet-wide aggregate that does not filter yet must not leak other projects);
  * scope-aware list endpoints filter with allows() / sql_filter().
"""
import contextvars
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from starlette.requests import HTTPConnection

logger = logging.getLogger("centinela.access_scope")

UNRESTRICTED = None          # sentinel: scope None means "sees everything"
_current: contextvars.ContextVar = contextvars.ContextVar("centinela_access_scope", default=UNRESTRICTED)
_cache: Dict[str, Tuple[float, Optional[List[str]]]] = {}
_lock = threading.Lock()
CACHE_SECONDS = 60

# Routes a restricted user may call. Asset-named routes are checked by name; list routes filter their rows; the rest carry no project data.
SCOPE_AWARE_PREFIXES = (
    "/api/inventory", "/api/remediation", "/api/reports/", "/api/gitlab/changes", "/api/gitlab/projects/", "/api/gitlab/branch-diff", "/api/stats",
    "/api/preflight", "/api/checklist-evidence/", "/api/functional-tests/", "/api/quality-gates/check", "/api/vulnerability/",
)
NO_PROJECT_DATA = ("/api/health", "/api/manual", "/api/glosario", "/api/auth/status", "/api/config", "/api/llm/models", "/api/coverage",
                   "/api/engines/status", "/api/users/me", "/api/access-scopes/me")


def default_policy() -> str:
    return "none" if os.getenv("ACCESS_SCOPE_DEFAULT", "all").strip().lower() == "none" else "all"


def _subjects(claims: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    users = [str(claims.get(k)).lower() for k in ("preferred_username", "email", "sub") if claims.get(k)]
    groups = [str(g).lower() for g in (claims.get("groups") or []) if isinstance(g, str)]
    return users, groups


def resolve(claims: Optional[Dict[str, Any]]) -> Optional[List[str]]:
    """Scope for a caller: None = unrestricted, else the list of asset prefixes they may see (possibly empty)."""
    from core.auth import is_admin
    if not claims or claims.get("sub") == "service-token" or is_admin(claims):
        return UNRESTRICTED
    users, groups = _subjects(claims)
    key = "|".join(users) + "#" + "|".join(sorted(groups))
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    from core import db_manager
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT DISTINCT asset_prefix FROM public.access_scopes
                        WHERE (subject_type = 'user' AND lower(subject) = ANY(%s)) OR (subject_type = 'group' AND lower(subject) = ANY(%s))""",
                    (users or [""], groups or [""]))
        prefixes = [r[0] for r in cur.fetchall()]
    scope = prefixes if prefixes else (UNRESTRICTED if default_policy() == "all" else [])
    with _lock:
        if len(_cache) > 1000:
            _cache.clear()
        _cache[key] = (now + CACHE_SECONDS, scope)
    return scope


def invalidate() -> None:
    with _lock:
        _cache.clear()


def set_current(scope: Optional[List[str]]):
    return _current.set(scope)


def current() -> Optional[List[str]]:
    return _current.get()


def _norm(p: str) -> str:
    return (p or "").strip().rstrip("/")


def allows(asset_name: Optional[str], scope: Any = "current") -> bool:
    """True when the asset is inside the scope: equal to a prefix, below it ('<p>/...') or one of its branches ('<p>@...')."""
    scope = current() if scope == "current" else scope
    if scope is UNRESTRICTED:
        return True
    name = asset_name or ""
    for raw in scope:
        p = _norm(raw)
        if p and (name == p or name.startswith(p + "/") or name.startswith(p + "@")):
            return True
    return False


def prefix_within(prefix: Optional[str], scope: Any = "current") -> bool:
    """A group prefix requested by a restricted user must sit inside one of their granted prefixes."""
    scope = current() if scope == "current" else scope
    if scope is UNRESTRICTED:
        return True
    return allows(_norm(prefix), scope)


def sql_filter(column: str, scope: Any = "current") -> Tuple[str, list]:
    """(' AND (...)', params) restricting `column` (an asset_name column) to the scope; ('', []) when unrestricted.
    An empty scope yields a clause that matches nothing."""
    scope = current() if scope == "current" else scope
    if scope is UNRESTRICTED:
        return "", []
    exact, likes = [], []
    for raw in scope:
        p = _norm(raw)
        if not p:
            continue
        esc = p.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        exact.append(p)
        likes += [esc + "/%", esc + "@%"]
    if not exact:
        return " AND FALSE", []
    return f" AND ({column} = ANY(%s) OR {column} LIKE ANY(%s))", [exact, likes]


def vuln_filter(alias: str = "v", scope: Any = "current") -> Tuple[str, list]:
    """Clause restricting vulnerability_log rows (alias) to assets inside the scope."""
    clause, params = sql_filter("sc_i.asset_name", scope)
    if not clause:
        return "", []
    return f" AND {alias}.asset_id IN (SELECT sc_i.id FROM public.infra_inventory sc_i WHERE TRUE{clause})", params


# Inside the scope-aware prefixes, these are still fleet-wide aggregates or administrative actions: closed to restricted callers.
RESTRICTED_DENY = {
    ("GET", "/api/reports/executive"), ("GET", "/api/reports/cmmi"),
    ("POST", "/api/inventory"), ("POST", "/api/inventory/source-zip"), ("POST", "/api/inventory/test-connection"),
    ("GET", "/api/stats/extended"), ("GET", "/api/stats/dashboard-charts"), ("GET", "/api/stats/daily-detections"),
    ("GET", "/api/stats/tops"), ("GET", "/api/stats/soar-roi"),
}
# These list everything when called without an asset: a restricted caller must name one.
REQUIRE_ASSET = {("GET", "/api/quality-gates/check")}


def route_allowed_for_restricted(path: str, method: str = "GET") -> bool:
    if (method.upper(), path.rstrip("/") or "/") in RESTRICTED_DENY:
        return False
    return path.startswith(SCOPE_AWARE_PREFIXES) or path.startswith(NO_PROJECT_DATA)


# ------------------------------------------------------------------------------------------------------------ request dependency
def _asset_by_id(asset_id: str) -> Optional[str]:
    from core import db_manager
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT asset_name FROM public.infra_inventory WHERE id::text = %s", (str(asset_id),))
        r = cur.fetchone()
    return r[0] if r else None


def _asset_by_vuln(vuln_id: str) -> Optional[str]:
    from core import db_manager
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT i.asset_name FROM public.vulnerability_log v JOIN public.infra_inventory i ON i.id = v.asset_id
                        WHERE v.id::text = %s""", (str(vuln_id),))
        r = cur.fetchone()
    return r[0] if r else None


def _asset_by_run(run_id: str) -> Optional[str]:
    from core import db_manager
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT asset_name FROM public.functional_test_runs WHERE id::text = %s", (str(run_id),))
        r = cur.fetchone()
    return r[0] if r else None


def _gitlab_project_allowed(project: str, scope) -> bool:
    from core import gitlab_instances
    return any(allows(inst.asset_name(project), scope) for inst in gitlab_instances.configured_instances())


def check_request(path: str, path_params: Dict[str, Any], query: Dict[str, Any], scope: Any = "current", method: str = "GET") -> Optional[str]:
    """None when the request is allowed for the scope, else the reason it is not (pure: no FastAPI objects, easy to test)."""
    scope = current() if scope == "current" else scope
    if scope is UNRESTRICTED:
        return None
    if not route_allowed_for_restricted(path, method):
        return "ruta de toda la flota o administrativa, no disponible con alcance restringido"
    if (method.upper(), path.rstrip("/")) in REQUIRE_ASSET and not (query.get("asset") or query.get("asset_name")):
        return "indique el activo: sin él la consulta abarca toda la flota"
    names: List[str] = []
    for key in ("asset_name", "asset"):
        if path_params.get(key):
            names.append(str(path_params[key]))
    if path_params.get("asset_id"):
        names.append(_asset_by_id(path_params["asset_id"]) or "")
    if path_params.get("vuln_id"):
        names.append(_asset_by_vuln(path_params["vuln_id"]) or "")
    if path_params.get("run_id"):
        names.append(_asset_by_run(path_params["run_id"]) or "")
    if path_params.get("project_id") and not _gitlab_project_allowed(str(path_params["project_id"]), scope):
        return "proyecto fuera de su alcance"
    if path_params.get("bundle_id"):
        from core import group_reports
        st = group_reports.get_status(str(path_params["bundle_id"])) or {}
        names += list(st.get("asset_names") or [""])
    for key in ("asset", "asset_name"):
        for v in (query.get(key) if isinstance(query.get(key), list) else [query.get(key)]):
            if v:
                names.append(str(v))
    for v in (query.get("assets") or []) if isinstance(query.get("assets"), list) else ([query["assets"]] if query.get("assets") else []):
        names += [x for x in str(v).split(",") if x]
    if query.get("prefix") and not prefix_within(str(query["prefix"]), scope):
        return "grupo fuera de su alcance"
    for n in names:
        if not allows(n, scope):
            return "activo fuera de su alcance"
    return None


def enforce_request_scope(request: "HTTPConnection") -> None:
    """FastAPI dependency (added to every router in main.py): 403 when a restricted caller names something outside their scope.
    Typed as HTTPConnection so it also runs on the alerts WebSocket (a restricted user does not get the fleet-wide alert feed)."""
    from fastapi import HTTPException
    q: Dict[str, Any] = {}
    for k in ("asset", "asset_name", "assets", "prefix"):
        vals = request.query_params.getlist(k)
        if vals:
            q[k] = vals if len(vals) > 1 or k == "assets" else vals[0]
    reason = check_request(request.url.path, dict(request.path_params), q, method=getattr(request, "method", "GET") or "GET")
    if reason:
        raise HTTPException(status_code=403, detail=f"Acceso denegado: {reason}.")
