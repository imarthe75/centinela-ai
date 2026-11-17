"""Role-based permissions by function (2026-11-13).

Until now the four Authentik role groups only changed a badge: any signed-in user could call any write endpoint — including
POST /api/users/role, so a Viewer could make itself Admin. The data scope (core.access_scope) limits WHICH projects a user sees;
this module limits WHAT the user may do.

  Viewer   read (within its scope) and download reports
  Auditor  same as Viewer; meant for people who review all projects (give them a broad scope, or none with ACCESS_SCOPE_DEFAULT=all)
  Analyst  + triage: approve/reject remediations and AI suppression proposals, suppressions, triage rules, incidents, on-demand scans
  Admin    + platform: users and roles, data scopes, assets and their credentials, settings, test credentials, host containment,
           Wazuh agent actions. The API service token counts as Admin.

Fail-closed: a write path not listed below needs Admin, and a caller with no Centinela group gets nothing (403).
API_ROLE_MODE: enforce (default) | log (only reports what would be denied, in /api/auth/status) | off.
"""
import logging
import os
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("centinela.roles")

LEVEL = {"Viewer": 1, "Auditor": 2, "Analyst": 3, "Admin": 4}
GROUP_TO_ROLE = {"centinela admin": "Admin", "centinela admins": "Admin", "centinela analyst": "Analyst",
                 "centinela auditor": "Auditor", "centinela viewer": "Viewer"}
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

# Reads that expose platform administration (other people's accounts, credentials metadata, grants).
ADMIN_READ_PREFIXES = ("/api/users", "/api/access-scopes", "/api/test-credentials")
SELF_SERVICE = ("/api/users/me", "/api/access-scopes/me")

# Writes everyone with a role may do: generating a report is a read of data already in scope.
VIEWER_WRITE_PREFIXES = ("/api/reports/",)

# Analyst writes: triage and on-demand checks. Anything else that writes is Admin.
ANALYST_WRITE_PREFIXES = (
    "/api/remediation/", "/api/suppressions", "/api/suppression-proposals/", "/api/triage/", "/api/incidents/",
    "/api/gitlab/scan", "/api/gitlab/scan-project/", "/api/gitlab/projects/", "/api/gitlab/rescan-changed", "/api/gitlab/changes/refresh",
    "/api/gitlab/autofix/", "/api/gitlab/mr-review/", "/api/scan/", "/api/cis-benchmark/check/", "/api/os-patch/check/",
    "/api/tls/check/", "/api/dns/check", "/api/inventory/test-connection", "/api/investigate/runtime", "/api/ai-tokens/probe",
    "/api/compliance/resident-loop",
)
ANALYST_WRITE_PATTERNS = (("/api/inventory/", "/ping"),)   # (prefix, suffix)


def mode() -> str:
    m = os.getenv("API_ROLE_MODE", "enforce").strip().lower()
    return m if m in ("off", "log", "enforce") else "enforce"


def role_of(claims: Optional[Dict[str, Any]]) -> Optional[str]:
    """Highest Centinela role in the caller's groups; the service token is Admin; None = no Centinela group (Disabled)."""
    claims = claims or {}
    if claims.get("sub") == "service-token":
        return "Admin"
    best = None
    for g in claims.get("groups") or []:
        r = GROUP_TO_ROLE.get(str(g).strip().lower()) if isinstance(g, str) else None
        if r and (best is None or LEVEL[r] > LEVEL[best]):
            best = r
    return best


def required_role(method: str, path: str) -> str:
    """Minimum role for a request. Unknown write paths need Admin (fail-closed)."""
    method = method.upper()
    if path.startswith(SELF_SERVICE):
        return "Viewer"
    if path.startswith(ADMIN_READ_PREFIXES):
        return "Admin"
    if method in SAFE_METHODS:
        return "Viewer"
    if path.startswith(VIEWER_WRITE_PREFIXES):
        return "Viewer"
    if path.startswith(ANALYST_WRITE_PREFIXES) or any(path.startswith(p) and path.endswith(s) for p, s in ANALYST_WRITE_PATTERNS):
        return "Analyst"
    return "Admin"


def check(method: str, path: str, claims: Optional[Dict[str, Any]]) -> Tuple[bool, str, Optional[str], str]:
    """(allowed, required role, caller role, reason)."""
    need = required_role(method, path)
    have = role_of(claims)
    if have is None:
        return False, need, None, "no Centinela role"
    if LEVEL[have] < LEVEL[need]:
        return False, need, have, f"role {have} < {need}"
    return True, need, have, ""
