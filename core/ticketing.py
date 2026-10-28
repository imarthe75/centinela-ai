"""Ticket creation in an external tracker (Redmine or Gitea) for a finding. Pure functions + one sender, configured ONLY by environment.

Why this module exists (2026-10-14): `POST /api/remediation/{id}/ticket` used to hard-code internal hostnames AND an admin username/password literal in
the source (also published in the public mirror). Credentials never belong in code: each tracker needs its own variables and, without them, the endpoint
answers 503 "not configured" instead of guessing.

  Redmine:  REDMINE_URL, REDMINE_API_KEY, REDMINE_PROJECT_ID
  Gitea:    GITEA_URL, GITEA_TOKEN, GITEA_REPO ("owner/repo")
Authentication is by API key / token header, never username+password.
"""
import os
from typing import Any, Dict, Mapping, Tuple
from urllib.parse import urlparse

import requests

TARGETS = ("redmine", "gitea")
TIMEOUT = 10


class TicketingNotConfigured(Exception):
    """Raised with the list of missing variables so the API can say exactly what to set."""

    def __init__(self, target: str, missing: list):
        super().__init__(f"integración '{target}' no configurada: falta(n) {', '.join(missing)}")
        self.target, self.missing = target, missing


class TicketingError(Exception):
    pass


def _base(url: str) -> str:
    u = urlparse(url or "")
    if u.scheme not in ("http", "https") or not u.netloc:
        raise TicketingError(f"URL inválida ({url!r}): debe empezar con http:// o https://")
    return url.rstrip("/")


def load_config(target: str, env: Mapping[str, str] = os.environ) -> Dict[str, str]:
    if target not in TARGETS:
        raise ValueError(f"destino desconocido {target!r}; use uno de {TARGETS}")
    names = {"redmine": ("REDMINE_URL", "REDMINE_API_KEY", "REDMINE_PROJECT_ID"), "gitea": ("GITEA_URL", "GITEA_TOKEN", "GITEA_REPO")}[target]
    missing = [n for n in names if not (env.get(n) or "").strip()]
    if missing:
        raise TicketingNotConfigured(target, missing)
    cfg = {n: env[n].strip() for n in names}
    cfg["base"] = _base(cfg[names[0]])
    return cfg


def build_request(target: str, cfg: Dict[str, str], vuln: Mapping[str, Any], description: str) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
    title = f"[{vuln['severity']}] {vuln['cve_id']} - {vuln['asset_name']}"
    if target == "redmine":
        return (f"{cfg['base']}/issues.json", {"Content-Type": "application/json", "X-Redmine-API-Key": cfg["REDMINE_API_KEY"]},
                {"issue": {"project_id": cfg["REDMINE_PROJECT_ID"], "subject": title, "description": description,
                           "priority_id": 4 if vuln["severity"] in ("CRITICAL", "HIGH") else 2}})
    repo = cfg["GITEA_REPO"].strip("/")
    if repo.count("/") != 1:
        raise TicketingError("GITEA_REPO debe tener la forma 'propietario/repositorio'")
    return (f"{cfg['base']}/api/v1/repos/{repo}/issues", {"Content-Type": "application/json", "Authorization": f"token {cfg['GITEA_TOKEN']}"},
            {"title": title, "body": description})


def send_ticket(target: str, vuln: Mapping[str, Any], description: str, env: Mapping[str, str] = os.environ, post=requests.post) -> Dict[str, Any]:
    cfg = load_config(target, env)
    url, headers, payload = build_request(target, cfg, vuln, description)
    res = post(url, json=payload, headers=headers, timeout=TIMEOUT)
    if res.status_code not in (200, 201):
        raise TicketingError(f"{target} respondió {res.status_code}: {res.text[:300]}")
    data = res.json()
    if target == "redmine":
        tid = (data.get("issue") or {}).get("id")
        return {"status": "created", "url": f"{cfg['base']}/issues/{tid}", "id": tid}
    tid = data.get("number")
    return {"status": "created", "url": f"{cfg['base']}/{cfg['GITEA_REPO'].strip('/')}/issues/{tid}", "id": tid}
