#!/usr/bin/env python3
"""
Create/verify the Centinela push + merge-request webhooks on GitLab projects (idempotent).

GitLab CE has no group-level webhooks (Premium feature), so hooks are created per project. Each
project gets two hooks (a GitLab hook has a single URL):
  * push events           -> POST {base}/api/gitlab/push-webhook   (re-scan of develop/main/... on push)
  * merge request events  -> POST {base}/api/gitlab/mr-webhook     (shift-left MR review + status check)
Both carry the shared secret (`GITLAB_WEBHOOK_TOKEN` from .env) as GitLab's "secret token".

Safe by default: DRY RUN unless --apply. The admin/maintainer token is read from a 0600 file or the
GITLAB_ADMIN_TOKEN env var -- never from the command line, never printed.

Known GitLab preconditions this script CHECKS and reports (it only changes them with explicit flags):
  * Admin > Settings > Network > "Allow requests to the local network from webhooks" must be enabled
    to reach a private IP/host (--enable-local-requests changes it; needs an admin token).
  * If Centinela is served with an internal/self-signed certificate, GitLab must trust it
    (/etc/gitlab/trusted-certs) or hooks are created with --no-ssl-verify (NOT recommended; the
    gitlab-config auditor flags hooks with SSL verification disabled).

Examples:
  python3 scripts/setup_gitlab_webhooks.py --token-file ~/.config/gitlab-admin-token            # dry run
  python3 scripts/setup_gitlab_webhooks.py --token-file ... --apply --projects 'arquitectura/*'
"""
import argparse
import fnmatch
import os
import re
import sys
from typing import Any, Dict, List, Optional

import requests

PUSH_PATH = "/api/gitlab/push-webhook"
MR_PATH = "/api/gitlab/mr-webhook"


def read_env_value(key: str, env_file: str = ".env") -> Optional[str]:
    if os.getenv(key):
        return os.getenv(key)
    for cand in (env_file, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")):
        if os.path.isfile(cand):
            for line in open(cand, encoding="utf-8"):
                m = re.match(rf"^{re.escape(key)}=(.*)$", line.strip())
                if m:
                    return m.group(1).strip("\"'")
    return None


class Gl:
    def __init__(self, base: str, token: str):
        self.base, self.h = base.rstrip("/"), {"PRIVATE-TOKEN": token}

    def req(self, method: str, path: str, **kw) -> requests.Response:
        return requests.request(method, f"{self.base}/api/v4{path}", headers=self.h, timeout=30, **kw)

    def projects(self, patterns: List[str]) -> List[Dict[str, Any]]:
        out, page = [], 1
        while True:
            r = self.req("GET", "/projects", params={"per_page": 100, "page": page, "archived": "false", "membership": "true"})
            r.raise_for_status()
            batch = r.json()
            out += batch
            if len(batch) < 100:
                break
            page += 1
        if patterns:
            out = [p for p in out if any(fnmatch.fnmatch(p["path_with_namespace"], pat) for pat in patterns)]
        return out


def ensure_hook(gl: Gl, project: Dict[str, Any], url: str, secret: str, kind: str, verify_ssl: bool, apply: bool) -> Dict[str, Any]:
    pid = project["id"]
    r = gl.req("GET", f"/projects/{pid}/hooks")
    if r.status_code == 403:
        return {"project": project["path_with_namespace"], "kind": kind, "result": "NO_PERMISSION (needs Maintainer)"}
    r.raise_for_status()
    existing = next((h for h in r.json() if h.get("url") == url), None)
    payload = {"url": url, "token": secret, "enable_ssl_verification": verify_ssl,
               "push_events": kind == "push", "merge_requests_events": kind == "mr",
               "push_events_branch_filter": "", "tag_push_events": False, "issues_events": False}
    if existing:
        drift = (existing.get("enable_ssl_verification") != verify_ssl
                 or existing.get("push_events") != payload["push_events"]
                 or existing.get("merge_requests_events") != payload["merge_requests_events"])
        if not drift:
            return {"project": project["path_with_namespace"], "kind": kind, "hook_id": existing["id"], "result": "OK (already configured)"}
        if apply:
            gl.req("PUT", f"/projects/{pid}/hooks/{existing['id']}", data=payload).raise_for_status()
        return {"project": project["path_with_namespace"], "kind": kind, "hook_id": existing["id"], "result": "UPDATED" if apply else "WOULD UPDATE"}
    if not apply:
        return {"project": project["path_with_namespace"], "kind": kind, "result": "WOULD CREATE"}
    c = gl.req("POST", f"/projects/{pid}/hooks", data=payload)
    if c.status_code not in (200, 201):
        hint = ""
        if c.status_code == 422 and "url" in c.text.lower():
            hint = (" -- GitLab rejected the URL: almost certainly Admin > Settings > Network > 'Allow requests to the local "
                    "network from webhooks' is disabled (target is a private address) or the hostname does not resolve from GitLab")
        return {"project": project["path_with_namespace"], "kind": kind, "result": f"CREATE FAILED HTTP {c.status_code}: {c.text[:80]}{hint}"}
    return {"project": project["path_with_namespace"], "kind": kind, "hook_id": c.json()["id"], "result": "CREATED"}


def test_hook(gl: Gl, project: Dict[str, Any], hook_id: int, kind: str) -> str:
    """Ask GitLab to deliver a test event; report what Centinela actually answered."""
    event = "push_events" if kind == "push" else "merge_requests_events"
    r = gl.req("POST", f"/projects/{project['id']}/hooks/{hook_id}/test/{event}")
    if r.status_code in (200, 201):
        return f"delivered (HTTP {r.status_code})"
    return f"NOT delivered: HTTP {r.status_code} {r.text[:160]}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gitlab-url", default=read_env_value("GITLAB_URL") or "")
    ap.add_argument("--token-file", help="file (mode 0600) holding a Maintainer/admin GitLab token")
    ap.add_argument("--centinela-url", default="https://centinela.example.internal", help="base URL GitLab will call")
    ap.add_argument("--projects", nargs="*", default=[], help="fnmatch patterns on path_with_namespace (default: all)")
    ap.add_argument("--apply", action="store_true", help="really create/update hooks (default: dry run)")
    ap.add_argument("--no-ssl-verify", action="store_true", help="create hooks with TLS verification disabled (not recommended)")
    ap.add_argument("--enable-local-requests", action="store_true", help="admin: allow webhooks to private addresses")
    ap.add_argument("--send-test", action="store_true", help="after creating, ask GitLab to deliver a test event and report the result")
    a = ap.parse_args()

    token = os.getenv("GITLAB_ADMIN_TOKEN", "")
    if a.token_file:
        st = os.stat(os.path.expanduser(a.token_file))
        if st.st_mode & 0o077:
            print(f"❌ {a.token_file} is readable by others; chmod 600 it first.")
            return 2
        token = open(os.path.expanduser(a.token_file)).read().strip()
    secret = read_env_value("GITLAB_WEBHOOK_TOKEN")
    if not (token and a.gitlab_url and secret):
        print("❌ need a GitLab token (--token-file / GITLAB_ADMIN_TOKEN), GITLAB_URL and GITLAB_WEBHOOK_TOKEN in .env")
        return 2

    gl = Gl(a.gitlab_url, token)
    me = gl.req("GET", "/user")
    me.raise_for_status()
    print(f"authenticated as {me.json()['username']} (admin={me.json().get('is_admin')}) | mode: {'APPLY' if a.apply else 'DRY RUN'}")

    s = gl.req("GET", "/application/settings")
    if s.status_code == 200:
        allowed = s.json().get("allow_local_requests_from_web_hooks_and_services")
        print(f"GitLab 'allow local requests from webhooks': {allowed}")
        if not allowed:
            if a.enable_local_requests and a.apply:
                gl.req("PUT", "/application/settings", data={"allow_local_requests_from_web_hooks_and_services": "true"}).raise_for_status()
                print("  -> enabled (instance-wide setting changed)")
            else:
                print("  ⚠️ hooks to a private address will be blocked; re-run with --enable-local-requests --apply (admin) or enable it in Admin > Settings > Network")
    else:
        print("(token is not an admin: cannot read/change the local-requests instance setting)")

    projects = gl.projects(a.projects)
    print(f"projects in scope: {len(projects)}")
    tally: Dict[str, int] = {}
    for p in projects:
        for kind, path in (("push", PUSH_PATH), ("mr", MR_PATH)):
            res = ensure_hook(gl, p, a.centinela_url.rstrip("/") + path, secret, kind, not a.no_ssl_verify, a.apply)
            if a.send_test and a.apply and res.get("hook_id"):
                res["test"] = test_hook(gl, p, res["hook_id"], kind)
            key = res["result"].split(" ")[0] + (" " + res["result"].split(" ")[1] if res["result"].startswith("OK") else "")
            tally[key] = tally.get(key, 0) + 1
            if not res["result"].startswith("OK") or res.get("test"):
                print(f"  {res['project']:55s} {res['kind']:4s} {res['result']}" + (f" | test: {res['test']}" if res.get("test") else ""))
    print("summary:", tally)
    return 0


if __name__ == "__main__":
    sys.exit(main())
