"""
Re-scan every project in the GitLab `edomex-casmart` group with the branch-aware clone logic
added 2026-08-28.

Why: the fleet loop was doing `git clone --depth 1` of each project's DEFAULT branch. For this
group every project keeps `main` as a near-empty stub (a lone README or .gitlab-ci.yml) and the
real code lives on `develop` / `desarrollo`. So SIAT / SIDECO / compramex / calculadora were all
being "audited" against empty trees, reporting ~0 findings. GitLabIntegrator.pick_branch() now
resolves the develop-style branch; this script forces an immediate re-scan of the group instead
of waiting for the next periodic cycle.

Runs the same per-project engine set as GitLabIntegrator.scan_all_projects():
SAST, SCA, Standards, IaC, CMMI, WCAG, SonarQube, Semgrep -- each reconciles its own stale
findings for the asset when asset_id is given.
"""
import sys
sys.path.insert(0, "/app")

import os
import urllib.parse
import requests

from core import db_manager
from auditors.gitlab_integration import GitLabIntegrator
from auditors import (auditor_master_vulnerabilities, auditor_sca_dependencies,
                      auditor_compliance_standards, auditor_iac_k8s, auditor_cmmi_v3,
                      auditor_accessibility_wcag, auditor_sonarqube, auditor_semgrep)

GROUP = "edomex-casmart"


def group_projects(g):
    u = g.gitlab_url
    h = {"PRIVATE-TOKEN": g.token} if g.token else {}
    gid = urllib.parse.quote(GROUP, safe="")
    out, page = [], 1
    while True:
        r = requests.get(f"{u}/api/v4/groups/{gid}/projects", headers=h,
                         params={"include_subgroups": "true", "per_page": 100, "page": page,
                                 "simple": "true", "archived": "false"}, timeout=30)
        r.raise_for_status()
        js = r.json()
        if not js:
            break
        out += js
        nxt = r.headers.get("X-Next-Page")
        if not nxt:
            break
        page = int(nxt)
    return out


def register_asset(path_ns, web_url):
    with db_manager.get_db_cursor() as cur:
        cur.execute("""
            INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, last_audit, status)
            VALUES (%s, 'GitLab-Repo', %s, 'MEDIUM', NOW(), 'monitored')
            ON CONFLICT (asset_name) DO UPDATE SET last_audit = NOW(), status = 'monitored'
            RETURNING id
        """, (f"GitLab/{path_ns}", web_url))
        return cur.fetchone()[0]


def scan_one(g, proj):
    path_ns = proj["path_with_namespace"]
    branch = g.pick_branch(proj["id"])
    target = g.clone_or_pull(proj["http_url_to_repo"], path_ns, branch=branch)
    if not target or not os.path.isdir(target):
        print(f"  !! {path_ns}: clone failed, skipped")
        return None
    aid = register_asset(path_ns, proj.get("web_url", proj["http_url_to_repo"]))
    java_n = sum(1 for r, _, fs in os.walk(target) for f in fs if f.endswith((".java", ".ts", ".js", ".py")))
    print(f"\n{'='*72}\n{path_ns}  branch={branch!r}  asset_id={aid}  source_files~{java_n}\n{'='*72}")
    c = {}
    c["sast"] = len(auditor_master_vulnerabilities.run_master_vulnerability_scan(target, asset_id=aid))
    c["sca"] = len(auditor_sca_dependencies.run_sca_audit(target, asset_id=aid))
    c["standards"] = len(auditor_compliance_standards.run_compliance_standards_audit(target, asset_id=aid))
    c["iac"] = len(auditor_iac_k8s.run_iac_scan(target, asset_id=aid))
    c["cmmi"] = len(auditor_cmmi_v3.run_cmmi_audit(target, asset_id=aid))
    c["wcag"] = len(auditor_accessibility_wcag.run_wcag_accessibility_audit(target, asset_id=aid))
    try:
        sg = auditor_semgrep.scan_path(target, aid, path_ns)
        auditor_semgrep.persist_findings(sg)
        c["semgrep"] = len(sg)
    except Exception as e:
        print(f"  semgrep failed: {e}")
        c["semgrep"] = -1
    try:
        c["sonarqube"] = len(auditor_sonarqube.run_sonarqube_audit(target, asset_id=aid, repo_display_name=path_ns))
    except Exception as e:
        print(f"  sonarqube failed: {e}")
        c["sonarqube"] = -1
    print(f"  -> {path_ns}: {c}")
    return aid, path_ns, branch, c


def main():
    g = GitLabIntegrator()
    projs = group_projects(g)
    print(f"{len(projs)} projects in group {GROUP}")
    results = []
    for p in projs:
        r = scan_one(g, p)
        if r:
            results.append(r)

    print(f"\n\n{'#'*72}\nRESUMEN\n{'#'*72}")
    with db_manager.get_db_cursor() as cur:
        for aid, path_ns, branch, c in results:
            cur.execute("""
                SELECT
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED')) open_total,
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED') AND finding_category='VULNERABILITY') open_vuln,
                  count(*) FILTER (WHERE status='RESOLVED') resolved
                FROM vulnerability_log WHERE asset_id = %s
            """, (aid,))
            o = cur.fetchone()
            print(f"  {path_ns:52} [{branch}]  scanned={c}  open={o[0]} (vuln={o[1]})  resolved={o[2]}")


if __name__ == "__main__":
    main()
