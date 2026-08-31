"""
Fresh re-scan of siat-atencion-citas (backend+frontend) and sideco-solicitud-web
(backend+frontend) -- the developer updated all four over the weekend (2026-08-30/31).

Runs the full GitLabIntegrator.scan_all_projects() engine set PLUS the new
auditor_authz (Broken Access Control / BOLA / client-side-only authz), each engine
reconciling its own stale findings for the asset (marks RESOLVED anything the fresh
scan no longer reproduces).

Then prints, per asset, the split the user asked for:
  * NEEDS_VERSION_BUMP  -- SCA/dependency CVEs whose only real fix is upgrading a library
  * FIXABLE_NO_UPGRADE  -- everything else (code change, config, Spring authz rule, security
                           header, CSRF, input validation, secret removal, etc.)
"""
import sys, os, json
sys.path.insert(0, "/app")

from datetime import datetime
from core import db_manager
from auditors.gitlab_integration import GitLabIntegrator
from auditors import (auditor_master_vulnerabilities, auditor_sca_dependencies,
                      auditor_compliance_standards, auditor_iac_k8s, auditor_cmmi_v3,
                      auditor_accessibility_wcag, auditor_sonarqube, auditor_semgrep,
                      auditor_authz)

PROJECT_IDS = [95, 94, 93, 92]  # citas/backend, citas/frontend, solicitud/backend, solicitud/frontend

# scan_engine values whose findings are, by nature, "upgrade a dependency"
SCA_ENGINES = {"sca-native", "sca", "trivy", "grype", "osv", "dependency-check"}
# cve_id prefixes that mean "dependency CVE" regardless of engine
SCA_CVE_PREFIXES = ("SCA-", "CVE-", "GHSA-", "OSV-", "PYSEC-", "RUSTSEC-", "NPM-")


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
    nfiles = sum(1 for r, _, fs in os.walk(target) for f in fs
                 if f.endswith((".java", ".ts", ".js", ".py", ".xml", ".json")))
    print(f"\n{'='*74}\n{path_ns}  branch={branch!r}  asset_id={aid}  files~{nfiles}\n{'='*74}")
    c = {}
    c["sast"] = len(auditor_master_vulnerabilities.run_master_vulnerability_scan(target, asset_id=aid))
    c["sca"] = len(auditor_sca_dependencies.run_sca_audit(target, asset_id=aid))
    c["standards"] = len(auditor_compliance_standards.run_compliance_standards_audit(target, asset_id=aid))
    c["iac"] = len(auditor_iac_k8s.run_iac_scan(target, asset_id=aid))
    c["cmmi"] = len(auditor_cmmi_v3.run_cmmi_audit(target, asset_id=aid))
    c["wcag"] = len(auditor_accessibility_wcag.run_wcag_accessibility_audit(target, asset_id=aid))
    c["authz"] = len(auditor_authz.run_authz_audit(target, asset_id=aid))
    try:
        sg = auditor_semgrep.scan_path(target, aid, path_ns)
        auditor_semgrep.persist_findings(sg)
        c["semgrep"] = len(sg)
    except Exception as e:
        import traceback; traceback.print_exc()
        c["semgrep"] = -1
    try:
        c["sonarqube"] = len(auditor_sonarqube.run_sonarqube_audit(target, asset_id=aid, repo_display_name=path_ns))
    except Exception as e:
        import traceback; traceback.print_exc()
        c["sonarqube"] = -1
    print(f"  -> {path_ns}: {c}")
    return aid, path_ns, branch, c


def is_sca(cve_id, scan_engine):
    se = (scan_engine or "").lower()
    if se in SCA_ENGINES:
        return True
    cid = (cve_id or "").upper()
    return cid.startswith(SCA_CVE_PREFIXES)


def main():
    g = GitLabIntegrator()
    h = {"PRIVATE-TOKEN": g.token} if g.token else {}
    import requests
    results = []
    for pid in PROJECT_IDS:
        p = requests.get(f"{g.gitlab_url}/api/v4/projects/{pid}", headers=h, timeout=30).json()
        r = scan_one(g, p)
        if r:
            results.append(r)

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    print(f"\n\n{'#'*74}\nRESUMEN — {stamp}\n{'#'*74}")
    export = {"generated": stamp, "assets": []}
    with db_manager.get_db_cursor() as cur:
        for aid, path_ns, branch, c in results:
            cur.execute("""
                SELECT cve_id, severity, scan_engine, url_path, finding_category, status,
                       LEFT(description, 400)
                FROM vulnerability_log
                WHERE asset_id = %s AND status NOT IN ('RESOLVED','SUPPRESSED')
                ORDER BY
                  CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
                                WHEN 'LOW' THEN 3 ELSE 4 END, scan_engine, cve_id
            """, (aid,))
            rows = cur.fetchall()
            need_bump, no_bump = [], []
            for cve_id, sev, se, loc, cat, st, desc in rows:
                rec = {"cve_id": cve_id, "severity": sev, "scan_engine": se, "location": loc,
                       "category": cat, "description": desc}
                (need_bump if is_sca(cve_id, se) else no_bump).append(rec)

            def sev_count(lst):
                from collections import Counter
                return dict(Counter(r["severity"] for r in lst))

            print(f"\n### {path_ns}  (asset {aid}, branch {branch})")
            print(f"    total abiertas: {len(rows)}")
            print(f"    REQUIEREN subir versión de librería : {len(need_bump):3}  {sev_count(need_bump)}")
            print(f"    RESOLUBLES SIN actualizar librerías : {len(no_bump):3}  {sev_count(no_bump)}")
            by_engine = {}
            for r in no_bump:
                by_engine.setdefault(r["scan_engine"], 0)
                by_engine[r["scan_engine"]] += 1
            print(f"      sin-actualización por motor: {by_engine}")

            export["assets"].append({
                "asset_id": aid, "path": path_ns, "branch": branch, "scanned_counts": c,
                "total_open": len(rows),
                "needs_version_bump": need_bump,
                "fixable_without_upgrade": no_bump,
            })

    out = "/app/scratch/citas_solicitud_scan_2026-08-31.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(export, fh, ensure_ascii=False, indent=1)
    print(f"\nExport -> {out}")


if __name__ == "__main__":
    main()
    os._exit(0)
