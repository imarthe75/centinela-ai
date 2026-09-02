"""
Full security analysis of the GitLab `teca` group (8 repos) -- access granted 2026-09-01.

Runs the same per-repo engine set as the SIAT/SIDECO analysis
(GitLabIntegrator.scan_all_projects() + auditor_authz): SAST nativo, SCA/OSV, Standards
(STRIDE/ISO), IaC/k8s, CMMI, WCAG accesibilidad, control de acceso (Broken Access Control),
Semgrep multi-lenguaje, SonarQube. Each engine reconciles its own stale findings for the asset.

Then exports a report-ready JSON: per repo, only finding_category='VULNERABILITY' (drops
SonarQube code-smells, CMMI process-debt, ISO-25010 metrics, scan markers), split into
  * fixable_without_upgrade -- code / config / authz-rule / validation / secret change
  * needs_version_bump      -- SCA/CVE of a library, only fixed by upgrading it
Infra findings (ZAP/CIS/nmap) are excluded but for a pure GitLab-Repo asset there are none.
"""
import sys, os, json
sys.path.insert(0, "/app")
from datetime import datetime
from collections import Counter
from core import db_manager
from auditors.gitlab_integration import GitLabIntegrator
from auditors import (auditor_master_vulnerabilities, auditor_sca_dependencies,
                      auditor_compliance_standards, auditor_iac_k8s, auditor_cmmi_v3,
                      auditor_accessibility_wcag, auditor_sonarqube, auditor_semgrep,
                      auditor_authz)

# force SonarQube to actually run even if scanned <24h ago
auditor_sonarqube._recently_scanned = lambda *a, **k: False

GROUP = "starters"
SCA_ENGINES = {"sca-native", "sca", "trivy", "grype", "osv", "dependency-check"}
SCA_CVE_PREFIXES = ("SCA-", "CVE-", "GHSA-", "OSV-", "PYSEC-", "RUSTSEC-", "NPM-")
INFRA_ENGINES = {"zap", "zap-dast", "nuclei", "cis-benchmark", "trivy-image", "openvas", "nmap"}
INFRA_CVE_MARKERS = ("HSTS", "STRICT-TRANSPORT", "SERVER-BANNER", "CIS-", "SSH-ROOT",
                     "CLICKJACK", "COOKIE-SECURE", "COOKIE-FLAG")

OUT = "/app/scratch/starters_scan_2026-09-02.json"


def is_sca(cve, se):
    return (se or "").lower() in SCA_ENGINES or (cve or "").upper().startswith(SCA_CVE_PREFIXES)


def is_infra(cve, se):
    return (se or "").lower() in INFRA_ENGINES or any(m in (cve or "").upper() for m in INFRA_CVE_MARKERS)


def register_asset(path_ns, web_url):
    with db_manager.get_db_cursor() as cur:
        cur.execute("""
            INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, last_audit, status)
            VALUES (%s, 'GitLab-Repo', %s, 'MEDIUM', NOW(), 'monitored')
            ON CONFLICT (asset_name) DO UPDATE SET last_audit = NOW(), status = 'monitored'
            RETURNING id
        """, (f"GitLab/{path_ns}", web_url))
        return cur.fetchone()[0]


def group_projects(g):
    import urllib.parse, requests
    h = {"PRIVATE-TOKEN": g.token} if g.token else {}
    gid = urllib.parse.quote(GROUP, safe="")
    out, page = [], 1
    while True:
        r = requests.get(f"{g.gitlab_url}/api/v4/groups/{gid}/projects", headers=h,
                         params={"include_subgroups": "true", "per_page": 100, "page": page,
                                 "archived": "false"}, timeout=30)
        js = r.json()
        if not js:
            break
        out += js
        nxt = r.headers.get("X-Next-Page")
        if not nxt:
            break
        page = int(nxt)
    return sorted(out, key=lambda p: p["path_with_namespace"])


def scan_one(g, proj):
    path_ns = proj["path_with_namespace"]
    branch = g.pick_branch(proj["id"])
    target = g.clone_or_pull(proj["http_url_to_repo"], path_ns, branch=branch)
    if not target or not os.path.isdir(target):
        print(f"  !! {path_ns}: clone failed, skipped")
        return None
    aid = register_asset(path_ns, proj.get("web_url", proj["http_url_to_repo"]))
    import subprocess
    head = subprocess.run(["git", "-C", target, "log", "-1", "--format=%h %ci %s"],
                          capture_output=True, text=True, timeout=15).stdout.strip()
    nfiles = sum(1 for r, _, fs in os.walk(target) for f in fs
                 if f.endswith((".java", ".ts", ".js", ".py", ".xml", ".json", ".go", ".php")))
    print(f"\n{'='*76}\n{path_ns}  branch={branch!r}  asset_id={aid}  files~{nfiles}\n  HEAD {head}\n{'='*76}")
    c = {}
    for name, fn in [
        ("sast", lambda: auditor_master_vulnerabilities.run_master_vulnerability_scan(target, asset_id=aid)),
        ("sca", lambda: auditor_sca_dependencies.run_sca_audit(target, asset_id=aid)),
        ("standards", lambda: auditor_compliance_standards.run_compliance_standards_audit(target, asset_id=aid)),
        ("iac", lambda: auditor_iac_k8s.run_iac_scan(target, asset_id=aid)),
        ("cmmi", lambda: auditor_cmmi_v3.run_cmmi_audit(target, asset_id=aid)),
        ("wcag", lambda: auditor_accessibility_wcag.run_wcag_accessibility_audit(target, asset_id=aid)),
        ("authz", lambda: auditor_authz.run_authz_audit(target, asset_id=aid)),
    ]:
        try:
            c[name] = len(fn() or [])
        except Exception:
            import traceback; traceback.print_exc()
            c[name] = -1
    try:
        sg = auditor_semgrep.scan_path(target, aid, path_ns)
        auditor_semgrep.persist_findings(sg)
        c["semgrep"] = len(sg)
    except Exception:
        import traceback; traceback.print_exc()
        c["semgrep"] = -1
    try:
        c["sonarqube"] = len(auditor_sonarqube.run_sonarqube_audit(target, asset_id=aid, repo_display_name=path_ns) or [])
    except Exception:
        import traceback; traceback.print_exc()
        c["sonarqube"] = -1
    print(f"  -> {path_ns}: {c}")
    return aid, path_ns, branch, head, c


def main():
    g = GitLabIntegrator()
    projs = group_projects(g)
    print(f"{len(projs)} proyectos en el grupo '{GROUP}'")
    results = []
    for p in projs:
        r = scan_one(g, p)
        if r:
            results.append(r)

    gen = datetime.now().strftime("%Y-%m-%d %H:%M")
    export = {"generated": gen, "group": GROUP, "scope_note": (
        "Análisis completo del grupo GitLab 'starters'. Solo hallazgos de categoría VULNERABILITY "
        "(se omiten code-smells de SonarQube, métricas ISO-25010 y deuda de proceso CMMI). "
        "Divididos por tipo de remediación: los que se corrigen con un cambio de código o "
        "configuración, y los que exigen subir la versión de una librería."), "assets": []}

    print(f"\n\n{'#'*76}\nRESUMEN — {gen}\n{'#'*76}")
    with db_manager.get_db_cursor() as cur:
        for aid, path_ns, branch, head, c in results:
            cur.execute("""
                SELECT cve_id, severity, scan_engine, url_path, finding_category, description
                FROM vulnerability_log
                WHERE asset_id = %s AND status NOT IN ('RESOLVED','SUPPRESSED')
                  AND finding_category = 'VULNERABILITY'
                ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                       WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                         scan_engine, cve_id
            """, (aid,))
            need, nobump, dropped_infra = [], [], 0
            for cve, sev, se, loc, cat, desc in cur.fetchall():
                if is_infra(cve, se):
                    dropped_infra += 1
                    continue
                rec = {"cve_id": cve, "severity": sev, "scan_engine": se,
                       "location": loc, "description": desc}
                (need if is_sca(cve, se) else nobump).append(rec)

            print(f"\n### {path_ns}  (asset {aid}, rama {branch})")
            print(f"    VULNERABILITY abiertas: {len(need)+len(nobump)}   (infra descartadas: {dropped_infra})")
            print(f"    requieren subir versión : {len(need):3}  {dict(Counter(r['severity'] for r in need))}")
            print(f"    sin actualizar librería : {len(nobump):3}  {dict(Counter(r['severity'] for r in nobump))}")
            print(f"      por motor: {dict(Counter(r['scan_engine'] for r in nobump))}")
            export["assets"].append({
                "asset_id": aid, "path": path_ns, "branch": branch, "head": head,
                "scanned_counts": c, "total_open": len(need) + len(nobump),
                "needs_version_bump": need, "fixable_without_upgrade": nobump,
            })

    json.dump(export, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\nExport -> {OUT}")


if __name__ == "__main__":
    main()
    os._exit(0)
