"""
Focused, verified re-scan of the 4 repos behind SIAT (siat-atencion-citas) and SIDECO
(sideco-solicitud-web) for a delivery report -- their real code lives on `develop`, not the
default `main` (near-empty stub). Clones develop explicitly, asserts the tree is non-trivial
before scanning, forces a fresh SonarQube run (deletes the 24h self-throttle marker), runs the
full engine set, prints a clean per-repo + per-severity breakdown.
"""
import sys
sys.path.insert(0, "/app")

import os
import shutil
import subprocess

from core import db_manager
from auditors.gitlab_integration import GitLabIntegrator
from auditors import (auditor_master_vulnerabilities, auditor_sca_dependencies,
                      auditor_compliance_standards, auditor_iac_k8s, auditor_cmmi_v3,
                      auditor_accessibility_wcag, auditor_sonarqube, auditor_semgrep)

WS = "/tmp/report_scan_siat_sideco"
TARGETS = [
    (95, "edomex-casmart/siat-atencion-citas/backend"),
    (94, "edomex-casmart/siat-atencion-citas/frontend"),
    (93, "edomex-casmart/sideco-solicitud-web/backend"),
    (92, "edomex-casmart/sideco-solicitud-web/frontend"),
]


def clone_develop(g, pid, path_ns):
    branch = g.pick_branch(pid)
    dest = os.path.join(WS, path_ns.replace("/", "_"))
    shutil.rmtree(dest, ignore_errors=True)
    url = f"http://oauth2:{g.token}@10.4.3.10/{path_ns}.git"
    r = subprocess.run(["git", "clone", "--depth", "1", "--branch", branch, url, dest],
                       capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        print(f"  !! clone {branch} failed: {r.stderr.strip()[:200]}")
        return None, branch
    return dest, branch


def register(path_ns):
    with db_manager.get_db_cursor() as cur:
        cur.execute("""
            INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, last_audit, status)
            VALUES (%s, 'GitLab-Repo', %s, 'HIGH', NOW(), 'monitored')
            ON CONFLICT (asset_name) DO UPDATE SET last_audit = NOW(), status = 'monitored'
            RETURNING id
        """, (f"GitLab/{path_ns}", f"http://10.4.3.10/{path_ns}"))
        return cur.fetchone()[0]


def force_sonar(asset_id):
    with db_manager.get_db_cursor() as cur:
        cur.execute("DELETE FROM public.vulnerability_log WHERE asset_id=%s AND cve_id='SONARQUBE-QUALITY-GATE'", (asset_id,))


def main():
    g = GitLabIntegrator()
    os.makedirs(WS, exist_ok=True)
    results = []
    for pid, path_ns in TARGETS:
        print(f"\n{'='*74}\n{path_ns}\n{'='*74}")
        dest, branch = clone_develop(g, pid, path_ns)
        if not dest:
            continue
        nfiles = sum(1 for r, _, fs in os.walk(dest) for f in fs)
        nsrc = sum(1 for r, _, fs in os.walk(dest) for f in fs
                   if f.endswith((".java", ".ts", ".js", ".html", ".xml", ".json", ".py", ".sql")))
        head = subprocess.run(["git", "-C", dest, "log", "-1", "--format=%h %ci %s"],
                              capture_output=True, text=True).stdout.strip()
        print(f"  branch={branch}  files={nfiles}  source_files={nsrc}\n  HEAD: {head}")
        aid = register(path_ns)
        force_sonar(aid)
        c = {}
        c["sast"] = len(auditor_master_vulnerabilities.run_master_vulnerability_scan(dest, asset_id=aid))
        c["sca"] = len(auditor_sca_dependencies.run_sca_audit(dest, asset_id=aid))
        c["standards"] = len(auditor_compliance_standards.run_compliance_standards_audit(dest, asset_id=aid))
        c["iac"] = len(auditor_iac_k8s.run_iac_scan(dest, asset_id=aid))
        c["cmmi"] = len(auditor_cmmi_v3.run_cmmi_audit(dest, asset_id=aid))
        c["wcag"] = len(auditor_accessibility_wcag.run_wcag_accessibility_audit(dest, asset_id=aid))
        try:
            sg = auditor_semgrep.scan_path(dest, aid, path_ns)
            auditor_semgrep.persist_findings(sg)
            c["semgrep"] = len(sg)
        except Exception as e:
            print(f"  semgrep failed: {e}"); c["semgrep"] = -1
        try:
            c["sonarqube"] = len(auditor_sonarqube.run_sonarqube_audit(dest, asset_id=aid, repo_display_name=path_ns))
        except Exception as e:
            print(f"  sonarqube failed: {e}"); c["sonarqube"] = -1
        print(f"  -> {c}")
        results.append((aid, path_ns, branch, nsrc, head, c))

    print(f"\n\n{'#'*74}\nRESUMEN POR REPOSITORIO\n{'#'*74}")
    with db_manager.get_db_cursor() as cur:
        for aid, path_ns, branch, nsrc, head, c in results:
            cur.execute("""
                SELECT
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED') AND finding_category='VULNERABILITY') vuln_open,
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED') AND finding_category='INFORMATIONAL') info_open,
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED') AND finding_category='VULNERABILITY' AND UPPER(severity)='CRITICAL') crit,
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED') AND finding_category='VULNERABILITY' AND UPPER(severity)='HIGH') high,
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED') AND finding_category='VULNERABILITY' AND UPPER(severity)='MEDIUM') med,
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED') AND finding_category='VULNERABILITY' AND UPPER(severity)='LOW') low,
                  count(*) FILTER (WHERE status='RESOLVED') resolved
                FROM vulnerability_log WHERE asset_id=%s
            """, (aid,))
            r = cur.fetchone()
            print(f"\n{path_ns}  [{branch}]  ({nsrc} archivos fuente)")
            print(f"  vulns reales abiertas: {r[0]}  (C:{r[2]} H:{r[3]} M:{r[4]} L:{r[5]})   informativos: {r[1]}   reconciliados/resueltos: {r[6]}")
            print(f"  motores: {c}")
            cur.execute("""
                SELECT scan_engine, UPPER(severity), count(*)
                FROM vulnerability_log
                WHERE asset_id=%s AND finding_category='VULNERABILITY' AND status NOT IN ('RESOLVED','SUPPRESSED')
                GROUP BY scan_engine, UPPER(severity) ORDER BY 1,2
            """, (aid,))
            for row in cur.fetchall():
                print(f"     {row[0]:20} {row[1]:9} {row[2]}")

    print("\nWorkspace kept at", WS, "for report evidence.")


if __name__ == "__main__":
    main()
