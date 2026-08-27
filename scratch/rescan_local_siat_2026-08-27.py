"""
Re-scan the 3 Local/siat/* folder assets in place (code snapshot 2026-08-20/21) with the
current, improved detectors -- CVSS-real SCA severity, everything-claude-code exclusion,
tightened STRIDE regexes, WCAG engine, realigned CMMI. Each native engine reconciles its own
stale findings (marks RESOLVED anything the fresh scan no longer reproduces) when asset_id is
given. Mirrors auditors.gitlab_integration.GitLabIntegrator.scan_all_projects()'s per-repo set.

User decision 2026-08-27: "Re-escanear ahora las carpetas tal cual".
"""
import sys
sys.path.insert(0, "/app")

from core import db_manager

ASSETS = {
    "/app/siat/backend-sideco-develop":  "Local/siat/backend-sideco-develop",
    "/app/siat/frontend-sideco-develop": "Local/siat/frontend-sideco-develop",
    "/app/siat/siat-develop-2026":       "Local/siat/siat-develop-2026",
}


def resolve_asset_id(name):
    with db_manager.get_db_cursor() as cur:
        cur.execute("""
            INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, last_audit, status)
            VALUES (%s, 'GitLab-Repo', %s, 'MEDIUM', NOW(), 'monitored')
            ON CONFLICT (asset_name) DO UPDATE SET last_audit = NOW(), status = 'monitored'
            RETURNING id
        """, (name, name))
        return cur.fetchone()[0]


def scan_one(target_dir, name):
    from auditors import (auditor_master_vulnerabilities, auditor_sca_dependencies,
                          auditor_compliance_standards, auditor_iac_k8s, auditor_cmmi_v3,
                          auditor_accessibility_wcag, auditor_semgrep, auditor_sonarqube,
                          auditor_llm_governance)
    aid = resolve_asset_id(name)
    print(f"\n{'='*70}\n{name}  (asset_id={aid})  {target_dir}\n{'='*70}")
    counts = {}
    counts["sast"] = len(auditor_master_vulnerabilities.run_master_vulnerability_scan(target_dir, asset_id=aid))
    counts["sca"] = len(auditor_sca_dependencies.run_sca_audit(target_dir, asset_id=aid))
    counts["standards"] = len(auditor_compliance_standards.run_compliance_standards_audit(target_dir, asset_id=aid))
    counts["iac"] = len(auditor_iac_k8s.run_iac_scan(target_dir, asset_id=aid))
    counts["cmmi"] = len(auditor_cmmi_v3.run_cmmi_audit(target_dir, asset_id=aid))
    counts["wcag"] = len(auditor_accessibility_wcag.run_wcag_accessibility_audit(target_dir, asset_id=aid))
    counts["llm_gov"] = len(auditor_llm_governance.run_llm_governance_audit(target_dir, asset_id=aid))
    try:
        sg = auditor_semgrep.scan_path(target_dir, aid, name)
        auditor_semgrep.persist_findings(sg)
        counts["semgrep"] = len(sg)
    except Exception as e:
        print(f"  semgrep failed: {e}")
        counts["semgrep"] = -1
    try:
        counts["sonarqube"] = len(auditor_sonarqube.run_sonarqube_audit(target_dir, asset_id=aid,
                                                                        repo_display_name=name))
    except Exception as e:
        print(f"  sonarqube failed: {e}")
        counts["sonarqube"] = -1
    print(f"\n  -> {name}: {counts}")
    return aid, counts


def main():
    results = {}
    for target_dir, name in ASSETS.items():
        results[name] = scan_one(target_dir, name)

    print(f"\n\n{'#'*70}\nRESUMEN + estado post-scan en DB\n{'#'*70}")
    with db_manager.get_db_cursor() as cur:
        for name, (aid, counts) in results.items():
            cur.execute("""
                SELECT
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED')) open_total,
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED') AND finding_category='VULNERABILITY') open_vuln,
                  count(*) FILTER (WHERE status='RESOLVED') resolved,
                  count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED') AND severity IN ('CRITICAL','HIGH')) open_hi
                FROM vulnerability_log WHERE asset_id = %s
            """, (aid,))
            r = cur.fetchone()
            print(f"  {name}: scanned={counts}  |  open={r[0]} (vuln={r[1]}, crit/high={r[3]})  resolved(total)={r[2]}")


if __name__ == "__main__":
    main()
