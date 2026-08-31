# -*- coding: utf-8 -*-
"""
v2: same as compare_citas_solicitud_2026-09.py but FORCES a fresh SonarQube run (the 24h
cache was hiding remediation -- SonarQube last scanned solicitud/backend at 2026-08-31 11:10,
before the dev team's 12:18 "passwords directamente" cleanup commit).

before  = current DB open VULNERABILITY rows per asset (== the 2026-08-31 report state)
scan    = clone develop HEAD + every engine incl. forced SonarQube; each reconciles
after   = new DB open set
diff by fingerprint: CORREGIDO / PENDIENTE / NUEVO, split by needs-library-upgrade
"""
import sys, os, json, subprocess
sys.path.insert(0, "/app")
from datetime import datetime
from core import db_manager
from auditors.gitlab_integration import GitLabIntegrator
from auditors import (auditor_master_vulnerabilities, auditor_sca_dependencies,
                      auditor_compliance_standards, auditor_iac_k8s, auditor_cmmi_v3,
                      auditor_accessibility_wcag, auditor_sonarqube, auditor_semgrep,
                      auditor_authz)

# force SonarQube to actually run
auditor_sonarqube._recently_scanned = lambda *a, **k: False

ASSETS = [
    (95, 47764, "edomex-casmart/siat-atencion-citas/backend",  "develop"),
    (94, 47765, "edomex-casmart/siat-atencion-citas/frontend", "develop"),
    (93, 47766, "edomex-casmart/sideco-solicitud-web/backend",  "develop"),
    (92, 47767, "edomex-casmart/sideco-solicitud-web/frontend", "develop"),
]
SCA_ENG = {"sca-native", "sca", "trivy", "grype", "osv"}
SCA_PFX = ("SCA-", "CVE-", "GHSA-", "OSV-", "PYSEC-", "RUSTSEC-", "NPM-")
INFRA_ENG = {"zap", "zap-dast", "nuclei", "cis-benchmark"}
INFRA_MARK = ("HSTS", "TLS", "SSL", "HTTPS", "X-FRAME", "X-CONTENT-TYPE", "STRICT-TRANSPORT",
              "SERVER-BANNER", "HTTP-HEADER", "CIS-", "SSH-", "CLICKJACK", "COOKIE-SECURE")


def is_sca(cve, eng):
    return (eng or "").lower() in SCA_ENG or (cve or "").upper().startswith(SCA_PFX)


def is_infra(cve, eng):
    return (eng or "").lower() in INFRA_ENG or any(m in (cve or "").upper() for m in INFRA_MARK)


def snapshot(cur, aid):
    cur.execute("""SELECT fingerprint_hash, cve_id, severity, scan_engine, url_path, status,
                          finding_category, LEFT(description,400)
                   FROM vulnerability_log WHERE asset_id=%s AND status <> 'SUPPRESSED'""", (aid,))
    out = {}
    for fp, cve, sev, eng, loc, st, cat, desc in cur.fetchall():
        out[fp or f"nofp::{cve}::{loc}"] = dict(cve=cve, sev=sev, engine=eng, loc=loc,
                                                status=st, category=cat, desc=desc)
    return out


def scan(target, aid, name):
    for fn in (
        lambda: auditor_master_vulnerabilities.run_master_vulnerability_scan(target, asset_id=aid),
        lambda: auditor_sca_dependencies.run_sca_audit(target, asset_id=aid),
        lambda: auditor_compliance_standards.run_compliance_standards_audit(target, asset_id=aid),
        lambda: auditor_iac_k8s.run_iac_scan(target, asset_id=aid),
        lambda: auditor_cmmi_v3.run_cmmi_audit(target, asset_id=aid),
        lambda: auditor_accessibility_wcag.run_wcag_accessibility_audit(target, asset_id=aid),
        lambda: auditor_authz.run_authz_audit(target, asset_id=aid),
        lambda: auditor_sonarqube.run_sonarqube_audit(target, asset_id=aid, repo_display_name=name),
    ):
        try:
            fn()
        except Exception:
            import traceback; traceback.print_exc()
    try:
        sg = auditor_semgrep.scan_path(target, aid, name)
        auditor_semgrep.persist_findings(sg)
    except Exception:
        import traceback; traceback.print_exc()


def main():
    g = GitLabIntegrator()
    h = {"PRIVATE-TOKEN": g.token} if g.token else {}
    import requests
    res = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "assets": []}

    for pid, aid, name, branch in ASSETS:
        proj = requests.get(f"{g.gitlab_url}/api/v4/projects/{pid}", headers=h, timeout=30).json()
        with db_manager.get_db_cursor() as cur:
            before = snapshot(cur, aid)
        target = g.clone_or_pull(proj["http_url_to_repo"], name, branch=branch)
        head = subprocess.run(["git", "-C", target, "log", "-1", "--format=%h %ci %s"],
                              capture_output=True, text=True, timeout=15).stdout.strip()
        print(f"\n=== {name}  HEAD {head} ===")
        scan(target, aid, name)
        with db_manager.get_db_cursor() as cur:
            after = snapshot(cur, aid)

        cor, pen, nue = [], [], []
        for k, r in before.items():
            if r["status"] in ("RESOLVED", "SUPPRESSED"):
                continue
            if r["category"] != "VULNERABILITY" or is_infra(r["cve"], r["engine"]):
                continue
            n = after.get(k)
            (cor if (n is None or n["status"] == "RESOLVED") else pen).append(r)
        for k, r in after.items():
            if r["status"] in ("RESOLVED", "SUPPRESSED"):
                continue
            if r["category"] != "VULNERABILITY" or is_infra(r["cve"], r["engine"]):
                continue
            if k not in before or before[k]["status"] in ("RESOLVED", "SUPPRESSED"):
                nue.append(r)

        sp = lambda rows: ([x for x in rows if not is_sca(x["cve"], x["engine"])],
                           [x for x in rows if is_sca(x["cve"], x["engine"])])
        c_no, c_up = sp(cor); p_no, p_up = sp(pen); n_no, n_up = sp(nue)
        print(f"  CORREGIDO {len(cor):3}  (sin-upgrade {len(c_no)}, upgrade {len(c_up)})")
        print(f"  PENDIENTE {len(pen):3}  (sin-upgrade {len(p_no)}, upgrade {len(p_up)})")
        print(f"  NUEVO     {len(nue):3}  (sin-upgrade {len(n_no)}, upgrade {len(n_up)})")
        res["assets"].append(dict(
            asset_id=aid, path=name, branch=branch, head=head,
            corregido=cor, pendiente=pen, nuevo=nue,
            counts=dict(cor=len(cor), pen=len(pen), nue=len(nue),
                        cor_no=len(c_no), cor_up=len(c_up), pen_no=len(p_no),
                        pen_up=len(p_up), nue_no=len(n_no), nue_up=len(n_up))))

    out = "/app/scratch/compare_citas_solicitud_v2_2026-09.json"
    json.dump(res, open(out, "w"), ensure_ascii=False, indent=1)
    print(f"\nExport -> {out}\n\n===== RESUMEN =====")
    for a in res["assets"]:
        c = a["counts"]
        print(f"{a['path']:44} corregido={c['cor']:3} pendiente={c['pen']:3} nuevo={c['nue']:3}  "
              f"| pendiente: sin-upgrade {c['pen_no']}, upgrade {c['pen_up']}")


if __name__ == "__main__":
    main()
    os._exit(0)
