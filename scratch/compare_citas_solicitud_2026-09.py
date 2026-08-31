# -*- coding: utf-8 -*-
"""
Re-scan siat-atencion-citas + sideco-solicitud-web (backend+frontend, develop) after the dev
team's remediation commits, and diff against the state left by the 2026-08-31 analysis.

Per asset:
  * snapshot BEFORE  (fingerprint_hash -> row) of every non-SUPPRESSED row
  * git HEAD before/after the pull
  * run the same engine set as gitlab_integration.scan_all_projects() + auditor_authz
    (each engine calls reconcile_resolved_findings -> anything the fresh code no longer
     reproduces flips to RESOLVED)
  * snapshot AFTER
  * classify by fingerprint:
      CORREGIDO  = was open before, RESOLVED now
      PENDIENTE  = open before and still open
      NUEVO      = open now, not present before
Only finding_category='VULNERABILITY' is reported (infra / code-smell / process rows excluded,
same scope as the 2026-08-31 report).
Writes /app/scratch/compare_citas_solicitud_2026-09.json
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

ASSETS = [
    (95, 47764, "edomex-casmart/siat-atencion-citas/backend"),
    (94, 47765, "edomex-casmart/siat-atencion-citas/frontend"),
    (93, 47766, "edomex-casmart/sideco-solicitud-web/backend"),
    (92, 47767, "edomex-casmart/sideco-solicitud-web/frontend"),
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
                          finding_category, LEFT(description,300)
                   FROM vulnerability_log WHERE asset_id=%s AND status <> 'SUPPRESSED'""", (aid,))
    out = {}
    for fp, cve, sev, eng, loc, st, cat, desc in cur.fetchall():
        key = fp or f"nofp::{cve}::{loc}"
        out[key] = dict(cve=cve, sev=sev, engine=eng, loc=loc, status=st,
                        category=cat, desc=desc)
    return out


def git_head(path):
    try:
        return subprocess.run(["git", "-C", path, "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return "?"


def git_last_commit(path):
    try:
        r = subprocess.run(["git", "-C", path, "log", "-1", "--format=%h %ci %s"],
                           capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception:
        return "?"


def scan(target, aid, name):
    auditor_master_vulnerabilities.run_master_vulnerability_scan(target, asset_id=aid)
    auditor_sca_dependencies.run_sca_audit(target, asset_id=aid)
    auditor_compliance_standards.run_compliance_standards_audit(target, asset_id=aid)
    auditor_iac_k8s.run_iac_scan(target, asset_id=aid)
    auditor_cmmi_v3.run_cmmi_audit(target, asset_id=aid)
    auditor_accessibility_wcag.run_wcag_accessibility_audit(target, asset_id=aid)
    auditor_authz.run_authz_audit(target, asset_id=aid)
    try:
        sg = auditor_semgrep.scan_path(target, aid, name)
        auditor_semgrep.persist_findings(sg)
    except Exception:
        import traceback; traceback.print_exc()
    try:
        auditor_sonarqube.run_sonarqube_audit(target, asset_id=aid, repo_display_name=name)
    except Exception:
        import traceback; traceback.print_exc()


def main():
    g = GitLabIntegrator()
    h = {"PRIVATE-TOKEN": g.token} if g.token else {}
    import requests
    result = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "assets": []}

    for pid, aid, name in ASSETS:
        proj = requests.get(f"{g.gitlab_url}/api/v4/projects/{pid}", headers=h, timeout=30).json()
        branch = g.pick_branch(pid)

        # locate existing clone (if any) to read its HEAD *before* the pull
        # clone_or_pull uses /tmp/centinela_gitlab_scans/<ns with _>  -- mirror that
        clone_dir = f"/tmp/centinela_gitlab_scans/{name.replace('/', '_')}"
        head_before = git_head(clone_dir) if os.path.isdir(os.path.join(clone_dir, ".git")) else "(sin clon previo)"

        with db_manager.get_db_cursor() as cur:
            before = snapshot(cur, aid)

        target = g.clone_or_pull(proj["http_url_to_repo"], name, branch=branch)
        head_after = git_head(target)
        last_commit = git_last_commit(target)
        print(f"\n=== {name}  {head_before} -> {head_after}  ({branch}) ===")
        scan(target, aid, name)

        with db_manager.get_db_cursor() as cur:
            after = snapshot(cur, aid)

        corregido, pendiente, nuevo = [], [], []
        for key, row in before.items():
            was_open = row["status"] not in ("RESOLVED", "SUPPRESSED")
            if not was_open:
                continue
            if row["category"] != "VULNERABILITY" or is_infra(row["cve"], row["engine"]):
                continue
            now = after.get(key)
            if now is None or now["status"] == "RESOLVED":
                corregido.append(row)
            else:
                pendiente.append(row)
        for key, row in after.items():
            if row["status"] in ("RESOLVED", "SUPPRESSED"):
                continue
            if row["category"] != "VULNERABILITY" or is_infra(row["cve"], row["engine"]):
                continue
            if key not in before or before[key]["status"] in ("RESOLVED", "SUPPRESSED"):
                nuevo.append(row)

        def split(rows):
            up = [r for r in rows if is_sca(r["cve"], r["engine"])]
            noup = [r for r in rows if not is_sca(r["cve"], r["engine"])]
            return up, noup

        c_up, c_no = split(corregido)
        p_up, p_no = split(pendiente)
        n_up, n_no = split(nuevo)
        print(f"  CORREGIDO {len(corregido):3} (sin-upgrade {len(c_no)}, upgrade {len(c_up)})")
        print(f"  PENDIENTE {len(pendiente):3} (sin-upgrade {len(p_no)}, upgrade {len(p_up)})")
        print(f"  NUEVO     {len(nuevo):3} (sin-upgrade {len(n_no)}, upgrade {len(n_up)})")

        result["assets"].append(dict(
            asset_id=aid, path=name, branch=branch,
            head_before=head_before, head_after=head_after, last_commit=last_commit,
            corregido=corregido, pendiente=pendiente, nuevo=nuevo,
            counts=dict(corregido=len(corregido), pendiente=len(pendiente), nuevo=len(nuevo),
                        pendiente_sin_upgrade=len(p_no), pendiente_upgrade=len(p_up),
                        corregido_sin_upgrade=len(c_no), corregido_upgrade=len(c_up),
                        nuevo_sin_upgrade=len(n_no), nuevo_upgrade=len(n_up)),
        ))

    out = "/app/scratch/compare_citas_solicitud_2026-09.json"
    json.dump(result, open(out, "w"), ensure_ascii=False, indent=1)
    print(f"\nExport -> {out}")
    print("\n\n===== RESUMEN =====")
    for a in result["assets"]:
        c = a["counts"]
        print(f"{a['path']:44} {a['head_before']}->{a['head_after']}  "
              f"corregido={c['corregido']:3}  pendiente={c['pendiente']:3}  nuevo={c['nuevo']:3}")


if __name__ == "__main__":
    main()
    os._exit(0)
