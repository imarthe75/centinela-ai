"""
Escanea la rama `develop-damc-seguridad` de sideco-solicitud-web/backend (project 93) y la
compara contra el estado actual de `develop` (asset 47766) para decir qué corrigieron los
cambios de Daniel Miranda (commit 46bc15a5 "configuraciones de seguridad"), qué sigue
pendiente y qué es nuevo.

La rama se escanea en un ACTIVO SEPARADO para no alterar el seguimiento de `develop`.
El diff se hace a nivel (familia de hallazgo, archivo) -- estable frente a cambios de línea.
"""
import sys, os, json, subprocess, re
sys.path.insert(0, "/app")
from datetime import datetime
from collections import Counter, defaultdict
from core import db_manager
from auditors.gitlab_integration import GitLabIntegrator
from auditors import (auditor_master_vulnerabilities, auditor_sca_dependencies,
                      auditor_compliance_standards, auditor_iac_k8s, auditor_cmmi_v3,
                      auditor_accessibility_wcag, auditor_sonarqube, auditor_semgrep,
                      auditor_authz)

auditor_sonarqube._recently_scanned = lambda *a, **k: False

PROJECT_ID = 93
BRANCH = "develop-damc-seguridad"
BASELINE_ASSET = 47766                       # sideco-solicitud-web/backend en develop
BRANCH_ASSET_NAME = "GitLab/edomex-casmart/sideco-solicitud-web/backend @develop-damc-seguridad"
OUT = "/app/scratch/sideco_backend_branch_2026-09-01.json"

SCA_ENG = {"sca-native", "sca", "trivy", "grype", "osv"}
SCA_PFX = ("SCA-", "CVE-", "GHSA-", "OSV-")
INFRA_ENG = {"zap", "zap-dast", "nuclei", "cis-benchmark", "nmap"}
INFRA_MARK = ("HSTS", "STRICT-TRANSPORT", "SERVER-BANNER", "CIS-", "SSH-ROOT", "CLICKJACK")


def is_sca(cve, se): return (se or "").lower() in SCA_ENG or (cve or "").upper().startswith(SCA_PFX)
def is_infra(cve, se): return (se or "").lower() in INFRA_ENG or any(m in (cve or "").upper() for m in INFRA_MARK)
def famkey(cve): return (cve or "").split(":")[0]
def filekey(loc):
    s = re.sub(r":\d+(?:-\d+)?$", "", (loc or "").strip())
    # semgrep sometimes stores an absolute clone path and sometimes a repo-relative one for the
    # same finding (known quirk) -- collapse both to the repo-relative path so the diff doesn't
    # see the absolute variant as "corregido".
    s = re.sub(r"^/tmp/centinela_gitlab_scans/[^/]+/", "", s)
    return s


def register_branch_asset(web_url):
    with db_manager.get_db_cursor() as cur:
        cur.execute("""
            INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, last_audit, status)
            VALUES (%s, 'GitLab-Repo', %s, 'MEDIUM', NOW(), 'monitored')
            ON CONFLICT (asset_name) DO UPDATE SET last_audit = NOW(), status = 'monitored'
            RETURNING id
        """, (BRANCH_ASSET_NAME, web_url))
        return cur.fetchone()[0]


def snapshot(cur, aid):
    cur.execute("""SELECT cve_id, severity, scan_engine, url_path, finding_category, LEFT(description,600)
                   FROM vulnerability_log
                   WHERE asset_id=%s AND status NOT IN ('RESOLVED','SUPPRESSED')
                     AND finding_category='VULNERABILITY'""", (aid,))
    rows = []
    for cve, sev, se, loc, cat, desc in cur.fetchall():
        if is_infra(cve, se):
            continue
        rows.append(dict(cve=cve, sev=sev, engine=se, loc=loc or "", desc=desc,
                         fam=famkey(cve), fk=filekey(loc or ""), is_sca=is_sca(cve, se)))
    return rows


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
    import requests
    h = {"PRIVATE-TOKEN": g.token} if g.token else {}
    proj = requests.get(f"{g.gitlab_url}/api/v4/projects/{PROJECT_ID}", headers=h, timeout=30).json()

    with db_manager.get_db_cursor() as cur:
        base = snapshot(cur, BASELINE_ASSET)

    baid = register_branch_asset(proj.get("web_url", proj["http_url_to_repo"]))
    target = g.clone_or_pull(proj["http_url_to_repo"], f"{proj['path_with_namespace']}__branch", branch=BRANCH)
    head = subprocess.run(["git", "-C", target, "log", "-1", "--format=%h %ci %s"],
                          capture_output=True, text=True, timeout=15).stdout.strip()
    print(f"\n=== {BRANCH}  HEAD {head}  asset={baid} ===")
    scan(target, baid, proj["path_with_namespace"] + " (" + BRANCH + ")")

    with db_manager.get_db_cursor() as cur:
        after = snapshot(cur, baid)

    # diff by (familia, archivo). una familia+archivo con N hallazgos en base y 0 en after = corregida.
    base_by = defaultdict(list)
    for r in base:
        base_by[(r["fam"], r["fk"])].append(r)
    after_by = defaultdict(list)
    for r in after:
        after_by[(r["fam"], r["fk"])].append(r)

    corregido, pendiente, nuevo = [], [], []
    for k, rs in base_by.items():
        if k in after_by:
            pendiente += after_by[k]        # sigue presente -> reportar el estado actual
        else:
            corregido += rs
    for k, rs in after_by.items():
        if k not in base_by:
            nuevo += rs

    def sp(rows):
        return ([x for x in rows if not x["is_sca"]], [x for x in rows if x["is_sca"]])
    c_no, c_up = sp(corregido); p_no, p_up = sp(pendiente); n_no, n_up = sp(nuevo)

    print(f"\nCORREGIDO {len(corregido):3}  (sin-upgrade {len(c_no)}, upgrade {len(c_up)})")
    print(f"PENDIENTE {len(pendiente):3}  (sin-upgrade {len(p_no)}, upgrade {len(p_up)})")
    print(f"NUEVO     {len(nuevo):3}  (sin-upgrade {len(n_no)}, upgrade {len(n_up)})")
    print("corregido por familia:", dict(Counter(r["fam"] for r in corregido)))
    print("nuevo por familia    :", dict(Counter(r["fam"] for r in nuevo)))

    res = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
           "repo": proj["path_with_namespace"], "branch": BRANCH, "branch_head": head,
           "baseline": "develop (asset 47766)",
           "corregido": corregido, "pendiente": pendiente, "nuevo": nuevo,
           "counts": dict(cor=len(corregido), pen=len(pendiente), nue=len(nuevo),
                          cor_no=len(c_no), cor_up=len(c_up), pen_no=len(p_no),
                          pen_up=len(p_up), nue_no=len(n_no), nue_up=len(n_up))}
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\nExport -> {OUT}")


if __name__ == "__main__":
    main()
    os._exit(0)
