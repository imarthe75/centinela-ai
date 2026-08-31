"""
Re-export the citas / solicitud-web findings from the DB (data already persisted by the
2026-08-31 scan) applying the filters the user asked for:
  * finding_category = 'VULNERABILITY' only  -> drop SonarQube code-smells/bugs, CMMI
    process-debt, ISO-25010 maintainability metrics, scan markers
  * drop infrastructure findings (isolated dev server) -> no ZAP/DAST, no CIS, no
    TLS/HTTP-header/server-hardening findings; keep only what lives IN the repository
  * split: needs library version bump (SCA/CVE) vs fixable without any upgrade
"""
import sys, os, json
sys.path.insert(0, "/app")
from datetime import datetime
from core import db_manager

ASSETS = [
    (47764, "edomex-casmart/siat-atencion-citas/backend",   "develop"),
    (47765, "edomex-casmart/siat-atencion-citas/frontend",  "develop"),
    (47766, "edomex-casmart/sideco-solicitud-web/backend",  "develop"),
    (47767, "edomex-casmart/sideco-solicitud-web/frontend", "develop"),
]

SCA_ENGINES = {"sca-native", "sca", "trivy", "grype", "osv", "dependency-check"}
SCA_CVE_PREFIXES = ("SCA-", "CVE-", "GHSA-", "OSV-", "PYSEC-", "RUSTSEC-", "NPM-")

# engines / cve_ids that describe the deployed server or transport, not the source code
INFRA_ENGINES = {"zap", "zap-dast", "nuclei", "cis-benchmark", "trivy-image", "openvas", "nmap"}
INFRA_CVE_MARKERS = ("HSTS", "TLS", "SSL", "HTTPS", "X-FRAME", "X-CONTENT-TYPE", "CSP-",
                     "STRICT-TRANSPORT", "SERVER-BANNER", "HTTP-HEADER", "CIS-", "SSH-",
                     "CLICKJACK", "COOKIE-SECURE", "COOKIE-FLAG")


def is_sca(cve_id, se):
    if (se or "").lower() in SCA_ENGINES:
        return True
    return (cve_id or "").upper().startswith(SCA_CVE_PREFIXES)


def is_infra(cve_id, se, desc):
    if (se or "").lower() in INFRA_ENGINES:
        return True
    cid = (cve_id or "").upper()
    return any(m in cid for m in INFRA_CVE_MARKERS)


def main():
    gen = datetime.now().strftime("%Y-%m-%d %H:%M")
    export = {"generated": gen, "scope_note": (
        "Solo hallazgos del código en el repositorio (rama develop). Se excluyen por decisión "
        "explícita: vulnerabilidades de infraestructura / servidor de desarrollo aislado "
        "(TLS/HTTPS, cabeceras HTTP del servidor, hardening de SO, DAST). Solo se incluyen "
        "hallazgos de categoría VULNERABILITY (se omiten code-smells de SonarQube, métricas "
        "ISO-25010 y deuda de proceso CMMI)."), "assets": []}

    with db_manager.get_db_cursor() as cur:
        for aid, path_ns, branch in ASSETS:
            cur.execute("""
                SELECT cve_id, severity, scan_engine, url_path, finding_category, description
                FROM vulnerability_log
                WHERE asset_id = %s
                  AND status NOT IN ('RESOLVED','SUPPRESSED')
                  AND finding_category = 'VULNERABILITY'
                ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                       WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                         scan_engine, cve_id
            """, (aid,))
            need, nobump, dropped_infra = [], [], 0
            for cve_id, sev, se, loc, cat, desc in cur.fetchall():
                if is_infra(cve_id, se, desc):
                    dropped_infra += 1
                    continue
                rec = {"cve_id": cve_id, "severity": sev, "scan_engine": se,
                       "location": loc, "description": desc}
                (need if is_sca(cve_id, se) else nobump).append(rec)

            from collections import Counter
            print(f"### {path_ns} (asset {aid})")
            print(f"    VULNERABILITY abiertas (código): {len(need)+len(nobump)}   (infra descartadas: {dropped_infra})")
            print(f"    requieren subir versión : {len(need):3}  {dict(Counter(r['severity'] for r in need))}")
            print(f"    sin actualizar librería : {len(nobump):3}  {dict(Counter(r['severity'] for r in nobump))}")
            print(f"      por motor: {dict(Counter(r['scan_engine'] for r in nobump))}\n")
            export["assets"].append({
                "asset_id": aid, "path": path_ns, "branch": branch,
                "infra_dropped": dropped_infra,
                "total_open": len(need) + len(nobump),
                "needs_version_bump": need,
                "fixable_without_upgrade": nobump,
            })

    out = "/app/scratch/citas_solicitud_scan_2026-08-31.json"
    json.dump(export, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"Export -> {out}")


if __name__ == "__main__":
    main()
