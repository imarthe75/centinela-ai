#!/usr/bin/env python3
"""
One-off (2026-09-23): remove SonarQube findings that live inside vendored / generated code
(e.g. the PrimeNG theme under src/assets/layout/...) -- 42k INFORMATIONAL rows (43% of all
SonarQube rows) that were never the teams' own code. The scanner now excludes these paths
(auditor_sonarqube.SONAR_EXCLUSIONS), so they would never be re-created.

Safety: light backup table first; rows carrying a real human remediation decision are skipped.
    docker exec -w /app -e PYTHONPATH=/app centinela-backend python3 scripts/purge_vendored_sonar_noise.py [--apply]
"""
import os
import sys

sys.path.insert(0, os.environ.get("APP_ROOT", "/app"))
from core import db_manager  # noqa: E402

PAT = r"(^|/)(node_modules|vendor|dist)/|/assets/(layout|demo|themes?)/|\.min\.(js|css)(:|$)|\.bundle\.js(:|$)"
BACKUP = "vulnerability_log_vendored_noise_backup_20260923"
WHERE = """scan_engine = 'sonarqube' AND url_path ~ %s
           AND NOT EXISTS (SELECT 1 FROM public.remediation_history rh
                           WHERE rh.vuln_id = vulnerability_log.id AND rh.approval_token <> 'PENDING_APPROVAL')"""


def main(apply: bool) -> None:
    with db_manager.get_db_cursor() as cur:
        cur.execute(f"SELECT count(*) FROM public.vulnerability_log WHERE {WHERE}", (PAT,))
        n = cur.fetchone()[0]
        print(f"vendored SonarQube rows eligible for purge: {n}")
        if not apply:
            print("dry run (use --apply)")
            return
        cur.execute(f"""CREATE TABLE IF NOT EXISTS public.{BACKUP} AS
                        SELECT id, asset_id, cve_id, severity, status, url_path, detected_at, fingerprint_hash
                        FROM public.vulnerability_log WHERE {WHERE}""", (PAT,))
        cur.execute(f"DELETE FROM public.remediation_history WHERE vuln_id IN "
                    f"(SELECT id FROM public.vulnerability_log WHERE {WHERE})", (PAT,))
        cur.execute(f"DELETE FROM public.vulnerability_log WHERE {WHERE}", (PAT,))
        print(f"deleted {cur.rowcount} rows (backup in public.{BACKUP})")


if __name__ == "__main__":
    main("--apply" in sys.argv)
    sys.stdout.flush()
    os._exit(0)
