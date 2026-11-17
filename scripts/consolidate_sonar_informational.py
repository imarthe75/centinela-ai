#!/usr/bin/env python3
"""One-time consolidation (ADR-0019 phase 2): open informational SonarQube rows stored one per line become one row per (rule, file),
the identity a fresh scan now writes. Without it, the next scan of every project would mark ~110k per-line rows RESOLVED and the
comparison reports would show a remediation that never happened.

Before touching an asset, its affected rows are copied to public.vulnerability_log_sonar_info_backup_20261029. One transaction per
asset. Rows carrying a human remediation decision are never touched.

usage (inside centinela-backend):  python3 scripts/consolidate_sonar_informational.py --dry-run [--limit N] [--asset NAME]
                                   python3 scripts/consolidate_sonar_informational.py
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditors import auditor_sonarqube  # noqa: E402
from core import agent_ledger, db_manager  # noqa: E402

BACKUP = "public.vulnerability_log_sonar_info_backup_20261029"


def assets_to_process(cur, only: str = None):
    cur.execute("""SELECT i.id::text, i.asset_name, count(*) FROM public.vulnerability_log v JOIN public.infra_inventory i ON i.id = v.asset_id
                    WHERE v.scan_engine = 'sonarqube' AND v.finding_category = 'INFORMATIONAL' AND v.status NOT IN ('RESOLVED', 'SUPPRESSED')
                      AND (%s::text IS NULL OR i.asset_name = %s)
                    GROUP BY 1, 2 ORDER BY 3 DESC""", (only, only))
    return cur.fetchall()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="run every change and roll it back")
    ap.add_argument("--limit", type=int, default=0, help="process only the N assets with most rows")
    ap.add_argument("--asset", default=None)
    args = ap.parse_args()
    with db_manager.get_db_cursor() as cur:
        assets = assets_to_process(cur, args.asset)
        if not args.dry_run:
            cur.execute(f"CREATE TABLE IF NOT EXISTS {BACKUP} (LIKE public.vulnerability_log INCLUDING DEFAULTS)")
            cur.execute(f"COMMENT ON TABLE {BACKUP} IS 'Copia de las filas informativas de SonarQube por ocurrencia antes de agruparlas por regla y archivo (ADR-0019, 2026-10-29).'")
    if args.limit:
        assets = assets[:args.limit]
    total = {"assets": 0, "rows_before": 0, "groups": 0, "deleted": 0}
    t0 = time.time()
    for aid, name, n in assets:
        with db_manager.get_db_connection() as conn:
            cur = conn.cursor()
            try:
                if not args.dry_run:
                    cur.execute(f"""INSERT INTO {BACKUP} SELECT v.* FROM public.vulnerability_log v
                                     WHERE v.asset_id = %s AND v.scan_engine = 'sonarqube' AND v.finding_category = 'INFORMATIONAL'
                                       AND v.status NOT IN ('RESOLVED', 'SUPPRESSED')
                                       AND NOT EXISTS (SELECT 1 FROM {BACKUP} b WHERE b.id = v.id)""", (aid,))
                st = auditor_sonarqube.consolidate_informational_rows(cur, aid)
                (conn.rollback if args.dry_run else conn.commit)()
            except Exception:
                conn.rollback()
                import traceback
                print(f"FAILED {name}:")
                traceback.print_exc()
                continue
        total["assets"] += 1
        for k in ("rows_before", "groups", "deleted"):
            total[k] += st[k]
        print(f"{'DRY ' if args.dry_run else ''}{name}: {st['rows_before']} filas -> {st['groups']} grupos ({st['deleted']} eliminadas)", flush=True)
    print(f"TOTAL {'(dry-run) ' if args.dry_run else ''}{total} en {time.time() - t0:.0f}s")
    if not args.dry_run and total["assets"]:
        agent_ledger.record_action("sonar_informational_consolidated",
                                   f"{total['rows_before']} filas informativas de SonarQube agrupadas en {total['groups']} (regla, archivo)",
                                   actor="claude-assistant", detail=total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
