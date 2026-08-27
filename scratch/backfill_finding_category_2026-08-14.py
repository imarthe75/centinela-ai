"""
One-time backfill: populate the new finding_category column (added 2026-08-14) on all existing
vulnerability_log rows, using the exact same classify_finding_category() every future write goes
through -- guarantees the backfill can never drift from live classification logic.
"""
import os
import sys

sys.path.insert(0, "/app")

from core import db_manager
from core.deduplication_engine import classify_finding_category


def main():
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT id, cve_id, scan_engine, description FROM public.vulnerability_log")
        rows = cur.fetchall()
        print(f"Fetched {len(rows)} rows.")

        informational_ids = []
        vulnerability_ids = []
        for row_id, cve_id, scan_engine, description in rows:
            category = classify_finding_category(cve_id, scan_engine, description)
            (informational_ids if category == "INFORMATIONAL" else vulnerability_ids).append(row_id)

        print(f"INFORMATIONAL: {len(informational_ids)}  VULNERABILITY: {len(vulnerability_ids)}")

        if informational_ids:
            cur.execute(
                "UPDATE public.vulnerability_log SET finding_category = 'INFORMATIONAL' WHERE id = ANY(%s)",
                (informational_ids,)
            )
        if vulnerability_ids:
            cur.execute(
                "UPDATE public.vulnerability_log SET finding_category = 'VULNERABILITY' WHERE id = ANY(%s)",
                (vulnerability_ids,)
            )
        print(f"Updated {len(informational_ids)} rows to INFORMATIONAL, {len(vulnerability_ids)} rows to VULNERABILITY.")


if __name__ == "__main__":
    main()
    os._exit(0)
