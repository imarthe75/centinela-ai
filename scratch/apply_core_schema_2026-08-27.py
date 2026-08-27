"""
One-off: apply core.schema.ensure_core_schema() against the live centinela_db immediately,
so finding_suppressions / agent_actions exist before the services are restarted with the
startup hook that also calls it. Idempotent -- safe to re-run.
"""
import os
import sys

sys.path.insert(0, "/app")

from core import db_manager
from core.schema import ensure_core_schema, CORE_SCHEMA_STATEMENTS


def main():
    with db_manager.get_db_cursor() as cur:
        ensure_core_schema(cur)
        cur.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema='public' AND table_name IN ('finding_suppressions','agent_actions')
            ORDER BY table_name
        """)
        print("Present:", [r[0] for r in cur.fetchall()])
        for t in ("finding_suppressions", "agent_actions"):
            cur.execute("""
                SELECT column_name, data_type FROM information_schema.columns
                WHERE table_schema='public' AND table_name=%s ORDER BY ordinal_position
            """, (t,))
            print(f"\n{t}:")
            for name, dtype in cur.fetchall():
                print(f"  {name:<18} {dtype}")
    print(f"\nApplied {len(CORE_SCHEMA_STATEMENTS)} statements OK.")


if __name__ == "__main__":
    main()
