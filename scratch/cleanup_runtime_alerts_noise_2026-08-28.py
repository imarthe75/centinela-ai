"""
One-time cleanup of runtime_alerts (2026-08-28).

Context: the "Búsqueda de Amenazas en Tiempo Real - Log Maestro" view was ~99.9% noise --
15,675 of 16,188 rows were Falco firing non-stop against Centinela's own ephemeral scanner
containers (ZAP/trivy/etc.) plus Zeek's own liveness heartbeat appended every 5 min. Ingestion
is now filtered at the source (centinela.py::process_falco_alerts skips NOISE_RULES; the Zeek
heartbeat now replaces its single row instead of appending). This clears the backlog and
normalises the mixed-case priority values already stored ('Critical'/'Warning'/'Notice'/'Debug'
from Falco vs 'CRITICAL'/'INFO' from Centinela's own writers).

Keeps exactly one recent ZEEK-CONN-HEARTBEAT row -- /api/health's Zeek-ingestion check only
verifies a recent one exists.
"""
import sys
sys.path.insert(0, "/app")
from core import db_manager

NOISE_RULES = (
    "Drop and execute new binary in container",
    "Read sensitive file untrusted",
    "PTRACE attached to process",
    "Falco internal: syscall event drop",
)

PRIORITY_NORMALISE = """
    UPDATE runtime_alerts SET priority = CASE UPPER(priority)
        WHEN 'EMERGENCY' THEN 'CRITICAL' WHEN 'ALERT' THEN 'CRITICAL'
        WHEN 'ERROR' THEN 'HIGH' WHEN 'WARNING' THEN 'MEDIUM'
        WHEN 'NOTICE' THEN 'LOW' WHEN 'INFORMATIONAL' THEN 'INFO' WHEN 'DEBUG' THEN 'INFO'
        WHEN 'CRITICAL' THEN 'CRITICAL' WHEN 'HIGH' THEN 'HIGH'
        WHEN 'MEDIUM' THEN 'MEDIUM' WHEN 'LOW' THEN 'LOW'
        ELSE 'INFO'
    END
    WHERE priority IS DISTINCT FROM CASE UPPER(priority)
        WHEN 'EMERGENCY' THEN 'CRITICAL' WHEN 'ALERT' THEN 'CRITICAL'
        WHEN 'ERROR' THEN 'HIGH' WHEN 'WARNING' THEN 'MEDIUM'
        WHEN 'NOTICE' THEN 'LOW' WHEN 'INFORMATIONAL' THEN 'INFO' WHEN 'DEBUG' THEN 'INFO'
        WHEN 'CRITICAL' THEN 'CRITICAL' WHEN 'HIGH' THEN 'HIGH'
        WHEN 'MEDIUM' THEN 'MEDIUM' WHEN 'LOW' THEN 'LOW'
        ELSE 'INFO'
    END
"""


def main():
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT count(*) FROM runtime_alerts")
        before = cur.fetchone()[0]

        cur.execute(
            "DELETE FROM runtime_alerts WHERE rule_name = ANY(%s)", (list(NOISE_RULES),)
        )
        deleted_noise = cur.rowcount

        # Keep only the single most recent heartbeat.
        cur.execute("""
            DELETE FROM runtime_alerts
            WHERE rule_name = 'ZEEK-CONN-HEARTBEAT'
              AND id NOT IN (
                  SELECT id FROM runtime_alerts
                  WHERE rule_name = 'ZEEK-CONN-HEARTBEAT'
                  ORDER BY detected_at DESC LIMIT 1
              )
        """)
        deleted_hb = cur.rowcount

        cur.execute(PRIORITY_NORMALISE)
        normalised = cur.rowcount

        cur.execute("SELECT count(*) FROM runtime_alerts")
        after = cur.fetchone()[0]

        cur.execute("SELECT rule_name, priority, count(*) FROM runtime_alerts GROUP BY rule_name, priority ORDER BY count(*) DESC")
        remaining = cur.fetchall()

    print(f"before={before}  deleted_noise={deleted_noise}  deleted_old_heartbeats={deleted_hb}  priority_rows_normalised={normalised}  after={after}")
    print("remaining rows:")
    for r in remaining:
        print("  ", r)


if __name__ == "__main__":
    main()
