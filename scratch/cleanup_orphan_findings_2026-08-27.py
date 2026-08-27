"""
2026-08-27 cleanup of the mess left by the gitlab_integration.py asset-registration bug
(a swallowed "server closed the connection unexpectedly" let whole repo scans run with
asset_id=None) plus the auditor_llm_governance.py raw-INSERT/ON-CONFLICT-DO-NOTHING duplicate
bug. Both root causes fixed in the same commit; this removes the accumulated bad rows.

Safe because: every affected repo is re-scanned cleanly by the fleet loop within 24h now that
registration is fixed, and the deleted rows are unattributed (invisible in every asset-scoped
view, never AI-correlated) SonarQube/SAST/SCA/standards/CMMI/WCAG/Semgrep/LLM-gov artifacts --
no human decision (remediation_history.approval_token) is attached to any of them (asserted
below before deleting).
"""
import sys
sys.path.insert(0, "/app")
from core import db_manager


def main():
    with db_manager.get_db_cursor() as cur:
        # ---- 1. NULL asset_id findings from the buggy engines ----
        cur.execute("""
            SELECT count(*) FROM vulnerability_log
            WHERE asset_id IS NULL
              AND (scan_engine IN ('sonarqube','sast-native','sca-native','standards-audit',
                                   'cmmi-audit','accessibility-wcag','semgrep','heuristics-engine')
                   OR scan_engine IS NULL)
        """)
        n_null = cur.fetchone()[0]

        # guard: no approved/acted remediation attached to any of these
        cur.execute("""
            SELECT count(*) FROM remediation_history r
            JOIN vulnerability_log v ON r.vuln_id = v.id
            WHERE v.asset_id IS NULL
              AND COALESCE(r.approval_token, 'PENDING_APPROVAL') NOT IN ('PENDING_APPROVAL')
        """)
        acted = cur.fetchone()[0]
        assert acted == 0, f"ABORT: {acted} NULL-asset findings have a real remediation decision"

        cur.execute("""
            DELETE FROM remediation_history
            WHERE vuln_id IN (
                SELECT id FROM vulnerability_log
                WHERE asset_id IS NULL
                  AND (scan_engine IN ('sonarqube','sast-native','sca-native','standards-audit',
                                       'cmmi-audit','accessibility-wcag','semgrep','heuristics-engine')
                       OR scan_engine IS NULL))
        """)
        rh1 = cur.rowcount
        cur.execute("""
            DELETE FROM vulnerability_log
            WHERE asset_id IS NULL
              AND (scan_engine IN ('sonarqube','sast-native','sca-native','standards-audit',
                                   'cmmi-audit','accessibility-wcag','semgrep','heuristics-engine')
                   OR scan_engine IS NULL)
        """)
        d1 = cur.rowcount

        # ---- 2. findings pointing at deleted/nonexistent assets ----
        cur.execute("""
            SELECT count(*) FROM vulnerability_log v
            WHERE v.asset_id IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM infra_inventory i WHERE i.id = v.asset_id)
        """)
        n_dangle = cur.fetchone()[0]
        cur.execute("""
            DELETE FROM remediation_history WHERE vuln_id IN (
                SELECT v.id FROM vulnerability_log v
                WHERE v.asset_id IS NOT NULL
                  AND NOT EXISTS (SELECT 1 FROM infra_inventory i WHERE i.id = v.asset_id))
        """)
        rh2 = cur.rowcount
        cur.execute("""
            DELETE FROM vulnerability_log v
            WHERE v.asset_id IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM infra_inventory i WHERE i.id = v.asset_id)
        """)
        d2 = cur.rowcount

        # ---- 3. remaining exact duplicate groups (asset_id,cve_id,url_path) not RESOLVED ----
        # keep the highest id (most recent), delete the rest, only where no real approval exists
        cur.execute("""
            WITH dups AS (
                SELECT id, row_number() OVER (
                    PARTITION BY asset_id, cve_id, url_path ORDER BY id DESC) rn
                FROM vulnerability_log
                WHERE status NOT IN ('RESOLVED','SUPPRESSED')
            ), losers AS (SELECT id FROM dups WHERE rn > 1)
            SELECT count(*) FROM losers l
            WHERE EXISTS (SELECT 1 FROM remediation_history r
                          WHERE r.vuln_id = l.id
                            AND COALESCE(r.approval_token,'PENDING_APPROVAL') <> 'PENDING_APPROVAL')
        """)
        dup_acted = cur.fetchone()[0]
        assert dup_acted == 0, f"ABORT: {dup_acted} duplicate rows carry a real remediation decision"

        cur.execute("""
            WITH dups AS (
                SELECT id, row_number() OVER (
                    PARTITION BY asset_id, cve_id, url_path ORDER BY id DESC) rn
                FROM vulnerability_log
                WHERE status NOT IN ('RESOLVED','SUPPRESSED')
            )
            DELETE FROM remediation_history WHERE vuln_id IN (SELECT id FROM dups WHERE rn > 1)
        """)
        rh3 = cur.rowcount
        cur.execute("""
            WITH dups AS (
                SELECT id, row_number() OVER (
                    PARTITION BY asset_id, cve_id, url_path ORDER BY id DESC) rn
                FROM vulnerability_log
                WHERE status NOT IN ('RESOLVED','SUPPRESSED')
            )
            DELETE FROM vulnerability_log WHERE id IN (SELECT id FROM dups WHERE rn > 1)
        """)
        d3 = cur.rowcount

        print(f"1. NULL-asset findings deleted:      {d1}  (of {n_null} matched)  + {rh1} remediation_history")
        print(f"2. dangling-asset findings deleted:  {d2}  (of {n_dangle} matched) + {rh2} remediation_history")
        print(f"3. duplicate-group rows deleted:     {d3}  + {rh3} remediation_history")

        # ---- verify ----
        cur.execute("SELECT count(*) FROM vulnerability_log WHERE asset_id IS NULL")
        print(f"\nremaining asset_id IS NULL: {cur.fetchone()[0]}")
        cur.execute("""SELECT count(*) FROM vulnerability_log v WHERE v.asset_id IS NOT NULL
                       AND NOT EXISTS (SELECT 1 FROM infra_inventory i WHERE i.id=v.asset_id)""")
        print(f"remaining dangling asset_id: {cur.fetchone()[0]}")
        cur.execute("""SELECT count(*) FROM (
            SELECT 1 FROM vulnerability_log WHERE status NOT IN ('RESOLVED','SUPPRESSED')
            GROUP BY asset_id, cve_id, url_path HAVING count(*) > 1) t""")
        print(f"remaining duplicate groups: {cur.fetchone()[0]}")
        cur.execute("""SELECT count(*) FROM vulnerability_log
                       WHERE fingerprint_hash IS NULL AND status NOT IN ('RESOLVED','SUPPRESSED')""")
        print(f"remaining NULL fingerprint (open): {cur.fetchone()[0]}")


if __name__ == "__main__":
    main()
