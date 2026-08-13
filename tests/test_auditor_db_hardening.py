"""
Unit test for DB Hardening Auditor module using standard unittest.
"""
import unittest
from auditors.auditor_db_hardening import check_db_tls, audit_database_security
from core.db_manager import get_db_cursor

class TestDBHardening(unittest.TestCase):
    def test_check_db_tls_non_existent(self):
        res = check_db_tls("127.0.0.1", 59999)
        self.assertFalse(res["tls_active"])
        self.assertIsNone(res["version"])

    def test_audit_database_security_persists_findings(self):
        """
        Regression test for a real bug: audit_database_security() used to call
        get_db_connection() (a @contextmanager) without 'with', raising AttributeError on
        conn.cursor() -- caught by the caller's broad except, so this function never wrote a
        single row to vulnerability_log in production (confirmed live: 0/17940 rows before the
        fix). This exercises the real end-to-end persistence path against the real DB, not a
        mock, since the bug was specifically in how the DB connection was obtained/used.
        """
        # endpoint has no recognizable DB-type substring (postgres/mysql/etc.) so the auditor's
        # own default-port branch applies (port 5432) -- the real, stored url_path is
        # "127.0.0.1:5432", not the endpoint string verbatim.
        test_endpoint = "127.0.0.1:59999"
        expected_location = "127.0.0.1:5432"
        try:
            audit_database_security(None, test_endpoint, "SQL")
            with get_db_cursor() as cur:
                cur.execute(
                    "SELECT cve_id, fingerprint_hash FROM vulnerability_log "
                    "WHERE scan_engine='db-hardening' AND asset_id IS NULL AND url_path = %s",
                    (expected_location,)
                )
                rows = cur.fetchall()
            self.assertTrue(any(r[0] == "DB-NO-TLS-ENCRYPTION" for r in rows))
            self.assertTrue(all(r[1] for r in rows))  # fingerprint_hash populated -> real dedup wiring
        finally:
            with get_db_cursor() as cur:
                cur.execute(
                    "DELETE FROM vulnerability_log WHERE scan_engine='db-hardening' AND asset_id IS NULL AND url_path=%s",
                    (expected_location,)
                )

if __name__ == "__main__":
    unittest.main()
