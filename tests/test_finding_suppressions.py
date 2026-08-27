"""
Item 3 (2026-08-27): learned false-positive / accepted-risk suppressions.

Integration tests against the real centinela_db (same style as test_deduplication_null_asset.py):
a suppression keyed on cve_id / fingerprint / url_path_pattern makes log_finding_deduplicated()
return ("suppressed", ...) and NOT create/reopen a vulnerability_log row, while still bumping
the suppression's own re-detection counter.
"""
import unittest

from core.db_manager import get_db_cursor
from core.deduplication_engine import (
    log_finding_deduplicated,
    find_active_suppression,
    calculate_fingerprint,
)

TEST_CVE = "TEST-SUPPRESSION-DEDUP"
TEST_ENGINE = "test-verification"


class TestFindingSuppressions(unittest.TestCase):
    def tearDown(self):
        with get_db_cursor() as cur:
            cur.execute("DELETE FROM vulnerability_log WHERE cve_id = %s", (TEST_CVE,))
            cur.execute("DELETE FROM finding_suppressions WHERE cve_id = %s", (TEST_CVE,))

    def test_new_finding_matching_active_suppression_is_not_inserted(self):
        with get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO finding_suppressions (cve_id, reason, scope, created_by)
                VALUES (%s, 'regex false positive on descriptive string', 'FALSE_POSITIVE', 'pytest')
                RETURNING id
            """, (TEST_CVE,))
            supp_id = cur.fetchone()[0]

        with get_db_cursor() as cur:
            action, row_id = log_finding_deduplicated(
                cur, None, TEST_CVE, "HIGH", "first detection", TEST_ENGINE,
                url_path=f"{TEST_CVE}:1", preserve_status=True,
            )
        self.assertEqual(action, "suppressed")
        self.assertEqual(row_id, -1, "a brand-new suppressed finding must not be inserted")

        with get_db_cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE cve_id = %s", (TEST_CVE,))
            self.assertEqual(cur.fetchone()[0], 0)
            cur.execute("SELECT match_count FROM finding_suppressions WHERE id = %s", (supp_id,))
            self.assertEqual(cur.fetchone()[0], 1, "re-detection must be counted on the suppression")

    def test_existing_open_finding_is_parked_in_suppressed(self):
        # 1. finding exists and is OPEN
        with get_db_cursor() as cur:
            action, row_id = log_finding_deduplicated(
                cur, None, TEST_CVE, "HIGH", "real-looking detection", TEST_ENGINE,
                url_path=f"{TEST_CVE}:7", preserve_status=True,
            )
        self.assertEqual(action, "inserted")

        # 2. analyst suppresses it by fingerprint
        fp = calculate_fingerprint(None, TEST_CVE, f"{TEST_CVE}:7")
        with get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO finding_suppressions (cve_id, fingerprint_hash, reason, created_by)
                VALUES (%s, %s, 'accepted risk', 'pytest')
            """, (TEST_CVE, fp))

        # 3. next scan re-detects -> row goes SUPPRESSED, same id, no duplicate
        with get_db_cursor() as cur:
            action2, row_id2 = log_finding_deduplicated(
                cur, None, TEST_CVE, "HIGH", "re-detected", TEST_ENGINE,
                url_path=f"{TEST_CVE}:7", preserve_status=True,
            )
        self.assertEqual(action2, "suppressed")
        self.assertEqual(row_id2, row_id)

        with get_db_cursor() as cur:
            cur.execute("SELECT status FROM vulnerability_log WHERE id = %s", (row_id,))
            self.assertEqual(cur.fetchone()[0], "SUPPRESSED")
            cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE cve_id = %s", (TEST_CVE,))
            self.assertEqual(cur.fetchone()[0], 1)

    def test_inactive_or_expired_suppression_does_not_match(self):
        with get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO finding_suppressions (cve_id, reason, created_by, active)
                VALUES (%s, 'was a FP, re-enabled', 'pytest', FALSE)
            """, (TEST_CVE,))
            cur.execute("""
                INSERT INTO finding_suppressions (cve_id, reason, created_by, expires_at)
                VALUES (%s, 'temporary mute, already expired', 'pytest', NOW() - INTERVAL '1 hour')
            """, (TEST_CVE,))

        with get_db_cursor() as cur:
            match = find_active_suppression(cur, None, TEST_CVE, "deadbeef", f"{TEST_CVE}:1")
            self.assertIsNone(match)
            action, row_id = log_finding_deduplicated(
                cur, None, TEST_CVE, "HIGH", "should insert normally", TEST_ENGINE,
                url_path=f"{TEST_CVE}:1", preserve_status=True,
            )
        self.assertEqual(action, "inserted")
        self.assertGreater(row_id, 0)

    def test_url_path_pattern_scopes_the_match(self):
        with get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO finding_suppressions (cve_id, url_path_pattern, reason, created_by)
                VALUES (%s, %s, 'only the vendored dir is a FP', 'pytest')
            """, (TEST_CVE, "vendor/%"))

        with get_db_cursor() as cur:
            in_scope = find_active_suppression(cur, None, TEST_CVE, "x", "vendor/lib/thing.js:3")
            out_scope = find_active_suppression(cur, None, TEST_CVE, "x", "src/app/thing.js:3")
        self.assertIsNotNone(in_scope)
        self.assertIsNone(out_scope)


if __name__ == "__main__":
    unittest.main()
