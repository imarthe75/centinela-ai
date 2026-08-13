"""
Regression test for log_finding_deduplicated() with asset_id=None.

Real bug found live: Tier 1/2 of log_finding_deduplicated() compared "asset_id = %s". In SQL,
NULL = NULL evaluates to NULL (never TRUE), so any finding logged with asset_id=None (a
legitimate, intentional value for aggregate/org-wide findings like HEURISTIC-SECURITY-DEBT's
"no single asset" bucket) could never find its own previously-inserted row and fell through to
Tier 3 (INSERT) on every single call. Confirmed live: 983 duplicate rows for one such alert,
versus real in-place updates for every asset-attributed finding using the exact same function.
Fixed with "asset_id IS NOT DISTINCT FROM %s" (NULL-safe equality).
"""
import threading
import unittest
from core.db_manager import get_db_cursor
from core.deduplication_engine import log_finding_deduplicated

class TestDeduplicationNullAsset(unittest.TestCase):
    TEST_CVE = "TEST-NULL-ASSET-DEDUP"

    def tearDown(self):
        with get_db_cursor() as cur:
            cur.execute("DELETE FROM vulnerability_log WHERE cve_id=%s", (self.TEST_CVE,))

    def test_repeated_calls_with_none_asset_id_update_in_place(self):
        with get_db_cursor() as cur:
            action1, id1 = log_finding_deduplicated(
                cur, None, self.TEST_CVE, "HIGH", "first description", "test-verification",
                url_path=self.TEST_CVE, preserve_status=True
            )
        self.assertEqual(action1, "inserted")

        with get_db_cursor() as cur:
            action2, id2 = log_finding_deduplicated(
                cur, None, self.TEST_CVE, "HIGH", "second, different description", "test-verification",
                url_path=self.TEST_CVE, preserve_status=True
            )
        self.assertEqual(action2, "updated")
        self.assertEqual(id1, id2, "second call must update the same row, not insert a duplicate")

        with get_db_cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE cve_id=%s", (self.TEST_CVE,))
            count = cur.fetchone()[0]
        self.assertEqual(count, 1, "exactly one row should exist after two calls with the same fingerprint")


class TestDeduplicationConcurrentRace(unittest.TestCase):
    """
    Regression test for a real bug: log_finding_deduplicated()'s Tier 1 was a plain SELECT
    with no locking, and vulnerability_log had no unique constraint on fingerprint_hash at all
    (see CLAUDE.md gotcha #3). Two callers racing for the exact same brand-new fingerprint could
    both see "not found" in their own SELECT and both fall through to INSERT -- confirmed live
    via a real backfill that produced 61 duplicate rows for one finding in a single batch (839
    duplicates total across the fleet, cleaned up alongside this fix). Fixed with a real unique
    index (idx_vulnerability_log_fingerprint_unique) and an atomic
    `INSERT ... ON CONFLICT (fingerprint_hash) DO UPDATE` as Tier 3's actual write, so the
    database itself -- not a racy application-level check -- is what prevents the duplicate.
    """
    TEST_CVE = "TEST-CONCURRENT-RACE-DEDUP"

    def tearDown(self):
        with get_db_cursor() as cur:
            cur.execute("DELETE FROM vulnerability_log WHERE cve_id=%s", (self.TEST_CVE,))

    def test_concurrent_calls_for_new_fingerprint_produce_one_row(self):
        barrier = threading.Barrier(5)
        errors = []

        def worker():
            try:
                barrier.wait(timeout=5)  # maximize real overlap between threads' SELECT/INSERT
                with get_db_cursor() as cur:
                    log_finding_deduplicated(
                        cur, None, self.TEST_CVE, "HIGH", "raced description", "test-verification",
                        url_path=self.TEST_CVE, preserve_status=True
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], f"worker thread(s) raised: {errors}")
        with get_db_cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE cve_id=%s", (self.TEST_CVE,))
            count = cur.fetchone()[0]
        self.assertEqual(count, 1, "exactly one row should exist even when 5 threads race for the same new fingerprint")


if __name__ == "__main__":
    unittest.main()
