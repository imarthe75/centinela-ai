"""
Item 4 (2026-08-27): unified autonomous-action ledger.

Integration tests against the real centinela_db: record_action() writes a row, honours an
externally-supplied cursor (same transaction), coerces an invalid outcome, serialises detail
to JSONB, and -- critically -- never raises even when the write itself fails.
"""
import unittest

from core.db_manager import get_db_cursor
from core import agent_ledger

MARKER = "pytest-agent-ledger-marker"


class TestAgentLedger(unittest.TestCase):
    def tearDown(self):
        with get_db_cursor() as cur:
            cur.execute("DELETE FROM agent_actions WHERE summary LIKE %s", (f"%{MARKER}%",))

    def test_record_action_own_cursor_persists_row(self):
        new_id = agent_ledger.record_action(
            agent_ledger.ACTION_AI_CORRELATION,
            f"{MARKER} own-cursor",
            entity_type="vulnerability", entity_id=999999, outcome="success",
            detail={"k": "v", "n": 3},
        )
        self.assertIsInstance(new_id, int)
        with get_db_cursor() as cur:
            cur.execute("SELECT action_type, outcome, detail FROM agent_actions WHERE id = %s", (new_id,))
            row = cur.fetchone()
        self.assertEqual(row[0], agent_ledger.ACTION_AI_CORRELATION)
        self.assertEqual(row[1], "success")
        self.assertEqual(row[2], {"k": "v", "n": 3})  # psycopg2 decodes JSONB to dict

    def test_shared_cursor_is_same_transaction(self):
        with get_db_cursor() as cur:
            rid = agent_ledger.record_action(
                agent_ledger.ACTION_ZAP_REAP, f"{MARKER} shared-cursor",
                outcome="success", cur=cur,
            )
            self.assertIsInstance(rid, int)
            # visible within the same open transaction
            cur.execute("SELECT COUNT(*) FROM agent_actions WHERE id = %s", (rid,))
            self.assertEqual(cur.fetchone()[0], 1)

    def test_invalid_outcome_is_coerced_not_rejected(self):
        rid = agent_ledger.record_action(
            agent_ledger.ACTION_MR_REVIEW, f"{MARKER} bad-outcome", outcome="banana",
        )
        with get_db_cursor() as cur:
            cur.execute("SELECT outcome FROM agent_actions WHERE id = %s", (rid,))
            self.assertEqual(cur.fetchone()[0], "success")

    def test_record_action_never_raises_on_write_failure(self):
        class BoomCursor:
            def execute(self, *a, **k):
                raise RuntimeError("simulated DB failure")

            def fetchone(self):
                raise AssertionError("should not be reached")

        # must return None, not propagate -- a ledger failure cannot break the caller's real work
        result = agent_ledger.record_action(
            agent_ledger.ACTION_AI_CORRELATION, f"{MARKER} boom", cur=BoomCursor(),
        )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
