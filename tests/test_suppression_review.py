"""
Risk-verdict assessment (structured + legacy-phrase paths) and the human review workflow for
AI-proposed suppressions (approve / reject endpoints).

The endpoint tests run against the real centinela_db schema but inside ONE connection that is
ROLLED BACK at the end (project rule #8: tests must not leave synthetic rows in production audit
tables) -- db_manager.get_db_cursor is patched to hand every caller a cursor on that connection.
"""
import contextlib
import unittest
from datetime import timedelta
from unittest import mock

from fastapi.testclient import TestClient
from psycopg2.extras import RealDictCursor

from core import db_manager
from core.deduplication_engine import assess_real_risk_verdict, get_sla_delta


class TestAssessRealRiskVerdict(unittest.TestCase):
    def check(self, bi, raw, expected, **kw):
        r = assess_real_risk_verdict(bi, "", raw_severity=raw, **kw)
        self.assertEqual((r["real_severity"], r["risk_verdict"]), expected, msg=bi[:50])

    def test_legacy_phrase_path(self):
        self.check("Riesgo real de SEGURIDAD prácticamente nulo (MD5 ...", "HIGH", ("INFO", "CONFIRMED_NO_RISK"))
        self.check("Riesgo real BAJO: apunta a localhost", "CRITICAL", ("LOW", "DOWNGRADED"))
        self.check("Riesgo real BAJO-MODERADO: no hay fuga", "CRITICAL", ("MEDIUM", "DOWNGRADED"))
        self.check("Riesgo real ALTO: host interno real", "CRITICAL", ("HIGH", "DOWNGRADED"))
        self.check("Riesgo real ALTO: x", "HIGH", (None, None))
        self.check("Riesgo real BAJO condicionado a que el catálogo sea de admins", "CRITICAL", (None, "CONDITIONAL"))
        self.check("texto sin veredicto", "HIGH", (None, None))

    def test_structured_path_wins_and_never_raises_severity(self):
        self.check("x", "MEDIUM", ("INFO", "CONFIRMED_NO_RISK"), ai_real_severity="Nulo", ai_depends_on_assumption=False)
        self.check("x", "CRITICAL", ("LOW", "DOWNGRADED"), ai_real_severity="Bajo", ai_depends_on_assumption=False)
        self.check("x", "CRITICAL", (None, "CONDITIONAL"), ai_real_severity="Bajo", ai_depends_on_assumption=True)
        self.check("x", "LOW", (None, None), ai_real_severity="Crítico", ai_depends_on_assumption=False)


class TestSuppressionReviewEndpoints(unittest.TestCase):
    def setUp(self):
        self._stack = contextlib.ExitStack()
        self.addCleanup(self._cleanup)
        conn_cm = db_manager.get_db_connection()
        self.conn = self._stack.enter_context(conn_cm)

        @contextlib.contextmanager
        def shared_cursor(cursor_factory=None):
            cur = self.conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cur
            finally:
                cur.close()

        self._stack.enter_context(mock.patch.object(db_manager, "get_db_cursor", shared_cursor))
        from main import app
        self.client = TestClient(app)
        cur = self.conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM infra_inventory LIMIT 1")
        self.asset_id = cur.fetchone()["id"]
        cur.execute("""
            INSERT INTO vulnerability_log (asset_id, cve_id, severity, status, real_severity, risk_verdict,
                                           business_impact, url_path, fingerprint_hash, detected_at, sla_due_date)
            VALUES (%s, 'TEST-REVIEW-FLOW', 'CRITICAL', 'CORRELATED', 'INFO', 'CONFIRMED_NO_RISK',
                    'Riesgo real NULO: patrón seguro', 'a/b.ts:1', 'test-review-flow-fp', NOW(), NOW() + INTERVAL '90 days')
            RETURNING id, detected_at
        """, (self.asset_id,))
        v = cur.fetchone()
        self.vuln_id, self.detected_at = v["id"], v["detected_at"]
        cur.execute("""
            INSERT INTO finding_suppressions (asset_id, cve_id, reason, scope, created_by, active, review_status)
            VALUES (%s, 'TEST-REVIEW-FLOW', 'Propuesta automática: x', 'FALSE_POSITIVE', 'centinela-ai', FALSE, 'PENDING')
            RETURNING id
        """, (self.asset_id,))
        self.sid = cur.fetchone()["id"]

    def _cleanup(self):
        # addCleanup (not tearDown) so a failure inside setUp still rolls back and releases the
        # connection + the db_manager patch instead of leaking them into every later test.
        try:
            self.conn.rollback()
        finally:
            self._stack.close()

    def _vuln(self):
        cur = self.conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT status, real_severity, risk_verdict, sla_due_date FROM vulnerability_log WHERE id = %s", (self.vuln_id,))
        return cur.fetchone()

    def test_pending_proposal_is_listed(self):
        r = self.client.get("/api/suppression-proposals", params={"status": "PENDING"})
        self.assertEqual(r.status_code, 200)
        ours = [p for p in r.json()["proposals"] if p["id"] == str(self.sid)]
        self.assertEqual(len(ours), 1)
        self.assertEqual(ours[0]["affected_count"], 1)

    def test_approve_suppresses_matching_findings_and_cannot_be_repeated(self):
        r = self.client.post(f"/api/suppression-proposals/{self.sid}/approve", json={"reviewer": "pytest", "note": "ok"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["suppressed_findings"], 1)
        self.assertEqual(self._vuln()["status"], "SUPPRESSED")
        cur = self.conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT active, fingerprint_hash, url_path_pattern FROM finding_suppressions "
                    "WHERE cve_id = 'TEST-REVIEW-FLOW' AND fingerprint_hash IS NOT NULL")
        narrow = cur.fetchall()
        # exactly one narrow, fingerprint-keyed, ACTIVE suppression -- never an asset+cve blanket mute
        self.assertEqual([(n["active"], n["fingerprint_hash"]) for n in narrow], [(True, "test-review-flow-fp")])
        cur.execute("SELECT active FROM finding_suppressions WHERE id = %s", (self.sid,))
        self.assertFalse(cur.fetchone()["active"])
        self.assertEqual(self.client.post(f"/api/suppression-proposals/{self.sid}/approve", json={}).status_code, 404)

    def test_reject_reverts_to_tool_severity_and_recomputes_sla(self):
        r = self.client.post(f"/api/suppression-proposals/{self.sid}/reject", json={"reviewer": "pytest"})
        self.assertEqual(r.status_code, 200, r.text)
        v = self._vuln()
        self.assertIsNone(v["real_severity"])
        self.assertEqual(v["risk_verdict"], "ANALYST_OVERRIDDEN")
        self.assertEqual(v["status"], "CORRELATED")
        self.assertEqual(v["sla_due_date"], self.detected_at + get_sla_delta("CRITICAL"))
        self.assertEqual(get_sla_delta("CRITICAL"), timedelta(hours=24))


if __name__ == "__main__":
    unittest.main()
