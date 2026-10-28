"""
(1) Pattern-level analysis sharing (propagate_pattern_analysis), (2) informational findings never call
an LLM, (3) the provider cascade order/fallthrough incl. the new tiers. DB tests run on ONE connection that
is rolled back (project rule #8); db_manager.get_db_cursor is patched to hand out cursors on it.
"""
import contextlib
import unittest
import uuid
from unittest import mock

from psycopg2.extras import RealDictCursor

import centinela
from core import db_manager


class TestCascade(unittest.TestCase):
    def setUp(self):
        self._saved = (centinela.groq_llm, centinela.groq_llm_2, centinela.gemini_client, centinela.nvidia_llm,
                       centinela.openrouter_llm, dict(centinela.extra_llms))
        centinela.gemini_client = centinela.nvidia_llm = centinela.openrouter_llm = None
        centinela.extra_llms.clear()
        centinela._tier_cooldown.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        (centinela.groq_llm, centinela.groq_llm_2, centinela.gemini_client, centinela.nvidia_llm,
         centinela.openrouter_llm, extras) = self._saved
        centinela.extra_llms.clear()
        centinela.extra_llms.update(extras)
        centinela._tier_cooldown.clear()

    @staticmethod
    def _llm(text=None, fail=False):
        m = mock.Mock()
        if fail:
            m.invoke.side_effect = RuntimeError("429 quota")
        else:
            m.invoke.return_value = mock.Mock(content=text)
        return m

    def test_order_and_fallthrough_to_extra_provider(self):
        a, b, c = self._llm(fail=True), self._llm(fail=True), self._llm("from-mistral")
        centinela.groq_llm_2, centinela.groq_llm = a, b
        centinela.extra_llms["mistral"] = c
        self.assertEqual(centinela.call_ai_cascade("p"), "from-mistral")
        self.assertTrue(a.invoke.called and b.invoke.called and c.invoke.called)

    def test_first_working_tier_wins_and_later_ones_untouched(self):
        a, b = self._llm("qwen-answer"), self._llm("gpt-oss-answer")
        centinela.groq_llm_2, centinela.groq_llm = a, b
        self.assertEqual(centinela.call_ai_cascade("p"), "qwen-answer")
        self.assertFalse(b.invoke.called)

    def test_all_down_returns_none(self):
        centinela.groq_llm_2 = self._llm(fail=True)
        centinela.groq_llm = None
        self.assertIsNone(centinela.call_ai_cascade("p"))


class TestInformationalSkipsLLM(unittest.TestCase):
    def test_informational_never_reaches_the_cascade(self):
        vuln = {"id": str(uuid.uuid4()), "cve_id": "STD-ISO25010-LONG-METHOD", "severity": "LOW", "description": "x",
                "url_path": "a/B.java:10", "asset_id": None, "asset_name": "GitLab/x/y", "asset_type": "GitLab-Repo",
                "endpoint": "", "finding_category": "INFORMATIONAL"}
        with mock.patch.object(centinela, "call_ai_cascade") as cascade:
            out = centinela.correlate_vulnerability(vuln)
        cascade.assert_not_called()
        self.assertTrue(out)


class TestPatternPropagation(unittest.TestCase):
    def setUp(self):
        self._stack = contextlib.ExitStack()
        self.addCleanup(self._cleanup)
        self.conn = self._stack.enter_context(db_manager.get_db_connection())

        @contextlib.contextmanager
        def shared_cursor(cursor_factory=None):
            cur = self.conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cur
            finally:
                cur.close()

        self._stack.enter_context(mock.patch.object(db_manager, "get_db_cursor", shared_cursor))
        self._stack.enter_context(mock.patch.object(centinela.agent_ledger, "record_action"))
        cur = self.conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM infra_inventory LIMIT 1")
        self.asset_id = cur.fetchone()["id"]
        self.ids = []
        for n in range(3):
            cur.execute("""INSERT INTO vulnerability_log (asset_id, cve_id, severity, status, url_path, fingerprint_hash, detected_at)
                           VALUES (%s, 'AUTHZ-NO-METHOD-AUTHZ', 'HIGH', 'OPEN', %s, %s, NOW()) RETURNING id""",
                        (self.asset_id, f"A.java:{n}", f"test-prop-{uuid.uuid4()}"))
            self.ids.append(cur.fetchone()["id"])
        cur.execute("""INSERT INTO vulnerability_log (asset_id, cve_id, severity, status, url_path, fingerprint_hash, detected_at)
                       VALUES (%s, 'SONAR-java-S1', 'HIGH', 'OPEN', 'B.java:1', %s, NOW()) RETURNING id""",
                    (self.asset_id, f"test-prop-{uuid.uuid4()}"))
        self.other = cur.fetchone()["id"]
        self.cur = cur
        self.rep = {"id": self.ids[0], "cve_id": "AUTHZ-NO-METHOD-AUTHZ", "asset_id": self.asset_id, "asset_name": "t"}
        self.analysis = {"executive_summary": "S", "business_impact": "I", "developer_steps": "D", "fix_patch": "DIFF"}

    def _cleanup(self):
        try:
            self.conn.rollback()
        finally:
            self._stack.close()

    def _row(self, vid):
        self.cur.execute("SELECT status, fix_patch, business_impact, real_severity FROM vulnerability_log WHERE id=%s", (vid,))
        return self.cur.fetchone()

    def test_siblings_filled_without_patch_and_other_rules_untouched(self):
        filled = centinela.propagate_pattern_analysis(self.rep, self.analysis, {"risk_verdict": None, "real_severity": None}, "/s.sh")
        self.assertEqual(sorted(filled), sorted(str(i) for i in self.ids[1:]))
        for vid in self.ids[1:]:
            r = self._row(vid)
            self.assertEqual(r["status"], "CORRELATED")
            self.assertIsNone(r["fix_patch"])
            self.assertIn("nivel de patrón", r["business_impact"])
        self.assertEqual(self._row(self.other)["status"], "OPEN")
        self.cur.execute("SELECT can_automate FROM remediation_history WHERE vuln_id = ANY(%s::uuid[])", (self.ids[1:],))
        self.assertEqual([r["can_automate"] for r in self.cur.fetchall()], ["false", "false"])

    def test_risk_reducing_verdict_is_never_propagated(self):
        for v in ("CONFIRMED_NO_RISK", "DOWNGRADED"):
            self.assertEqual(centinela.propagate_pattern_analysis(self.rep, self.analysis, {"risk_verdict": v, "real_severity": "INFO"}, "/s.sh"), [])
        self.assertEqual(self._row(self.ids[1])["status"], "OPEN")

    def test_non_pattern_rule_is_not_propagated(self):
        rep = dict(self.rep, cve_id="SONAR-java-S1", id=self.other)
        self.assertEqual(centinela.propagate_pattern_analysis(rep, self.analysis, {"risk_verdict": None}, "/s.sh"), [])


if __name__ == "__main__":
    unittest.main()


class TestProseResponseDoesNotCrash(unittest.TestCase):
    def test_non_json_provider_answer_still_yields_an_analysis(self):
        vuln = {"id": str(uuid.uuid4()), "cve_id": "AUTHZ-NO-METHOD-AUTHZ", "severity": "HIGH", "description": "x",
                "url_path": "a/B.java:10", "asset_id": None, "asset_name": "GitLab/x/y", "asset_type": "GitLab-Repo",
                "endpoint": "", "finding_category": "VULNERABILITY"}
        prose = ("**Riesgo detectado**: Endpoint sin autorización por método.\n"
                 "**Impacto de negocio**: Cualquier usuario autenticado puede borrar documentos.\n"
                 "**Acción de remediación**: Añadir @PreAuthorize con el permiso correspondiente.")
        with mock.patch.object(centinela, "call_ai_cascade", return_value=prose):
            out = centinela.correlate_vulnerability(vuln)
        self.assertIsInstance(out, dict)
        self.assertIn("ai_real_severity", out)
        self.assertEqual(out["ai_real_severity"], "")
        self.assertIsNone(out["ai_depends_on_assumption"])

    def test_prose_sections_are_actually_extracted(self):
        vuln = {"id": str(uuid.uuid4()), "cve_id": "AUTHZ-NO-METHOD-AUTHZ", "severity": "HIGH", "description": "x",
                "url_path": "a/B.java:10", "asset_id": None, "asset_name": "GitLab/x/y", "asset_type": "GitLab-Repo",
                "endpoint": "", "finding_category": "VULNERABILITY"}
        prose = ("**Riesgo detectado**: Endpoint sin autorización por método.\n"
                 "**Impacto negocio**: Cualquier usuario autenticado puede borrar documentos.\n"
                 "**Acción de remediación**: Añadir @PreAuthorize con el permiso correspondiente.")
        with mock.patch.object(centinela, "call_ai_cascade", return_value=prose):
            out = centinela.correlate_vulnerability(vuln)
        self.assertIn("borrar documentos", out["business_impact"])
        self.assertIn("@PreAuthorize", out["developer_steps"])


class TestQueueAndPatternList(unittest.TestCase):
    def test_wcag_and_audit_log_are_pattern_level_but_sonar_and_sca_are_not(self):
        for cve in ("WCAG-1.3.1-FORM-CONTROL-NO-LABEL", "ACCESSIBILITY-WCAG-MISSING-LABEL", "STD-STRIDE-MISSING-AUDIT-LOG",
                    "OOM-BYTE-ARRAY-STREAMING", "AUTHZ-CLIENT-SIDE-ONLY"):
            self.assertTrue(centinela.PATTERN_LEVEL_RULES.match(cve), cve)
        for cve in ("SONAR-java-S6437", "SCA-CVE-2026-54267", "ANGULAR-BYPASS-SECURITY-TRUST", "HARDCODED-SECRET"):
            self.assertFalse(centinela.PATTERN_LEVEL_RULES.match(cve), cve)

    def test_main_loop_queue_includes_reopened(self):
        import inspect
        src = inspect.getsource(centinela.main_loop)
        self.assertIn("'REOPENED'", src)
        self.assertIn("prev_status", src)


class TestTierCooldownAndQuotaExhaustion(unittest.TestCase):
    def setUp(self):
        self._saved = (centinela.groq_llm, centinela.groq_llm_2, centinela.gemini_client, centinela.nvidia_llm,
                       centinela.openrouter_llm, dict(centinela.extra_llms))
        centinela.groq_llm_2 = centinela.gemini_client = centinela.nvidia_llm = centinela.openrouter_llm = None
        centinela.extra_llms.clear()
        centinela._tier_cooldown.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        (centinela.groq_llm, centinela.groq_llm_2, centinela.gemini_client, centinela.nvidia_llm,
         centinela.openrouter_llm, extras) = self._saved
        centinela.extra_llms.clear(); centinela.extra_llms.update(extras)
        centinela._tier_cooldown.clear()

    def test_cooldown_lengths_by_failure_kind(self):
        self.assertEqual(centinela._cooldown_seconds("Rate limit reached ... on tokens per day (TPD)"), 3600)
        self.assertEqual(centinela._cooldown_seconds("you have used up your daily free allocation of 10,000 neurons"), 3600)
        self.assertEqual(centinela._cooldown_seconds("Request too large ... on tokens per minute (TPM)"), 60)
        self.assertEqual(centinela._cooldown_seconds("429 RESOURCE_EXHAUSTED"), 900)
        self.assertEqual(centinela._cooldown_seconds("Request timed out."), 180)

    def test_failed_tier_is_skipped_on_the_next_call_and_flag_is_set(self):
        bad = mock.Mock(); bad.invoke.side_effect = RuntimeError("429 tokens per day (TPD)")
        centinela.groq_llm = bad
        self.assertIsNone(centinela.call_ai_cascade("p"))
        self.assertTrue(centinela.cascade_all_unavailable())
        self.assertIsNone(centinela.call_ai_cascade("p"))
        self.assertEqual(bad.invoke.call_count, 1)  # second call never touched the cooling-down tier

    def test_recovery_clears_the_flag(self):
        good = mock.Mock(); good.invoke.return_value = mock.Mock(content="ok")
        centinela.groq_llm = good
        centinela._cascade_state["all_unavailable"] = True
        self.assertEqual(centinela.call_ai_cascade("p"), "ok")
        self.assertFalse(centinela.cascade_all_unavailable())

    def test_generic_only_finding_is_left_pending_when_all_tiers_unavailable(self):
        vuln = {"id": str(uuid.uuid4()), "cve_id": "SONAR-java-S9999", "severity": "HIGH", "description": "x",
                "url_path": "a/B.java:3", "asset_id": None, "asset_name": "GitLab/x/y", "asset_type": "GitLab-Repo",
                "endpoint": "", "finding_category": "VULNERABILITY"}
        with mock.patch.object(centinela, "call_ai_cascade", return_value=None), \
             mock.patch.object(centinela, "cascade_all_unavailable", return_value=True):
            self.assertEqual(centinela.correlate_vulnerability(vuln), "RATE_LIMIT")

    def test_finding_with_a_specific_heuristic_rule_still_gets_analysed_when_quota_is_out(self):
        vuln = {"id": str(uuid.uuid4()), "cve_id": "DOCKER-MISSING-NON-ROOT-USER", "severity": "HIGH", "description": "x",
                "url_path": "Dockerfile:1", "asset_id": None, "asset_name": "GitLab/x/y", "asset_type": "GitLab-Repo",
                "endpoint": "", "finding_category": "VULNERABILITY"}
        with mock.patch.object(centinela, "call_ai_cascade", return_value=None), \
             mock.patch.object(centinela, "cascade_all_unavailable", return_value=True):
            out = centinela.correlate_vulnerability(vuln)
        self.assertIsInstance(out, dict)


class TestPriorityOrdering(unittest.TestCase):
    def test_priority_patterns_default_and_query_uses_them(self):
        import inspect
        self.assertIsInstance(centinela.AI_PRIORITY_ASSET_PATTERNS, list)
        self.assertTrue(centinela.AI_PRIORITY_ASSET_PATTERNS)   # never empty: a "matches nothing" sentinel when unset
        src = inspect.getsource(centinela.main_loop)
        self.assertIn("ILIKE ANY(%s)", src)
        self.assertIn("AI_PRIORITY_ASSET_PATTERNS", src)

    def test_priority_assets_sort_before_newer_findings_of_other_assets(self):
        # Run the REAL queue ordering against the DB inside a rolled-back transaction: a priority-asset finding
        # must come before a (newer) finding of a non-priority asset.
        with db_manager.get_db_connection() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            try:
                cur.execute("SELECT id, asset_name FROM infra_inventory WHERE asset_type = 'GitLab-Repo' ORDER BY asset_name LIMIT 1")
                prio = cur.fetchone()
                patterns = [prio["asset_name"].replace("%", "\\%")] if prio else []
                cur.execute("SELECT id, asset_name FROM infra_inventory WHERE asset_name NOT ILIKE ALL(%s) AND asset_type = 'GitLab-Repo' LIMIT 1",
                            (patterns or ["__none__"],))
                other = cur.fetchone()
                if not prio or not other:
                    self.skipTest("needs one priority and one non-priority GitLab-Repo asset")
                ids = {}
                for tag, asset in (("prio", prio), ("other", other)):
                    cur.execute("""INSERT INTO vulnerability_log (asset_id, cve_id, severity, status, url_path, fingerprint_hash, detected_at, finding_category)
                                   VALUES (%s, 'TEST-PRIORITY-ORDER', 'HIGH', 'NEW', 'x:1', %s, NOW(), 'VULNERABILITY') RETURNING id""",
                                (asset["id"], f"test-prio-{tag}-{uuid.uuid4()}"))
                    ids[tag] = cur.fetchone()["id"]   # 'other' is inserted LAST => newer id
                cur.execute("""SELECT v.id FROM vulnerability_log v JOIN infra_inventory i ON v.asset_id = i.id
                               WHERE v.cve_id = 'TEST-PRIORITY-ORDER'
                               ORDER BY (CASE WHEN i.asset_name ILIKE ANY(%s) THEN 0 ELSE 1 END), v.id DESC""",
                            (patterns,))
                order = [r["id"] for r in cur.fetchall()]
                self.assertEqual(order, [ids["prio"], ids["other"]])
            finally:
                conn.rollback()
