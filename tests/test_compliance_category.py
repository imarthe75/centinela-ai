"""Accessibility (WCAG) findings are the COMPLIANCE category (owner decision 2026-10-29): visible, with SLA and AI analysis, but never
counted as security vulnerabilities. These tests pin that across the classifier, the group report, the comparison and /api/stats.
DB tests run inside a transaction that is rolled back (rule 8: no rows left behind)."""
import contextlib
import unittest
from unittest import mock

from core import db_manager, group_reports as gr, scan_comparison as sc
from core.deduplication_engine import classify_finding_category, is_compliance_rule


class TestClassifier(unittest.TestCase):
    def test_wcag_rules_are_compliance(self):
        for rule, engine in (("WCAG-1.1.1-IMG-MISSING-ALT", "accessibility-wcag"), ("ACCESSIBILITY-WCAG-MISSING-LABEL", "sast-native"),
                             ("WCAG-4.1.2-AXE-BUTTON-NAME", "smart-tests"), ("ANY-RULE", "wcag-render")):
            self.assertEqual(classify_finding_category(rule, engine), "COMPLIANCE", rule)
            self.assertTrue(is_compliance_rule(rule, engine))

    def test_other_rules_unchanged(self):
        self.assertEqual(classify_finding_category("CODE-INJECTION-EVAL", "sast-native"), "VULNERABILITY")
        self.assertEqual(classify_finding_category("SCAN-AUDIT", "sast-native"), "INFORMATIONAL")
        self.assertFalse(is_compliance_rule("XSS-WCAG-LIKE-NAME", "sast-native"))   # prefix match only, not substring

    def test_comparison_reclassifies_old_baselines(self):
        # Baselines snapshotted before COMPLIANCE existed stored WCAG findings as VULNERABILITY.
        old = {"cve_id": "WCAG-1.1.1-IMG-MISSING-ALT", "scan_engine": "accessibility-wcag", "finding_category": "VULNERABILITY"}
        self.assertEqual(sc.item_category(old), "COMPLIANCE")
        self.assertEqual(sc.item_category({"cve_id": "R1", "finding_category": "INFORMATIONAL"}), "INFORMATIONAL")
        s = sc.summarize({"SOLVENTADO": [dict(old, severity="LOW")], "PERSISTE": [{"cve_id": "R1", "severity": "HIGH"}]})
        self.assertEqual(s["COMPLIANCE"], {"SOLVENTADO": {"LOW": 1}})
        self.assertEqual(s["VULNERABILITY"], {"PERSISTE": {"HIGH": 1}})


class TestCountsAgainstDb(unittest.TestCase):
    def setUp(self):
        self._stack = contextlib.ExitStack()
        self.conn = self._stack.enter_context(db_manager.get_db_connection())

        @contextlib.contextmanager
        def shared_cursor(cursor_factory=None):
            cur = self.conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cur
            finally:
                cur.close()
        self._stack.enter_context(mock.patch.object(db_manager, "get_db_cursor", shared_cursor))
        cur = self.conn.cursor()
        cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES ('test-comp/a@x', 'GitLab-Repo', 't') RETURNING id")
        self.aid = cur.fetchone()[0]
        ins = """INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status, finding_category, scan_engine)
                 VALUES (%s, %s, %s, 'd', 'OPEN', %s, %s)"""
        cur.execute(ins, (self.aid, "R1", "HIGH", "VULNERABILITY", "sast-native"))
        cur.execute(ins, (self.aid, "WCAG-1.1.1-IMG-MISSING-ALT", "MEDIUM", "COMPLIANCE", "accessibility-wcag"))
        cur.execute(ins, (self.aid, "WCAG-2.4.1-NO-SKIP-LINK", "LOW", "COMPLIANCE", "accessibility-wcag"))
        cur.execute(ins, (self.aid, "Q1", "LOW", "INFORMATIONAL", "sonarqube"))

    def tearDown(self):
        self.conn.rollback()
        self._stack.close()

    def test_group_summary_counts_compliance_apart(self):
        s = gr.group_summary(self.conn.cursor(), [str(self.aid)])
        t = s["totals"]
        self.assertEqual((t["vulns"], t["high"], t["med"], t["compliance"], t["info"]), (1, 1, 0, 2, 1))
        self.assertEqual({x["cve_id"] for x in s["top_rules"]}, {"R1"})
        self.assertIn("Cumplimiento: accesibilidad (WCAG)", gr.render_group_general_html("G", s))

    def test_stats_and_asset_report(self):
        from fastapi.testclient import TestClient
        from main import app
        c = TestClient(app)
        r = c.get("/api/stats")
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()
        self.assertGreaterEqual(d["code_compliance"], 2)
        self.assertEqual(d["compliance_total"], d["code_compliance"] + d["infra_compliance"])
        r = c.get("/api/remediation", params={"asset": "test-comp/a@x", "category": "COMPLIANCE", "status_scope": "all"})
        self.assertEqual(r.status_code, 200, r.text)
        r = c.get("/api/reports/asset/test-comp/a@x", params={"format": "html"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("Cumplimiento de Accesibilidad — WCAG 2.1 (2)", r.text)
        self.assertIn("Hallazgos de Seguridad (1)", r.text)


if __name__ == "__main__":
    unittest.main()
