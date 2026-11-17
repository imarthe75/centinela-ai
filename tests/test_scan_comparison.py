"""Comparativo "último escaneo vs anterior" (core/scan_comparison.py) and semgrep reconciliation.

DB tests run inside one connection that is ROLLED BACK (project rule #8): no synthetic rows survive.
"""
import contextlib
import unittest
from unittest import mock

from core import db_manager, scan_comparison as sc


class TestClassifyPure(unittest.TestCase):
    def test_classes(self):
        baseline = [
            {"finding_id": "a", "cve_id": "R1", "severity": "HIGH", "url_path": "x/A.java:10"},     # fixed
            {"finding_id": "b", "cve_id": "R2", "severity": "MEDIUM", "url_path": "x/B.java:5"},    # moved to line 9
            {"finding_id": "c", "cve_id": "R3", "severity": "LOW", "url_path": "x/C.java:1"},       # re-detected
            {"finding_id": "d", "cve_id": "R4", "severity": "HIGH", "url_path": "x/D.java:1"},      # not re-evaluated
            {"finding_id": "e", "cve_id": "R5", "severity": "HIGH", "url_path": "x/E.java:1"},      # suppressed
            {"finding_id": "f", "cve_id": "R6", "severity": "HIGH", "url_path": "x/F.java:1"},      # row deleted
        ]
        current = {
            "a": {"status": "RESOLVED", "url_path": "x/A.java:10"},
            "b": {"status": "RESOLVED", "url_path": "x/B.java:5"},
            "c": {"status": "CORRELATED", "url_path": "x/C.java:1", "severity": "CRITICAL", "redetected": True},
            "d": {"status": "OPEN", "url_path": "x/D.java:1", "redetected": False},
            "e": {"status": "SUPPRESSED", "url_path": "x/E.java:1"},
        }
        appeared = [
            {"id": "b2", "cve_id": "R2", "severity": "CRITICAL", "status": "NEW", "url_path": "x/B.java:9"},
            {"id": "n1", "cve_id": "R7", "severity": "HIGH", "status": "NEW", "url_path": "x/N.java:3"},
            {"id": "r1", "cve_id": "R8", "severity": "LOW", "status": "REOPENED", "url_path": "x/R.java:3"},
        ]
        out = sc.classify(baseline, current, appeared)
        ids = {k: [i["finding_id"] for i in v] for k, v in out.items()}
        self.assertEqual(ids["SOLVENTADO"], ["a"])
        self.assertEqual(ids["MOVIDO"], ["b"])
        self.assertEqual(ids["PERSISTE"], ["c"])
        self.assertEqual(ids["NO_REVERIFICADO"], ["d"])
        self.assertEqual(ids["SUPRIMIDO"], ["e"])
        self.assertEqual(ids["SIN_REGISTRO"], ["f"])
        self.assertEqual(ids["NUEVO"], ["n1"])          # b2 is the moved twin, not new
        self.assertEqual(ids["REAPARECIDO"], ["r1"])
        # what is still open reports its current severity
        self.assertEqual(out["MOVIDO"][0]["severity"], "CRITICAL")
        self.assertEqual(out["PERSISTE"][0]["severity"], "CRITICAL")
        self.assertEqual(out["SOLVENTADO"][0]["severity"], "HIGH")

    def test_one_twin_per_resolved_finding(self):
        # two old rows of the same rule in one file, only one reappears at a new line -> one moved, one fixed
        baseline = [{"finding_id": "a", "cve_id": "R", "severity": "HIGH", "url_path": "f.java:1"},
                    {"finding_id": "b", "cve_id": "R", "severity": "HIGH", "url_path": "f.java:2"}]
        current = {"a": {"status": "RESOLVED"}, "b": {"status": "RESOLVED"}}
        out = sc.classify(baseline, current, [{"id": "z", "cve_id": "R", "severity": "HIGH", "status": "NEW", "url_path": "f.java:7"}])
        self.assertEqual(len(out["MOVIDO"]), 1)
        self.assertEqual(len(out["SOLVENTADO"]), 1)
        self.assertNotIn("NUEVO", out)

    def test_location_key(self):
        self.assertEqual(sc.location_key("src/A.java:120"), "src/A.java")
        self.assertEqual(sc.location_key("deployment.yaml:20-25"), "deployment.yaml")
        self.assertEqual(sc.location_key("http://h:8080/app/login.xhtml?source=x"), "http://h:8080/app/login.xhtml")
        self.assertEqual(sc.location_key(None), "")

    def test_render_html_handles_no_runs(self):
        comps = [{"asset": {"id": "1", "name": "A<x>"}, "available": False, "runs": {}, "reason": "sin línea base"}]
        h = sc.render_html(comps, "T")
        self.assertIn("A&lt;x&gt;", h)
        self.assertIn("sin línea base", h)


class TestComparisonAgainstDb(unittest.TestCase):
    """Whole flow on the real schema: run baseline -> simulated scan writes -> comparison."""

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

    def tearDown(self):
        self.conn.rollback()
        self._stack.close()

    def test_flow(self):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES ('test-scan-comparison@x', 'GitLab-Repo', 'test') RETURNING id")
        aid = cur.fetchone()[0]
        ins = """INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status, url_path, scan_engine, finding_category, detected_at)
                 VALUES (%s, %s, %s, 'd', %s, %s, 'sast-native', 'VULNERABILITY', now() - interval '1 day') RETURNING id"""
        cur.execute(ins, (aid, "R-FIXED", "HIGH", "OPEN", "a.java:1")); fixed = cur.fetchone()[0]
        cur.execute(ins, (aid, "R-STAYS", "CRITICAL", "CORRELATED", "b.java:1")); stays = cur.fetchone()[0]
        cur.execute(ins, (aid, "R-OLD", "LOW", "RESOLVED", "c.java:1"))      # already closed: not in the baseline

        run_id = sc.open_run(str(aid), "test", "abc123")
        self.assertIsNotNone(run_id)
        cur.execute("SELECT baseline_count FROM scan_runs WHERE id = %s", (run_id,))
        self.assertEqual(cur.fetchone()[0], 2)

        # the "scan": closes one, re-detects the other, finds a new one
        cur.execute("UPDATE vulnerability_log SET status = 'RESOLVED' WHERE id = %s", (fixed,))
        cur.execute("UPDATE vulnerability_log SET detected_at = now() + interval '1 second' WHERE id = %s", (stays,))
        cur.execute(ins.replace("now() - interval '1 day'", "now() + interval '1 second'"), (aid, "R-NEW", "MEDIUM", "NEW", "d.java:4"))
        sc.close_run(run_id, True)

        comp = sc.compare_asset(cur, str(aid))
        self.assertTrue(comp["available"])
        classes = {k: [i["cve_id"] for i in v] for k, v in comp["classes"].items()}
        self.assertEqual(classes, {"SOLVENTADO": ["R-FIXED"], "PERSISTE": ["R-STAYS"], "NUEVO": ["R-NEW"]})
        self.assertEqual(comp["runs"]["latest"]["commit_sha"], "abc123")
        html = sc.render_html([comp], "proyecto-e")
        self.assertIn("R-FIXED", html)
        # the API returns the same comparison
        from fastapi.testclient import TestClient
        from main import app
        r = TestClient(app).get("/api/reports/comparison/asset/test-scan-comparison@x", params={"format": "json"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()[0]["summary"]["VULNERABILITY"]["SOLVENTADO"], {"HIGH": 1})
        r = TestClient(app).get("/api/reports/comparison/group", params={"prefix": "test-scan-comparison@", "format": "html"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("R-STAYS", r.text)
        # a newer run that is still in progress is flagged, not compared
        sc.open_run(str(aid), "test")
        comp2 = sc.compare_asset(cur, str(aid))
        self.assertIsNotNone(comp2["runs"]["running"])
        self.assertEqual(comp2["runs"]["latest"]["id"], run_id)

    def test_semgrep_reconciles_only_complete_runs(self):
        from auditors import auditor_semgrep
        cur = self.conn.cursor()
        cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES ('test-semgrep-reconcile@x', 'GitLab-Repo', 'test') RETURNING id")
        aid = str(cur.fetchone()[0])
        old = {"asset_id": aid, "cve_id": "java.lang.security.x.path-traversal", "severity": "HIGH",
               "description": "d", "url_path": "src/R.java:61", "scan_engine": "semgrep"}
        auditor_semgrep.persist_findings(auditor_semgrep.SemgrepFindings([old], asset_id=aid, complete=True))

        q = "SELECT status FROM vulnerability_log WHERE asset_id = %s AND cve_id = %s"
        auditor_semgrep.persist_findings(auditor_semgrep.SemgrepFindings([], asset_id=aid, complete=False))   # failed run
        cur.execute(q, (aid, old["cve_id"]))
        self.assertEqual(cur.fetchone()[0], "OPEN")
        auditor_semgrep.persist_findings(auditor_semgrep.SemgrepFindings([], asset_id=aid, complete=True))    # clean run
        cur.execute(q, (aid, old["cve_id"]))
        self.assertEqual(cur.fetchone()[0], "RESOLVED")

    def test_semgrep_keeps_findings_of_files_that_timed_out(self):
        from auditors import auditor_semgrep
        cur = self.conn.cursor()
        cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES ('test-semgrep-timeout@x', 'GitLab-Repo', 'test') RETURNING id")
        aid = str(cur.fetchone()[0])
        slow = {"asset_id": aid, "cve_id": "java.spring.security.audit.spring-sqli", "severity": "HIGH",
                "description": "d", "url_path": "src/FumpModel.java:40", "scan_engine": "semgrep"}
        fixed = {"asset_id": aid, "cve_id": "java.lang.security.x.weak-random", "severity": "MEDIUM",
                 "description": "d", "url_path": "src/Other.java:7", "scan_engine": "semgrep"}
        auditor_semgrep.persist_findings(auditor_semgrep.SemgrepFindings([slow, fixed], asset_id=aid, complete=True))
        # next complete run: FumpModel.java timed out (not analyzed), Other.java analyzed and clean
        auditor_semgrep.persist_findings(auditor_semgrep.SemgrepFindings(
            [], asset_id=aid, complete=True, skipped_files={"src/FumpModel.java"}))
        q = "SELECT status FROM vulnerability_log WHERE asset_id = %s AND cve_id = %s"
        cur.execute(q, (aid, slow["cve_id"]))
        self.assertEqual(cur.fetchone()[0], "OPEN")
        cur.execute(q, (aid, fixed["cve_id"]))
        self.assertEqual(cur.fetchone()[0], "RESOLVED")


if __name__ == "__main__":
    unittest.main()
