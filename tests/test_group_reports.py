"""Group reports (core/group_reports.py): consolidated summary, ZIP bundle builder and the API around them.

DB tests run inside one connection that is ROLLED BACK (project rule #8). Bundles are written to a temporary directory.
"""
import contextlib
import tempfile
import time
import unittest
import zipfile
from unittest import mock

from core import db_manager, group_reports as gr


class TestBundleBuilder(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patch = mock.patch.object(gr, "BUNDLE_DIR", self.tmp.name)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def _wait(self, bid, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            st = gr.get_status(bid)
            if st["status"] in ("done", "failed"):
                return st
            time.sleep(0.05)
        self.fail("bundle did not finish")

    def test_zip_contents_and_failures_are_reported(self):
        assets = [{"id": "1", "name": "GitLab2/grupo-b/proyecto-e/proyecto-e-web@develop"}, {"id": "2", "name": "GitLab2/grupo-b/proyecto-e/proyecto-e-backend@develop"}]

        def asset_pdf(name):
            if "backend" in name:
                raise RuntimeError("boom")
            return b"%PDF-asset"
        bid = gr.start_bundle("GitLab2/grupo-b/proyecto-e", assets, lambda: b"%PDF-group", lambda: b"%PDF-cmp", asset_pdf)
        st = self._wait(bid)
        self.assertEqual(st["status"], "done")
        self.assertEqual((st["done"], st["total"]), (4, 4))
        self.assertEqual([f["item"] for f in st["failed"]], ["GitLab2/grupo-b/proyecto-e/proyecto-e-backend@develop"])
        with zipfile.ZipFile(gr.zip_path(bid)) as z:
            names = z.namelist()
            stem = names[0].split("/")[0]
            self.assertIn(f"{stem}/00_REPORTE_GENERAL_GRUPO.pdf", names)
            self.assertIn(f"{stem}/01_COMPARATIVO_GRUPO.pdf", names)
            self.assertIn(f"{stem}/activos/proyecto-e-web@develop.pdf", names)       # short name: common group prefix removed
            self.assertNotIn(f"{stem}/activos/proyecto-e-backend@develop.pdf", names)
            index = z.read(f"{stem}/INDICE.txt").decode()
            self.assertIn("ERROR", index)
            self.assertIn("Errores: 1", index)

    def test_limits_and_invalid_ids(self):
        with self.assertRaises(ValueError):
            gr.start_bundle("x", [], bytes, bytes, lambda n: b"")
        with self.assertRaises(ValueError):
            gr.start_bundle("x", [{"id": str(i), "name": f"a{i}"} for i in range(gr.BUNDLE_MAX_ASSETS + 1)], bytes, bytes, lambda n: b"")
        self.assertIsNone(gr.get_status("../../etc/passwd"))
        self.assertIsNone(gr.zip_path("00000000-0000-0000-0000-000000000000"))

    def test_stale_running_bundle_is_reported_interrupted(self):
        bid = "11111111-1111-1111-1111-111111111111"
        import os
        os.makedirs(f"{self.tmp.name}/{bid}")
        gr._write_status(bid, {"id": bid, "status": "running", "file": "x.zip"})
        with mock.patch.object(gr.time, "time", return_value=time.time() + gr.STALE_SECONDS + 5):
            self.assertEqual(gr.get_status(bid)["status"], "interrupted")


class TestGroupSummaryAgainstDb(unittest.TestCase):
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

    def test_summary_uses_effective_severity_and_open_only(self):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES ('test-grp/a@x', 'GitLab-Repo', 't') RETURNING id")
        aid = cur.fetchone()[0]
        ins = """INSERT INTO vulnerability_log (asset_id, cve_id, severity, real_severity, description, status, finding_category)
                 VALUES (%s, %s, %s, %s, 'd', %s, %s)"""
        cur.execute(ins, (aid, "R1", "CRITICAL", None, "OPEN", "VULNERABILITY"))
        cur.execute(ins, (aid, "R2", "CRITICAL", "LOW", "CORRELATED", "VULNERABILITY"))   # downgraded by the risk analysis
        cur.execute(ins, (aid, "R3", "HIGH", None, "RESOLVED", "VULNERABILITY"))
        cur.execute(ins, (aid, "Q1", "MEDIUM", None, "OPEN", "INFORMATIONAL"))
        s = gr.group_summary(cur, [str(aid)])
        t = s["totals"]
        self.assertEqual((t["vulns"], t["crit"], t["high"], t["low"], t["info"], t["resolved"]), (2, 1, 0, 1, 1, 1))
        self.assertEqual({x["cve_id"] for x in s["top_rules"]}, {"R1", "R2"})
        html = gr.render_group_general_html("Grupo <x>", s)
        self.assertIn("Grupo &lt;x&gt;", html)
        self.assertIn("a@x", html)          # common prefix "test-grp/" removed from the row label

        from fastapi.testclient import TestClient
        from main import app
        c = TestClient(app)
        r = c.get("/api/reports/group/general", params={"prefix": "test-grp/", "format": "json"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["totals"]["crit"], 1)
        self.assertEqual(c.get("/api/reports/group/general", params={"prefix": "no-such-group/"}).status_code, 404)
        self.assertEqual(c.get("/api/reports/group/bundle/not-a-uuid").status_code, 404)


if __name__ == "__main__":
    unittest.main()
