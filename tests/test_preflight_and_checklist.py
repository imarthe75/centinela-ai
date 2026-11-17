"""ADR-0012 D10: /api/preflight and /api/checklist-evidence helpers on the disposable test DB (one connection, always rolled back)."""
import unittest
import uuid

from fastapi.testclient import TestClient

from api.routers import preflight as pf
from core import db_manager


class _Base(unittest.TestCase):
    def setUp(self):
        self._cm = db_manager.get_db_connection()
        self.conn = self._cm.__enter__()
        self.addCleanup(self._done)
        self.cur = self.conn.cursor()
        self.name = f"GitLab/test/pf-{uuid.uuid4().hex[:8]}"
        self.cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint, last_audit) VALUES (%s,'GitLab-Repo','http://x','2026-10-13T00:00:00+00:00') RETURNING id",
                         (self.name,))
        self.aid = self.cur.fetchone()[0]

    def _done(self):
        try:
            self.conn.rollback()
        finally:
            self._cm.__exit__(None, None, None)

    def finding(self, rule, sev, path, status="OPEN", cat="VULNERABILITY", engine="sast-native", real=None, verdict=None):
        self.cur.execute("""INSERT INTO vulnerability_log (asset_id, cve_id, severity, real_severity, risk_verdict, status, url_path, scan_engine,
                            finding_category, fingerprint_hash, detected_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())""",
                         (self.aid, rule, sev, real, verdict, status, path, engine, cat, f"t-{uuid.uuid4()}"))


class TestPreflight(_Base):
    def test_only_requested_files_open_findings_and_effective_severity(self):
        self.finding("AUTHZ-NO-METHOD-AUTHZ", "HIGH", "src/A.java:10")
        self.finding("SONAR-java-S1", "CRITICAL", "src/A.java:99", real="LOW", verdict="DOWNGRADED")
        self.finding("X", "HIGH", "src/B.java:1")                              # not requested
        self.finding("Y", "HIGH", "src/A.java:5", status="RESOLVED")           # closed
        self.finding("Z", "HIGH", "src/A.java:6", status="SUPPRESSED")
        self.finding("STD-ISO25010-LONG-METHOD", "LOW", "src/A.java:7", cat="INFORMATIONAL")
        out = pf.preflight_query(self.cur, self.name, ["src/A.java", "src/C.java", "../etc/passwd", ""])
        self.assertTrue(out["known_asset"])
        self.assertEqual(out["paths"], ["src/A.java", "src/C.java"])            # traversal / empty dropped
        got = {(f["rule"], f["line"], f["severity"]) for f in out["findings"]}
        self.assertEqual(got, {("AUTHZ-NO-METHOD-AUTHZ", 10, "HIGH"), ("SONAR-java-S1", 99, "LOW")})
        self.assertEqual(out["paths_without_findings"], ["src/C.java"])
        self.assertIn("sast-native", out["engines_seen"])
        self.assertTrue(out["last_audit"])
        with_info = pf.preflight_query(self.cur, self.name, ["src/A.java"], include_informational=True)
        self.assertIn("STD-ISO25010-LONG-METHOD", {f["rule"] for f in with_info["findings"]})

    def test_branch_asset_is_found_by_project_name(self):
        self.cur.execute("UPDATE infra_inventory SET asset_name = %s WHERE id=%s", (self.name + "@develop", self.aid))
        self.finding("R", "MEDIUM", "a/B.ts:3")
        out = pf.preflight_query(self.cur, self.name, ["a/B.ts"])
        self.assertTrue(out["known_asset"])
        self.assertEqual(out["asset"], self.name + "@develop")
        self.assertEqual(len(out["findings"]), 1)

    def test_unknown_asset_does_not_claim_clean(self):
        out = pf.preflight_query(self.cur, "GitLab/nope/never", ["a.java"])
        self.assertFalse(out["known_asset"])
        self.assertEqual(out["findings"], [])
        self.assertIn("NO significa", out["note"])


class TestChecklistEvidence(_Base):
    def test_counts_are_split_and_use_effective_severity(self):
        self.finding("A", "CRITICAL", "a:1")
        self.finding("B", "CRITICAL", "b:1", real="INFO", verdict="CONFIRMED_NO_RISK")
        self.finding("C", "HIGH", "c:1")
        self.finding("WCAG-1.1.1-IMG-ALT", "MEDIUM", "t.html:1")
        self.finding("ACCESSIBILITY-WCAG-MISSING-LABEL", "LOW", "t.html:2")
        self.finding("STD-ISO25010-LONG-METHOD", "LOW", "d:1", cat="INFORMATIONAL")
        self.finding("D", "HIGH", "d:2", status="RESOLVED")
        ev = pf.checklist_evidence(self.cur, self.name)
        self.assertEqual(ev["security"]["open_by_effective_severity"], {"CRITICAL": 1, "HIGH": 1, "INFO": 1})
        self.assertEqual(ev["accessibility"]["open_total"], 2)
        self.assertEqual(ev["code_quality"]["informational_open"], 1)
        self.assertIn("sast-native", ev["engines_last_detection"])
        self.assertTrue(ev["not_evaluated_by_centinela"])
        self.assertIn("signs_nothing", ev)
        self.assertEqual(ev["security"]["informs_points"], ["3.10"])
        self.assertEqual(ev["secrets"]["open_total"], 0)
        pts = {p["id"]: p for p in ev["checklist_points"]}
        self.assertEqual(sorted(pts), ["3.10", "3.7", "5.8"])
        self.assertIn("0B-2", pts["3.10"]["text"])            # text comes from the skill's official 0A-4 file

    def test_checklist_points_degrade_to_ids_without_the_file(self):
        self.assertEqual(pf.checklist_points(["3.10"], path="/nonexistent/0A-4.json"),
                         [{"id": "3.10", "text": None, "responde": None, "critico": None}])

    def test_unknown_asset_is_none(self):
        self.assertIsNone(pf.checklist_evidence(self.cur, "GitLab/nope/never"))


class TestHttp(unittest.TestCase):
    def test_routes_are_registered_and_validate_input(self):
        import main
        c = TestClient(main.app)
        self.assertEqual(c.get("/api/preflight").status_code, 422)                       # asset is required
        r = c.get("/api/preflight", params={"asset": "GitLab/nope/never", "paths": "a.java"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["known_asset"])
        self.assertEqual(c.get("/api/checklist-evidence/GitLab/nope/never").status_code, 404)
        too_many = ",".join(f"f{i}.java" for i in range(pf.MAX_PATHS + 1))
        self.assertEqual(c.get("/api/preflight", params={"asset": "x", "paths": too_many}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
