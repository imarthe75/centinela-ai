"""ADR-0002 of centinela-smart-tests on Centinela's side: usability/accessibility observations accepted as findings under the static rule
id (core/smart_tests_ingest.py), and CI test report summaries (core/ci_test_reports.py, POST /api/ingest/smart-tests/ci).

DB tests run in the disposable test database (scripts/run_tests.sh): pure validation needs no DB; the endpoint test creates a throwaway
asset and deletes everything it wrote (rule 8)."""
import os
import unittest
import uuid
from unittest import mock

from fastapi.testclient import TestClient

from core import ci_test_reports as ci
from core import db_manager
from core import smart_tests_ingest as sti

TOKEN = "test-ci-token-" + uuid.uuid4().hex


def obs(category, rule, security=False, status="FAILED", severity="LOW"):
    return {"case_id": f"HEUR-{uuid.uuid4().hex[:4]}", "status": status, "criterion": "c", "detail": "d",
            "evidence": [{"kind": "text", "value": "2 peticiones", "note": ""}], "reason": "",
            "security_relevant": security, "meta": {"category": category, "rule": rule, "severity": severity}}


class TestObservations(unittest.TestCase):
    def test_usability_allowlist_and_no_security_mark_needed(self):
        accepted, rejected = sti.validate({"asset_name": "a", "results": [
            obs("usability", "ANGULAR-SUBMIT-NO-BUSY-GUARD"), obs("usability", "DESTRUCTIVE-ACTION-NO-CONFIRM", severity="MEDIUM"),
            obs("usability", "INVENTED-RULE")]})
        self.assertEqual([(a[1], a[2]) for a in accepted], [("ANGULAR-SUBMIT-NO-BUSY-GUARD", "LOW"), ("DESTRUCTIVE-ACTION-NO-CONFIRM", "MEDIUM")])
        self.assertEqual(len(rejected), 1)
        self.assertIn("INVENTED-RULE", rejected[0]["reason"])

    def test_accessibility_rule_must_be_a_wcag_21_aa_axe_id(self):
        accepted, rejected = sti.validate({"asset_name": "a", "results": [
            obs("accessibility", "WCAG-1.4.3-AXE-COLOR-CONTRAST", severity="MEDIUM"),
            obs("accessibility", "WCAG-9.9.9-AXE-NOPE"), obs("accessibility", "COLOR-CONTRAST")]})
        self.assertEqual([a[1] for a in accepted], ["WCAG-1.4.3-AXE-COLOR-CONTRAST"])
        self.assertEqual(len(rejected), 2)

    def test_passed_observation_and_non_failed_are_rejected(self):
        _, rejected = sti.validate({"asset_name": "a", "results": [
            {**obs("usability", "NATIVE-BROWSER-DIALOG"), "status": "PASSED", "meta": {}}]})
        self.assertEqual(len(rejected), 1)

    def test_classification_of_runtime_form_rules(self):
        from core import coverage_matrix as cm
        from core.deduplication_engine import classify_finding_category
        for rule in ("SMART-TESTS-FORM-INVALID-SUBMITTED", "SMART-TESTS-FORM-NO-FIELD-ERROR"):
            self.assertIsNotNone(cm.classify_rule(rule))
            self.assertEqual(classify_finding_category(rule, "smart-tests", ""), "INFORMATIONAL")


SUMMARY = {"tests": 10, "failures": 1, "errors": 0, "skipped": 2, "suites": 2, "duration_s": 3.2, "coverage_line_pct": 81.5,
           "coverage_branch_pct": None, "has_401_tests": True, "has_403_tests": False, "has_409_tests": None,
           "failed_tests": [{"test": "A.b", "kind": "failure", "source": "x.xml"}], "detection_note": "por nombre"}


class TestCIValidate(unittest.TestCase):
    def test_valid_and_stable_key(self):
        a = ci.validate({"asset_name": "x", "run": {"commit": "abc", "pipeline": "1"}, "summary": SUMMARY})
        b = ci.validate({"asset_name": "x", "run": {"commit": "abc", "pipeline": "1"}, "summary": SUMMARY})
        self.assertEqual(a["report_key"], b["report_key"])
        self.assertEqual((a["tests"], a["coverage_line_pct"], a["has_403_tests"]), (10, 81.5, False))
        self.assertNotIn("source", a["summary"]["failed_tests"][0])

    def test_rejects_inconsistent_or_malformed(self):
        for bad in ({**SUMMARY, "failures": 9, "skipped": 5}, {**SUMMARY, "tests": -1}, {**SUMMARY, "tests": "10"},
                    {**SUMMARY, "coverage_line_pct": 120}, {**SUMMARY, "has_403_tests": "no"}):
            with self.assertRaises(ci.CIReportError):
                ci.validate({"asset_name": "x", "summary": bad})
        with self.assertRaises(ci.CIReportError):
            ci.validate({"summary": SUMMARY})


class TestCIEndpoint(unittest.TestCase):
    def setUp(self):
        from main import app
        self.client = TestClient(app)
        self.name = f"ci-test-asset-{uuid.uuid4().hex[:8]}"
        with db_manager.get_db_cursor() as cur:
            cur.execute("INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint) VALUES (%s, 'GitLab-Repo', %s) RETURNING id",
                        (self.name, self.name))
            self.asset_id = str(cur.fetchone()[0])

    def tearDown(self):
        with db_manager.get_db_cursor() as cur:
            cur.execute("DELETE FROM agent_actions WHERE entity_type = 'ci_test_report' AND asset_id = %s", (self.asset_id,))
            cur.execute("DELETE FROM ci_test_reports WHERE asset_name = %s", (self.name,))
            cur.execute("DELETE FROM infra_inventory WHERE id = %s", (self.asset_id,))

    def test_fail_closed_store_replace_and_list(self):
        url = "/api/ingest/smart-tests/ci"
        body = {"asset_name": self.name, "run": {"project": "p", "ref": "desarrollo", "commit": "abc123", "pipeline": "77"}, "summary": SUMMARY}
        with mock.patch.dict(os.environ, {"SMART_TESTS_INGEST_TOKEN": ""}):
            self.assertEqual(self.client.post(url, json=body).status_code, 503)
        with mock.patch.dict(os.environ, {"SMART_TESTS_INGEST_TOKEN": TOKEN}):
            h = {"Authorization": f"Bearer {TOKEN}"}
            self.assertEqual(self.client.post(url, json=body).status_code, 401)
            self.assertEqual(self.client.post(url, json={**body, "summary": {**SUMMARY, "tests": -3}}, headers=h).status_code, 422)
            self.assertEqual(self.client.post(url, json={**body, "asset_name": "no-existe-" + uuid.uuid4().hex}, headers=h).status_code, 404)
            r1 = self.client.post(url, json=body, headers=h)
            self.assertEqual(r1.status_code, 200, r1.text)
            self.assertTrue(r1.json()["created"])
            r2 = self.client.post(url, json={**body, "summary": {**SUMMARY, "failures": 0}}, headers=h)
            self.assertEqual(r2.json()["report_id"], r1.json()["report_id"])
            self.assertFalse(r2.json()["created"])
        rows = self.client.get("/api/functional-tests/ci-reports", params={"asset": self.name}).json()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["failures"], rows[0]["coverage_line_pct"], rows[0]["has_403_tests"]), (0, 81.5, False))


if __name__ == "__main__":
    unittest.main()
