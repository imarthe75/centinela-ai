"""Full functional-test runs from centinela-smart-tests (core/functional_tests.py, POST /api/ingest/smart-tests/run, /api/functional-tests/*).

Store/query tests run inside one connection that is ROLLED BACK; the endpoint test writes through the real API to the disposable test
database and deletes its run afterwards (rule 8).
"""
import contextlib
import os
import unittest
import uuid
from unittest import mock

from fastapi.testclient import TestClient

from core import db_manager, functional_tests as ft

TOKEN = "test-run-token-" + uuid.uuid4().hex


def case(cid, status, evidence=True, reason="", security=False, category=None):
    return {"case_id": cid, "status": status, "criterion": "RQ-1 · CA1", "detail": "d",
            "evidence": [{"kind": "http", "value": "POST /x -> 201", "note": ""}] if evidence else [],
            "reason": reason, "security_relevant": security, "meta": {"category": category} if category else {}}


def payload(project="proj-test-" + uuid.uuid4().hex[:6], **run):
    return {"asset_name": "no-existe-en-inventario", "source": "centinela-smart-tests",
            "run": {"project": project, "cycle": "c1", "package": "PKG", "started": "2026-10-20", "finished": "2026-10-21",
                    "planned_in_package": 5, **run},
            "results": [case("CI-1", "PASSED"), case("CI-2", "FAILED", security=True, category="access_control"),
                        case("CI-3", "BLOCKED", evidence=False, reason="sin cuenta SP"),
                        case("CI-4", "NOT_EXECUTED", evidence=False, reason="pantalla no automatizada")],
            "summary": {"counts": {"PASSED": 999}}}       # sender summary is ignored


class TestValidateRun(unittest.TestCase):
    def test_invalid_case_rejects_the_whole_run(self):
        p = payload()
        p["results"].append(case("CI-5", "PASSED", evidence=False))          # PASSED without evidence
        with self.assertRaises(ft.RunError) as e:
            ft.validate_run(p)
        self.assertIn("CI-5", str(e.exception))

    def test_shape_errors(self):
        for bad in ({}, {"run": {}}, {"run": {"project": "p"}, "results": []},
                    {"run": {"project": "p", "planned_in_package": 1}, "results": [case("a", "PASSED"), case("b", "PASSED")]},
                    {"run": {"project": "p"}, "results": [case("a", "PASSED"), case("a", "PASSED")]}):
            with self.assertRaises(ft.RunError):
                ft.validate_run(bad)

    def test_run_key_is_stable_and_explicit_id_wins(self):
        self.assertEqual(ft.run_key({"project": "p", "cycle": "c"}, "a"), ft.run_key({"project": "p", "cycle": "c"}, "a"))
        self.assertNotEqual(ft.run_key({"project": "p", "cycle": "c"}, "a"), ft.run_key({"project": "p", "cycle": "d"}, "a"))
        self.assertEqual(ft.run_key({"project": "p", "run_id": "R-1"}, "a"), "R-1")


class TestStoreAndQuery(unittest.TestCase):
    def setUp(self):
        self._stack = contextlib.ExitStack()
        self.conn = self._stack.enter_context(db_manager.get_db_connection())

    def tearDown(self):
        self.conn.rollback()
        self._stack.close()

    def test_store_recomputes_summary_and_resend_replaces(self):
        cur = self.conn.cursor()
        p = payload()
        out = ft.store_run(cur, p)
        self.assertTrue(out["created"])
        self.assertFalse(out["asset_linked"])
        s = out["summary"]
        self.assertEqual(s["counts"], {"PASSED": 1, "FAILED": 1, "BLOCKED": 1, "NOT_EXECUTED": 1})
        self.assertEqual((s["planned"], s["not_reported"], s["executed"], s["pass_rate_over_executed_pct"]), (5, 1, 2, 50.0))
        p["results"] = p["results"][:2]                                     # same run, re-sent with fewer cases
        out2 = ft.store_run(cur, p)
        self.assertEqual(out2["run_id"], out["run_id"])
        self.assertFalse(out2["created"])
        run = ft.get_run(cur, out["run_id"])
        self.assertEqual([c["case_id"] for c in run["cases"]], ["CI-1", "CI-2"])
        self.assertTrue(run["cases"][1]["security_relevant"])
        self.assertIn(out["run_id"], [r["id"] for r in ft.list_runs(cur, p["run"]["project"])])
        self.assertIsNone(ft.get_run(cur, str(uuid.uuid4())))


class TestEndpoints(unittest.TestCase):
    def setUp(self):
        from main import app
        self.client = TestClient(app)
        self.created = []

    def tearDown(self):
        with db_manager.get_db_cursor() as cur:
            for rid in self.created:
                cur.execute("DELETE FROM functional_test_runs WHERE id = %s", (rid,))
                cur.execute("DELETE FROM agent_actions WHERE entity_type = 'functional_test_run' AND entity_id = %s", (rid,))

    def test_fail_closed_then_store_then_read(self):
        url = "/api/ingest/smart-tests/run"
        with mock.patch.dict(os.environ, {"SMART_TESTS_INGEST_TOKEN": ""}):
            self.assertEqual(self.client.post(url, json=payload()).status_code, 503)
        with mock.patch.dict(os.environ, {"SMART_TESTS_INGEST_TOKEN": TOKEN}):
            self.assertEqual(self.client.post(url, json=payload()).status_code, 401)
            self.assertEqual(self.client.post(url, json=payload(), headers={"Authorization": "Bearer nope"}).status_code, 401)
            bad = payload()
            bad["results"][0]["evidence"] = []
            self.assertEqual(self.client.post(url, json=bad, headers={"Authorization": f"Bearer {TOKEN}"}).status_code, 422)
            r = self.client.post(url, json=payload(), headers={"Authorization": f"Bearer {TOKEN}"})
            self.assertEqual(r.status_code, 200, r.text)
            rid = r.json()["run_id"]
            self.created.append(rid)
            st = self.client.get("/api/functional-tests/status").json()
            self.assertTrue(st["ingest_enabled"])
            self.assertNotIn(TOKEN, str(st))
        got = self.client.get(f"/api/functional-tests/runs/{rid}")
        self.assertEqual(got.status_code, 200)
        self.assertEqual(len(got.json()["cases"]), 4)
        self.assertEqual(self.client.get("/api/functional-tests/runs/no-es-uuid").status_code, 404)


if __name__ == "__main__":
    unittest.main()
