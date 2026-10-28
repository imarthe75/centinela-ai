"""Ingestion endpoint for centinela-smart-tests (ADR-0015): fail-closed token, validation with the shared result model, real write to
the disposable test database (rows removed in tearDown)."""
import os
import unittest
import uuid
from unittest import mock

from fastapi.testclient import TestClient

from core import db_manager, smart_tests_ingest as sti

TOKEN = "test-ingest-token-" + uuid.uuid4().hex


def _result(case_id="CI-1", status="FAILED", security=True, category="access_control", evidence=True, severity="HIGH"):
    return {"case_id": case_id, "status": status, "criterion": "RQ-1·CA1", "detail": "un perfil sin privilegios entró a administración",
            "evidence": [{"kind": "http", "value": "GET /api/x -> 200", "note": ""}] if evidence else [],
            "reason": "" if status in ("PASSED", "FAILED") else "motivo", "substitution": "", "security_relevant": security,
            "meta": {"category": category, "severity": severity}}


class TestValidate(unittest.TestCase):
    def test_only_failed_security_supported_category_with_evidence_is_accepted(self):
        payload = {"asset_name": "a", "results": [
            _result("ok"), _result("passed", status="PASSED", security=False), _result("not-sec", security=False),
            _result("other-cat", category="performance"), _result("no-ev", evidence=False)]}
        accepted, rejected = sti.validate(payload)
        self.assertEqual([r.case_id for r, _, _ in accepted], ["ok"])
        self.assertEqual({x["case_id"] for x in rejected}, {"passed", "not-sec", "other-cat", "no-ev"})

    def test_each_supported_category_maps_to_its_rule(self):
        for cat, (rule, default_sev, _lbl, _cwe) in sti.CATEGORIES.items():
            accepted, rejected = sti.validate({"asset_name": "a", "results": [_result(category=cat, severity="")]})
            self.assertEqual(rejected, [], cat)
            self.assertEqual(accepted[0][1], rule, cat)
            self.assertEqual(accepted[0][2], default_sev, cat)  # empty severity -> the category default

    def test_aliases_resolve_to_a_supported_category(self):
        for alias, target in sti.ALIASES.items():
            accepted, rejected = sti.validate({"asset_name": "a", "results": [_result(category=alias, severity="")]})
            self.assertEqual(rejected, [], alias)
            self.assertEqual(accepted[0][1], sti.CATEGORIES[target][0], alias)

    def test_unsupported_category_is_rejected_not_guessed(self):
        _, rejected = sti.validate({"asset_name": "a", "results": [_result(category="chaos-monkey")]})
        self.assertEqual(len(rejected), 1)
        self.assertIn("categoría no soportada", rejected[0]["reason"])

    def test_meta_severity_overrides_category_default(self):
        # data_integrity defaults MEDIUM; an explicit CRITICAL must win
        accepted, _ = sti.validate({"asset_name": "a", "results": [_result(category="data_integrity", severity="CRITICAL")]})
        self.assertEqual(accepted[0][2], "CRITICAL")

    def test_severity_falls_back_to_category_default_when_unknown(self):
        # audit_logging defaults MEDIUM; an unknown severity falls back to the category default, not a flat HIGH
        accepted, _ = sti.validate({"asset_name": "a", "results": [_result(category="audit_logging", severity="URGENTE")]})
        self.assertEqual(accepted[0][2], "MEDIUM")

    def test_payload_shape_errors(self):
        for bad in ({}, {"asset_name": "a"}, {"asset_name": "a", "results": []}, {"asset_name": "", "results": [_result()]}):
            with self.assertRaises(sti.IngestError):
                sti.validate(bad)


class TestEndpoint(unittest.TestCase):
    def setUp(self):
        from main import app
        self.client = TestClient(app)
        self.name = f"http://smart-tests-{uuid.uuid4().hex[:8]}.example.test/"
        with db_manager.get_db_cursor() as cur:
            cur.execute("INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint) VALUES (%s, 'URL', %s) RETURNING id", (self.name, self.name))
            self.asset_id = str(cur.fetchone()[0])

    def tearDown(self):
        with db_manager.get_db_cursor() as cur:
            cur.execute("DELETE FROM public.vulnerability_log WHERE asset_id = %s", (self.asset_id,))
            cur.execute("DELETE FROM public.infra_inventory WHERE id = %s", (self.asset_id,))

    def _post(self, body, token=TOKEN):
        h = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.post("/api/ingest/smart-tests", json=body, headers=h)

    def test_disabled_without_configured_token(self):
        with mock.patch.dict(os.environ, {"SMART_TESTS_INGEST_TOKEN": ""}):
            self.assertEqual(self._post({"asset_name": self.name, "results": [_result()]}).status_code, 503)

    def test_wrong_or_missing_token_is_rejected_before_the_body_is_read(self):
        with mock.patch.dict(os.environ, {"SMART_TESTS_INGEST_TOKEN": TOKEN}):
            self.assertEqual(self._post({"asset_name": self.name, "results": [_result()]}, token="wrong").status_code, 401)
            self.assertEqual(self._post({"asset_name": self.name, "results": [_result()]}, token=None).status_code, 401)
            r = self.client.post("/api/ingest/smart-tests", content=b"not json", headers={"Content-Type": "application/json"})
            self.assertEqual(r.status_code, 401)

    def test_unknown_asset_and_nothing_acceptable(self):
        with mock.patch.dict(os.environ, {"SMART_TESTS_INGEST_TOKEN": TOKEN}):
            self.assertEqual(self._post({"asset_name": "http://no-such-asset.example.test/", "results": [_result()]}).status_code, 404)
            self.assertEqual(self._post({"asset_name": self.name, "results": [_result(security=False)]}).status_code, 422)

    def test_writes_one_deduplicated_finding_per_case(self):
        body = {"asset_name": self.name, "run": {"project": "demo", "cycle": "c1", "finished": "2026-10-15T00:00:00"},
                "results": [_result("CI-7"), _result("CI-8", status="PASSED", security=False)]}
        with mock.patch.dict(os.environ, {"SMART_TESTS_INGEST_TOKEN": TOKEN}):
            r1 = self._post(body)
            r2 = self._post(body)
        self.assertEqual(r1.status_code, 200, r1.text)
        self.assertEqual(r1.json()["accepted"], 1)
        self.assertEqual(r1.json()["findings"][0]["outcome"], "inserted")
        self.assertEqual(r2.json()["findings"][0]["outcome"], "updated")
        with db_manager.get_db_cursor() as cur:
            cur.execute("SELECT cve_id, scan_engine, url_path, severity FROM public.vulnerability_log WHERE asset_id = %s", (self.asset_id,))
            rows = cur.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(tuple(rows[0]), (sti.RULE_ACCESS_CONTROL, "smart-tests", "smart-tests:demo:CI-7", "HIGH"))


if __name__ == "__main__":
    unittest.main()
