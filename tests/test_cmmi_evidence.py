"""CMMI evidence collectors (DECISIONS/0007 phase A). Repository checks run on REAL temporary git repos; the GitLab
collectors run against a REAL local HTTP server speaking the GitLab REST shape; DB persistence runs inside one
transaction that is rolled back (rule #8)."""
import contextlib
import http.server
import json
import os
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from unittest import mock

from psycopg2.extras import RealDictCursor

from auditors import auditor_cmmi_evidence as ev
from core import db_manager


def make_repo(files, commits=2):
    d = tempfile.mkdtemp()
    subprocess.run(["git", "init", "-q", d], check=True)
    for rel, content in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(content)
    for i in range(commits):
        open(os.path.join(d, f"f{i}.txt"), "w").write(str(i))
        subprocess.run(["git", "-C", d, "add", "-A"], check=True)
        subprocess.run(["git", "-C", d, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", f"c{i}"], check=True)
    return d


def fake_gitlab(routes):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            hit = routes.get(path)
            status, body, headers = hit if hit else (404, {}, {})
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestRepoCollectors(unittest.TestCase):
    def ctx(self, files, **kw):
        return {"clone_dir": make_repo(files, **kw)}

    def test_git_history_and_shallow_clone_honesty(self):
        self.assertEqual(ev.cm_git_history(self.ctx({}, commits=3))["status"], ev.CUMPLE)
        self.assertEqual(ev.cm_git_history({"clone_dir": tempfile.mkdtemp()})["status"], ev.NO_CUMPLE)  # not a git repo
        self.assertEqual(ev.cm_git_history({})["status"], ev.NO_EVALUADO)                              # no clone at all

    def test_indicator_items_never_turn_absence_into_a_failure(self):
        empty = self.ctx({"README.md": "x"})
        for fn in (ev.ts_design_docs, ev.dar_adr_records, ev.pi_api_contract, ev.pi_integration_tests):
            self.assertEqual(fn(empty)["status"], ev.NO_EVALUADO, fn.__name__)

    def test_indicator_items_pass_when_evidence_exists(self):
        self.assertEqual(ev.ts_design_docs(self.ctx({"docs/arquitectura.md": "x"}))["status"], ev.CUMPLE)
        self.assertEqual(ev.dar_adr_records(self.ctx({"docs/adr/0001-uso-de-x.md": "x"}))["status"], ev.CUMPLE)
        self.assertEqual(ev.pi_api_contract(self.ctx({"openapi.yaml": "openapi: 3.0.0"}))["status"], ev.CUMPLE)
        self.assertEqual(ev.pi_api_contract(self.ctx({"pom.xml": "<dependency>springdoc-openapi-ui</dependency>"}))["status"], ev.CUMPLE)
        self.assertEqual(ev.pi_integration_tests(self.ctx({"src/test/java/XIT.java": "class XIT {}"}))["status"], ev.CUMPLE)
        self.assertEqual(ev.pi_integration_tests(self.ctx({"src/test/java/A.java": "@SpringBootTest class A {}"}))["status"], ev.CUMPLE)

    def test_schema_versioning_not_applicable_without_a_database(self):
        self.assertEqual(ev.cm_schema_versioned(self.ctx({"src/main/resources/db/changelog/001.xml": "<x/>"}))["status"], ev.CUMPLE)
        self.assertEqual(ev.cm_schema_versioned(self.ctx({"app.py": "print(1)"}))["status"], ev.NO_APLICA)
        self.assertEqual(ev.cm_schema_versioned(self.ctx({"src/E.java": "@Entity class E {}"}))["status"], ev.NO_CUMPLE)
        # as a DESIGN indicator (TS) the same absence is only 'not evaluated'
        self.assertEqual(ev.ts_data_design_versioned(self.ctx({"src/E.java": "@Entity class E {}"}))["status"], ev.NO_EVALUADO)


class TestGitLabCollectors(unittest.TestCase):
    def setUp(self):
        self.srv = None
        self.addCleanup(lambda: self.srv and self.srv.shutdown())

    def api(self, routes):
        self.srv = fake_gitlab(routes)
        return ev.GitLabAPI(f"http://127.0.0.1:{self.srv.server_address[1]}", "tok")

    def test_pr_requires_every_sampled_mr_to_have_a_reviewer_who_is_not_the_author(self):
        mrs = [{"iid": 1, "author": {"id": 1}, "reviewers": []}, {"iid": 2, "author": {"id": 1}, "reviewers": []}]
        routes = {"/api/v4/projects/7/merge_requests": (200, mrs, {}),
                  "/api/v4/projects/7/merge_requests/1/notes": (200, [{"system": False, "author": {"id": 2}}], {}),
                  "/api/v4/projects/7/merge_requests/2/notes": (200, [{"system": True, "author": {"id": 3}}, {"system": False, "author": {"id": 1}}], {}),
                  "/api/v4/projects/7/merge_requests/2/approvals": (200, {"approved_by": []}, {})}
        r = ev.pr_merged_mr_reviewed({"api": self.api(routes), "project_id": 7})
        self.assertEqual(r["status"], ev.NO_CUMPLE)     # MR 2 only has a system note and a self-comment
        self.assertEqual((r["detail"]["merged_mrs_sampled"], r["detail"]["with_recorded_review"]), (2, 1))

    def test_pr_passes_with_reviewers_field_or_approval_and_is_not_evaluated_without_mrs(self):
        mrs = [{"iid": 1, "author": {"id": 1}, "reviewers": [{"id": 9}]}, {"iid": 2, "author": {"id": 1}, "reviewers": []}]
        routes = {"/api/v4/projects/7/merge_requests": (200, mrs, {}),
                  "/api/v4/projects/7/merge_requests/2/notes": (200, [], {}),
                  "/api/v4/projects/7/merge_requests/2/approvals": (200, {"approved_by": [{"user": {"id": 5}}]}, {})}
        self.assertEqual(ev.pr_merged_mr_reviewed({"api": self.api(routes), "project_id": 7})["status"], ev.CUMPLE)
        self.srv.shutdown()
        empty = self.api({"/api/v4/projects/7/merge_requests": (200, [], {})})
        self.assertEqual(ev.pr_merged_mr_reviewed({"api": empty, "project_id": 7})["status"], ev.NO_EVALUADO)
        self.srv.shutdown()
        broken = self.api({})   # 404 for everything: cannot conclude anything
        self.assertEqual(ev.pr_merged_mr_reviewed({"api": broken, "project_id": 7})["status"], ev.NO_EVALUADO)

    def test_vv_needs_tests_and_a_green_latest_pipeline(self):
        d = make_repo({"src/test/java/ATest.java": "class ATest {}"})
        ok = self.api({"/api/v4/projects/7/pipelines": (200, [{"status": "success"}, {"status": "failed"}], {})})
        self.assertEqual(ev.vv_tests_green({"api": ok, "project_id": 7, "clone_dir": d})["status"], ev.CUMPLE)
        self.srv.shutdown()
        red = self.api({"/api/v4/projects/7/pipelines": (200, [{"status": "failed"}], {})})
        self.assertEqual(ev.vv_tests_green({"api": red, "project_id": 7, "clone_dir": d})["status"], ev.NO_CUMPLE)
        self.srv.shutdown()
        no_tests = self.api({"/api/v4/projects/7/pipelines": (200, [{"status": "success"}], {})})
        self.assertEqual(ev.vv_tests_green({"api": no_tests, "project_id": 7, "clone_dir": make_repo({"a.txt": "x"})})["status"], ev.NO_CUMPLE)

    def test_git_history_uses_all_branches_not_the_default_branch_statistic(self):
        shallow_clone = make_repo({}, commits=1)           # 1 visible commit: proves nothing by itself
        # real case seen on proyecto-g: statistics say 1 (default branch only) but other branches hold more history
        api = self.api({"/api/v4/projects/7/repository/commits": (200, [{"id": "a"}, {"id": "b"}, {"id": "c"}], {}),
                        "/api/v4/projects/7": (200, {"statistics": {"commit_count": 1}}, {})})
        r = ev.cm_git_history({"api": api, "project_id": 7, "clone_dir": shallow_clone})
        self.assertEqual((r["status"], r["detail"]["commits_all_branches"], r["detail"]["commits_default_branch"]), (ev.CUMPLE, 3, 1))
        self.srv.shutdown()
        one = self.api({"/api/v4/projects/7/repository/commits": (200, [{"id": "a"}], {}),
                        "/api/v4/projects/7": (200, {"statistics": {"commit_count": 1}}, {})})
        self.assertEqual(ev.cm_git_history({"api": one, "project_id": 7, "clone_dir": shallow_clone})["status"], ev.NO_CUMPLE)
        self.srv.shutdown()
        broken = self.api({})   # API gave nothing -> falls back to the clone
        self.assertEqual(ev.cm_git_history({"api": broken, "project_id": 7, "clone_dir": make_repo({}, commits=3)})["status"], ev.CUMPLE)

    def test_tags_and_protected_branch(self):
        api = self.api({"/api/v4/projects/7/repository/tags": (200, [{"name": "v1"}], {"X-Total": "3"}),
                        "/api/v4/projects/7/releases": (200, [], {"X-Total": "0"}),
                        "/api/v4/projects/7/protected_branches": (200, [{"name": "main"}], {})})
        self.assertEqual(ev.cm_release_tags({"api": api, "project_id": 7})["status"], ev.CUMPLE)
        self.assertEqual(ev.cm_protected_default_branch({"api": api, "project_id": 7, "default_branch": "main"})["status"], ev.CUMPLE)
        self.assertEqual(ev.cm_protected_default_branch({"api": api, "project_id": 7, "default_branch": "develop"})["status"], ev.NO_CUMPLE)
        self.srv.shutdown()
        denied = self.api({"/api/v4/projects/7/protected_branches": (403, {}, {})})
        self.assertEqual(ev.cm_protected_default_branch({"api": denied, "project_id": 7, "default_branch": "main"})["status"], ev.NO_EVALUADO)


class TestAreaDefinitions(unittest.TestCase):
    def test_all_19_cmmi_areas_are_declared_and_match_the_registry(self):
        from core.coverage_matrix import CMMI_CA_19
        self.assertEqual(set(ev.CMMI_AREA_ITEMS), set(CMMI_CA_19))
        self.assertEqual(len(ev.CMMI_AREA_ITEMS), 19)

    def test_every_collector_named_exists_and_unmeasurable_items_have_none(self):
        for area, spec in ev.CMMI_AREA_ITEMS.items():
            for key, desc, src, scope, absence, collector in spec["items"]:
                if collector is not None:
                    self.assertIn(collector, ev.COLLECTORS, key)
                else:
                    self.assertIn(src, ("artefacto", "atestacion", "politica"), f"{key}: a missing collector must be an artifact/attestation/policy dependency")
                self.assertIn(absence, (ev.NO_CUMPLE, ev.NO_EVALUADO))


class TestPersistenceAndReport(unittest.TestCase):
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
        from core.schema import ensure_core_schema
        ensure_core_schema(self.conn.cursor())
        cur = self.conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM infra_inventory LIMIT 1")
        self.asset_id = cur.fetchone()["id"]
        self.cur = cur

    def _cleanup(self):
        try:
            self.conn.rollback()
        finally:
            self._stack.close()

    def test_report_always_lists_19_areas_and_unmeasured_ones_are_not_evaluated(self):
        rep = ev.build_area_report(self.asset_id)
        self.assertEqual(len(rep["areas"]), 19)
        rdm = next(a for a in rep["areas"] if a["area"] == "RDM")
        self.assertEqual((rdm["state"], rdm["items_evaluated"]), ("NO_EVALUADA", 0))
        self.assertIn("NO es una evaluación", rep["reliability_note"])

    def test_upsert_is_idempotent_and_partial_state_is_reported(self):
        for status in (ev.NO_CUMPLE, ev.CUMPLE):   # second write must REPLACE the first, not duplicate it
            ev.save_evidence(self.cur, "ASSET", self.asset_id, "CM", "cm.git_history", {"status": status, "detail": {"commits_visible": 5}})
        self.cur.execute("SELECT count(*) AS n FROM cmmi_evidence WHERE asset_id = %s AND item_key = 'cm.git_history'", (self.asset_id,))
        self.assertEqual(self.cur.fetchone()["n"], 1)
        cm = next(a for a in ev.build_area_report(self.asset_id)["areas"] if a["area"] == "CM")
        self.assertEqual(cm["state"], "PARCIAL_CUMPLE")        # 1 of 5 CM items evaluated, and met
        self.assertEqual((cm["items_evaluated"], cm["items_met"]), (1, 1))
        self.assertLess(cm["items_evaluated"], cm["items_total"])

    def test_org_evidence_uses_a_null_asset_and_upserts_once(self):
        for _ in range(2):
            ev.save_evidence(self.cur, "ORG", None, "PAD", "pad.manifests_valid", {"status": ev.CUMPLE, "detail": {"manifests": 48}})
        self.cur.execute("SELECT count(*) AS n FROM cmmi_evidence WHERE scope = 'ORG' AND item_key = 'pad.manifests_valid'")
        self.assertEqual(self.cur.fetchone()["n"], 1)

    def test_expired_evidence_stops_counting(self):
        ev.save_evidence(self.cur, "ASSET", self.asset_id, "PR", "pr.merged_mr_reviewed", {"status": ev.CUMPLE, "detail": {}}, valid_days=-1)
        pr = next(a for a in ev.build_area_report(self.asset_id)["areas"] if a["area"] == "PR")
        self.assertEqual(pr["state"], "NO_EVALUADA")


class TestOrgCollectorsAgainstThisRepository(unittest.TestCase):
    def test_pad_manifests_are_valid_in_this_repo(self):
        with mock.patch.object(ev, "REPO_ROOT", str(__import__("pathlib").Path(__file__).resolve().parents[1])):
            r = ev.pad_manifests_valid({})
        self.assertEqual(r["status"], ev.CUMPLE, r["detail"])
        self.assertGreaterEqual(r["detail"]["manifests"], 47)


if __name__ == "__main__":
    unittest.main()
