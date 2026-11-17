"""Change detection (core/change_detection.py): re-analyze only what changed since the last analysis.

DB tests share one connection that is ROLLED BACK (project rule #8); GitLab is simulated (list_branches / get_project_details).
"""
import contextlib
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from auditors import gitlab_integration as gi
from core import change_detection as cd, db_manager, gitlab_instances, job_queue

P = "grupo-prueba/proyecto-cd"
INST = gitlab_instances.get_instance("primary")


class TestPure(unittest.TestCase):
    def test_classify(self):
        e = "eng1"
        self.assertEqual(cd.classify("a", e, "a", False, True, True, e), cd.EN_COLA)
        self.assertEqual(cd.classify("a", e, "a", False, False, False, e), cd.SIN_VERIFICAR)
        self.assertEqual(cd.classify("a", e, None, True, True, False, e), cd.RAMA_ELIMINADA)
        self.assertEqual(cd.classify(None, None, "b", False, True, False, e), cd.SIN_ANALISIS)
        self.assertEqual(cd.classify("a", e, "b", False, True, False, e), cd.CAMBIOS)
        self.assertEqual(cd.classify("a", "old", "a", False, True, False, e), cd.REGLAS_NUEVAS)
        self.assertEqual(cd.classify("a", None, "a", False, True, False, e), cd.REGLAS_NUEVAS)
        self.assertEqual(cd.classify("a", e, "a", False, True, False, e), cd.AL_DIA)

    def test_manual_rescan_only_for_code_changes(self):
        self.assertEqual(set(cd.MANUAL_RESCAN_STATES), {cd.CAMBIOS, cd.SIN_ANALISIS})

    def test_pick_fleet_branch(self):
        self.assertEqual(cd.pick_fleet_branch([{"name": "main", "default": True}, {"name": "Desarrollo"}]), "Desarrollo")
        self.assertEqual(cd.pick_fleet_branch([{"name": "main", "default": True}, {"name": "feature/x"}]), "main")
        self.assertEqual(cd.pick_fleet_branch([{"name": "develop"}, {"name": "dev"}]), "develop")
        self.assertIsNone(cd.pick_fleet_branch([]))

    def test_engine_version_tracks_content(self):
        import tempfile, os, time
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "auditors"))
            os.makedirs(os.path.join(root, "core"))
            f = os.path.join(root, "auditors", "a.py")
            open(f, "w").write("x = 1\n")
            open(os.path.join(root, "core", "deduplication_engine.py"), "w").write("y = 1\n")
            v1 = cd.engine_version(root)
            self.assertEqual(v1, cd.engine_version(root))
            time.sleep(0.01)
            open(f, "w").write("x = 2\n")
            os.utime(f, (time.time() + 5, time.time() + 5))
            self.assertNotEqual(v1, cd.engine_version(root))


class TestAgainstDb(unittest.TestCase):
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
        self._stack.enter_context(mock.patch.object(cd, "REFRESH_WORKERS", 1))
        self.remote = {"develop": "c2", "feature-a": "f1", "main": "m1"}
        self._stack.enter_context(mock.patch.object(gi.GitLabIntegrator, "list_branches",
                                                    lambda _self, _p: [{"name": n, "default": n == "main", "commit_sha": c,
                                                                        "last_commit_at": "2026-10-28T10:00:00Z"} for n, c in self.remote.items()]))
        self._stack.enter_context(mock.patch.object(gi.GitLabIntegrator, "get_project_details",
                                                    lambda _self, _p: {"id": 1, "path_with_namespace": P, "http_url_to_repo": "http://x/y.git"}))
        cur = self.conn.cursor()
        self.ids = {}
        for br in ("develop", "feature-a", "gone"):
            cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES (%s, 'GitLab-Repo', 'test') RETURNING id",
                        (INST.asset_name(P, br),))
            self.ids[br] = cur.fetchone()[0]
        eng = cd.engine_version()
        # develop analyzed at c1 (now c2 -> CAMBIOS); feature-a analyzed at f1 with current rules (AL_DIA); gone: branch deleted
        for br, sha in (("develop", "c1"), ("feature-a", "f1"), ("gone", "z1")):
            cur.execute("INSERT INTO scan_runs (asset_id, source, commit_sha, engine_version, status, finished_at) "
                        "VALUES (%s, 'gitlab:primary', %s, %s, 'DONE', now())", (self.ids[br], sha, eng))

    def tearDown(self):
        self.conn.rollback()
        self._stack.close()

    def _states(self):
        return {x["asset_name"].split("@")[1]: x for x in cd.asset_states(prefix=INST.asset_name(P) + "@")}

    def test_states_before_and_after_refresh(self):
        self.assertTrue(all(s["state"] == cd.SIN_VERIFICAR for s in self._states().values()))
        r = cd.refresh_project(INST, P)
        self.assertEqual(r["fleet_branch"], "develop")
        st = self._states()
        self.assertEqual(st["develop"]["state"], cd.CAMBIOS)
        self.assertTrue(st["develop"]["rescan_allowed"] and st["develop"]["is_fleet_branch"])
        self.assertEqual(st["feature-a"]["state"], cd.AL_DIA)
        self.assertFalse(st["feature-a"]["rescan_allowed"])
        self.assertEqual(st["gone"]["state"], cd.RAMA_ELIMINADA)

    def test_rescan_changed_queues_only_changes_and_tracks_progress(self):
        r = cd.enqueue_changed(prefix=INST.asset_name(P) + "@")
        self.assertEqual(r["queued"], [INST.asset_name(P, "develop")])
        self.assertEqual({x["state"] for x in r["skipped"]}, {cd.AL_DIA, cd.RAMA_ELIMINADA})
        cur = self.conn.cursor()
        cur.execute("SELECT target, payload FROM scan_jobs WHERE payload->>'batch_id' = %s", (r["batch_id"],))
        rows = cur.fetchall()
        self.assertEqual(len(rows), 1)
        target, payload = rows[0]
        self.assertEqual(target, f"primary:{P}")           # fleet branch -> same target as the daily run
        self.assertEqual(payload["branch"], "develop")
        self.assertNotIn("separate_asset", payload)
        p = cd.batch_progress(r["batch_id"])
        self.assertEqual((p["total"], p["queued"], p["percent"], p["finished"]), (1, 1, 0, False))
        self.assertEqual(self._states()["develop"]["state"], cd.EN_COLA)
        # a second request joins the running batch item instead of queueing it twice
        r2 = cd.enqueue_changed(prefix=INST.asset_name(P) + "@")
        self.assertEqual(r2["queued"], [])
        self.assertEqual(r2["already_queued"], [INST.asset_name(P, "develop")])
        cur.execute("UPDATE scan_jobs SET status = 'DONE', finished_at = now() WHERE payload->>'batch_id' = %s", (r2["batch_id"],))
        p2 = cd.batch_progress(r2["batch_id"])
        self.assertEqual((p2["done"], p2["percent"], p2["finished"]), (1, 100, True))

    def test_non_fleet_branch_is_queued_as_its_own_asset(self):
        self.remote["feature-a"] = "f2"
        r = cd.enqueue_changed(assets=[INST.asset_name(P, "feature-a")])
        cur = self.conn.cursor()
        cur.execute("SELECT target, payload FROM scan_jobs WHERE payload->>'batch_id' = %s", (r["batch_id"],))
        target, payload = cur.fetchone()
        self.assertEqual(target, f"primary:{P}@feature-a")
        self.assertTrue(payload["separate_asset"])

    def test_nothing_changed_queues_nothing(self):
        self.remote["develop"] = "c1"
        r = cd.enqueue_changed(prefix=INST.asset_name(P) + "@")
        self.assertIsNone(r["batch_id"])
        self.assertEqual(r["queued"], [])

    def test_branch_scan_refused_when_unchanged(self):
        with self.assertRaises(gi.UnchangedSinceLastAnalysis):
            gi.enqueue_branch_scan(P, "feature-a", "primary")
        self.remote["feature-a"] = "f2"
        r = gi.enqueue_branch_scan(P, "feature-a", "primary")
        self.assertTrue(r["job_id"])

    def test_fleet_skip_when_unchanged_and_recorded_once(self):
        window = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.assertEqual(cd.fleet_branch_unchanged(INST, P, window)[0], False)   # develop c1 -> c2
        self.remote["develop"] = "c1"
        cd.refresh_project(INST, P)
        unchanged, reason = cd.fleet_branch_unchanged(INST, P, window)
        self.assertTrue(unchanged)
        self.assertIn("develop@c1", reason)
        target = f"primary:{P}"
        self.assertFalse(job_queue.finished_since(gi.GITLAB_JOB_KIND, target, window))
        job_queue.record_skipped(gi.GITLAB_JOB_KIND, target, "sin cambios")
        self.assertTrue(job_queue.finished_since(gi.GITLAB_JOB_KIND, target, window))

    def test_rules_changed_is_not_a_manual_rescan_but_is_a_fleet_rescan(self):
        self.remote["develop"] = "c1"
        cur = self.conn.cursor()
        cur.execute("UPDATE scan_runs SET engine_version = 'old' WHERE asset_id = %s", (self.ids["develop"],))
        cd.refresh_project(INST, P)
        st = self._states()["develop"]
        self.assertEqual(st["state"], cd.REGLAS_NUEVAS)
        self.assertFalse(st["rescan_allowed"])
        self.assertFalse(cd.fleet_branch_unchanged(INST, P, datetime.now(timezone.utc) - timedelta(minutes=5))[0])

    def test_worker_skips_a_job_whose_branch_is_already_analyzed(self):
        job = {"target": f"primary:{P}@feature-a", "payload": {"instance": "primary", "branch": "feature-a", "separate_asset": True,
                                                              "project": {"id": 1, "path_with_namespace": P}}}
        with mock.patch.object(gi.GitLabIntegrator, "scan_single_project") as scan:
            res = gi.run_scan_job(job)
        scan.assert_not_called()
        self.assertEqual(res["status"], "skipped")
        self.assertIn("feature-a@f1", res["reason"])

    def test_worker_scans_when_the_branch_moved(self):
        self.remote["feature-a"] = "f2"
        job = {"target": f"primary:{P}@feature-a", "payload": {"instance": "primary", "branch": "feature-a", "separate_asset": True,
                                                              "project": {"id": 1, "path_with_namespace": P}}}
        with mock.patch.object(gi.GitLabIntegrator, "scan_single_project", return_value={"status": "success"}) as scan:
            gi.run_scan_job(job)
        scan.assert_called_once()

    def test_periodic_job_still_scans_when_only_the_rules_changed(self):
        self.remote["develop"] = "c1"
        cur = self.conn.cursor()
        cur.execute("UPDATE scan_runs SET engine_version = 'old' WHERE asset_id = %s", (self.ids["develop"],))
        job = {"target": f"primary:{P}", "payload": {"instance": "primary", "project": {"id": 1, "path_with_namespace": P}}}
        with mock.patch.object(gi.GitLabIntegrator, "scan_single_project", return_value={"status": "success"}) as scan:
            gi.run_scan_job(job)
        scan.assert_called_once()


if __name__ == "__main__":
    unittest.main()
