"""Multi-instance GitLab registry: naming, host attribution, clone-host guard, no credential bleed."""
import os
import unittest
from unittest import mock

from core import gitlab_instances as gi

ENV = {"GITLAB_URL": "http://gl-one.test", "GITLAB_TOKEN": "tok-one",
       "GITLAB2_URL": "http://gl-two.test/", "GITLAB2_TOKEN": "tok-two"}


@mock.patch.dict(os.environ, ENV, clear=False)
class TestRegistry(unittest.TestCase):
    def test_instances_and_naming(self):
        keys = [i.key for i in gi.configured_instances()]
        self.assertEqual(keys[:2], ["primary", "gitlab2"])
        p, g2 = gi.get_instance(None), gi.get_instance("gitlab2")
        self.assertEqual(g2.url, "http://gl-two.test")  # trailing slash stripped
        self.assertEqual(p.asset_name("a/b"), "GitLab/a/b")      # historical name preserved
        self.assertEqual(g2.asset_name("a/b"), "GitLab2/a/b")    # same path on 2 instances != same asset
        self.assertNotEqual(p.clone_folder("a/b"), g2.clone_folder("a/b"))
        self.assertEqual(p.clone_folder("a/b"), "a_b")

    def test_unconfigured_key_never_falls_back_to_primary(self):
        with self.assertRaises(KeyError):
            gi.get_instance("gitlab7")

    def test_asset_prefix_longest_match(self):
        self.assertEqual(gi.instance_for_asset_name("GitLab2/x/y").key, "gitlab2")
        self.assertEqual(gi.instance_for_asset_name("GitLab/x/y").key, "primary")
        self.assertIsNone(gi.instance_for_asset_name("proyecto-k-proyecto-j-srv"))
        self.assertEqual(gi.strip_asset_prefix("GitLab2/x/y"), "x/y")

    def test_host_attribution(self):
        self.assertEqual(gi.instance_for_host("http://gl-two.test/g/p/-/merge_requests/1").key, "gitlab2")
        self.assertEqual(gi.instance_for_host("gl-one.test").key, "primary")
        self.assertIsNone(gi.instance_for_host("http://evil.example/g/p"))

    def test_describe_never_leaks_token(self):
        self.assertNotIn("tok-two", str(gi.describe()))


@mock.patch.dict(os.environ, ENV, clear=False)
class TestIntegratorUsesRightCredentials(unittest.TestCase):
    def test_integrator_binds_instance_and_refuses_foreign_host(self):
        from auditors.gitlab_integration import GitLabIntegrator
        g2 = GitLabIntegrator(instance="gitlab2")
        self.assertEqual((g2.gitlab_url, g2.token), ("http://gl-two.test", "tok-two"))
        # a repo URL on the OTHER instance's (or any) host must never receive this token
        self.assertEqual(g2.clone_or_pull("http://gl-one.test/a/b.git", "a/b"), "")
        self.assertEqual(g2.clone_or_pull("http://evil.example/a/b.git", "a/b"), "")

    def test_webhook_payload_attribution_is_fail_closed(self):
        from fastapi import HTTPException
        from main import _gitlab_instance_from_payload
        self.assertEqual(_gitlab_instance_from_payload({"project": {"web_url": "http://gl-two.test/a/b"}}), "gitlab2")
        with self.assertRaises(HTTPException) as cm:
            _gitlab_instance_from_payload({"project": {"web_url": "http://evil.example/a/b"}})
        self.assertEqual(cm.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()


class BranchAssetTests(unittest.TestCase):
    def test_branch_asset_and_folder_names(self):
        from core import gitlab_instances as gi
        p = gi.get_instance(None)
        self.assertEqual(p.asset_name("a/b"), "GitLab/a/b")                      # regular scan keeps its historical name
        self.assertEqual(p.asset_name("a/b", "feature/x"), "GitLab/a/b@feature/x")
        self.assertEqual(p.clone_folder("a/b"), "a_b")
        self.assertNotEqual(p.clone_folder("a/b", "feature/x"), p.clone_folder("a/b", "feature_x"))   # no slug collisions
        self.assertNotEqual(p.clone_folder("a/b", "develop"), p.clone_folder("a/b"))                  # never shares the regular clone

    def test_parse_asset_name_roundtrip(self):
        from core import gitlab_instances as gi
        p = gi.get_instance(None)
        inst, path, branch = gi.parse_asset_name(p.asset_name("a/b", "release/1.2@rc"))
        self.assertEqual((inst.key, path, branch), ("primary", "a/b", "release/1.2@rc"))
        self.assertEqual(gi.parse_asset_name("GitLab/a/b")[1:], ("a/b", None))
        self.assertEqual(gi.strip_asset_prefix("GitLab/a/b@dev"), "a/b")


@mock.patch.dict(os.environ, ENV, clear=False)
class TestScanExclusions(unittest.TestCase):
    def test_exact_project_and_group_matching(self):
        g2, p = gi.get_instance("gitlab2"), gi.get_instance(None)
        ex = ["GitLab2/grupo-b/proyecto-i", "GitLab2/grupo-b/proyecto-h/", "GitLab/maintainer/core-org"]
        self.assertTrue(gi.is_scan_excluded(g2, "grupo-b/proyecto-i", ex))
        self.assertFalse(gi.is_scan_excluded(g2, "grupo-b/proyecto-i-demo-template", ex))   # no accidental prefix match
        self.assertTrue(gi.is_scan_excluded(g2, "grupo-b/proyecto-h/proyecto-h-migracion", ex))  # group entry
        self.assertFalse(gi.is_scan_excluded(p, "grupo-b/proyecto-i", ex))                  # other instance, same path
        self.assertTrue(gi.is_scan_excluded(p, "maintainer/core-org", ex))
        self.assertFalse(gi.is_scan_excluded(p, "arquitectura/core-org", ex))

    def test_file_parsing_ignores_comments_and_missing_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# comentario\n\n  GitLab2/a/b  \n")
        try:
            self.assertEqual(gi.scan_exclusions(fh.name), ["GitLab2/a/b"])
        finally:
            os.unlink(fh.name)
        self.assertEqual(gi.scan_exclusions("/nonexistent/exclude.txt"), [])

    def test_worker_drops_excluded_periodic_job_but_runs_manual_branch_scan(self):
        from auditors import gitlab_integration as gl
        job = {"target": "gitlab2:grupo-b/proyecto-i", "payload": {"instance": "gitlab2", "project": {"path_with_namespace": "grupo-b/proyecto-i"}}}
        with mock.patch.object(gi, "scan_exclusions", return_value=["GitLab2/grupo-b/proyecto-i"]), \
             mock.patch.object(gl.GitLabIntegrator, "scan_single_project", return_value={"status": "success"}) as scan:
            self.assertEqual(gl.run_scan_job(job)["reason"], "excluded")
            scan.assert_not_called()
            job["payload"].update(branch="develop", separate_asset=True)
            self.assertEqual(gl.run_scan_job(job)["status"], "success")
            scan.assert_called_once()
