"""Git-history secrets job: every guard, and the property that matters most -- a TruffleHog failure/timeout/oversized repo is never reported as 'clean'."""
import json
import subprocess
import unittest
from unittest import mock

from auditors import secrets_history_job as J
from core.gitlab_instances import GitLabInstance

INST = GitLabInstance("gitlab2", "http://gitlab.example", "TOKEN123", "GitLab2/", "gitlab2__")
JOB = {"target": "gitlab2:g/p", "payload": {"instance": "gitlab2", "project": {"id": 7, "path_with_namespace": "g/p", "http_url_to_repo": "http://gitlab.example/g/p.git"}}}
PROJ = {"id": 7, "path_with_namespace": "g/p", "http_url_to_repo": "http://gitlab.example/g/p.git", "default_branch": "main"}


def fake_integ(proj=PROJ, branch="main"):
    i = mock.Mock()
    i.instance, i.gitlab_url, i.token = INST, INST.url, INST.token
    i.get_project_details.return_value = proj
    i.pick_branch.return_value = branch
    return i


def stats(mb):
    return mock.Mock(status_code=200, json=lambda: {"statistics": {"repository_size": int(mb * 1_048_576)}})


class Cursor:
    def __init__(self, row): self.row = row
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, *a, **k): pass
    def fetchone(self): return self.row


def run(row=("11111111-1111-1111-1111-111111111111",), mb=10, th=None, clone=None, integ=None):
    th = th or mock.Mock(returncode=0, stdout="", stderr="")
    with mock.patch("auditors.gitlab_integration.GitLabIntegrator", return_value=integ or fake_integ()), \
         mock.patch("requests.get", return_value=stats(mb)), \
         mock.patch("core.db_manager.get_db_cursor", return_value=Cursor(row)), \
         mock.patch.object(J, "_clone_full", clone or (lambda *a, **k: None)), \
         mock.patch("subprocess.run", return_value=th) as sp, \
         mock.patch("auditors.auditor_secrets.log_secrets") as log:
        out = J.run_secrets_history_job(JOB)
    return out, sp, log


LINE = json.dumps({"DetectorName": "PrivateKey", "Verified": False, "Redacted": "-----BEGIN", "SourceMetadata": {"Data": {"Git": {"file": "k.pem", "line": 1, "commit": "abcdef0123"}}}})


class TestJob(unittest.TestCase):
    def test_findings_are_logged_to_the_primary_branch_asset(self):
        out, sp, log = run(th=mock.Mock(returncode=0, stdout=LINE, stderr=""))
        self.assertEqual((out["status"], out["secrets"], out["asset"]), ("success", 1, "GitLab2/g/p@main"))
        log.assert_called_once()
        self.assertEqual(log.call_args[0][0], "11111111-1111-1111-1111-111111111111")
        self.assertIn("--no-verification", sp.call_args[0][0])          # nothing leaves the host unless SECRETS_VERIFY_LIVE=1

    def test_clean_history_is_a_success_with_zero(self):
        out, _, log = run()
        self.assertEqual((out["status"], out["secrets"]), ("success", 0))
        log.assert_not_called()

    def test_oversized_repo_is_skipped_and_says_so_not_clean(self):
        out, sp, log = run(mb=J.MAX_MB + 1)
        self.assertEqual(out["status"], "skipped")
        self.assertTrue(out["reason"].startswith("repo_too_large"))
        sp.assert_not_called()

    def test_trufflehog_failure_raises_instead_of_reporting_clean(self):
        with self.assertRaises(RuntimeError):
            run(th=mock.Mock(returncode=2, stdout="", stderr="boom"))

    def test_trufflehog_timeout_propagates(self):
        with mock.patch("auditors.gitlab_integration.GitLabIntegrator", return_value=fake_integ()), mock.patch("requests.get", return_value=stats(1)), \
             mock.patch("core.db_manager.get_db_cursor", return_value=Cursor(("a",))), mock.patch.object(J, "_clone_full"), \
             mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("trufflehog", 1)):
            with self.assertRaises(subprocess.TimeoutExpired):
                J.run_secrets_history_job(JOB)

    def test_unregistered_asset_raises_so_the_queue_retries(self):
        with self.assertRaises(RuntimeError):
            run(row=None)

    def test_project_not_found_raises(self):
        with self.assertRaises(RuntimeError):
            run(integ=fake_integ(proj=None))

    def test_the_temp_clone_is_always_removed(self):
        made = []
        real_mkdtemp = J.tempfile.mkdtemp
        with mock.patch.object(J.tempfile, "mkdtemp", side_effect=lambda **k: made.append(real_mkdtemp(**k)) or made[-1]):
            with self.assertRaises(RuntimeError):
                run(th=mock.Mock(returncode=2, stdout="", stderr="x"))
        import os
        self.assertTrue(made and not os.path.exists(made[0]))


class TestCloneGuard(unittest.TestCase):
    def test_refuses_to_send_the_token_to_another_host(self):
        with mock.patch("subprocess.run") as sp:
            with self.assertRaises(RuntimeError):
                J._clone_full("http://evil.example/g/p.git", INST, "/tmp/x")
        sp.assert_not_called()

    def test_token_is_never_echoed_in_the_error(self):
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=128, stderr="fatal: could not read from http://oauth2:TOKEN123@gitlab.example/g/p.git")):
            with self.assertRaises(RuntimeError) as cm:
                J._clone_full("http://gitlab.example/g/p.git", INST, "/tmp/x")
        self.assertNotIn("TOKEN123", str(cm.exception))


class TestCloneBuildsAnIndex(unittest.TestCase):
    def test_after_a_no_checkout_clone_the_index_is_rebuilt_so_trufflehog_can_open_the_repo(self):
        calls = []
        with mock.patch("subprocess.run", side_effect=lambda cmd, **k: calls.append(cmd) or mock.Mock(returncode=0, stderr="")):
            J._clone_full("http://gitlab.example/g/p.git", INST, "/tmp/dest")
        self.assertEqual(calls[0][:3], ["git", "clone", "--quiet"])
        self.assertIn("--no-checkout", calls[0])
        self.assertEqual(calls[1], ["git", "-C", "/tmp/dest", "read-tree", "HEAD"])

    def test_a_failing_read_tree_fails_the_job(self):
        results = iter([mock.Mock(returncode=0, stderr=""), mock.Mock(returncode=1, stderr="fatal: bad HEAD")])
        with mock.patch("subprocess.run", side_effect=lambda *a, **k: next(results)):
            with self.assertRaises(RuntimeError):
                J._clone_full("http://gitlab.example/g/p.git", INST, "/tmp/dest")


class TestAggregation(unittest.TestCase):
    def f(self, typ="JWT", file="dump.sql", line=1, commit="aaaaaaaa", sev="MEDIUM"):
        return {"type": typ, "file": file, "line": line, "commit": commit, "severity": sev, "description": typ, "masked_context": "x", "verified": None}

    def test_thousands_of_detections_in_one_file_become_one_finding(self):
        out = J.aggregate_detections([self.f(line=i, commit=f"c{i % 7}") for i in range(500)])
        self.assertEqual(len(out), 1)
        self.assertIn("500 detecciones en 7 commit(s)", out[0]["description"])
        self.assertIn("VOLCADO de base de datos", out[0]["description"])          # a .sql with many detections is called out as a dump

    def test_different_files_and_detectors_stay_separate(self):
        out = J.aggregate_detections([self.f(file="a.properties"), self.f(file="b.properties"), self.f(typ="JDBC", file="a.properties")])
        self.assertEqual(len(out), 3)
        self.assertNotIn("detecciones", out[0]["description"])                     # a single detection is not rewritten

    def test_highest_severity_wins(self):
        out = J.aggregate_detections([self.f(sev="MEDIUM"), self.f(sev="HIGH", line=2)])
        self.assertEqual(out[0]["severity"], "HIGH")

    def test_a_few_sql_detections_are_not_called_a_dump(self):
        out = J.aggregate_detections([self.f(line=i) for i in range(3)])
        self.assertNotIn("VOLCADO", out[0]["description"])
