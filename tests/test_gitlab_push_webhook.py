"""
Unit tests for GitLab Push Webhook & Multi-Branch Re-scan logic.

Validates:
1. Branch filtering (develop, desarrollo, main, master, and custom env overrides).
2. Webhook security (X-Gitlab-Token header verification).
3. Payload handling (push events, branch deletion, tag pushes, unmonitored branches).
4. Single-project scan invocation with branch parameter.
"""
import os
import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from auditors.gitlab_integration import is_monitored_branch, DEFAULT_MONITORED_BRANCHES, GitLabIntegrator
from main import app


class TestBranchFiltering(unittest.TestCase):
    def test_default_monitored_branches(self):
        for br in ("develop", "desarrollo", "main", "master", "dev", "development"):
            self.assertTrue(is_monitored_branch(br), f"Expected '{br}' to be monitored by default")
            self.assertTrue(is_monitored_branch(br.upper()), f"Expected '{br.upper()}' (case-insensitive) to be monitored")

    def test_unmonitored_branches(self):
        for br in ("feature/login", "bugfix/123", "temp-patch", "experimental", ""):
            self.assertFalse(is_monitored_branch(br), f"Expected '{br}' not to be monitored by default")

    def test_custom_monitored_branches_env(self):
        with patch.dict(os.environ, {"GITLAB_MONITORED_BRANCHES": "release,staging,production"}):
            self.assertTrue(is_monitored_branch("release"))
            self.assertTrue(is_monitored_branch("staging"))
            self.assertTrue(is_monitored_branch("production"))
            self.assertFalse(is_monitored_branch("develop"))


class TestGitLabPushWebhook(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_push_webhook_unauthorized_token(self):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": "secret_token_123"}):
            resp = self.client.post(
                "/api/gitlab/push-webhook",
                headers={"X-Gitlab-Token": "wrong_token"},
                json={"object_kind": "push"}
            )
            self.assertEqual(resp.status_code, 401)
            self.assertIn("invalid X-Gitlab-Token", resp.text)

    def test_push_webhook_ignores_non_push(self):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": "secret_token_123"}):
            resp = self.client.post(
                "/api/gitlab/push-webhook",
                headers={"X-Gitlab-Token": "secret_token_123"},
                json={"object_kind": "tag_push"}
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ignored")
            self.assertIn("object_kind=tag_push", data["reason"])

    def test_push_webhook_ignores_branch_deletion(self):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": "secret_token_123"}):
            resp = self.client.post(
                "/api/gitlab/push-webhook",
                headers={"X-Gitlab-Token": "secret_token_123"},
                json={
                    "object_kind": "push",
                    "ref": "refs/heads/develop",
                    "after": "0000000000000000000000000000000000000000",
                    "project": {"id": 42}
                }
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ignored")
            self.assertEqual(data["reason"], "branch deletion event")

    def test_push_webhook_ignores_tag_ref(self):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": "secret_token_123"}):
            resp = self.client.post(
                "/api/gitlab/push-webhook",
                headers={"X-Gitlab-Token": "secret_token_123"},
                json={
                    "object_kind": "push",
                    "ref": "refs/tags/v1.0.0",
                    "after": "1234567890abcdef1234567890abcdef12345678",
                    "project": {"id": 42}
                }
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ignored")
            self.assertIn("not a branch push", data["reason"])

    def test_push_webhook_ignores_unmonitored_feature_branch(self):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": "secret_token_123"}):
            resp = self.client.post(
                "/api/gitlab/push-webhook",
                headers={"X-Gitlab-Token": "secret_token_123"},
                json={
                    "object_kind": "push",
                    "ref": "refs/heads/feature/login-redesign",
                    "after": "1234567890abcdef1234567890abcdef12345678",
                    "project": {"id": 42}
                }
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ignored")
            self.assertIn("not in monitored baseline list", data["reason"])

    @patch("api.routers.gitlab._run_push_scan_bg")
    def test_push_webhook_accepts_monitored_branches(self, mock_run_bg):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": "secret_token_123"}):
            for branch in ("develop", "desarrollo", "main", "master"):
                resp = self.client.post(
                    "/api/gitlab/push-webhook",
                    headers={"X-Gitlab-Token": "secret_token_123"},
                    json={
                        "object_kind": "push",
                        "ref": f"refs/heads/{branch}",
                        "after": "abc1234567890defabc1234567890defabc12345",
                        "total_commits_count": 2,
                        "project": {
                            "id": 99,
                            "path_with_namespace": "org-x/proyecto-k-backend",
                            "web_url": "http://192.0.2.14/org-x/proyecto-k-backend",
                            "git_http_url": "http://192.0.2.14/org-x/proyecto-k-backend.git"
                        }
                    }
                )
                self.assertEqual(resp.status_code, 200)
                data = resp.json()
                self.assertEqual(data["status"], "accepted")
                self.assertEqual(data["branch"], branch)
                self.assertEqual(data["project_id"], 99)
                self.assertEqual(data["commits_count"], 2)


class TestSingleProjectScan(unittest.TestCase):
    @patch.object(GitLabIntegrator, "scan_single_project")
    def test_trigger_single_project_scan_endpoint(self, mock_scan):
        mock_scan.return_value = {
            "status": "success",
            "project_id": 101,
            "path_with_namespace": "org-x/test-repo",
            "branch": "develop",
            "total_vulnerabilities": 5
        }
        client = TestClient(app)
        resp = client.post("/api/gitlab/scan-project/101?branch=develop")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["result"]["total_vulnerabilities"], 5)
        mock_scan.assert_called_once_with("101", branch="develop", separate_asset=False)


if __name__ == "__main__":
    unittest.main()


class TestWebhookHardening(unittest.TestCase):
    """Regression tests for the fail-open webhook + token-leak-on-clone issues (2026-09-23)."""

    def setUp(self):
        self.client = TestClient(app)

    def test_push_webhook_disabled_when_token_unset(self):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": ""}):
            resp = self.client.post("/api/gitlab/push-webhook", json={"object_kind": "tag_push"})
            self.assertEqual(resp.status_code, 503)

    def test_mr_webhook_disabled_when_token_unset(self):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": ""}):
            resp = self.client.post("/api/gitlab/mr-webhook", json={"object_kind": "tag_push"})
            self.assertEqual(resp.status_code, 503)

    def test_mr_webhook_rejects_wrong_and_missing_token(self):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": "s3cret"}):
            self.assertEqual(self.client.post("/api/gitlab/mr-webhook", json={}).status_code, 401)
            self.assertEqual(self.client.post("/api/gitlab/mr-webhook", headers={"X-Gitlab-Token": "nope"}, json={}).status_code, 401)

    @patch("api.routers.gitlab._run_push_scan_bg")
    def test_push_webhook_never_forwards_payload_repo_url(self, mock_bg):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": "s3cret"}):
            resp = self.client.post(
                "/api/gitlab/push-webhook",
                headers={"X-Gitlab-Token": "s3cret"},
                json={"object_kind": "push", "ref": "refs/heads/main", "after": "a" * 40,
                      "project": {"id": 7, "web_url": "http://192.0.2.14/g/x",
                                  "http_url_to_repo": "http://attacker.example/x.git"}},
            )
            self.assertEqual(resp.status_code, 200)
            args = mock_bg.call_args[0]
            self.assertEqual(args[0], 7)          # only the project id, never the attacker URL
            self.assertEqual(args[2], "primary")  # instance deduced from the trusted host, not the payload clone URL
            self.assertNotIn("attacker", repr(args))

    @patch("api.routers.gitlab._run_push_scan_bg")
    def test_push_webhook_from_unconfigured_host_is_rejected(self, mock_bg):
        with patch.dict(os.environ, {"GITLAB_WEBHOOK_TOKEN": "s3cret"}):
            resp = self.client.post(
                "/api/gitlab/push-webhook",
                headers={"X-Gitlab-Token": "s3cret"},
                json={"object_kind": "push", "ref": "refs/heads/main", "after": "a" * 40,
                      "project": {"id": 7, "web_url": "http://attacker.example/g/x"}},
            )
            self.assertEqual(resp.status_code, 403)
            mock_bg.assert_not_called()

    def test_clone_refuses_foreign_host_and_does_not_leak_token(self):
        gl = GitLabIntegrator(gitlab_url="http://192.0.2.14", token="TOPSECRET")
        with patch("auditors.gitlab_integration.subprocess.run") as run:
            out = gl.clone_or_pull("http://attacker.example/x.git", "evil/x")
            self.assertEqual(out, "")
            run.assert_not_called()

    def test_clone_injects_token_only_for_own_host(self):
        gl = GitLabIntegrator(gitlab_url="http://192.0.2.14", token="TOPSECRET")
        with patch("auditors.gitlab_integration.subprocess.run") as run, \
             patch("auditors.gitlab_integration.os.path.exists", return_value=False), \
             patch("auditors.gitlab_integration.os.makedirs"):
            gl.clone_or_pull("http://192.0.2.14/grp/proj.git", "grp/proj")
            cmd = run.call_args[0][0]
            self.assertIn("http://oauth2:TOPSECRET@192.0.2.14/grp/proj.git", cmd)
