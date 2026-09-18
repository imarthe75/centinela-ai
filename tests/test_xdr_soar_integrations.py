"""
Unit tests for Centinela AI Gap Closure:
- GitLab MR Webhook Inbound Loop Closure (handle_mr_merged)
- Wazuh EDR & Telemetry incident engine integration
- Multi-role Authz DAST config fallback
- Reusable GitLab CI/CD Quality Gate template
- AI-assisted auto-patch generation helper logic
"""
import os
import unittest
from unittest.mock import patch, MagicMock

from core.incident_engine import (
    is_standalone_worthy,
    classify_tactic,
    extract_indicators,
)
from remediation.gitlab_autofix import handle_mr_merged
from auditors import auditor_authz_dast


class TestGitLabMRMergedHandler(unittest.TestCase):
    def test_handle_mr_merged_branch_parsing(self):
        payload = {
            "object_kind": "merge_request",
            "project": {"id": 42},
            "object_attributes": {
                "iid": 12,
                "action": "merge",
                "state": "merged",
                "source_branch": "centinela-fix/docker-missing-non-root-user-105",
                "target_branch": "main",
                "title": "🛡️ [Centinela SOAR] Fix DOCKER-MISSING-NON-ROOT-USER",
                "url": "http://10.4.3.10/kardex/app/-/merge_requests/12",
            }
        }
        with patch("core.db_manager.get_db_cursor") as mock_cursor:
            mock_cur = MagicMock()
            mock_cur.fetchall.return_value = [{"id": 105, "asset_id": 1, "cve_id": "DOCKER-MISSING-NON-ROOT-USER", "severity": "HIGH"}]
            mock_cursor.return_value.__enter__.return_value = mock_cur

            res = handle_mr_merged(payload)
            self.assertEqual(res["status"], "resolved")
            self.assertEqual(res["vuln_id"], 105)
            self.assertEqual(res["mr_iid"], 12)
            self.assertEqual(res["resolved_count"], 1)

    def test_handle_mr_merged_cve_in_title(self):
        payload = {
            "object_kind": "merge_request",
            "project": {"id": 99},
            "object_attributes": {
                "iid": 7,
                "action": "merge",
                "state": "merged",
                "source_branch": "fix-feature-branch",
                "title": "Merge fix for CVE-2024-1234 vuln_id: 88",
                "url": "http://10.4.3.10/starters/base/-/merge_requests/7",
            }
        }
        with patch("core.db_manager.get_db_cursor") as mock_cursor:
            mock_cur = MagicMock()
            mock_cur.fetchall.return_value = [{"id": 88, "asset_id": 2, "cve_id": "CVE-2024-1234", "severity": "CRITICAL"}]
            mock_cursor.return_value.__enter__.return_value = mock_cur

            res = handle_mr_merged(payload)
            self.assertEqual(res["status"], "resolved")
            self.assertEqual(res["vuln_id"], 88)
            self.assertEqual(res["cve_id"], "CVE-2024-1234")


class TestIncidentEngineWazuh(unittest.TestCase):
    def test_standalone_worthy_wazuh_prefix(self):
        self.assertTrue(is_standalone_worthy("WAZUH-1002", "Privilege escalation detected"))
        self.assertTrue(is_standalone_worthy("WAZUH-5501", "PAM authentication failure"))

    def test_standalone_worthy_sudo_substrings(self):
        self.assertTrue(is_standalone_worthy("HOST-ALERT", "User executed SUDO command"))
        self.assertTrue(is_standalone_worthy("SECURITY_EVENT", "Failed login for user admin"))
        self.assertTrue(is_standalone_worthy("KERNEL", "Attempted RUN_AS_ROOT privilege escalation"))

    def test_classify_tactic_wazuh_sudo(self):
        tactic = classify_tactic("WAZUH-1002", "User dev executed sudo /bin/bash as root")
        self.assertEqual(tactic, "Privilege Escalation")

    def test_classify_tactic_wazuh_auth_failure(self):
        tactic = classify_tactic("WAZUH-5501", "PAM authentication failure for user root")
        self.assertEqual(tactic, "Initial Access")

    def test_extract_indicators_wazuh_fields(self):
        output_fields = {
            "srcip": "10.4.3.45",
            "dstip": "10.4.3.10",
            "srcuser": "deploy-agent",
            "dstuser": "root"
        }
        res = extract_indicators("WAZUH-1002", "Sudo execution", output_fields)
        self.assertIn("10.4.3.45", res["ips"])
        self.assertIn("10.4.3.10", res["ips"])
        self.assertIn("deploy-agent", res["users"])
        self.assertIn("root", res["users"])


class TestAuthzDastConfig(unittest.TestCase):
    def test_env_fallback_credentials(self):
        with patch.dict(os.environ, {
            "AUTHZ_ADMIN_TOKEN": "mock-admin-jwt",
            "AUTHZ_USER_TOKEN": "mock-user-jwt",
            "AUTHZ_BASE_URL": "http://api.kardex.internal:8080"
        }):
            cfg = auditor_authz_dast._load_config("Kardex-API")
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg["base_url"], "http://api.kardex.internal:8080")
            self.assertEqual(len(cfg["roles"]), 2)
            self.assertEqual(cfg["roles"][0]["token"], "mock-admin-jwt")
            self.assertEqual(cfg["roles"][1]["token"], "mock-user-jwt")

    def test_missing_config_returns_none(self):
        with patch.dict(os.environ, {}, clear=True):
            cfg = auditor_authz_dast._load_config("NonExistentAssetXYZ123")
            self.assertIsNone(cfg)


class TestGitLabCITemplate(unittest.TestCase):
    def test_template_file_exists_and_contains_jobs(self):
        template_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates", "centinela-quality-gate.gitlab-ci.yml"))
        if not os.path.exists(template_path):
            template_path = "/opt/centinela-ai/templates/centinela-quality-gate.gitlab-ci.yml"
        self.assertTrue(os.path.isfile(template_path), f"File {template_path} must exist")
        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("centinela:mr-security-gate:", content)
        self.assertIn("centinela:cmmi-iso-quality-gate:", content)
        self.assertIn("CENTINELA_BLOCKING_SEVERITY", content)
        self.assertIn("CENTINELA_MIN_CMMI_LEVEL", content)


if __name__ == "__main__":
    unittest.main()
