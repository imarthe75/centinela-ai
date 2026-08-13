"""
Unit + live-integration tests for the SonarQube auditor.
"""
import os
import shutil
import tempfile
import unittest

import requests

from auditors.auditor_sonarqube import (
    _sanitize_project_key,
    _map_sonar_severity,
    _build_cve_id,
    _build_url_path,
    _extract_ce_task_id_from_output,
    _build_marker_description,
    _materialize_host_visible_copy,
    run_sonarqube_audit,
    SONAR_HOST_URL,
)
from core.db_manager import get_db_cursor


class TestSonarQubePureFunctions(unittest.TestCase):
    def test_sanitize_project_key_strips_unsafe_chars(self):
        self.assertEqual(_sanitize_project_key("arquitectura/core-casmarts"), "arquitectura-core-casmarts")
        self.assertEqual(_sanitize_project_key("GitLab/edomex-casmart/compramex"), "gitlab-edomex-casmart-compramex")

    def test_sanitize_project_key_handles_empty(self):
        self.assertEqual(_sanitize_project_key(""), "centinela-unknown-project")
        self.assertEqual(_sanitize_project_key(None), "centinela-unknown-project")

    def test_map_sonar_severity_legacy_field(self):
        self.assertEqual(_map_sonar_severity({"severity": "BLOCKER"}), "CRITICAL")
        self.assertEqual(_map_sonar_severity({"severity": "CRITICAL"}), "CRITICAL")
        self.assertEqual(_map_sonar_severity({"severity": "MAJOR"}), "HIGH")
        self.assertEqual(_map_sonar_severity({"severity": "MINOR"}), "MEDIUM")
        self.assertEqual(_map_sonar_severity({"severity": "INFO"}), "LOW")

    def test_map_sonar_severity_impacts_field(self):
        # Newer SonarQube (10.x+) Clean Code taxonomy shape -- no legacy "severity" key at all.
        self.assertEqual(_map_sonar_severity({"impacts": [{"softwareQuality": "SECURITY", "severity": "HIGH"}]}), "HIGH")
        self.assertEqual(_map_sonar_severity({"impacts": [{"softwareQuality": "MAINTAINABILITY", "severity": "MEDIUM"}]}), "MEDIUM")
        self.assertEqual(_map_sonar_severity({"impacts": [{"softwareQuality": "RELIABILITY", "severity": "LOW"}]}), "LOW")

    def test_map_sonar_severity_unknown_defaults_medium(self):
        self.assertEqual(_map_sonar_severity({}), "MEDIUM")

    def test_build_cve_id_replaces_colon(self):
        self.assertEqual(_build_cve_id("python:S2077"), "SONAR-python-S2077")
        self.assertEqual(_build_cve_id(None), "SONAR-unknown-rule")

    def test_build_url_path_strips_project_prefix(self):
        issue = {"component": "centinela-test:src/app.py", "line": 42}
        self.assertEqual(_build_url_path(issue, "centinela-test"), "src/app.py:42")

    def test_build_url_path_falls_back_to_text_range(self):
        issue = {"component": "centinela-test:src/app.py", "textRange": {"startLine": 10}}
        self.assertEqual(_build_url_path(issue, "centinela-test"), "src/app.py:10")

    def test_extract_ce_task_id_from_output(self):
        stdout = (
            "INFO  ANALYSIS SUCCESSFUL, you can find the results at: "
            "http://centinela-sonarqube:9000/dashboard?id=centinela-test\n"
            "INFO  More about the report processing at "
            "http://centinela-sonarqube:9000/api/ce/task?id=97970a63-09fb-4430-9082-b40da7afa276\n"
        )
        self.assertEqual(
            _extract_ce_task_id_from_output(stdout),
            "97970a63-09fb-4430-9082-b40da7afa276"
        )

    def test_extract_ce_task_id_from_output_missing(self):
        self.assertIsNone(_extract_ce_task_id_from_output("no task id here"))
        self.assertIsNone(_extract_ce_task_id_from_output(""))

    def test_marker_description_success(self):
        desc = _build_marker_description("success", {
            "gate_status": "OK", "issue_count": 3,
            "measures": {"ncloc": "120", "complexity": "15"}
        })
        self.assertIn("Quality Gate: OK", desc)
        self.assertIn("3 issues", desc)
        self.assertIn("Auditoría SonarQube completada", desc)
        self.assertIn("auditoría sonarqube completada", desc.lower())

    def test_marker_description_scan_failed(self):
        desc = _build_marker_description("scan_failed", {"reason": "timeout"})
        self.assertIn("no pudo completarse", desc)
        self.assertIn("timeout", desc)


class TestMaterializeHostVisibleCopy(unittest.TestCase):
    """
    Regression test for a real bug: shutil.copytree()'s default (symlinks=False) tries to
    copy the FILE CONTENT a symlink points to, which fails outright for a broken symlink --
    confirmed live against two real GitLab repos (arquitectura/consulta-smart,
    arquitectura/consulta-rag-universal), both containing a broken symlink named "backups".
    """

    def test_copies_source_with_broken_symlink(self):
        src = tempfile.mkdtemp(prefix="centinela_sonar_src_")
        try:
            with open(os.path.join(src, "real_file.py"), "w") as f:
                f.write("print('hello')\n")
            os.symlink(
                os.path.join(src, "this_target_does_not_exist"),
                os.path.join(src, "backups")
            )

            dest = _materialize_host_visible_copy(src, "centinela-pytest-symlink-test")
            try:
                self.assertTrue(os.path.isfile(os.path.join(dest, "real_file.py")))
                self.assertTrue(os.path.islink(os.path.join(dest, "backups")))
            finally:
                shutil.rmtree(dest, ignore_errors=True)
        finally:
            shutil.rmtree(src, ignore_errors=True)


def _sonar_reachable() -> bool:
    try:
        return requests.get(f"{SONAR_HOST_URL}/api/system/status", timeout=3).status_code == 200
    except Exception:
        return False


@unittest.skipUnless(
    _sonar_reachable(),
    f"SonarQube not reachable at {SONAR_HOST_URL} -- skipping live integration test"
)
class TestSonarQubeLiveIntegration(unittest.TestCase):
    """
    Real end-to-end test: clones a temp dir with a real Python file containing a known
    SonarQube-detectable issue, runs a real scan, and verifies a real row landed in
    vulnerability_log via a real SELECT -- same shape as
    test_auditor_iac_k8s.py's test_run_iac_scan_persists_findings. Skipped (never mocked
    as if it ran) if no live SonarQube server is reachable.
    """

    def test_run_sonarqube_audit_persists_real_row(self):
        tmpdir = tempfile.mkdtemp(prefix="centinela_sonar_test_")
        try:
            with open(os.path.join(tmpdir, "vulnerable.py"), "w") as f:
                f.write(
                    "import os\n\n"
                    "def run_command(user_input):\n"
                    "    os.system(user_input)  # deliberately unsafe for test detection\n"
                )
            issues = run_sonarqube_audit(
                tmpdir, asset_id=None, project_key="centinela-pytest-throwaway",
                repo_display_name="centinela-pytest-throwaway"
            )
            self.assertIsInstance(issues, list)

            with get_db_cursor() as cur:
                cur.execute(
                    "SELECT id FROM vulnerability_log "
                    "WHERE scan_engine='sonarqube' AND cve_id='SONARQUBE-QUALITY-GATE' "
                    "AND asset_id IS NULL ORDER BY id DESC LIMIT 1"
                )
                self.assertIsNotNone(cur.fetchone(), "Expected a SONARQUBE-QUALITY-GATE marker row")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
