"""
Unit test for the native IaC (Kubernetes/Terraform) auditor.
"""
import os
import tempfile
import unittest
from auditors.auditor_iac_k8s import audit_kubernetes_yaml, audit_terraform_tf, run_iac_scan
from core.db_manager import get_db_cursor

class TestIaCK8sAudit(unittest.TestCase):
    def test_k8s_privileged_container_detected(self):
        content = "apiVersion: v1\nkind: Pod\nspec:\n  privileged: true\n"
        findings = audit_kubernetes_yaml("pod.yaml", content)
        self.assertTrue(any(f["cve_id"] == "K8S-PRIVILEGED-CONTAINER" for f in findings))

    def test_terraform_open_security_group_detected(self):
        content = 'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        findings = audit_terraform_tf("main.tf", content)
        self.assertTrue(any(f["cve_id"] == "TF-OPEN-SECURITY-GROUP" for f in findings))

    def test_run_iac_scan_persists_findings(self):
        """
        Regression test for a real bug: run_iac_scan() detected real K8s/Terraform
        misconfigurations but never wrote a single one to vulnerability_log (no INSERT
        anywhere in the function) -- confirmed live: 0 K8S-*/TF-* rows in the DB despite the
        auditor running on every GitLab-Integrator cycle. This exercises the real persistence
        path end-to-end.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "deploy.yaml"), "w") as f:
                f.write("apiVersion: v1\nkind: Pod\nspec:\n  privileged: true\n")
            try:
                findings = run_iac_scan(tmpdir, asset_id=None)
                self.assertTrue(len(findings) >= 1)
                with get_db_cursor() as cur:
                    cur.execute(
                        "SELECT url_path, fingerprint_hash FROM vulnerability_log "
                        "WHERE scan_engine='iac-native' AND cve_id='K8S-PRIVILEGED-CONTAINER' "
                        "AND url_path = 'deploy.yaml:4'"
                    )
                    row = cur.fetchone()
                self.assertIsNotNone(row, "finding was not persisted")
                self.assertIsNotNone(row[1], "fingerprint_hash must be populated for real dedup")
            finally:
                with get_db_cursor() as cur:
                    cur.execute(
                        "DELETE FROM vulnerability_log WHERE scan_engine='iac-native' AND url_path='deploy.yaml:4'"
                    )

if __name__ == "__main__":
    unittest.main()
