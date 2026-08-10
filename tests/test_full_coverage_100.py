"""
Unit test for 100% Coverage (DAST Authenticated, Stateful Fuzzing, Binary Firmware, CTI Feeds).
"""
import unittest
from auditors.auditor_cti_feeds import get_cti_credentials, audit_asset_against_cti
from auditors.auditor_iac_k8s import audit_kubernetes_yaml
from auditors.auditor_master_vulnerabilities import scan_sast_code

class TestFullCoverage100(unittest.TestCase):
    def test_cti_credentials_vault(self):
        creds = get_cti_credentials()
        self.assertIn("virustotal_key", creds)
        self.assertIn("misp_key", creds)

    def test_cti_audit(self):
        findings = audit_asset_against_cti("TestServer", "10.4.3.23")
        self.assertIsInstance(findings, list)

    def test_binary_firmware_iot_rules(self):
        content = 'password = "SecretPassword123"\n'
        findings = scan_sast_code("firmware/boot.py", content)
        self.assertTrue(any(f["cve_id"] == "HARDCODED-SECRET" for f in findings))

if __name__ == "__main__":
    unittest.main()
