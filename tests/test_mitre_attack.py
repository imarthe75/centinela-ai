"""
Unit tests for MITRE ATT&CK mapping, including the SonarQube rule-number mapping added
alongside auditors/auditor_sonarqube.py.
"""
import unittest

from core.mitre_attack import map_finding


class TestMitreAttackExistingMappings(unittest.TestCase):
    def test_cmd_injection_maps(self):
        self.assertEqual(map_finding("CMD-INJECTION-SHELL-TRUE", ""), ("T1059", "Command and Scripting Interpreter", "Execution"))

    def test_zap_header_maps(self):
        result = map_finding("ZAP-10038", "x-powered-by header exposed")
        self.assertEqual(result[0], "T1592.002")

    def test_scan_audit_unmapped(self):
        self.assertIsNone(map_finding("SCAN-AUDIT", "no se detectaron vulnerabilidades"))

    def test_heuristic_security_debt_unmapped(self):
        self.assertIsNone(map_finding("HEURISTIC-SECURITY-DEBT", "resumen agregado"))


class TestMitreAttackSonarQube(unittest.TestCase):
    VULN_DESC = "**SonarQube VULNERABILITY** ({rule})\n{message}"
    CODE_SMELL_DESC = "**SonarQube CODE_SMELL** ({rule})\n{message}"

    def test_insecure_http_maps_to_aitm(self):
        desc = self.VULN_DESC.format(rule="python:S5332", message="Using HTTP protocol is insecure.")
        self.assertEqual(map_finding("SONAR-python-S5332", desc), ("T1557", "Adversary-in-the-Middle", "Collection"))

    def test_cert_validation_disabled_maps_to_aitm(self):
        desc = self.VULN_DESC.format(rule="java:S4830", message="Enable server certificate validation.")
        self.assertEqual(map_finding("SONAR-java-S4830", desc)[0], "T1557")

    def test_hostname_verification_disabled_maps_to_aitm(self):
        desc = self.VULN_DESC.format(rule="python:S5527", message="Enable server hostname verification.")
        self.assertEqual(map_finding("SONAR-python-S5527", desc)[0], "T1557")

    def test_hardcoded_secret_variants_map_to_credential_access(self):
        for rule_key, safe_key in [("java:S6437", "SONAR-java-S6437"),
                                    ("typescript:S6418", "SONAR-typescript-S6418"),
                                    ("python:S2068", "SONAR-python-S2068"),
                                    ("secrets:S6698", "SONAR-secrets-S6698")]:
            desc = self.VULN_DESC.format(rule=rule_key, message="hard-coded credential")
            with self.subTest(rule=rule_key):
                self.assertEqual(map_finding(safe_key, desc), ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"))

    def test_docker_recursive_copy_maps_to_credential_access(self):
        desc = self.VULN_DESC.format(rule="docker:S6470", message="Copying recursively might add sensitive data.")
        self.assertEqual(map_finding("SONAR-docker-S6470", desc)[0], "T1552.001")

    def test_docker_root_user_maps_to_escape_to_host(self):
        desc = self.VULN_DESC.format(rule="docker:S6471", message="runs with root as the default user.")
        self.assertEqual(map_finding("SONAR-docker-S6471", desc), ("T1611", "Escape to Host", "Privilege Escalation"))

    def test_autoescape_disabled_maps_to_drive_by(self):
        desc = self.VULN_DESC.format(rule="python:S5247", message="disabling auto-escaping feature")
        self.assertEqual(map_finding("SONAR-python-S5247", desc)[0], "T1189")

    def test_angular_sanitization_disabled_maps_to_drive_by(self):
        desc = self.VULN_DESC.format(rule="typescript:S6268", message="disabling Angular built-in sanitization")
        self.assertEqual(map_finding("SONAR-typescript-S6268", desc)[0], "T1189")

    def test_version_disclosure_maps_to_recon(self):
        desc = self.VULN_DESC.format(rule="javascript:S5689", message="implicitly discloses version information")
        self.assertEqual(map_finding("SONAR-javascript-S5689", desc)[0], "T1592.002")

    def test_bind_all_interfaces_maps_to_exploit_public_facing(self):
        desc = self.VULN_DESC.format(rule="python:S8392", message="Avoid binding the application to all network interfaces.")
        self.assertEqual(map_finding("SONAR-python-S8392", desc)[0], "T1190")

    def test_code_smell_never_mapped_even_for_known_rule_number(self):
        # Same rule number as a real vulnerability mapping (S6471), but type=CODE_SMELL --
        # must NOT map, since CODE_SMELL isn't attacker-technique-shaped.
        desc = self.CODE_SMELL_DESC.format(rule="docker:S6471", message="cosmetic issue")
        self.assertIsNone(map_finding("SONAR-docker-S6471", desc))

    def test_unmapped_rule_number_returns_none(self):
        # S2245 (weak PRNG) is deliberately excluded -- no clean ATT&CK technique fit.
        desc = self.VULN_DESC.format(rule="python:S2245", message="pseudorandom number generator")
        self.assertIsNone(map_finding("SONAR-python-S2245", desc))

    def test_quality_gate_marker_never_mapped(self):
        self.assertIsNone(map_finding("SONARQUBE-QUALITY-GATE", "Auditoría SonarQube completada. Quality Gate: OK"))


if __name__ == "__main__":
    unittest.main()
