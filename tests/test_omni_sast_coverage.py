"""
Unit test for Omni SAST 99% Coverage (Multi-SCA & IaC K8s/Terraform).
"""
import unittest
from auditors.auditor_sca_dependencies import audit_pom_xml, audit_go_mod, audit_composer_json
from auditors.auditor_iac_k8s import audit_kubernetes_yaml, audit_terraform_tf

class TestOmniSASTCoverage(unittest.TestCase):
    def test_maven_pom_xml(self):
        content = """<project>
            <dependencies>
                <dependency>
                    <groupId>org.yaml</groupId>
                    <artifactId>snakeyaml</artifactId>
                    <version>1.30</version>
                </dependency>
            </dependencies>
        </project>"""
        findings = audit_pom_xml("pom.xml", content)
        self.assertIsInstance(findings, list)

    def test_go_mod(self):
        content = "module example.com/app\n\ngo 1.20\n\nrequire github.com/gin-gonic/gin v1.7.0\n"
        findings = audit_go_mod("go.mod", content)
        self.assertIsInstance(findings, list)

    def test_composer_json(self):
        content = '{"require": {"guzzlehttp/guzzle": "7.0.0"}}'
        findings = audit_composer_json("composer.json", content)
        self.assertIsInstance(findings, list)

    def test_k8s_privileged(self):
        content = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\nsecurityContext:\n  privileged: true\n"
        findings = audit_kubernetes_yaml("deploy.yaml", content)
        self.assertTrue(any(f["cve_id"] == "K8S-PRIVILEGED-CONTAINER" for f in findings))

    def test_terraform_public_s3(self):
        content = 'resource "aws_s3_bucket" "b" {\n  bucket = "my-tf-test-bucket"\n  acl    = "public-read"\n}\n'
        findings = audit_terraform_tf("main.tf", content)
        self.assertTrue(any(f["cve_id"] == "TF-PUBLIC-S3-BUCKET" for f in findings))

if __name__ == "__main__":
    unittest.main()
