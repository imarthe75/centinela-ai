import unittest
from auditors.auditor_master_vulnerabilities import scan_sast_code

class TestSASTModuleFindings(unittest.TestCase):

    def test_backdoor_controller_detection(self):
        content = """
        @RestController
        public class LocalAuthController {
            public String loginBackdoor() { return "bypass"; }
        }
        """
        findings = scan_sast_code("LocalAuthController.java", content)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("BACKDOOR-SANDBOX-CONTROLLER", rule_ids)

    def test_jvm_ssl_bypass_detection(self):
        content = """
        public class TrustAllManager implements X509TrustManager {
            public void checkClientTrusted() {}
        }
        """
        findings = scan_sast_code("TrustAllManager.java", content)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("JVM-GLOBAL-SSL-BYPASS", rule_ids)

    def test_jwt_in_url_param_detection(self):
        content = """
        @GetMapping("/download")
        public ResponseEntity<byte[]> downloadFile(@RequestParam("token") String token) {
            return null;
        }
        """
        findings = scan_sast_code("FileController.java", content)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("JWT-IN-URL-PARAM", rule_ids)

    def test_redis_jdk_serialization_detection(self):
        content = """
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        """
        findings = scan_sast_code("RedisConfig.java", content)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("REDIS-JDK-SERIALIZATION", rule_ids)

    def test_oom_byte_array_streaming_detection(self):
        content = """
        byte[] content = Files.readAllBytes(path);
        """
        findings = scan_sast_code("DocumentService.java", content)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("OOM-BYTE-ARRAY-STREAMING", rule_ids)

    def test_angular_bypass_security_trust(self):
        content = """
        this.sanitizer.bypassSecurityTrustHtml(unsafeContent);
        """
        findings = scan_sast_code("component.ts", content)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("ANGULAR-BYPASS-SECURITY-TRUST", rule_ids)

if __name__ == "__main__":
    unittest.main()
