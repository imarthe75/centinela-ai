"""
Unit tests for SAST Master Vulnerabilities Scanner (auditor_master_vulnerabilities.py).
Validates:
- HTML template scanning support (Bug 1.1)
- Multiline ORM N+1 query detection (Bug 1.2)
- Insecure Deserialization (CWE-502)
- Path Traversal (CWE-22)
- CSRF Protection Disabled (CWE-352 / CWE-693)
- Extended Hardcoded Secrets (CWE-798: GCP, Vault, Stripe, GitHub, GitLab, Slack, AWS)
- Weak Cryptography (CWE-327: MD5, SHA1, DES, AES/ECB)
- XML External Entity (XXE) Injection (CWE-611)
- Zero False Positives on Self-Audit
"""
import os
import textwrap
import unittest
from auditors.auditor_master_vulnerabilities import scan_sast_code, run_master_vulnerability_scan


class TestSASTMasterVulnerabilities(unittest.TestCase):

    def test_html_template_scanning(self):
        """Bug 1.1: .html files must be analyzed for frontend rules."""
        html_content = textwrap.dedent("""
        <!DOCTYPE html>
        <html>
        <body>
            <button class="btn btn-primary"></button>
            <div [innerHTML]="untrustedHtml"></div>
        </body>
        </html>
        """)
        findings = scan_sast_code("templates/login.component.html", html_content)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("ACCESSIBILITY-WCAG-MISSING-LABEL", rule_ids)
        self.assertIn("ANGULAR-BYPASS-SECURITY-TRUST", rule_ids)

    def test_html_file_dispatch_in_run_master_vulnerability_scan(self):
        """Bug 1.1: run_master_vulnerability_scan must dispatch .html files."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            html_file = os.path.join(tmpdir, "template.html")
            with open(html_file, "w", encoding="utf-8") as f:
                f.write('<button class="btn"></button>')
            findings = run_master_vulnerability_scan(target_dir=tmpdir, asset_id=None)
            rule_ids = [f["cve_id"] for f in findings]
            self.assertIn("ACCESSIBILITY-WCAG-MISSING-LABEL", rule_ids)

    def test_multiline_orm_n_plus_one(self):
        """Bug 1.2: ORM N+1 query loop across multiple lines must be detected with correct line number."""
        code = textwrap.dedent("""
        # Fetch users
        for user in User.objects.all():
            user.address.street
        """)
        findings = scan_sast_code("services/user_service.py", code)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("ORM-N-PLUS-ONE-QUERY", rule_ids)
        finding = next(f for f in findings if f["cve_id"] == "ORM-N-PLUS-ONE-QUERY")
        self.assertEqual(finding["line"], 3)

    def test_insecure_deserialization_pickle_and_marshal(self):
        """2.1: Python pickle and marshal deserialization."""
        code = textwrap.dedent("""
        import pickle
        import marshal
        data = pickle.loads(user_payload)
        obj = marshal.loads(raw_blob)
        """)
        findings = scan_sast_code("workers/tasks.py", code)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("INSECURE-DESERIALIZATION-PICKLE", rule_ids)
        self.assertIn("INSECURE-DESERIALIZATION-MARSHAL", rule_ids)

    def test_insecure_deserialization_yaml_and_node(self):
        """2.1: YAML unsafe load and Node.js serialize."""
        py_code = textwrap.dedent("""
        import yaml
        config = yaml.load(raw_yaml)
        unsafe_cfg = yaml.unsafe_load(raw_yaml)
        """)
        py_findings = scan_sast_code("config/parser.py", py_code)
        py_rules = [f["cve_id"] for f in py_findings]
        self.assertIn("INSECURE-DESERIALIZATION-YAML", py_rules)

        js_code = """
        const serialize = require('node-serialize');
        const obj = serialize.unserialize(req.body.data);
        """
        js_findings = scan_sast_code("server/routes.js", js_code)
        js_rules = [f["cve_id"] for f in js_findings]
        self.assertIn("INSECURE-DESERIALIZATION-NODE", js_rules)

    def test_path_traversal_python_java_node(self):
        """2.2: Path traversal across Python, Java, and Node.js."""
        py_code = 'with open(request.args.get("filename"), "r") as f: data = f.read()'
        py_findings = scan_sast_code("views.py", py_code)
        self.assertTrue(any(f["cve_id"] == "PATH-TRAVERSAL-UNSANITIZED" for f in py_findings))

        java_code = 'FileInputStream fis = new FileInputStream(request.getParameter("path"));'
        java_findings = scan_sast_code("FileHandler.java", java_code)
        self.assertTrue(any(f["cve_id"] == "PATH-TRAVERSAL-UNSANITIZED" for f in java_findings))

        js_code = 'fs.readFile(req.query.file, (err, data) => {});'
        js_findings = scan_sast_code("handler.js", js_code)
        self.assertTrue(any(f["cve_id"] == "PATH-TRAVERSAL-UNSANITIZED" for f in js_findings))

    def test_csrf_disabled_spring_and_express(self):
        """2.3: CSRF disabled in Spring Security and CSP disabled in Helmet."""
        spring_code1 = 'http.csrf().disable();'
        findings1 = scan_sast_code("SecurityConfig.java", spring_code1)
        self.assertTrue(any(f["cve_id"] == "SPRING-CSRF-DISABLED" for f in findings1))

        spring_code2 = 'http.csrf(csrf -> csrf.disable());'
        findings2 = scan_sast_code("WebSecurity.java", spring_code2)
        self.assertTrue(any(f["cve_id"] == "SPRING-CSRF-DISABLED" for f in findings2))

        express_code = 'app.use(helmet({ contentSecurityPolicy: false }));'
        findings3 = scan_sast_code("app.js", express_code)
        self.assertTrue(any(f["cve_id"] == "EXPRESS-CSP-DISABLED" for f in findings3))

    def test_extended_hardcoded_secrets(self):
        """2.4: Extended secrets patterns parity (GCP, Vault, Stripe, GitHub, GitLab, Slack, AWS)."""
        # Synthetic tokens constructed via concatenation to prevent GitHub push protection false positives
        stripe_tok = "sk_live_" + "51Abcdefghijklmnopqrstuvwx"
        gh_tok = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
        gl_tok = "glpat-" + "abcdefghijklmnopqrst12"
        slack_tok = "xoxb-" + "123456789012-123456789012-abcdefghijklmnopqrstuvwx"
        vault_tok = "hvs." + "CAESIJ1234567890abcdefghijklm"
        secrets_fixture = f'''
        aws_id = "AKIAIOSFODNN7EXAMPLE"
        stripe = "{stripe_tok}"
        gh_pat = "{gh_tok}"
        gl_pat = "{gl_tok}"
        slack = "{slack_tok}"
        vault = "{vault_tok}"
        gcp = {{"type": "service_account", "project_id": "prod-sec"}}
        '''
        findings = scan_sast_code("config/credentials.py", secrets_fixture)
        rule_ids = [f["cve_id"] for f in findings]
        self.assertIn("HARDCODED-SECRET-AWS-KEY", rule_ids)
        self.assertIn("HARDCODED-SECRET-STRIPE", rule_ids)
        self.assertIn("HARDCODED-SECRET-GITHUB", rule_ids)
        self.assertIn("HARDCODED-SECRET-GITLAB", rule_ids)
        self.assertIn("HARDCODED-SECRET-SLACK", rule_ids)
        self.assertIn("HARDCODED-SECRET-VAULT", rule_ids)
        self.assertIn("HARDCODED-SECRET-GCP-KEY", rule_ids)

    def test_weak_cryptography(self):
        """2.5: Weak or obsolete cryptographic algorithms."""
        py_code = textwrap.dedent("""
        import hashlib
        h1 = hashlib.md5(b"test").hexdigest()
        h2 = hashlib.sha1(b"test").hexdigest()
        """)
        findings_py = scan_sast_code("auth/hash.py", py_code)
        rule_ids_py = [f["cve_id"] for f in findings_py]
        self.assertIn("WEAK-CRYPTO-HASH", rule_ids_py)

        java_code = """
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher cipher2 = Cipher.getInstance("DES");
        MessageDigest md = MessageDigest.getInstance("MD5");
        """
        findings_java = scan_sast_code("CryptoService.java", java_code)
        rule_ids_java = [f["cve_id"] for f in findings_java]
        self.assertIn("WEAK-CRYPTO-CIPHER", rule_ids_java)
        self.assertIn("WEAK-CRYPTO-HASH", rule_ids_java)

        js_code = 'const hash = crypto.createHash("md5").update(data).digest("hex");'
        findings_js = scan_sast_code("utils/crypto.js", js_code)
        self.assertTrue(any(f["cve_id"] == "WEAK-CRYPTO-HASH" for f in findings_js))

    def test_xxe_parsers(self):
        """2.6: XXE vulnerability detection."""
        py_code = textwrap.dedent("""
        import xml.etree.ElementTree as ET
        tree = ET.parse("user_input.xml")
        """)
        findings_py = scan_sast_code("parser.py", py_code)
        self.assertTrue(any(f["cve_id"] == "XXE-INSECURE-PARSER" for f in findings_py))

        java_code = """
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        """
        findings_java = scan_sast_code("XmlReader.java", java_code)
        self.assertTrue(any(f["cve_id"] == "XXE-JAVA-XML-PARSER" for f in findings_java))

    def test_zero_false_positives_on_scanner_self_audit(self):
        """Self-audit check: scanner source code itself must produce 0 SAST findings."""
        scanner_file = os.path.abspath("auditors/auditor_master_vulnerabilities.py")
        with open(scanner_file, "r", encoding="utf-8") as f:
            content = f.read()

        findings = scan_sast_code(scanner_file, content)
        self.assertEqual(
            findings, [],
            f"Self-audit detected {len(findings)} false positive finding(s): {findings}"
        )


if __name__ == "__main__":
    unittest.main()
