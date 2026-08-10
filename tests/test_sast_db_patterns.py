"""
Unit test for SAST Backend & Frontend Security rules (React, Angular, Spring Boot, Python N+1).
"""
import unittest
from auditors.auditor_master_vulnerabilities import scan_sast_code

class TestSASTDBPatterns(unittest.TestCase):
    def test_orm_raw_query_injection(self):
        code = "user = User.objects.raw(f'SELECT * FROM users WHERE id = {user_input}')"
        findings = scan_sast_code("backend/models.py", code)
        self.assertTrue(any(f["cve_id"] == "ORM-RAW-QUERY-INJECTION" for f in findings))

    def test_frontend_exposed_db_credential(self):
        code = "const dbUrl = process.env.VITE_DB_URL || 'postgres://admin:pass@localhost:5432/mydb';"
        findings = scan_sast_code("frontend/src/config.js", code)
        self.assertTrue(any(f["cve_id"] == "FRONTEND-EXPOSED-DB-CREDENTIAL" for f in findings))

    def test_frontend_jwt_localstorage(self):
        code = "localStorage.setItem('auth_token', response.data.token);"
        findings = scan_sast_code("frontend/src/auth.ts", code)
        self.assertTrue(any(f["cve_id"] == "FRONTEND-JWT-LOCALSTORAGE" for f in findings))

    def test_react_dangerously_set_inner_html(self):
        code = "<div dangerouslySetInnerHTML={{ __html: userComment }} />"
        findings = scan_sast_code("frontend/src/Component.jsx", code)
        self.assertTrue(any(f["cve_id"] == "REACT-DANGEROUSLY-SET-INNER-HTML" for f in findings))

    def test_angular_bypass_security(self):
        code = "this.sanitizer.bypassSecurityTrustHtml(userProvidedHtml);"
        findings = scan_sast_code("frontend/src/app.component.ts", code)
        self.assertTrue(any(f["cve_id"] == "ANGULAR-BYPASS-SECURITY-TRUST" for f in findings))

    def test_springboot_native_query(self):
        code = '@Query(value = "SELECT * FROM users WHERE email = " + email, nativeQuery = true)'
        findings = scan_sast_code("backend/UserRepository.java", code)
        self.assertTrue(any(f["cve_id"] == "SPRINGBOOT-NATIVE-QUERY-RISK" for f in findings))

if __name__ == "__main__":
    unittest.main()
