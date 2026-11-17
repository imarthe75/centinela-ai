"""HARDCODED-SECRET in any naming style (jwtSecret, CLIENT_SECRET, @Value defaults, vendor live keys), with the false positives
measured on the fleet kept out (property names, template names, routes, prose), and the secret value never written to a finding."""
import unittest

from auditors.auditor_master_vulnerabilities import mask_secret_values, scan_sast_code, secret_literal_in_line

# Synthetic values built at runtime so this file itself carries no credential-looking literal.
VAL = "Zk" + "9" * 3 + "qWp2" + "x7Lm4Rt8"


class TestDetects(unittest.TestCase):
    def test_camel_case_and_constant_names(self):
        for line in (f'    private String jwtSecret = "{VAL}";', f'    static final String CLIENT_SECRET = "{VAL}";',
                     f"  apiKey: '{VAL}',", f'DB_PASSWORD = "{VAL}"', f'    String dsPasswd = "{VAL}";'):
            self.assertTrue(secret_literal_in_line(line), line)

    def test_spring_value_default_and_vendor_live_key(self):
        self.assertTrue(secret_literal_in_line('@Value("${modulo-a.api-key:' + VAL + '}")'))
        self.assertTrue(secret_literal_in_line('return k != null ? k : "fol_live_' + VAL + VAL + '";'))


class TestIgnores(unittest.TestCase):
    def test_names_routes_placeholders_and_prose(self):
        for line in ('public static final String PARAMETRO_MAIL_PASSWORD = "mail.password.recovery";',
                     'String TEMPLATE_UPDATE_PASSWORD = "TEMPLATE_UPDATE_PASSWORD";',
                     'private static final String PATH_API_KEY = "/api/v1/sistemas/{id}/llaves";',
                     'password: "${DB_PASSWORD}"', 'apiKey: process.env.MAPS_KEY',
                     'String password = "La contraseña no es valida";', 'password = ""'):
            self.assertFalse(secret_literal_in_line(line), line)


class TestFindingNeverCarriesTheValue(unittest.TestCase):
    def test_masked_in_description(self):
        src = f'public class C {{\n    private String jwtSecret = "{VAL}";\n}}\n'
        hits = [f for f in scan_sast_code("src/main/java/C.java", src) if f["cve_id"] == "HARDCODED-SECRET"]
        self.assertEqual(len(hits), 1)
        self.assertNotIn(VAL, hits[0]["description"])
        self.assertIn("jwtSecret", hits[0]["description"])

    def test_old_pattern_is_masked_too(self):
        self.assertNotIn(VAL, mask_secret_values(f'api_key = "{VAL}"'))


if __name__ == "__main__":
    unittest.main()
