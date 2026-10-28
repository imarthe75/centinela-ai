"""ADR-0012 D10: VALIDATION-REIMPLEMENTED (hand-written RFC/CURP patterns outside the institutional catalogue)."""
import unittest

from auditors.auditor_master_vulnerabilities import scan_coverage_rules
from core import deduplication_engine as de

CURP_TS = 'const CURP_RE = /^[A-Z]{4}\\d{6}[HM][A-Z]{5}[A-Z0-9]\\d$/;\n'
RFC_JAVA = 'private static final Pattern RFC = Pattern.compile("^[A-ZÑ&]{3,4}[0-9]{6}[A-Z0-9]{3}$");\n'


def rules(path, content):
    return [f for f in scan_coverage_rules(path, content) if f["cve_id"] == "VALIDATION-REIMPLEMENTED"]


class TestRule(unittest.TestCase):
    def test_curp_and_rfc_patterns_are_found_with_their_line(self):
        r = rules("src/app/forms/curp.ts", "// x\n" + CURP_TS)
        self.assertEqual([(f["line"], "CURP" in f["description"]) for f in r], [(2, True)])
        r = rules("src/main/java/Rfc.java", RFC_JAVA)
        self.assertEqual(len(r), 1)
        self.assertIn("RFC", r[0]["description"])

    def test_tests_vendored_and_other_languages_are_skipped(self):
        self.assertEqual(rules("src/app/curp.spec.ts", CURP_TS), [])
        self.assertEqual(rules("src/test/java/RfcTest.java", RFC_JAVA), [])
        self.assertEqual(rules("tests/test_curp.py", CURP_TS), [])
        self.assertEqual(rules("src/assets/plugins/x.js", CURP_TS), [])
        self.assertEqual(rules("README.md", CURP_TS), [])

    def test_unrelated_regexes_do_not_match(self):
        for line in ['const Z = /^[A-Z]{2}\\d{4}$/;', 'const P = /^[A-Z]{4}-\\d{3}$/;', 'x = "[A-Z]{4}"']:
            self.assertEqual(rules("a.ts", line + "\n"), [], line)

    def test_it_is_informational_not_a_vulnerability(self):
        self.assertEqual(de.classify_finding_category("VALIDATION-REIMPLEMENTED", "sast-native", ""), "INFORMATIONAL")


if __name__ == "__main__":
    unittest.main()
