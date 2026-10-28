"""A REOPENED finding (resolved, then detected again) is an OPEN finding. The CMMI/ISO and stats queries used to
filter `status IN ('OPEN','NEW','CORRELATED')`, which silently dropped reopened findings from every compliance
score -- inflating compliance for exactly the assets where a fixed problem came back."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestOpenFindingsDefinition(unittest.TestCase):
    def test_no_query_defines_open_without_reopened(self):
        offenders = []
        for rel in ("auditors/compliance_mapper.py", "main.py"):
            for n, line in enumerate((ROOT / rel).read_text().splitlines(), 1):
                if re.search(r"status IN \('OPEN', 'NEW', 'CORRELATED'\)", line):
                    offenders.append(f"{rel}:{n}")
        self.assertEqual(offenders, [], "these queries drop REOPENED findings: " + ", ".join(offenders))

    def test_reopened_vuln_counts_against_iso_control(self):
        from auditors.compliance_mapper import compute_iso_control_coverage
        clean = compute_iso_control_coverage([])
        with_reopened = compute_iso_control_coverage([{"cve_id": "HARDCODED-SECRET", "description": "x"}])
        self.assertGreater(clean["score"], with_reopened["score"])


if __name__ == "__main__":
    unittest.main()
