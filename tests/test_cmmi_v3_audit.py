"""
Unit test for CMMI V3.0 Level 5 Auditor.
"""
import unittest
from auditors.auditor_cmmi_v3 import audit_cmmi_v3_level5

class TestCMMIV3Audit(unittest.TestCase):
    def test_cmmi_swallowed_exception(self):
        content = "try:\n    do_something()\nexcept:\n    pass\n"
        findings = audit_cmmi_v3_level5("service.py", content)
        self.assertTrue(any(f["cve_id"] == "CMMI-CAR-SWALLOWED-EXCEPTION" for f in findings))

    def test_cmmi_hardcoded_sleep(self):
        content = "import time\ntime.sleep(10)\n"
        findings = audit_cmmi_v3_level5("worker.py", content)
        self.assertTrue(any(f["cve_id"] == "CMMI-MSR-HARDCODED-SLEEP" for f in findings))

if __name__ == "__main__":
    unittest.main()
