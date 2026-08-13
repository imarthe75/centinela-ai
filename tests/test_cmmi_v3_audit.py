"""
Unit test for CMMI V3.0 Level 5 Auditor.
"""
import os
import tempfile
import unittest
from auditors.auditor_cmmi_v3 import audit_cmmi_v3_level5, run_cmmi_audit
from core.db_manager import get_db_cursor

class TestCMMIV3Audit(unittest.TestCase):
    def test_cmmi_swallowed_exception(self):
        content = "try:\n    do_something()\nexcept:\n    pass\n"
        findings = audit_cmmi_v3_level5("service.py", content)
        self.assertTrue(any(f["cve_id"] == "CMMI-CAR-SWALLOWED-EXCEPTION" for f in findings))

    def test_cmmi_hardcoded_sleep(self):
        content = "import time\ntime.sleep(10)\n"
        findings = audit_cmmi_v3_level5("worker.py", content)
        self.assertTrue(any(f["cve_id"] == "CMMI-MSR-HARDCODED-SLEEP" for f in findings))

    def test_run_cmmi_audit_persists_with_asset_id_and_url_path(self):
        """
        Regression test for the real bug behind the "CMMI v3.0 per-asset" report being blind to
        its own engine's data: run_cmmi_audit() used to INSERT with no asset_id/url_path at all
        (confirmed live: 13,715/13,715 orphaned rows), so compliance_mapper's per-asset query
        (asset_id = %s OR url_path ILIKE %s) could never join a single one of them.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "service.py"), "w") as f:
                f.write("try:\n    do_something()\nexcept:\n    pass\n")
            try:
                findings = run_cmmi_audit(tmpdir, asset_id=None)
                self.assertTrue(len(findings) >= 1)
                with get_db_cursor() as cur:
                    cur.execute(
                        "SELECT asset_id, url_path, fingerprint_hash FROM vulnerability_log "
                        "WHERE scan_engine='cmmi-audit' AND cve_id='CMMI-CAR-SWALLOWED-EXCEPTION' "
                        "AND url_path = 'service.py:3'"
                    )
                    row = cur.fetchone()
                self.assertIsNotNone(row, "finding was not persisted with the expected url_path")
                self.assertIsNotNone(row[2], "fingerprint_hash must be populated for real dedup")
            finally:
                with get_db_cursor() as cur:
                    cur.execute(
                        "DELETE FROM vulnerability_log WHERE scan_engine='cmmi-audit' AND url_path='service.py:3'"
                    )

if __name__ == "__main__":
    unittest.main()
