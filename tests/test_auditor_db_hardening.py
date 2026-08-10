"""
Unit test for DB Hardening Auditor module using standard unittest.
"""
import unittest
from auditors.auditor_db_hardening import check_db_tls

class TestDBHardening(unittest.TestCase):
    def test_check_db_tls_non_existent(self):
        res = check_db_tls("127.0.0.1", 59999)
        self.assertFalse(res["tls_active"])
        self.assertIsNone(res["version"])

if __name__ == "__main__":
    unittest.main()
