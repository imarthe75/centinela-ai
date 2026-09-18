import unittest
from core import soar_engine

class TestSOAREngine(unittest.TestCase):
    def test_host_isolate_requires_manual_approval(self):
        res = soar_engine.evaluate_and_execute_response("host_isolate", "casmarts-server-01", "192.168.1.50", "admin", 0.99)
        self.assertEqual(res["mode"], "MANUAL_APPROVAL_REQUIRED")
        self.assertFalse(res["executed"])

    def test_dry_run_mode(self):
        res = soar_engine.evaluate_and_execute_response("proxy_ip_block", "sideco-app", "203.0.113.5", "unknown", 0.99, cti_hit=True)
        self.assertIn(res["mode"], ("DRY_RUN", "MANUAL_APPROVAL_REQUIRED"))
        self.assertFalse(res["executed"])

if __name__ == "__main__":
    unittest.main()
