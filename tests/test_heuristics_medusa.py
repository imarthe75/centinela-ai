"""
Integration test for the Heuristics Engine's temporal correlation (Rule 1: Control Plane
Intrusion -- an exposed-port finding + a suspicious runtime shell alert on the same asset within
the correlation window should produce a consolidated HEURISTIC-CONTROL-PLANE-INTRUSION alert).

Was previously a standalone __main__ script (never discovered by pytest -- 0 items collected, no
def test_*/class Test*), so this real integration test has silently never run as part of this
project's mandated pytest validation. Logic preserved, wrapped as a real pytest test.
"""
import unittest
from core import db_manager
from core import heuristics_engine
from auditors import auditor_medusa

class TestHeuristicsControlPlaneIntrusion(unittest.TestCase):
    TEST_ASSET_ID = 99999

    def setUp(self):
        with db_manager.get_db_cursor() as cur:
            cur.execute("DELETE FROM vulnerability_log WHERE asset_id = %s", (self.TEST_ASSET_ID,))
            cur.execute("DELETE FROM runtime_alerts WHERE asset_id = %s", (self.TEST_ASSET_ID,))
            cur.execute("DELETE FROM infra_inventory WHERE id = %s", (self.TEST_ASSET_ID,))
            cur.execute("""
                INSERT INTO infra_inventory (id, asset_name, asset_type, endpoint, criticality, last_audit, status)
                VALUES (%s, 'Test-Heuristic-Asset', 'IP', '127.0.0.1', 'High', NOW(), 'monitored')
            """, (self.TEST_ASSET_ID,))

    def tearDown(self):
        with db_manager.get_db_cursor() as cur:
            cur.execute("DELETE FROM vulnerability_log WHERE asset_id = %s", (self.TEST_ASSET_ID,))
            cur.execute("DELETE FROM runtime_alerts WHERE asset_id = %s", (self.TEST_ASSET_ID,))
            cur.execute("DELETE FROM infra_inventory WHERE id = %s", (self.TEST_ASSET_ID,))

    def test_exposed_port_plus_runtime_shell_alert_triggers_control_plane_intrusion(self):
        # 1. Exposed-port finding (Nmap-style)
        auditor_medusa.log_vulnerability(
            asset_id=self.TEST_ASSET_ID, cve_id="NMAP-SCAN", severity="MEDIUM",
            description="Test Nmap finding: Exposed Docker API Port 2375"
        )

        # 2. Suspicious runtime shell alert (Falco-style)
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields, detected_at)
                VALUES (%s, 'CRITICAL', 'Run shell in container', 'Interactive terminal session opened inside container test-container', '{"container.name": "test-container"}', NOW())
            """, (self.TEST_ASSET_ID,))

        # 3. Run the temporal correlation engine
        heuristics_engine.run_heuristics_correlation(minutes=5)

        # 4. Assert the consolidated alert was generated
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                SELECT cve_id, severity, status FROM vulnerability_log
                WHERE asset_id = %s AND cve_id = 'HEURISTIC-CONTROL-PLANE-INTRUSION'
            """, (self.TEST_ASSET_ID,))
            finding = cur.fetchone()

        self.assertIsNotNone(finding, "Heuristic Rule 1 (Control Plane Intrusion) did not fire")
        self.assertEqual(finding[0], "HEURISTIC-CONTROL-PLANE-INTRUSION")

if __name__ == "__main__":
    unittest.main()
