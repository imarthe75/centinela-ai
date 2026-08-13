"""
Integration test for POST /api/inventory duplicate-IP handling.

Was previously a standalone __main__ script (never discovered by pytest -- 0 items collected,
no def test_*/class Test*) that also hardcoded connection details for the orphaned duplicate
deployment removed 2026-08-04 (host "casmarts-core-db-primary", db "casmarts_security", user
"admin" -- see CLAUDE.md gotcha #2). Rewritten as a real pytest test against this project's
actual DB (via core.db_manager, matching every other test in this suite) and the real FastAPI
app in-process (via TestClient, no dependency on a specific host:port already listening).
"""
import unittest
from fastapi.testclient import TestClient
from main import app
from core.db_manager import get_db_cursor

client = TestClient(app)

class TestInventoryDuplicateIP(unittest.TestCase):
    TEST_IP = "192.168.1.199"

    def tearDown(self):
        with get_db_cursor() as cur:
            cur.execute("DELETE FROM infra_inventory WHERE endpoint = %s", (self.TEST_IP,))

    def test_two_assets_same_ip_both_registered(self):
        data1 = {
            "asset_name": "TestServer_A", "asset_type": "IP", "endpoint": self.TEST_IP,
            "criticality": "HIGH", "location_lat": 0.0, "location_lon": 0.0
        }
        data2 = {
            "asset_name": "TestServer_B_SameIP", "asset_type": "IP", "endpoint": self.TEST_IP,
            "criticality": "HIGH", "location_lat": 0.0, "location_lon": 0.0
        }

        r1 = client.post("/api/inventory", json=data1)
        r2 = client.post("/api/inventory", json=data2)
        self.assertIn(r1.status_code, (200, 201))
        self.assertIn(r2.status_code, (200, 201))

        with get_db_cursor() as cur:
            cur.execute("SELECT asset_name, endpoint FROM infra_inventory WHERE endpoint = %s", (self.TEST_IP,))
            rows = cur.fetchall()
        names = {r[0] for r in rows}
        self.assertIn("TestServer_A", names)
        self.assertIn("TestServer_B_SameIP", names)

if __name__ == "__main__":
    unittest.main()
