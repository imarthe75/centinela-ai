import os
import sys
import json
import time
from datetime import datetime

# Setup DB connection environment variables if running on host
# If we are on the host, DB_HOST=127.0.0.1 and port override is needed.
# We patch psycopg2 directly so the test runs perfectly either on the host or inside the container.
if os.getenv("DB_HOST") == "127.0.0.1" or not os.getenv("DB_HOST"):
    os.environ["DB_HOST"] = "127.0.0.1"
    import psycopg2
    orig_connect = psycopg2.connect
    psycopg2.connect = lambda *args, **kwargs: orig_connect(*args, **{**kwargs, 'port': 5434})
    print("🔌 [Test-Suite] Patched psycopg2 to connect to localhost:5434")

import db_manager
import auditor_medusa
import heuristics_engine
import discovery_osint

def run_integration_tests():
    print("🧪 [Test-Suite] Starting Centinela Evolution Integration Tests...")
    
    # 1. Verify Imports
    print("✅ [Test-Suite] Successfully imported auditor_medusa")
    print("✅ [Test-Suite] Successfully imported heuristics_engine")
    print("✅ [Test-Suite] Successfully imported discovery_osint")
    
    test_asset_id = 99999
    
    try:
        # Create a test asset in infra_inventory if it doesn't exist
        with db_manager.get_db_cursor() as cur:
            cur.execute("DELETE FROM vulnerability_log WHERE asset_id = %s", (test_asset_id,))
            cur.execute("DELETE FROM runtime_alerts WHERE asset_id = %s", (test_asset_id,))
            cur.execute("DELETE FROM infra_inventory WHERE id = %s", (test_asset_id,))
            
            cur.execute("""
                INSERT INTO infra_inventory (id, asset_name, asset_type, endpoint, criticality, last_audit, status)
                VALUES (%s, 'Test-Heuristic-Asset', 'IP', '127.0.0.1', 'High', NOW(), 'monitored')
            """, (test_asset_id,))
            print("✅ [Test-Suite] Initialized temporary test asset (ID: 99999)")

        # 2. Simulate exposure (NMAP scan vulnerability)
        print("📝 [Test-Suite] Simulating open port exposure in vulnerability_log...")
        auditor_medusa.log_vulnerability(
            asset_id=test_asset_id,
            cve_id="NMAP-SCAN",
            severity="MEDIUM",
            description="Test Nmap finding: Exposed Docker API Port 2375"
        )

        # 3. Simulate suspicious runtime shell alert in runtime_alerts
        print("📝 [Test-Suite] Simulating Falco container terminal alert...")
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields, detected_at)
                VALUES (%s, 'CRITICAL', 'Run shell in container', 'Interactive terminal session opened inside container test-container', '{\"container.name\": \"test-container\"}', NOW())
            """, (test_asset_id,))

        # 4. Trigger temporal heuristics correlation engine
        print("🧠 [Test-Suite] Running Heuristics Engine correlation...")
        heuristics_engine.run_heuristics_correlation(minutes=5)

        # 5. Assert that the HEURISTIC-CONTROL-PLANE-INTRUSION vulnerability was generated
        print("🧐 [Test-Suite] Verifying if consolidated heuristic alert exists in Postgres...")
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                SELECT cve_id, severity, description, status 
                FROM vulnerability_log 
                WHERE asset_id = %s AND cve_id = 'HEURISTIC-CONTROL-PLANE-INTRUSION'
            """, (test_asset_id,))
            finding = cur.fetchone()
            
        assert finding is not None, "❌ Heuristic alert was NOT generated!"
        
        print("\n🎉 INTEGRATION TEST PASSED SUCCESSFULLY! 🎉")
        print(f"Severity: {finding[1]}")
        print(f"CVE ID: {finding[0]}")
        print(f"Description:\n{finding[2]}")
        print(f"Status: {finding[3]}")
        
    except AssertionError as ae:
        print(f"❌ Assertion Failed: {ae}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Test encountered an error: {e}")
        sys.exit(1)
    finally:
        # Clean up test data
        print("\n🧹 [Test-Suite] Cleaning up test database records...")
        try:
            with db_manager.get_db_cursor() as cur:
                cur.execute("DELETE FROM vulnerability_log WHERE asset_id = %s", (test_asset_id,))
                cur.execute("DELETE FROM runtime_alerts WHERE asset_id = %s", (test_asset_id,))
                cur.execute("DELETE FROM infra_inventory WHERE id = %s", (test_asset_id,))
            print("✅ [Test-Suite] Database cleanup completed.")
        except Exception as cleanup_err:
            print(f"⚠️ Cleanup failed: {cleanup_err}")

if __name__ == "__main__":
    run_integration_tests()
