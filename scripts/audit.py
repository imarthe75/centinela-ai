import os
import json
import subprocess
import psycopg2
from core import db_manager
import time
from psycopg2.extras import RealDictCursor

# DB Config moved to db_manager.py

def run_trivy_scan(image_name):
    print(f"🐳 [Audit] Scanning Image: {image_name}")
    try:
        result = subprocess.run([
            'trivy', 'image', '--format', 'json', 
            '--severity', 'HIGH,CRITICAL', image_name
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception as e:
        print(f"❌ Trivy error: {e}")
    return None

def process_vulnerabilities():
    print("🔬 [Centinela-AI] Starting Vulnerability Audit Cycle...")
    
    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, asset_name, endpoint FROM infra_inventory WHERE asset_type = 'Container';")
                assets = cur.fetchall()

            for asset in assets:
                asset_id = asset['id']
                image_name = asset['endpoint']
                
                if image_name == 'local-build':
                    print(f"⏭️ Skipping unknown asset: {asset['asset_name']}")
                    continue

                print(f"🔍 [Centinela-AI] Auditing: {asset['asset_name']} ({image_name})")
                scan_result = run_trivy_scan(image_name)
                if not scan_result:
                    continue

                # Parse vulnerabilities
                results = scan_result.get('Results', [])
                for res in results:
                    vulnerabilities = res.get('Vulnerabilities', [])
                    for vuln in vulnerabilities:
                        cve_id = vuln.get('VulnerabilityID')
                        severity = vuln.get('Severity')
                        description = vuln.get('Title', vuln.get('Description', 'No description'))
                        
                        print(f"🚨 Found {severity} vuln: {cve_id} in {asset['asset_name']}")
                        
                        # Store in DB
                        with db_manager.get_db_cursor() as cur:
                            cur.execute("""
                                INSERT INTO vulnerability_log (asset_id, cve_id, severity, description)
                                VALUES (%s, %s, %s, %s)
                                ON CONFLICT (asset_id, cve_id) DO NOTHING;
                            """, (asset_id, cve_id, severity, description))

            print("✅ Audit cycle complete. Sleeping 5 minutes...")
            time.sleep(300) # Wait 5 min between full cycles
        except Exception as e:
            print(f"❌ [Audit] Error in scan cycle: {e}")
            time.sleep(60)

if __name__ == "__main__":
    process_vulnerabilities()
