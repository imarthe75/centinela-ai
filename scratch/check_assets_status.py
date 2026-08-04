import sys
import os
sys.path.insert(0, '/app')
from core import db_manager

targets = [
    'ce01-server',
    'ce02-server',
    'ce03-server',
    'ce04-server',
    'ce05-server',
    'ce06-server'
]

print("=== Checking Asset Inventory & Scan Status ===")
with db_manager.get_db_connection() as conn:
    with conn.cursor() as cur:
        for name in targets:
            cur.execute("""
                SELECT id, asset_name, asset_type, endpoint 
                FROM infra_inventory 
                WHERE asset_name = %s OR asset_name LIKE %s;
            """, (name, f"%{name}%"))
            rows = cur.fetchall()
            if not rows:
                print(f"❌ Asset '{name}' not found in infra_inventory!")
                continue
            
            for asset_id, asset_name, asset_type, endpoint in rows:
                print(f"\n🖥️ Asset: {asset_name} (ID: {asset_id}, Type: {asset_type}, Endpoint: {endpoint})")
                # Query count of vulnerabilities
                cur.execute("""
                    SELECT scan_engine, COUNT(*), MIN(status), MAX(status)
                    FROM vulnerability_log
                    WHERE asset_id = %s
                    GROUP BY scan_engine;
                """, (asset_id,))
                vulns = cur.fetchall()
                if not vulns:
                    print("  ⚠️ No vulnerability logs or scan history found for this asset!")
                else:
                    print("  Scans found:")
                    for engine, count, min_status, max_status in vulns:
                        print(f"    - Engine: {engine if engine else 'default/unspecified'} | Count: {count} | Status range: {min_status} to {max_status}")
