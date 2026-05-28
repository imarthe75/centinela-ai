import sys
sys.path.append("/app")
import auditor_ext
import db_manager

# Get the 8 servers
with db_manager.get_db_cursor() as cur:
    cur.execute("SELECT id, endpoint, asset_name FROM infra_inventory WHERE asset_name LIKE 'CLONE-%'")
    servers = cur.fetchall()

for asset_id, endpoint, asset_name in servers:
    print(f"🚀 Running manual scan for {asset_name} ({endpoint})...")
    auditor_ext.scan_appserver(asset_id, endpoint)
print("✅ Manual scans completed.")
