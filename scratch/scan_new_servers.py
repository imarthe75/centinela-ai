import sys
sys.path.append("/app")
from auditors import auditor_ext
from core import db_manager

targets = [
    (339, '10.4.2.243', 'ce01-server'),
    (340, '10.4.2.244', 'ce02-server'),
    (341, '10.4.2.245', 'ce03-server'),
    (342, '10.4.2.247', 'ce04-server'),
    (343, '10.4.2.248', 'ce05-server'),
    (344, '10.4.2.250', 'ce06-server')
]

for asset_id, endpoint, name in targets:
    print(f"🚀 Running manual scan for {name} ({endpoint})...")
    auditor_ext.scan_appserver(asset_id, endpoint)
print("✅ Manual scans completed.")
