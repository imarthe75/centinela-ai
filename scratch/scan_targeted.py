from auditors import auditor_ext
from core import db_manager

targets = [
    (260, '10.4.2.198', 'AppServer'),
    (293, '10.4.2.185', 'AppServer')
]

for asset_id, endpoint, a_type in targets:
    print(f"🚀 Targeted scan for {asset_id} ({endpoint})")
    auditor_ext.scan_appserver(asset_id, endpoint)

print("✅ All done")
