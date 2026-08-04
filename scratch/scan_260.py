from auditors import auditor_ext
from core import db_manager

asset_id = 260
endpoint = '10.4.2.185'
a_type = 'AppServer'

print(f"🚀 Targeted scan for {asset_id} ({endpoint})")
auditor_ext.scan_appserver(asset_id, endpoint)
print("✅ Done")
