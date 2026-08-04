import os
import sys
import subprocess
sys.path.append("/app")
from core import db_manager
import hvac

# Uvicorn is running on port 8000 inside the container centinela-backend
vault_addr = "http://casmarts-core-vault:8200"
vault_token = "hvs.6ddxqsuJlRSyuRzOIsXIL9n6"
client = hvac.Client(url=vault_addr, token=vault_token)

# Get the servers
with db_manager.get_db_cursor() as cur:
    cur.execute("SELECT id, endpoint, asset_name FROM infra_inventory WHERE asset_name LIKE 'CLONE-%'")
    servers = cur.fetchall()

print(f"Loaded {len(servers)} servers from database.")

for asset_id, endpoint, asset_name in servers:
    print(f"\n--- Processing {asset_name} ({endpoint}) ---")
    
    # Read secrets from Vault
    try:
        res = client.secrets.kv.v2.read_secret_version(
            path=f"casmarts/ansible/{asset_name}",
            mount_point="secret"
        )
        data = res["data"]["data"]
        sudo_pass = data.get("sudo_password", "")
        ansible_user = data.get("ansible_user", "")
    except Exception as e:
        print(f"⚠️ Vault error for {asset_name}: {e}. Skipping.")
        continue
        
    if not sudo_pass or not ansible_user:
        print(f"⚠️ Missing credentials in Vault for {asset_name}. Skipping.")
        continue
        
    print(f"🔒 Credentials loaded. Triggering Wazuh Agent installation playbook...")
    
    cmd = [
        "ansible-playbook", "-i", f"{endpoint},",
        "/app/scratch/install_wazuh_playbook.yml",
        "-e", f"ansible_user={ansible_user}",
        "-e", f"ansible_become_pass={sudo_pass}",
        "-e", f"ansible_ssh_pass={sudo_pass}",
        "-e", f"ansible_password={sudo_pass}",
        "-e", "ansible_ssh_common_args='-o StrictHostKeyChecking=no'"
    ]
    
    try:
        run_res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        print(f"Exit Code: {run_res.returncode}")
        print("stdout:")
        print(run_res.stdout)
        if run_res.returncode not in [0, 2]:
            print("stderr:")
            print(run_res.stderr)
    except Exception as e:
        print(f"❌ Playbook execution failed: {e}")
