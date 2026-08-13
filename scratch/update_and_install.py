import os
import sys
sys.path.append("/app")
import hvac

vault_addr = os.environ.get("VAULT_ADDR", "http://casmarts-core-vault:8200")
vault_token = os.environ["VAULT_TOKEN"]
client = hvac.Client(url=vault_addr, token=vault_token)

# CLONE-COMPRAMEX-DIGITAL-BD was decommissioned and removed from infra_inventory (dead IP,
# confirmed via ICMP/TCP -- see CLAUDE.md); this script is obsolete but kept for reference.
# Password read from env rather than a hardcoded weak literal, matching the rest of this file.
asset_name = "CLONE-COMPRAMEX-DIGITAL-BD"
new_password = os.environ["SCRATCH_PROVISION_PASSWORD"]
ansible_user = "compradigitalbd"

payload = {
    "sudo_password": new_password,
    "ansible_user": ansible_user
}

client.secrets.kv.v2.create_or_update_secret(
    path=f"casmarts/ansible/{asset_name}",
    secret=payload,
    mount_point="secret"
)

print(f"🔒 Vault secret updated for {asset_name} with user {ansible_user} and password {new_password}.")
