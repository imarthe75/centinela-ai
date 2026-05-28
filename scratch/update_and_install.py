import sys
sys.path.append("/app")
import hvac

vault_addr = "http://casmarts-core-vault:8200"
vault_token = "hvs.6ddxqsuJlRSyuRzOIsXIL9n6"
client = hvac.Client(url=vault_addr, token=vault_token)

asset_name = "CLONE-COMPRAMEX-DIGITAL-BD"
new_password = "password"
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
