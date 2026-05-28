import os
import hvac

vault_addr = "http://casmarts-core-vault:8200"
vault_token = "hvs.6ddxqsuJlRSyuRzOIsXIL9n6"

client = hvac.Client(url=vault_addr, token=vault_token)

# Write using KV v2
client.secrets.kv.v2.create_or_update_secret(
    path="casmarts/ansible/test_asset",
    secret={"sudo_password": "supersecretpassword", "ansible_user": "test_user"},
    mount_point="secret"
)
print("KV v2 write complete.")

# Test KV v1 read (sentinel.py way)
try:
    result = client.secrets.kv.v1.read_secret(
        path="casmarts/ansible/test_asset",
        mount_point="secret"
    )
    print("KV v1 read successful!")
    print(result)
except Exception as e:
    print(f"KV v1 read failed: {e}")

# Test KV v2 read version (correct way)
try:
    res = client.secrets.kv.v2.read_secret_version(
        path="casmarts/ansible/test_asset",
        mount_point="secret"
    )
    print("KV v2 read successful!")
    print(res['data']['data'])
except Exception as e:
    print(f"KV v2 read failed: {e}")
