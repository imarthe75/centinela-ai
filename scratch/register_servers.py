import requests
import json

# Uvicorn is running on port 8000 inside the container centinela-backend
url = "http://localhost:8000/api/inventory"

servers = [
    {
        "asset_name": "CLONE-COMPRAMEX-DIGITAL",
        "asset_type": "SERVER",
        "endpoint": "10.4.3.200",
        "criticality": "HIGH",
        "vault_sudo_token": "password",
        "vault_ansible_user": "compradigital"
    },
    {
        "asset_name": "CLONE-COMPRAMEX-DIGITAL-BD",
        "asset_type": "SERVER",
        "endpoint": "10.4.3.201",
        "criticality": "HIGH",
        "vault_sudo_token": "password",
        "vault_ansible_user": "compradigital.bd"
    },
    {
        "asset_name": "CLONE-COMPRAMEX-CORE",
        "asset_type": "SERVER",
        "endpoint": "10.4.3.202",
        "criticality": "HIGH",
        "vault_sudo_token": "password",
        "vault_ansible_user": "compramex"
    },
    {
        "asset_name": "CLONE-COMPRAMEX-CORE-BD",
        "asset_type": "SERVER",
        "endpoint": "10.4.3.203",
        "criticality": "HIGH",
        "vault_sudo_token": "password",
        "vault_ansible_user": "compramex-bd"
    },
    {
        "asset_name": "CLONE-PMCP",
        "asset_type": "SERVER",
        "endpoint": "10.4.3.204",
        "criticality": "HIGH",
        "vault_sudo_token": "password",
        "vault_ansible_user": "pmcp"
    },
    {
        "asset_name": "CLONE-PMCP-BD",
        "asset_type": "SERVER",
        "endpoint": "10.4.3.205",
        "criticality": "HIGH",
        "vault_sudo_token": "password",
        "vault_ansible_user": "pmcp-bd"
    },
    {
        "asset_name": "CLONE-SICOPA",
        "asset_type": "SERVER",
        "endpoint": "10.4.3.206",
        "criticality": "HIGH",
        "vault_sudo_token": "password",
        "vault_ansible_user": "sicopa"
    },
    {
        "asset_name": "CLONE-SICOPA-BD",
        "asset_type": "SERVER",
        "endpoint": "10.4.3.207",
        "criticality": "HIGH",
        "vault_sudo_token": "password",
        "vault_ansible_user": "sicopa-bd"
    }
]

for server in servers:
    print(f"Registering {server['asset_name']} ({server['endpoint']})...")
    res = requests.post(url, json=server)
    print(f"Response: {res.status_code} - {res.text}")
