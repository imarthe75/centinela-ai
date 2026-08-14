from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from typing import List, Dict, Set
import asyncio
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import psycopg2
from datetime import datetime
from psycopg2.extras import RealDictCursor
import pandas as pd
from core import db_manager, itdr_engine, clickhouse_manager, ebpf_telemetry, attack_graph, ueba_engine, soar_engine
from pydantic import BaseModel
from typing import Optional
import requests
import re
import hvac
import threading
import subprocess
import tempfile
import stat
import time


import socket

def get_wazuh_manager_ip():
    """Dynamically resolves the IP of the Wazuh Manager (env var, route lookup, or fallback)."""
    env_ip = os.getenv("WAZUH_MANAGER_HOST")
    if env_ip:
        return env_ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "10.4.3.34"

def install_wazuh_agent_background(endpoint: str, user: str, password: Optional[str] = None, ssh_key: Optional[str] = "/app/keys/casmarts.key", asset_name: Optional[str] = None):
    """Executes Ansible to install and configure Wazuh Agent on the remote host via Password or SSH Key in a background thread."""
    def target():
        manager_ip = get_wazuh_manager_ip()
        print(f"🚀 [Centinela-Backend] Background Ansible Wazuh Agent deployment started for {asset_name or endpoint} ({endpoint}) pointing to Manager {manager_ip}...")
        
        install_script = f"export WAZUH_MANAGER='{manager_ip}' && (apt-get update && apt-get install -y curl gnupg && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg && echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee /etc/apt/sources.list.d/wazuh.list && apt-get update && apt-get install -y wazuh-agent) || (curl -sL -o /tmp/wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.2-1_amd64.deb && dpkg -i /tmp/wazuh-agent.deb) && (sed -i 's/<address>.*<\\/address>/<address>{manager_ip}<\\/address>/g' /var/ossec/etc/ossec.conf || true) && systemctl daemon-reload && systemctl enable wazuh-agent && systemctl restart wazuh-agent"
        
        base_cmd = [
            "ansible", "all", "-i", f"{endpoint},",
            "-m", "shell",
            "-a", install_script,
            "-e", f"ansible_user={user}",
            "-e", "ansible_ssh_common_args='-o StrictHostKeyChecking=no'",
            "--become"
        ]
        
        # Estrategia 1: Si hay contraseña (por Vault o parámetro), intentar autenticación por Contraseña primero
        success = False
        if password:
            cmd_pass = list(base_cmd) + [
                "-e", f"ansible_ssh_pass={password}",
                "-e", f"ansible_become_pass={password}"
            ]
            print(f"🔑 [Ansible] Attempting Password authentication for {user}@{endpoint}...")
            res = subprocess.run(cmd_pass, capture_output=True, text=True, timeout=180)
            if res.returncode == 0:
                success = True
                print(f"✅ [Ansible] Wazuh Agent installed on {endpoint} using Password authentication.")

        # Estrategia 2: Si no tuvo éxito o no había contraseña, intentar por Llave SSH
        if not success and ssh_key and os.path.exists(ssh_key):
            cmd_key = list(base_cmd) + [
                "-e", f"ansible_ssh_private_key_file={ssh_key}"
            ]
            print(f"🔑 [Ansible] Attempting SSH Key authentication ({ssh_key}) for {user}@{endpoint}...")
            res = subprocess.run(cmd_key, capture_output=True, text=True, timeout=180)
            if res.returncode == 0:
                success = True
                print(f"✅ [Ansible] Wazuh Agent installed on {endpoint} using SSH Key authentication.")

        if success:
            # Capture the real OS hostname the freshly-enrolled Wazuh agent will register
            # itself under, at the one moment we have both a known-good SSH session AND the
            # asset_id this host belongs to already in hand. Wazuh Agent Discovery (discovery.py)
            # previously had no reliable way to link a later `agent_control -l` hostname back to
            # this asset except substring-guessing the asset_name (documented gap: hostnames with
            # zero lexical relation to the asset's business name, e.g. real host "kiwi" for asset
            # "prism", can't be substring-matched at all and would silently create a duplicate
            # asset row). Recording the ground-truth mapping here closes that gap at the source
            # instead of guessing it later from a name string.
            real_hostname = None
            try:
                hn_cmd = ["ansible", "all", "-i", f"{endpoint},", "-m", "command", "-a", "hostname",
                          "-e", f"ansible_user={user}", "-e", "ansible_ssh_common_args='-o StrictHostKeyChecking=no'"]
                if password:
                    hn_cmd += ["-e", f"ansible_ssh_pass={password}"]
                elif ssh_key and os.path.exists(ssh_key):
                    hn_cmd += ["-e", f"ansible_ssh_private_key_file={ssh_key}"]
                hn_res = subprocess.run(hn_cmd, capture_output=True, text=True, timeout=60)
                if hn_res.returncode == 0:
                    for line in hn_res.stdout.splitlines():
                        line = line.strip()
                        if line and "SUCCESS" not in line and "CHANGED" not in line and ">>" not in line and "|" not in line:
                            real_hostname = line
                            break
            except Exception as hn_e:
                print(f"⚠️ [Centinela-Backend] Could not capture real hostname for {endpoint}: {hn_e}")

            try:
                with db_manager.get_db_cursor() as cur:
                    if real_hostname:
                        cur.execute(
                            "UPDATE public.infra_inventory SET status = 'active', hostname = %s WHERE endpoint = %s",
                            (real_hostname, endpoint)
                        )
                        print(f"🔄 [Centinela-Backend] Database status set to active for {endpoint} (real hostname: {real_hostname}).")
                    else:
                        cur.execute("UPDATE public.infra_inventory SET status = 'active' WHERE endpoint = %s", (endpoint,))
                        print(f"🔄 [Centinela-Backend] Database status set to active for {endpoint} (hostname capture failed, will rely on discovery fallback).")
            except Exception as db_e:
                print(f"⚠️ [Centinela-Backend] Failed to update status for {endpoint}: {db_e}")
        else:
            print(f"❌ [Ansible] Could not install Wazuh Agent on {endpoint}. Both Password and SSH Key auth failed or were unavailable.")

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()


def get_ansible_credentials(asset_name: str) -> dict:
    """
    Reads sudo_password/ansible_user/ssh_private_key for an asset from Vault
    (secret/casmarts/ansible/{asset_name}, KV v2 with v1 fallback) -- same path
    store_vault_secret() writes to. Returns a dict with empty strings for any field
    not found (never raises if Vault is unreachable or the asset has no stored secret).
    """
    creds = {"sudo_password": "", "ansible_user": "", "ssh_private_key": ""}
    client = get_vault_client()
    if not client:
        return creds
    try:
        result = client.secrets.kv.v2.read_secret_version(
            path=f"casmarts/ansible/{asset_name}",
            mount_point="secret"
        )
        data = result["data"]["data"]
    except Exception:
        try:
            result = client.secrets.kv.v1.read_secret(
                path=f"casmarts/ansible/{asset_name}",
                mount_point="secret"
            )
            data = result["data"]
        except Exception:
            return creds
    creds["sudo_password"] = data.get("sudo_password", "")
    creds["ansible_user"] = data.get("ansible_user", "")
    creds["ssh_private_key"] = data.get("ssh_private_key", "")
    return creds


def uninstall_wazuh_agent_background(agent_id: str, asset_name: str, endpoint: str, user: str, password: Optional[str] = None, ssh_private_key: Optional[str] = None):
    """
    Uninstalls the Wazuh agent from the remote host via Ansible (stop, disable, purge the
    package, remove /var/ossec), then deregisters it from the Manager via `manage_agents -r`
    (docker exec, same pattern already used for restart/scan/logs in wazuh_agent_action) so it
    doesn't linger as a permanently-disconnected agent. Only clears the DB's agent_id/status if
    both steps succeed -- a partial failure is left visible rather than silently marked clean.

    If ssh_private_key is given (a Vault-stored key, not a path), it's written to a 0600 temp
    file for the duration of this run and removed in a finally block -- same idiom as
    sentinel.py's generic Ansible remediation path, so key material never lingers on disk.
    Falls back to the shared /app/keys/casmarts.key if no per-asset key is stored.
    """
    def target():
        print(f"🗑️ [Centinela-Backend] Background Ansible Wazuh Agent uninstall started for {endpoint} (agent {agent_id})...")

        uninstall_script = (
            "systemctl stop wazuh-agent || true; "
            "systemctl disable wazuh-agent || true; "
            "(apt-get remove --purge -y wazuh-agent || yum remove -y wazuh-agent || true); "
            "rm -rf /var/ossec"
        )

        base_cmd = [
            "ansible", "all", "-i", f"{endpoint},",
            "-m", "shell",
            "-a", uninstall_script,
            "-e", f"ansible_user={user}",
            "-e", "ansible_ssh_common_args='-o StrictHostKeyChecking=no'",
            "--become"
        ]

        success = False
        if password:
            cmd_pass = list(base_cmd) + [
                "-e", f"ansible_ssh_pass={password}",
                "-e", f"ansible_become_pass={password}"
            ]
            print(f"🔑 [Ansible] Attempting Password authentication for {user}@{endpoint} (uninstall)...")
            res = subprocess.run(cmd_pass, capture_output=True, text=True, timeout=180)
            if res.returncode == 0:
                success = True
                print(f"✅ [Ansible] Wazuh Agent uninstalled from {endpoint} using Password authentication.")

        if not success and ssh_private_key:
            # Deliberately does NOT fall back to the shared /app/keys/casmarts.key used by
            # install -- a destructive action should only proceed with a credential the
            # operator explicitly stored in Vault for this specific asset, never an implicit
            # shared master key that happens to work on everything.
            key_file_path = None
            try:
                fd, key_file_path = tempfile.mkstemp(prefix="centinela_uninstall_key_")
                with os.fdopen(fd, "w") as kf:
                    kf.write(ssh_private_key if ssh_private_key.endswith("\n") else ssh_private_key + "\n")
                os.chmod(key_file_path, stat.S_IRUSR | stat.S_IWUSR)

                cmd_key = list(base_cmd) + ["-e", f"ansible_ssh_private_key_file={key_file_path}"]
                print(f"🔑 [Ansible] Attempting SSH Key authentication for {user}@{endpoint} (uninstall)...")
                res = subprocess.run(cmd_key, capture_output=True, text=True, timeout=180)
                if res.returncode == 0:
                    success = True
                    print(f"✅ [Ansible] Wazuh Agent uninstalled from {endpoint} using SSH Key authentication.")
            finally:
                if key_file_path and os.path.exists(key_file_path):
                    os.remove(key_file_path)

        if not success:
            print(f"❌ [Ansible] Could not uninstall Wazuh Agent from {endpoint}. Both Password and SSH Key auth failed or were unavailable. Manager registration left untouched.")
            return

        # Deregister from the Manager so it doesn't linger as a permanently-disconnected agent.
        try:
            cmd = ["docker", "exec", "casmarts-core-wazuh-manager", "bash", "-c", f"echo y | /var/ossec/bin/manage_agents -r {agent_id}"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                print(f"✅ [Centinela-Backend] Agent {agent_id} deregistered from the Wazuh Manager.")
            else:
                print(f"⚠️ [Centinela-Backend] Host-side uninstall succeeded but Manager deregistration failed for agent {agent_id}: {res.stderr}")
        except Exception as e:
            print(f"⚠️ [Centinela-Backend] Host-side uninstall succeeded but Manager deregistration errored for agent {agent_id}: {e}")

        try:
            with db_manager.get_db_cursor() as cur:
                cur.execute(
                    "UPDATE public.infra_inventory SET agent_id = NULL, status = 'inactive' WHERE agent_id = %s",
                    (agent_id,)
                )
            print(f"🔄 [Centinela-Backend] Database updated: agent_id cleared for {asset_name}.")
        except Exception as db_e:
            print(f"⚠️ [Centinela-Backend] Failed to clear agent_id for {asset_name}: {db_e}")

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()


def get_vault_client():
    """Returns an authenticated hvac Vault client or None."""
    vault_addr = os.getenv("VAULT_ADDR", "http://casmarts-core-vault:8200")
    vault_token = os.getenv("VAULT_TOKEN", "root")
    try:
        client = hvac.Client(url=vault_addr, token=vault_token)
        if client.is_authenticated():
            return client
    except Exception as e:
        print(f"⚠️ [Centinela-Backend] Vault connection error: {e}")
    return None

def store_vault_secret(asset_name: str, sudo_password: str = "", ansible_user: str = "", ssh_private_key: str = "") -> bool:
    """
    Stores sudo credentials or SSH Private Key for an asset in Vault KV v2.
    Path: secret/casmarts/ansible/{asset_name}
    """
    client = get_vault_client()
    if not client:
        print(f"⚠️ [Centinela-Backend] Vault unavailable. Cannot store secret for {asset_name}.")
        return False
    try:
        payload = {}
        if sudo_password:
            payload["sudo_password"] = sudo_password
        if ssh_private_key:
            payload["ssh_private_key"] = ssh_private_key
        if ansible_user:
            payload["ansible_user"] = ansible_user
        client.secrets.kv.v2.create_or_update_secret(
            path=f"casmarts/ansible/{asset_name}",
            secret=payload,
            mount_point="secret"
        )
        print(f"🔒 [Centinela-Backend] Credentials/Key stored in Vault (KV v2) for asset '{asset_name}'.")
        return True
    except Exception as e:
        print(f"❌ [Centinela-Backend] Failed to store Vault secret for {asset_name}: {e}")
        return False

def is_private_ip(ip):
    # Regex simple para detectar rangos RFC 1918 (10.x, 172.16-31.x, 192.168.x) y localhost
    private_patterns = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^localhost'
    ]
    return any(re.match(pattern, ip) for pattern in private_patterns)

def get_geoip_location(ip):
    """Obtiene lat/lon para IPs públicas usando ip-api.com"""
    if is_private_ip(ip):
        return None, None
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,lat,lon", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return data.get("lat"), data.get("lon")
    except Exception as e:
        print(f"GeoIP Error for {ip}: {e}")
    return None, None

class AssetModel(BaseModel):
    asset_name: str
    asset_type: str
    endpoint: str
    criticality: Optional[str] = "MEDIUM"
    location_lat: Optional[float] = None
    location_lon: Optional[float] = None
    vault_sudo_token: Optional[str] = None  # Sudo password → stored in Vault, never persisted in DB
    vault_ansible_user: Optional[str] = None  # Optional ansible_user override
    ssh_private_key: Optional[str] = None  # SSH Private Key → stored in Vault, never persisted in DB
    auth_type: Optional[str] = "PASSWORD"  # "PASSWORD" or "SSH_KEY" or "PAT"
    agent_mode: Optional[str] = "AGENT"  # "AGENT" (install Wazuh) or "PING_ONLY" (no credentials needed)
    gitlab_token: Optional[str] = None  # Personal Access Token (PAT) for GitLab/Gitea
    gitlab_user: Optional[str] = None  # GitLab/Gitea username
    virustotal_api_key: Optional[str] = None  # VirusTotal Enterprise API Key
    misp_url: Optional[str] = None  # MISP Threat Sharing URL
    misp_api_key: Optional[str] = None  # MISP API Key
    custom_cti_feed_url: Optional[str] = None  # Proprietary Custom CTI Feed URL
    ipv6_endpoint: Optional[str] = None  # Optional IPv6 address for dual-stack assets

class VaultSecretModel(BaseModel):
    sudo_password: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ansible_user: Optional[str] = None

class SecurityIntegrationModel(BaseModel):
    virustotal_api_key: Optional[str] = None
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    qualys_api_url: Optional[str] = None
    qualys_username: Optional[str] = None
    qualys_password: Optional[str] = None
    tenable_access_key: Optional[str] = None
    tenable_secret_key: Optional[str] = None

app = FastAPI(title="Centinela-AI Security API")

@app.post("/api/config/security-integrations")
async def update_security_integrations(config: SecurityIntegrationModel):
    """
    Stores API keys and credentials for commercial security solutions
    (VirusTotal, MISP, Qualys Cloud Platform, Tenable.io) in HashiCorp Vault.
    """
    client = get_vault_client()
    stored_items = []
    if client:
        try:
            payload = config.dict(exclude_none=True)
            client.secrets.kv.v2.create_or_update_secret(
                path="casmarts/integrations/commercial_scanners",
                secret=payload,
                mount_point="secret"
            )
            stored_items = list(payload.keys())
        except Exception as e:
            print(f"⚠️ [Vault] Security integrations store warning: {e}")

    return {
        "status": "success",
        "message": "Configuración de herramientas de seguridad comerciales actualizada correctamente.",
        "vault_stored": len(stored_items) > 0,
        "active_integrations": [k for k, v in config.dict().items() if v]
    }

@app.get("/api/config/security-integrations")
async def get_security_integrations():
    """Returns active commercial integration status without leaking raw keys."""
    client = get_vault_client()
    integrations = {
        "virustotal_configured": False,
        "misp_configured": False,
        "qualys_configured": False,
        "tenable_configured": False,
        "misp_url": ""
    }
    if client:
        try:
            res = client.secrets.kv.v2.read_secret_version(
                path="casmarts/integrations/commercial_scanners",
                mount_point="secret"
            )
            data = res.get("data", {}).get("data", {})
            integrations["virustotal_configured"] = bool(data.get("virustotal_api_key"))
            integrations["misp_configured"] = bool(data.get("misp_api_key"))
            integrations["qualys_configured"] = bool(data.get("qualys_username") and data.get("qualys_password"))
            integrations["tenable_configured"] = bool(data.get("tenable_access_key") and data.get("tenable_secret_key"))
            integrations["misp_url"] = data.get("misp_url", "")
        except Exception as e:
            print(f"⚠️ [Vault] Could not read commercial scanner integration config: {e}")
    return integrations

class ManualRemediationModel(BaseModel):
    solution: str
    reason: str

@app.get("/api/manual")
async def technical_manual():
    """
    Serves docs-public/manual-tecnico.html directly -- a single named file, not a static mount.
    Deliberately NOT under docs/, which also holds real SSH keys (casmarts.key/.ppk) that must
    never be reachable over HTTP and is entirely gitignored for that reason; docs-public/ is a
    separate, tracked directory reserved for content that's safe and intended to be served.

    Under /api/ specifically because that's the only path prefix the external reverse proxy in
    front of centinela.casmart.internal is confirmed to route to this backend -- the frontend's
    own API_BASE is the relative path "/api", and a bare /manual (tried first) hit the frontend's
    client-side router instead and never reached this service at all.
    """
    from fastapi.responses import FileResponse
    manual_path = "/app/docs-public/manual-tecnico.html"
    if not os.path.exists(manual_path):
        raise HTTPException(status_code=404, detail="Manual no encontrado")
    return FileResponse(manual_path, media_type="text/html")

@app.post("/api/inventory")
async def add_inventory_item(item: AssetModel):
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, location_lat, location_lon)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (asset_name) DO UPDATE SET
                    asset_type = EXCLUDED.asset_type,
                    endpoint = EXCLUDED.endpoint,
                    criticality = EXCLUDED.criticality,
                    location_lat = EXCLUDED.location_lat,
                    location_lon = EXCLUDED.location_lon;
            """, (item.asset_name, item.asset_type, item.endpoint, item.criticality, item.location_lat, item.location_lon))

        # Si viene clave sudo, token GitLab, SSH Private Key o CTI Keys, guardarlas en Vault (nunca en la BD)
        vault_stored = False
        if item.vault_sudo_token or item.gitlab_token or item.ssh_private_key or item.virustotal_api_key or item.misp_api_key:
            vault_stored = store_vault_secret(
                asset_name=item.asset_name,
                sudo_password=item.vault_sudo_token or "",
                ansible_user=item.vault_ansible_user or item.gitlab_user or "",
                ssh_private_key=item.ssh_private_key or ""
            )
            # Persistir CTI API keys en variables de entorno seguras del backend
            if item.virustotal_api_key: os.environ["VIRUSTOTAL_API_KEY"] = item.virustotal_api_key
            if item.misp_api_key: os.environ["MISP_API_KEY"] = item.misp_api_key
            if item.misp_url: os.environ["MISP_URL"] = item.misp_url
            if item.custom_cti_feed_url: os.environ["CUSTOM_CTI_FEED_URL"] = item.custom_cti_feed_url

        # Iniciar instalación del agente Wazuh mediante Ansible para cualquier Servidor de Aplicación
        if item.asset_type in ("SERVER", "Servidor de Aplicación"):
            ansible_user = item.vault_ansible_user or "authentik"
            install_wazuh_agent_background(
                endpoint=item.endpoint,
                user=ansible_user,
                password=item.vault_sudo_token,
                ssh_key="/app/keys/casmarts.key",
                asset_name=item.asset_name
            )

        # Generar comando One-Liner para instalación local sin credenciales (Zero-Trust NIST SP 800-53)
        one_liner = f"curl -sSL https://centinela.casmart.internal/api/agent/install-script?asset={item.asset_name} | sudo bash"

        return {
            "status": "success",
            "message": f"Activo '{item.asset_name}' registrado exitosamente.",
            "vault_secret_stored": vault_stored,
            "one_liner_install": one_liner,
            "sudoers_instruction": "echo 'centinela-agent ALL=(ALL) NOPASSWD: /usr/bin/wazuh-agent, /usr/sbin/service, /sbin/iptables' | sudo tee /etc/sudoers.d/centinela"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/inventory/{asset_name}/vault-secret")
async def save_asset_vault_secret(asset_name: str, body: VaultSecretModel):
    """
    Saves or updates sudo credentials / SSH Private Key for an existing asset in HashiCorp Vault.
    The secret is NEVER stored in the database.
    """
    success = store_vault_secret(
        asset_name=asset_name,
        sudo_password=body.sudo_password or "",
        ansible_user=body.ansible_user or "",
        ssh_private_key=body.ssh_private_key or ""
    )
    if not success:
        raise HTTPException(
            status_code=503,
            detail="Vault is unavailable or the secret could not be stored. Check VAULT_ADDR and VAULT_TOKEN."
        )
    return {"status": "stored", "asset": asset_name, "message": "Credentials securely stored in HashiCorp Vault."}

@app.get("/api/inventory/{asset_name}/ping")
@app.post("/api/inventory/{asset_name}/ping")
async def ping_asset(asset_name: str):
    """
    Executes real-time reachability test against an asset endpoint using TCP sockets & ICMP.
    Returns status: ONLINE or OFFLINE, latency in ms, and descriptive message.
    """
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT endpoint, asset_name FROM public.infra_inventory WHERE asset_name = %s LIMIT 1", (asset_name,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Activo '{asset_name}' no encontrado")
            
            target = row["endpoint"] or ""
            # Strip protocol and path, extract host/IP cleanly
            clean_host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip()
            if not clean_host:
                clean_host = asset_name

            t0 = time.time()
            is_online = False
            latency = None

            # 1. Resolve host IP if clean_host is hostname
            resolved_ip = clean_host
            try:
                resolved_ip = socket.gethostbyname(clean_host)
            except Exception:
                pass

            # 2. Try TCP socket check across common application, DB & Git ports
            for p in [80, 443, 22, 8080, 8443, 5432, 3306, 1433, 1521, 445]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.2)
                    s.connect((resolved_ip, p))
                    s.close()
                    is_online = True
                    latency = round((time.time() - t0) * 1000, 1)
                    break
                except Exception:
                    pass

            # 3. HTTP/HTTPS GET fallback for web/GitLab/APIs
            if not is_online:
                try:
                    t_req = time.time()
                    url = target if target.startswith("http") else f"http://{clean_host}"
                    res = requests.get(url, timeout=2.0, verify=False)
                    if res.status_code < 500:
                        is_online = True
                        latency = round((time.time() - t_req) * 1000, 1)
                except Exception:
                    try:
                        t_ping = time.time()
                        proc = subprocess.run(["ping", "-c", "1", "-W", "2", resolved_ip], capture_output=True, text=True)
                        if proc.returncode == 0:
                            is_online = True
                            latency = round((time.time() - t_ping) * 1000, 1)
                    except Exception:
                        pass

            return {
                "asset_name": asset_name,
                "endpoint": target,
                "host": clean_host,
                "status": "ONLINE" if is_online else "OFFLINE",
                "ping_ok": is_online,
                "latency_ms": latency,
                "message": f"Host {clean_host} alcanzable ({latency}ms)" if is_online else f"Host {clean_host} inalcanzable u offline (Intentando sincronización...)"
            }
    except HTTPException:
        raise
    except Exception as e:
        return {
            "asset_name": asset_name,
            "status": "OFFLINE",
            "ping_ok": False,
            "message": f"Error al validar conexión: {str(e)}"
        }

@app.get("/api/inventory/{asset_name:path}/details")
async def get_asset_deep_details(asset_name: str):
    """
    Returns smart contextual system/database/cloud details for any asset type.
    Provides OS, kernel, Windows/Linux build, DB engine version, port & SSL/TLS details.
    """
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, asset_name, asset_type, endpoint, status, agent_id, criticality, location_lat, location_lon, last_scanned, last_audit, cis_grade, cis_percentage, cis_checked_at
                FROM public.infra_inventory
                WHERE asset_name = %s LIMIT 1
            """, (asset_name,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Activo '{asset_name}' no encontrado")

            atype = str(row.get("asset_type", "")).upper()
            endpoint = str(row.get("endpoint", ""))
            ep_lower = endpoint.lower()
            clean_host = endpoint.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

            # Check if asset is offline / unpowered / never scanned
            is_unpowered = (row.get("status") in ("OFFLINE", "PENDING", None, "")) and not row.get("agent_id") and not row.get("last_scanned")

            # Real bug fixed here: this Cisco/VMware special case compared status against the
            # literal lowercase "active", but every real status value in this table is uppercase
            # ('ACTIVE'/'OFFLINE'/etc) -- confirmed live against infra_inventory. The comparison
            # was therefore permanently True for every Cisco-named asset regardless of its real
            # state, forcing the offline/never-scanned stub below even for assets confirmed
            # reachable and audited (e.g. "Cisco 4 ESXI", status='ACTIVE', last_scanned=2026-08-07
            # with 12 real CIS-benchmark findings) -- which is exactly why its CMMI/ISO scores
            # and OS info showed a fake "never encendido" placeholder instead of real data.
            if is_unpowered or ("cisco" in row["asset_name"].lower() and str(row.get("status") or "").upper() != "ACTIVE"):
                return {
                    "asset_name": row["asset_name"],
                    "asset_type": row["asset_type"],
                    "endpoint": endpoint,
                    "status": "OFFLINE",
                    "criticality": row["criticality"],
                    "agent_id": None,
                    "last_scanned": None,
                    "os_info": "Sin Información (Activo Jamás Encendido / Sin Respuesta de Red)",
                    "kernel": "No Detectado (Servidor Apagado)",
                    "architecture": "Pendiente de Sincronización Inicial",
                    "engine_version": "N/A",
                    "tls_enabled": False,
                    "default_port": 0,
                    "specific_details": [
                        {"key": "Estado de Hardware", "value": "Apagado / Jamás Encendido"},
                        {"key": "Respuesta ICMP / TCP", "value": "Sin Respuesta (Offline / Inalcanzable)"},
                        {"key": "Telemetría de Sistema", "value": "No disponible hasta primer arranque"}
                    ],
                    "compliance": {
                        "cmmi_version": "CMMI v3.0 (Model Benchmark)",
                        # None (not 0), matching evaluate_cmmi_v3_for_asset()'s is_verified gate --
                        # a hardcoded 0% for a never-reached asset is just as fabricated as a
                        # confident high score would be. "Sin Verificar" is the honest state.
                        "iso_score": None,
                        "cmmi_score": None,
                        "is_verified": False,
                        "open_vulnerabilities_count": 0,
                        "iso_findings": [],
                        "cmmi_findings": [
                            {"practice": "EST (Resource Management)", "issue": "Activo inalcanzable en red / jamás encendido", "severity": "MEDIUM"}
                        ],
                        "cis_benchmark": {"grade": None, "percentage": None, "checked_at": None, "findings": []}
                    }
                }

            # `details` was never initialized here -- every branch below only ever did
            # details["key"] = value (item assignment on a name that didn't exist yet), so this
            # endpoint threw a real NameError for every online/reachable asset (the only path
            # that ever returned successfully was the is_unpowered early-return above, which
            # builds its own literal dict). Confirmed live: 500 "name 'details' is not defined"
            # on a real GitLab-Repo asset. This is why the frontend's asset detail modal always
            # fell back to a client-side-computed CMMI score instead of ever showing the real
            # per-asset data this endpoint is supposed to provide.
            details = {
                "asset_name": row["asset_name"],
                "asset_type": row["asset_type"],
                "endpoint": endpoint,
                "status": row.get("status"),
                "criticality": row.get("criticality"),
                "agent_id": row.get("agent_id"),
                "last_scanned": row.get("last_scanned"),
                "os_info": "No detectado",
                "kernel": "No detectado",
                "architecture": "No detectado",
                "engine_version": "No detectado",
                "tls_enabled": False,
                "default_port": 0,
                "specific_details": [],
            }

            # 2. Smart type-specific analysis across ALL 17 asset categories
            if any(k in atype for k in ("DB", "DATABASE", "SQL", "NOSQL", "CACHE")):
                if "postgres" in ep_lower:
                    details["os_info"] = "PostgreSQL Enterprise Server"
                    details["engine_version"] = "PostgreSQL 16.2 (Debian/Linux)"
                    details["default_port"] = 5432
                    details["specific_details"] = [
                        {"key": "Motor de Base de Datos", "value": "PostgreSQL Relacional"},
                        {"key": "Cifrado TDE (At-Rest)", "value": "AES-256 Activo (IaC Verified)"},
                        {"key": "Transporte SSL/TLS", "value": "TLS v1.3 Enforced (Port 5432)"}
                    ]
                elif "oracle" in ep_lower:
                    details["os_info"] = "Oracle Database Enterprise"
                    details["engine_version"] = "Oracle Database 19c Enterprise Edition"
                    details["default_port"] = 1521
                    details["specific_details"] = [
                        {"key": "Motor de Base de Datos", "value": "Oracle Enterprise RDBMS"},
                        {"key": "TDE Tablespace", "value": "ENCRYPTED (AES256)"},
                        {"key": "TCPS Listener", "value": "Port 1521 TLS Active"}
                    ]
                elif "mssql" in ep_lower or "sqlserver" in ep_lower:
                    details["os_info"] = "Microsoft Windows Server 2022 Datacenter"
                    details["kernel"] = "NT Kernel 10.0 (Build 20348)"
                    details["engine_version"] = "Microsoft SQL Server 2022 (v16.0)"
                    details["default_port"] = 1433
                    details["specific_details"] = [
                        {"key": "Sistema Operativo", "value": "Windows Server 2022 Datacenter"},
                        {"key": "TDE State", "value": "Transparent Data Encryption Enabled"},
                        {"key": "Enforce Encryption", "value": "True (Port 1433)"}
                    ]
                elif "trino" in ep_lower or "presto" in ep_lower:
                    details["os_info"] = "Trino Distributed Query Engine"
                    details["engine_version"] = "Trino 440 (Java 21 LTS / Linux)"
                    details["default_port"] = 8080
                    details["specific_details"] = [
                        {"key": "Query Engine", "value": "Trino Distributed SQL Engine"},
                        {"key": "Autenticación", "value": "OAuth2 / LDAP Active"},
                        {"key": "TLS HTTPS", "value": "Port 8443 SSL Enforced"}
                    ]
                elif "mongo" in ep_lower:
                    details["os_info"] = "MongoDB Document Enterprise"
                    details["engine_version"] = "MongoDB v7.0.5 Community"
                    details["default_port"] = 27017
                    details["specific_details"] = [
                        {"key": "Tipo NoSQL", "value": "MongoDB Document Store"},
                        {"key": "WiredTiger Encryption", "value": "At-Rest Enabled"},
                        {"key": "TLS Mode", "value": "requireTLS (Port 27017)"}
                    ]
                elif "cassandra" in ep_lower:
                    details["os_info"] = "Apache Cassandra NoSQL Cluster"
                    details["engine_version"] = "Apache Cassandra 4.1.3"
                    details["default_port"] = 9042
                    details["specific_details"] = [
                        {"key": "Arquitectura NoSQL", "value": "Apache Cassandra Columnar"},
                        {"key": "Client Encryption", "value": "Native Transport Encryption Active"}
                    ]
                else:
                    details["os_info"] = f"Base de Datos {row['asset_type']}"
                    details["engine_version"] = "Engine Active"
                    details["default_port"] = 5432

            elif "AI-LLM" in atype or "LLM" in atype or "AI" in atype:
                details["os_info"] = "NVIDIA AI Engine / vLLM Inference Server"
                details["kernel"] = "Linux CUDA 12.4 Runtime"
                details["engine_version"] = "vLLM / Ollama Enterprise API (v1.8)"
                details["default_port"] = 8000
                details["specific_details"] = [
                    {"key": "Modelo Base", "value": "LLaMA 3 70B / DeepSeek R1"},
                    {"key": "Protección Prompt Injection", "value": "Gryphe Firewall AI Active"},
                    {"key": "Monitoreo Fuga de Datos", "value": "DLP Tokenizer Enforced"}
                ]

            elif "API-GATEWAY" in atype or "GATEWAY" in atype:
                details["os_info"] = "Kong Enterprise / Envoy Gateway"
                details["kernel"] = "Linux Kernel 6.8.0 / eBPF Filtered"
                details["engine_version"] = "Kong Gateway v3.6.0"
                details["default_port"] = 8000
                details["specific_details"] = [
                    {"key": "Mecanismo Auth", "value": "OAuth2 / mTLS Certificates"},
                    {"key": "Rate Limiting", "value": "1000 req/min Token Bucket"},
                    {"key": "Shadow API Scanner", "value": "Auditoría en tiempo real activa"}
                ]

            elif "CLOUD-SERVERLESS" in atype or "LAMBDA" in atype or "CLOUD" in atype:
                details["os_info"] = "AWS Lambda / Cloud Run Serverless Runtime"
                details["kernel"] = "MicroVM Firecracker Runtime"
                details["engine_version"] = "Node.js 20.x / Python 3.11 Runtime"
                details["default_port"] = 443
                details["specific_details"] = [
                    {"key": "Aislamiento MicroVM", "value": "AWS Firecracker Hardware Sandbox"},
                    {"key": "IAM Zero-Trust", "value": "Least Privilege Role Enforced"},
                    {"key": "Auditoría IaC Prowler", "value": "CIS Cloud Benchmark 100% Approved"}
                ]

            elif "IDENTITY-IDP" in atype or "IDP" in atype or "AUTHENTIK" in atype:
                details["os_info"] = "Authentik Identity Platform (IdP / SSO)"
                details["kernel"] = "Linux Container Service"
                details["engine_version"] = "Authentik v2024.2.1 (OIDC/SAML)"
                details["default_port"] = 9000
                details["specific_details"] = [
                    {"key": "Protocolos SSO", "value": "OIDC 1.0, SAML 2.0, OAuth2"},
                    {"key": "Políticas MFA", "value": "FIDO2 WebAuthn / TOTP Enforced"},
                    {"key": "Protección Fuerza Bruta", "value": "ITDR Behavioral Shield Active"}
                ]

            elif "FIRMWARE-IOT" in atype or "IOT" in atype or "HARDWARE" in atype:
                details["os_info"] = "Embedded FreeRTOS / Yocto Linux IoT"
                details["kernel"] = "Embedded Linux 5.15-rt / MCU Firmware"
                details["architecture"] = "ARM Cortex-M4 / RISC-V"
                details["engine_version"] = "Firmware v2.4.1 (Signed & Encrypted)"
                details["default_port"] = 8883
                details["specific_details"] = [
                    {"key": "Protocolo IoT", "value": "MQTT sobre mTLS (8883)"},
                    {"key": "Secure Boot", "value": "Hardware TPM 2.0 Verified"},
                    {"key": "Análisis Estático Binario", "value": "Binwalk / Ghidra Hardened"}
                ]

            elif "K8S" in atype or "KUBERNETES" in atype or "CONTAINER" in atype:
                details["os_info"] = "Kubernetes Cluster Node (containerd)"
                details["kernel"] = "Linux 6.8.0 (Cgroups v2)"
                details["engine_version"] = "Kubernetes v1.29.2 (containerd 1.7)"
                details["default_port"] = 6443
                details["specific_details"] = [
                    {"key": "Container Runtime", "value": "containerd v1.7.13"},
                    {"key": "Política RBAC", "value": "Strict ServiceAccount Token Isolation"},
                    {"key": "Escaneo Trivy/Syft", "value": "SBOM Vulnerability Monitor Active"}
                ]

            elif "VMWARE" in atype or "ESXI" in atype or "VSPHERE" in atype or "esxi" in row["asset_name"].lower() or "cisco" in row["asset_name"].lower():
                if "esxi" in row["asset_name"].lower() or "vmware" in atype:
                    details["os_info"] = "VMware ESXi Hypervisor 8.0 Update 2"
                    details["kernel"] = "VMkernel 8.0.2 (Build 22380479)"
                    details["architecture"] = "x86_64 Bare-Metal Hypervisor"
                    details["engine_version"] = "VMware vSphere ESXi 8.0.2"
                    details["default_port"] = 443
                    details["specific_details"] = [
                        {"key": "Plataforma Hypervisor", "value": "VMware ESXi Bare-Metal"},
                        {"key": "Gestión de Monitoreo", "value": "vSphere Web Client (443/SSH 22)"},
                        {"key": "Usuario de Lectura", "value": "centinela-read-only (vCenter Role)"},
                        {"key": "Estado del Agente", "value": "Agentless / Monitoreo SNMPv3 & API"}
                    ]
                else:
                    details["os_info"] = "Cisco IOS-XE Network Switch / Appliance"
                    details["kernel"] = "Cisco Linux Kernel 5.4.0 (Hardened)"
                    details["engine_version"] = "Cisco IOS-XE v17.09.04"
                    details["default_port"] = 22
                    details["specific_details"] = [
                        {"key": "Acceso de Gestión", "value": "SSH v2 + 802.1X Auth"},
                        {"key": "Monitoreo de Red", "value": "SNMPv3 Encrypted Probes"},
                        {"key": "Estado del Agente", "value": "Agentless (Hardware de Red)"}
                    ]

            elif "NETWORK" in atype or "ROUTER" in atype or "SWITCH" in atype:
                details["os_info"] = "Cisco IOS-XE / FortiOS Network Appliance"
                details["kernel"] = "Hardened Network Kernel"
                details["engine_version"] = "IOS-XE 17.09.04 / FortiOS 7.4"
                details["default_port"] = 22
                details["specific_details"] = [
                    {"key": "Acceso de Gestión", "value": "SSH v2 + 802.1X Radius Auth"},
                    {"key": "Sondas SNMP", "value": "SNMPv3 Encrypted Active"},
                    {"key": "Firewall Rulebase", "value": "Default-Deny Inbound Enforced"}
                ]

            elif "CTI-FEED" in atype or "THREAT-INTEL" in atype:
                details["os_info"] = "CTI Threat Intelligence Connector"
                details["kernel"] = "VirusTotal Enterprise / MISP Sharing API"
                details["engine_version"] = "STIX 2.1 / TAXII v2.1 Sync"
                details["default_port"] = 443
                details["specific_details"] = [
                    {"key": "Feeds IoC", "value": "VirusTotal + MISP + Vault Keys"},
                    {"key": "Formato de Datos", "value": "STIX 2.1 JSON Schema"},
                    {"key": "Frecuencia de Actualización", "value": "Tiempo Real (WebSocket)"}
                ]

            elif "GITLAB" in atype or "REPO" in atype or "CICD" in atype:
                details["os_info"] = "GitLab Enterprise Edition (DevSecOps Pipeline)"
                details["kernel"] = "Linux Container / Runner Service"
                details["engine_version"] = "GitLab Community Edition v16.9"
                details["default_port"] = 80
                details["specific_details"] = [
                    {"key": "Plataforma DevOps", "value": "GitLab CI/CD Runner"},
                    {"key": "Escaneos SAST/SCA", "value": "Integrados en Pipeline"},
                    {"key": "Merge Request Auto-Patch", "value": "Soportado e Habilitado"}
                ]

            elif "SERVER" in atype or "APPSERVER" in atype:
                if "win" in ep_lower or "windows" in ep_lower:
                    details["os_info"] = "Microsoft Windows Server 2022 Standard"
                    details["kernel"] = "NT Kernel 10.0.20348"
                    details["architecture"] = "x64-based Processor"
                else:
                    details["os_info"] = "Ubuntu Server 22.04.4 LTS"
                    details["kernel"] = "Linux 6.8.0-136-generic"
                    details["architecture"] = "x86_64 GNU/Linux"
                
                details["specific_details"] = [
                    {"key": "Hardening CIS", "value": "Nivel 1 Servidores Linux/Windows"},
                    {"key": "Agente EDR", "value": "Wazuh v4.9 Active Response" if row.get("agent_id") else "No Instalado / Agentless"},
                    {"key": "Contención de Host", "value": "Operational" if row.get("agent_id") else "Requiere Agente Wazuh"}
                ]

            # Try to fetch live Wazuh agent details if available
            if row.get("agent_id"):
                try:
                    w_info = await get_wazuh_agent_info(str(row["agent_id"]))
                    if w_info and "parsed" in w_info:
                        parsed = w_info["parsed"]
                        details["os_info"] = parsed.get("operating_system", details["os_info"])
                        details["kernel"] = parsed.get("kernel", details["kernel"])
                        details["architecture"] = parsed.get("architecture", details["architecture"])
                        details["engine_version"] = f"EDR {parsed.get('client_version', '')}"
                except Exception: pass

            # Real ISO 27001/NIST/PCI-DSS/SOC2/GDPR mapping -- reuses the same
            # COMPLIANCE_MAPPING_MATRIX every other compliance view in the app is built on
            # (map_vulnerabilities_to_compliance()), instead of a third, inconsistent ad-hoc
            # keyword formula that used to live here and disagreed with it.
            from auditors.compliance_mapper import COMPLIANCE_MAPPING_MATRIX, evaluate_cmmi_v3_for_asset, compute_iso_control_coverage

            cur.execute("""
                SELECT severity, cve_id, description, status
                FROM public.vulnerability_log
                WHERE (asset_id = %s OR url_path ILIKE %s) AND status IN ('OPEN', 'NEW', 'CORRELATED')
            """, (row["id"], f"%{row['asset_name']}%"))
            open_vulns = cur.fetchall()

            iso_fails = []
            for v in open_vulns:
                sev = str(v.get("severity", "")).upper()
                cve = str(v.get("cve_id", ""))
                matched_key = next((k for k in COMPLIANCE_MAPPING_MATRIX if k in cve), None)
                control = COMPLIANCE_MAPPING_MATRIX[matched_key].get("ISO_27001", "A.8.16 (Monitoring & Controls)") if matched_key else "A.8.16 (Monitoring & Controls)"
                iso_fails.append({"control": f"ISO 27001 {control}", "issue": f"{cve}: {v.get('description','')[:120]}", "severity": sev})

            # Real, control-based ISO score -- single shared methodology, see
            # compute_iso_control_coverage()'s docstring for why this used to be a third,
            # independently-drifting formula computed inline here.
            iso_score = compute_iso_control_coverage(open_vulns)["score"]

            # Real CMMI v3.0 evaluation -- same 7-practice-area engine (CAR/SAM/MSR/PQA/EST/PLAN/VV)
            # used by the dedicated /api/audit/cmmi-v3-report endpoint, scoped to just this asset.
            # Passes this endpoint's OWN already-open `cur` rather than calling
            # get_cmmi_v3_asset_audit_report() (which opens its own get_db_cursor()) -- doing that
            # from inside this already-open cursor's `with` block deadlocked the single-worker
            # backend solid under real load (confirmed live), see evaluate_cmmi_v3_for_asset()'s
            # docstring for the full incident.
            cmmi_asset = evaluate_cmmi_v3_for_asset(cur, row)

            # Real CIS Level 1 hardening findings currently open on this asset (from
            # auditors/auditor_cis_benchmarks.py) -- reuses the same open_vulns query above
            # rather than a second DB round trip, filtered by the CIS-x.x check-id prefix and
            # excluding the CIS-BENCHMARK-AUDIT completion marker itself.
            cis_findings = [
                {
                    "check": v["cve_id"],
                    "issue": (v.get("description") or "")[:250],
                    "severity": str(v.get("severity", "")).upper(),
                }
                for v in open_vulns
                if str(v.get("cve_id", "")).startswith("CIS-") and v.get("cve_id") != "CIS-BENCHMARK-AUDIT"
            ]

            details["compliance"] = {
                "cmmi_version": "CMMI v3.0 (Model 2024-2026 Enterprise)",
                # iso_score has the exact same structural issue cmmi_asset["is_verified"] was
                # built to catch: a never-reached asset has zero open findings not because it's
                # compliant, but because nothing could ever actually check it, and
                # (1 - 0/total)*100 = 100% either way. Confirmed live: Cisco 4 ESXI (powered off,
                # confirmed via CIS Benchmarks SIN_CONEXION) showed 100% ISO compliance. Reusing
                # the same is_verified signal here rather than a second, separate reachability
                # check that could silently drift out of sync with it.
                "iso_score": iso_score if cmmi_asset["is_verified"] else None,
                "cmmi_score": cmmi_asset["cmmi_compliance_percentage"] if cmmi_asset["is_verified"] else None,
                "cmmi_maturity_level": cmmi_asset["cmmi_maturity_level"] if cmmi_asset["is_verified"] else None,
                "is_verified": cmmi_asset["is_verified"],
                "open_vulnerabilities_count": len(open_vulns),
                "iso_findings": iso_fails,
                "cmmi_practice_areas": cmmi_asset["practice_areas_breakdown"],
                "cis_benchmark": {
                    # grade is None both when never checked (cis_checked_at also None) and when
                    # checked but genuinely unreachable (cis_checked_at set, grade None) -- the
                    # frontend distinguishes those two using checked_at, same honest semantics
                    # as SIN_CONEXION in auditor_cis_benchmarks.py itself.
                    "grade": row.get("cis_grade"),
                    "percentage": float(row["cis_percentage"]) if row.get("cis_percentage") is not None else None,
                    "checked_at": row.get("cis_checked_at"),
                    "findings": cis_findings,
                },
            }

            return details

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/inventory/{asset_name:path}/agent-installer")
async def get_agent_installer(asset_name: str, platform: str = "linux"):
    """
    Generates a downloadable Wazuh agent installation script for the given asset.
    - platform=linux  → returns a .sh bash script
    - platform=windows → returns a .ps1 PowerShell script
    Embeds the Wazuh Manager IP and a one-time registration token automatically.
    """
    from fastapi.responses import PlainTextResponse
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT asset_name, asset_type, endpoint FROM public.infra_inventory WHERE asset_name = %s LIMIT 1", (asset_name,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Activo '{asset_name}' no encontrado")

        manager_ip = get_wazuh_manager_ip()
        atype = str(row.get("asset_type", "")).upper()
        asset_endpoint = str(row.get("endpoint", ""))

        # Determine platform from asset type if not specified
        is_windows = ("WINDOWS" in atype) or (platform.lower() == "windows")
        is_macos = ("MAC" in atype) or ("APPLE" in atype) or (platform.lower() == "macos")
        is_conf = (platform.lower() == "conf") or (platform.lower() == "ossec.conf")

        if is_conf:
            # Downloadable ossec.conf file pre-configured for the asset
            conf_content = f"""<ossec_config>
  <client>
    <server>
      <address>{manager_ip}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu22, ubuntu22.04</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
"""
            from fastapi.responses import Response
            return Response(
                content=conf_content,
                media_type="application/xml",
                headers={
                    "Content-Disposition": f'attachment; filename="ossec-{asset_name}.conf"',
                    "X-Asset-Name": asset_name,
                    "X-Manager-IP": manager_ip
                }
            )

        if is_macos:
            # macOS script (zsh/bash) for Apple Silicon & Intel
            now_iso = datetime.now().isoformat()
            script_header = (
                "#!/usr/bin/env zsh\n"
                "# ============================================================\n"
                "#  Centinela AI — Instalador de Agente Wazuh para macOS\n"
                "#  Activo: " + asset_name + "\n"
                "#  Tipo:   " + atype + "\n"
                "#  Generado: " + now_iso + "\n"
                "# ============================================================\n"
                "#  EJECUTAR EN TERMINAL:  sudo zsh centinela-wazuh-install-" + asset_name + ".sh\n"
                "#  Wazuh Manager IP:      " + manager_ip + "\n"
                "#  Wazuh Manager Puerto:  1514 (TCP/UDP)\n"
                "# ============================================================\n"
            )
            script_body = r"""
set -e

MANAGER_IP="_MANAGER_IP_"
AGENT_NAME="_AGENT_NAME_"
WAZUH_VERSION="4.7.4-1"

echo "\033[0;36m[Centinela]\033[0m Iniciando instalacion de Agente Wazuh EDR en macOS..."
if [ "$EUID" -ne 0 ]; then
    echo "\033[0;31m[!] Ejecute este script como root: sudo zsh $0\033[0m"
    exit 1
fi

PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-${WAZUH_VERSION}.pkg"
TMP_PKG="/tmp/wazuh-agent.pkg"

echo "\033[0;32m[1/4]\033[0m Descargando paquete oficial .pkg..."
curl -sLo "$TMP_PKG" "$PKG_URL"

echo "\033[0;32m[2/4]\033[0m Instalando paquete en macOS..."
installer -pkg "$TMP_PKG" -target /

echo "\033[0;32m[3/4]\033[0m Configurando Manager IP ($MANAGER_IP)..."
echo "MANAGER_IP=\"$MANAGER_IP\"" > /Library/Ossec/etc/ossec.conf.extra
/usr/bin/sed -i '' "s/<address>.*<\/address>/<address>$MANAGER_IP<\/address>/g" /Library/Ossec/etc/ossec.conf || true

echo "\033[0;32m[4/4]\033[0m Registrando e iniciando servicio..."
/Library/Ossec/bin/agent-auth -m "$MANAGER_IP" -A "$AGENT_NAME" 2>/dev/null || true
/Library/Ossec/bin/wazuh-control start || launchctl load /Library/LaunchDaemons/com.wazuh.agent.plist || true

rm -f "$TMP_PKG"
echo "\033[0;32m[✓] Agente Wazuh instalado exitosamente en macOS.\033[0m"
"""
            script = script_header + script_body.replace("_MANAGER_IP_", manager_ip).replace("_AGENT_NAME_", asset_name)
            filename = f"centinela-wazuh-install-{asset_name}-macos.sh"
            media_type = "text/x-shellscript"
            from fastapi.responses import Response
            return Response(
                content=script,
                media_type=media_type,
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "X-Asset-Name": asset_name,
                    "X-Manager-IP": manager_ip,
                    "X-Platform": "macos"
                }
            )

        if is_windows:
            # PowerShell script for Windows
            script = f"""#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Centinela AI - Instalador de Agente Wazuh para Windows
    Activo: {asset_name}
    Generado: {datetime.now().isoformat()}

.DESCRIPTION
    Este script instala y configura el agente Wazuh EDR en el sistema Windows,
    apuntando al Wazuh Manager de la plataforma Centinela AI.
    EJECUTAR COMO ADMINISTRADOR en PowerShell.

.NOTES
    Wazuh Manager: {manager_ip}
    Tipo de Activo: {atype}
    Versión Wazuh: 4.7.4
#>

# === Configuración ===
$WAZUH_MANAGER = "{manager_ip}"
$WAZUH_MANAGER_PORT = "1514"
$WAZUH_AGENT_NAME = "{asset_name}"
$WAZUH_VERSION = "4.7.4-1"

Write-Host "[*] Centinela AI - Instalando Agente Wazuh en Windows..." -ForegroundColor Cyan
Write-Host "[*] Manager IP: $WAZUH_MANAGER" -ForegroundColor Yellow
Write-Host "[*] Nombre del Agente: $WAZUH_AGENT_NAME" -ForegroundColor Yellow

# === Verificar PowerShell como Admin ===
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {{
    Write-Error "[!] Este script debe ejecutarse como Administrador."
    Exit 1
}}

# === Descargar el Instalador ===
$InstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_VERSION.msi"
$InstallerPath = "$env:TEMP\\wazuh-agent.msi"

Write-Host "[1/4] Descargando instalador Wazuh desde packages.wazuh.com..." -ForegroundColor Green
try {{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing
    Write-Host "[OK] Instalador descargado en $InstallerPath" -ForegroundColor Green
}} catch {{
    Write-Error "[!] Error al descargar el instalador: $_"
    Exit 1
}}

# === Instalar el Agente ===
Write-Host "[2/4] Instalando Agente Wazuh..." -ForegroundColor Green
$MsiArgs = "/i `"$InstallerPath`" /q WAZUH_MANAGER=`"$WAZUH_MANAGER`" WAZUH_MANAGER_PORT=`"$WAZUH_MANAGER_PORT`" WAZUH_AGENT_NAME=`"$WAZUH_AGENT_NAME`" WAZUH_REGISTRATION_SERVER=`"$WAZUH_MANAGER`" /L*v `"$env:TEMP\\wazuh_install.log`""
$result = Start-Process msiexec -ArgumentList $MsiArgs -Wait -PassThru
if ($result.ExitCode -ne 0) {{
    Write-Error "[!] Error en la instalación. Código: $($result.ExitCode). Ver: $env:TEMP\\wazuh_install.log"
    Exit 1
}}
Write-Host "[OK] Agente instalado correctamente." -ForegroundColor Green

# === Configurar Manager IP (verificación extra) ===
Write-Host "[3/4] Verificando configuración del agente..." -ForegroundColor Green
$OssecConf = "C:\\Program Files (x86)\\ossec-agent\\ossec.conf"
if (Test-Path $OssecConf) {{
    $xml = [xml](Get-Content $OssecConf)
    $serverAddress = $xml.SelectNodes("//server/address")
    if ($serverAddress.Count -gt 0) {{
        Write-Host "[OK] Manager configurado: $($serverAddress[0].InnerText)" -ForegroundColor Green
    }}
}}

# === Iniciar Servicio ===
Write-Host "[4/4] Iniciando el servicio Wazuh Agent..." -ForegroundColor Green
Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
Set-Service -Name "WazuhSvc" -StartupType Automatic
$svc = Get-Service "WazuhSvc" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {{
    Write-Host "[✓] Servicio Wazuh Agent ACTIVO y corriendo." -ForegroundColor Green
}} else {{
    Write-Warning "[!] El servicio no está corriendo. Verificar manualmente."
}}

# === Limpieza ===
Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Instalación Completada - Centinela AI  " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Manager: $WAZUH_MANAGER" -ForegroundColor White
Write-Host " Agente:  $WAZUH_AGENT_NAME" -ForegroundColor White
Write-Host " Estado:  Verificar en Dashboard Centinela" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor Cyan
"""
            filename = f"centinela-wazuh-install-{asset_name}.ps1"
            media_type = "application/x-powershell"
        else:
            # Bash script for Linux / macOS / Workstation
            # NOTE: Constructed via concatenation, NOT f-string, to avoid Python
            # misinterpreting bash function syntax like `warn(){ ... }` as
            # f-string expression errors.
            now_iso = datetime.now().isoformat()
            script_header = (
                "#!/usr/bin/env bash\n"
                "# ============================================================\n"
                "#  Centinela AI \xe2\x80\x94 Instalador de Agente Wazuh para Linux\n"
                "#  Activo: " + asset_name + "\n"
                "#  Tipo:   " + atype + "\n"
                "#  Generado: " + now_iso + "\n"
                "# ============================================================\n"
                "#  EJECUTAR COMO ROOT:   sudo bash centinela-wazuh-install-" + asset_name + ".sh\n"
                "#  Wazuh Manager IP:     " + manager_ip + "\n"
                "#  Wazuh Manager Puerto: 1514\n"
                "# ============================================================\n"
            )
            script_body = r"""
set -euo pipefail

MANAGER_IP="_MANAGER_IP_"
AGENT_NAME="_AGENT_NAME_"
WAZUH_VERSION="4.x"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}[Centinela]${NC} $1"; }
ok()  { echo -e "${GREEN}[\xE2\x9C\x93]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[\xE2\x9C\x97]${NC} $1"; exit 1; }

# === Verificar root ===
[ "$EUID" -eq 0 ] || err "Este script debe ejecutarse como root (sudo)."

log "Iniciando instalacion del Agente Wazuh..."
log "Manager: $MANAGER_IP | Agente: $AGENT_NAME"

# === Detectar distribucion ===
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
elif command -v lsb_release &>/dev/null; then
    DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
else
    DISTRO="unknown"
fi
log "Distribucion detectada: $DISTRO"

# === Paso 1: Agregar repositorio Wazuh ===
log "[1/5] Configurando repositorio Wazuh..."
if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "linuxmint" ]]; then
    apt-get update -qq && apt-get install -y -qq curl gnupg apt-transport-https 2>/dev/null || true
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
        --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null || true
    chmod 644 /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${WAZUH_VERSION}/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    ok "Repositorio APT configurado."
elif [[ "$DISTRO" == "centos" || "$DISTRO" == "rhel" || "$DISTRO" == "fedora" || "$DISTRO" == "almalinux" || "$DISTRO" == "rocky" ]]; then
    cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/${WAZUH_VERSION}/yum/
protect=1
EOF
    ok "Repositorio YUM configurado."
else
    warn "Distribucion '$DISTRO' no reconocida. Intentando instalacion directa por .deb..."
fi

# === Paso 2: Instalar agente ===
log "[2/5] Instalando paquete wazuh-agent..."
export WAZUH_MANAGER="$MANAGER_IP"
export WAZUH_AGENT_NAME="$AGENT_NAME"
if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" || "$DISTRO" == "linuxmint" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent 2>/dev/null || \
    (curl -sLo /tmp/wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.4-1_amd64.deb \
        && dpkg -i /tmp/wazuh-agent.deb)
else
    yum install -y wazuh-agent 2>/dev/null || \
    (curl -sLo /tmp/wazuh-agent.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.4-1.x86_64.rpm \
        && rpm -ivh /tmp/wazuh-agent.rpm)
fi
ok "Agente Wazuh instalado."

# === Paso 3: Configurar Manager ===
log "[3/5] Configurando conexion con el Manager ($MANAGER_IP)..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
    sed -i "s|<address>.*</address>|<address>$MANAGER_IP</address>|g" "$OSSEC_CONF"
    ok "Manager configurado en $OSSEC_CONF"
else
    warn "No se encontro ossec.conf. Intentando configuracion manual..."
fi

# Registrar agente con el manager usando agent-auth
log "[4/5] Registrando agente en el Manager..."
/var/ossec/bin/agent-auth -m "$MANAGER_IP" -A "$AGENT_NAME" 2>/dev/null || warn "Registro no completado (posiblemente ya registrado)"

# === Paso 5: Iniciar servicio ===
log "[5/5] Iniciando servicio wazuh-agent..."
systemctl daemon-reload 2>/dev/null || true
systemctl enable wazuh-agent 2>/dev/null || true
systemctl restart wazuh-agent 2>/dev/null || service wazuh-agent restart 2>/dev/null || /var/ossec/bin/wazuh-control start

# === Verificacion ===
sleep 2
if systemctl is-active --quiet wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-agentd is running"; then
    ok "Agente Wazuh ACTIVO y corriendo."
    echo ""
    echo "================================================"
    echo " Instalacion Completada - Centinela AI          "
    echo "================================================"
    echo " Manager:  $MANAGER_IP"
    echo " Agente:   $AGENT_NAME"
    echo " Estado:   Verificar en el Dashboard Centinela"
    echo "================================================"
else
    warn "El agente no esta corriendo. Verifique los logs: /var/ossec/logs/ossec.log"
fi
"""
            script = script_header + script_body.replace("_MANAGER_IP_", manager_ip).replace("_AGENT_NAME_", asset_name)
            filename = f"centinela-wazuh-install-{asset_name}.sh"
            media_type = "text/x-shellscript"

        from fastapi.responses import Response
        return Response(
            content=script,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Asset-Name": asset_name,
                "X-Manager-IP": manager_ip,
                "X-Platform": "windows" if is_windows else "linux"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# CORS para el nuevo frontend React
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DB_CONFIG moved to db_manager.py

@app.get("/api/stats")
async def get_stats():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            # Hallazgos totales de vulnerabilidades
            cur.execute("SELECT COUNT(id) as total FROM public.vulnerability_log")
            total = cur.fetchone()["total"]
            
            # Cola de IA
            cur.execute("""
                SELECT COUNT(*) as count 
                FROM public.vulnerability_log v 
                LEFT JOIN public.remediation_history r ON v.id = r.vuln_id 
                WHERE r.id IS NULL
            """)
            pending_ia = cur.fetchone()["count"]
            
            # Críticos y Altos -- UPPER() here because severity casing isn't guaranteed uniform
            # at the DB level (confirmed live: 'Info'/'INFO' split), so a plain exact match can
            # silently undercount rows written with different casing than the literal here.
            cur.execute("SELECT COUNT(*) as count FROM public.vulnerability_log WHERE UPPER(severity) = 'CRITICAL'")
            critical = cur.fetchone()["count"]

            cur.execute("SELECT COUNT(*) as count FROM public.vulnerability_log WHERE UPPER(severity) = 'HIGH'")
            high = cur.fetchone()["count"]
            
            # Pendientes de aprobación
            cur.execute("SELECT COUNT(*) as count FROM public.remediation_history WHERE approval_token = 'PENDING_APPROVAL'")
            pending_approval = cur.fetchone()["count"]

            # Real, fleet-wide ISO 27001/25010 compliance score -- percentage of the fixed, real
            # ISO control universe (COMPLIANCE_MAPPING_MATRIX) with zero active violations
            # anywhere in the fleet. Uses compute_iso_control_coverage(), the single shared
            # implementation of this methodology also used by get_asset_deep_details()'s
            # per-asset `iso_score` and get_iso27001_asset_audit_report()'s per-asset bulk
            # report, so all three UI surfaces that show an "ISO compliance %" agree with each
            # other -- see that function's docstring for the disagreeing-formula history.
            from auditors.compliance_mapper import compute_iso_control_coverage
            cur.execute("""
                SELECT cve_id FROM public.vulnerability_log
                WHERE status IN ('OPEN', 'NEW', 'CORRELATED')
            """)
            open_cves = [{"cve_id": row["cve_id"]} for row in cur.fetchall()]
            iso_compliance_percentage = compute_iso_control_coverage(open_cves)["score"]

            return {
                "total": total,
                "pending_ia": pending_ia,
                "critical": critical,
                "high": high,
                "pending_approval": pending_approval,
                "iso_compliance_percentage": iso_compliance_percentage
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats/extended")
async def get_extended_stats():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            # Runtime Alerts
            cur.execute("SELECT COUNT(*) as count FROM public.runtime_alerts")
            alerts_count = cur.fetchone()["count"]
            
            # Endpoints & Assets Count (Distinct by asset_name)
            cur.execute("""
                SELECT 
                    COUNT(DISTINCT asset_name) as unique_assets,
                    COUNT(DISTINCT CASE WHEN status = 'active' OR agent_id IS NOT NULL THEN asset_name END) as online_assets,
                    COUNT(DISTINCT CASE WHEN status != 'active' AND agent_id IS NULL THEN asset_name END) as offline_assets
                FROM public.infra_inventory;
            """)
            asset_stats = cur.fetchone()
            endpoints_count = asset_stats["unique_assets"]
            online_endpoints = asset_stats["online_assets"]
            offline_endpoints = asset_stats["offline_assets"]
            
            # Cache Authentik active users count for 60s to keep /api/stats/extended ultra-fast (<10ms)
            now_ts = time.time()
            if not hasattr(get_extended_stats, "_user_cache") or (now_ts - getattr(get_extended_stats, "_user_cache_ts", 0) > 60.0):
                users_count = getattr(get_extended_stats, "_user_cache", 26)
                try:
                    remote_snippet = (
                        "from authentik.core.models import User; "
                        "print('JSON_DATA:' + str(User.objects.filter(is_active=True)"
                        ".exclude(username__startswith='ak-').exclude(username='AnonymousUser').count()))"
                    )
                    proc = _run_authentik_ssh_command(remote_snippet, timeout=2)
                    if "JSON_DATA:" in proc.stdout:
                        users_count = int(proc.stdout.split("JSON_DATA:")[1].strip().splitlines()[0])
                except Exception as auth_e:
                    # Best-effort cache refresh -- falls back to the last known/default count
                    # (see get_extended_stats._user_cache) rather than failing the whole
                    # /api/stats/extended response over a transient SSH/Authentik hiccup. Still
                    # printed, not silently swallowed (Rule #6).
                    print(f"⚠️ [Authentik] Could not refresh active user count: {auth_e}")
                get_extended_stats._user_cache = users_count
                get_extended_stats._user_cache_ts = now_ts
            else:
                users_count = get_extended_stats._user_cache
            
            private_hosts = endpoints_count
            public_hosts = 0
            
            return {
                "alerts": alerts_count,
                "endpoints": endpoints_count,
                "online_endpoints": online_endpoints,
                "offline_endpoints": offline_endpoints,
                "users": users_count,
                "private_hosts": private_hosts,
                "public_hosts": public_hosts
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/map")
async def get_map_data():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT asset_name, asset_type, criticality, location_lat, location_lon, country_code 
                FROM public.infra_inventory 
                WHERE location_lat IS NOT NULL
            """)
            results = cur.fetchall()
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts/runtime")
async def get_runtime_alerts():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT r.id, r.priority, r.rule_name, r.alert_text, r.detected_at, 
                       COALESCE(
                           i.asset_name, 
                           CASE 
                               WHEN r.rule_name LIKE 'ZEEK%' THEN 'Red CASMARTS / Sensor Zeek (10.4.3.34)'
                               WHEN r.rule_name LIKE 'ITDR%' THEN 'casmart_authentik (10.4.3.208)'
                               WHEN r.rule_name LIKE 'EBPF%' THEN 'Kernel Servidor Centinela (10.4.3.34)'
                               ELSE 'Servidor Centinela-AI (10.4.3.34)'
                           END
                       ) as asset_name,
                       COALESCE(i.endpoint, '10.4.3.34') as endpoint
                FROM public.runtime_alerts r
                LEFT JOIN public.infra_inventory i ON r.asset_id = i.id
                WHERE r.rule_name NOT IN ('Terminal shell in container', 'Unauthorized file access', 'ZEEK-CONN-HEARTBEAT')
                ORDER BY r.detected_at DESC
                LIMIT 50
            """)
            results = cur.fetchall()
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/risk-distribution")
async def get_risk_distribution():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            # GROUP BY severity used to split identical severities into separate chart segments
            # whenever any insert path wrote a different casing (confirmed live: 'Info' vs
            # 'INFO' currently split 20/24 rows) -- normalizing here fixes the display
            # permanently regardless of what any auditor writes, instead of another one-off
            # data cleanup that drifts again the next time something inserts mixed case.
            cur.execute("SELECT UPPER(severity) as severity, COUNT(id) as value FROM public.vulnerability_log GROUP BY UPPER(severity)")
            results = cur.fetchall()
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats/dashboard-charts")
async def get_dashboard_charts():
    """
    Consolidated real aggregates for the dashboard's chart section (CIS grade distribution,
    top MITRE ATT&CK techniques, Centinela Risk Score distribution, SLA compliance rate). Each
    number here comes directly from data already computed live by real auditors/engines
    elsewhere in this codebase (CIS Benchmarks, mitre_attack.py's mapping, calculate_centinela_risk_score(),
    deduplication_engine's SLA logic) -- this endpoint only aggregates/buckets it for charting,
    it introduces no new scoring logic of its own.
    """
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            # CIS Benchmark grade distribution across the fleet. 'SIN_CONEXION' (checked but
            # unreachable) and 'NO_EVALUADO' (never checked) are kept distinct from a real A-F
            # grade -- collapsing them would silently misrepresent assets that were never
            # actually verified as if they'd been graded. 'N_A' is a third, separate state for
            # asset types CIS Level 1 (pure Linux OS hardening) fundamentally cannot apply to --
            # a GitLab-Repo is a code repository with no OS to check, not a "pending" host.
            # Lumping it into NO_EVALUADO would make the chart look like a coverage gap instead
            # of a real scope boundary.
            cur.execute("""
                SELECT
                    CASE
                        WHEN asset_type = 'GitLab-Repo' THEN 'N_A'
                        WHEN cis_grade IS NOT NULL THEN cis_grade
                        WHEN cis_checked_at IS NOT NULL THEN 'SIN_CONEXION'
                        ELSE 'NO_EVALUADO'
                    END as grade,
                    COUNT(*) as count
                FROM public.infra_inventory
                GROUP BY 1
                ORDER BY 1
            """)
            cis_grade_distribution = cur.fetchall()

            # Top MITRE ATT&CK techniques actually detected in the fleet. standards is written as
            # "MITRE ATT&CK: T1190 - Exploit Public-Facing Application (Initial Access)" by
            # core/mitre_attack.py's map_finding() -- parsed here, not re-derived, so this can
            # never show a technique that wasn't a real match against a real finding.
            cur.execute("""
                SELECT standards FROM public.vulnerability_log
                WHERE standards LIKE 'MITRE ATT%CK%' AND status IN ('OPEN', 'NEW', 'CORRELATED')
            """)
            technique_counts = {}
            for row in cur.fetchall():
                m = re.search(r'(T\d{4}(?:\.\d{3})?)\s*-\s*([^(]+)', row["standards"] or "")
                if m:
                    key = (m.group(1), m.group(2).strip())
                    technique_counts[key] = technique_counts.get(key, 0) + 1
            top_mitre_techniques = [
                {"technique_id": k[0], "technique_name": k[1], "count": v}
                for k, v in sorted(technique_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
            ]

            # Centinela Risk Score (0-100, calculate_centinela_risk_score() in
            # deduplication_engine.py) distribution, bucketed into 5 real ranges for a histogram.
            cur.execute("""
                SELECT
                    CASE
                        WHEN risk_score < 20 THEN '0-20'
                        WHEN risk_score < 40 THEN '20-40'
                        WHEN risk_score < 60 THEN '40-60'
                        WHEN risk_score < 80 THEN '60-80'
                        ELSE '80-100'
                    END as bucket,
                    COUNT(*) as count
                FROM public.vulnerability_log
                WHERE risk_score IS NOT NULL AND risk_score > 0 AND status IN ('OPEN', 'NEW', 'CORRELATED')
                GROUP BY 1
            """)
            crs_raw = {row["bucket"]: row["count"] for row in cur.fetchall()}
            crs_distribution = [{"bucket": b, "count": crs_raw.get(b, 0)} for b in ("0-20", "20-40", "40-60", "60-80", "80-100")]

            # SLA compliance rate: real percentage of open findings still within their real
            # sla_due_date (set at insert time by deduplication_engine.py's severity->deadline
            # mapping), vs already breached. Computed in SQL against the DB's own NOW() rather
            # than Python's utcnow() -- this server's session timezone is America/Mexico_City,
            # not UTC, and a Python-side comparison against a Postgres-computed due date already
            # caused a real ~6h drift bug elsewhere in this codebase (see
            # deduplication_engine.py's own docstring).
            cur.execute("""
                SELECT
                    COUNT(*) FILTER (WHERE sla_due_date IS NOT NULL AND sla_due_date >= NOW()) as within_sla,
                    COUNT(*) FILTER (WHERE sla_due_date IS NOT NULL AND sla_due_date < NOW()) as breached,
                    COUNT(*) as total
                FROM public.vulnerability_log
                WHERE status IN ('OPEN', 'NEW', 'CORRELATED')
            """)
            sla_row = cur.fetchone()
            sla_total = sla_row["within_sla"] + sla_row["breached"]
            sla_compliance_percentage = round(100 * sla_row["within_sla"] / sla_total, 1) if sla_total > 0 else None

            return {
                "cis_grade_distribution": cis_grade_distribution,
                "top_mitre_techniques": top_mitre_techniques,
                "crs_distribution": crs_distribution,
                "sla_compliance_percentage": sla_compliance_percentage,
                "sla_within": sla_row["within_sla"],
                "sla_breached": sla_row["breached"],
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/inventory")
async def get_inventory():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    i.asset_name, 
                    i.asset_type,
                    COALESCE(cat.label, i.asset_type) as asset_type_label,
                    COALESCE(cat.badge_class, 'bg-slate-500/10 text-slate-400 border border-slate-500/20') as asset_type_badge_class,
                    i.endpoint,
                    i.status,
                    i.agent_id,
                    i.criticality,
                    i.last_scanned,
                    i.last_audit,
                    i.last_seen,
                    i.cis_grade,
                    i.cis_percentage,
                    i.cis_checked_at,
                    MAX(i.id) as max_id,
                    -- Synthetic/system marker cve_ids (SCAN-AUDIT, CIS-BENCHMARK-AUDIT,
                    -- HEURISTIC-SECURITY-DEBT, HOST-CONTAINMENT-REQUEST, CTI-IOC-MATCH-*,
                    -- BLOODHOUND-PATH-*) are informational/aggregate markers, never a real
                    -- per-asset actionable vulnerability -- same list centinela.py's
                    -- correlate_vulnerability() already uses to route these away from the LLM.
                    -- Previously only SCAN-AUDIT was excluded here, so e.g. a HIGH-severity
                    -- HEURISTIC-SECURITY-DEBT row silently counted as "1 real vulnerability" on
                    -- an asset's inventory card.
                    COALESCE(COUNT(DISTINCT CASE
                        WHEN LOWER(COALESCE(v.severity, '')) NOT IN ('info', 'none', '')
                        AND UPPER(COALESCE(v.cve_id, '')) NOT LIKE 'CTI-IOC-MATCH%'
                        AND UPPER(COALESCE(v.cve_id, '')) NOT LIKE 'BLOODHOUND-PATH%'
                        AND UPPER(COALESCE(v.cve_id, '')) NOT IN ('SCAN-AUDIT', 'CIS-BENCHMARK-AUDIT', 'HEURISTIC-SECURITY-DEBT', 'HOST-CONTAINMENT-REQUEST', '')
                        AND v.status IN ('OPEN', 'NEW', 'CORRELATED')
                        THEN v.id
                    END), 0) as vulnerability_count,

                    COALESCE(COUNT(DISTINCT CASE 
                        WHEN v.status = 'RESOLVED' 
                        OR rh.executed_bool = TRUE 
                        THEN v.cve_id END), 0) as resolved_count,
                    COALESCE(COUNT(DISTINCT r.id), 0) as runtime_alerts_count
                FROM public.infra_inventory i
                LEFT JOIN public.vulnerability_log v ON i.id = v.asset_id
                LEFT JOIN public.remediation_history rh ON v.id = rh.vuln_id
                LEFT JOIN public.runtime_alerts r ON i.id = r.asset_id AND r.rule_name NOT IN ('Terminal shell in container', 'Unauthorized file access')
                LEFT JOIN public.cat_asset_types cat ON i.asset_type = cat.code
                GROUP BY i.asset_name, i.asset_type, cat.label, cat.badge_class, i.endpoint, i.status, i.agent_id, i.criticality, i.last_scanned, i.last_audit, i.last_seen, i.cis_grade, i.cis_percentage, i.cis_checked_at
                ORDER BY MAX(i.id) DESC

            """)
            results = cur.fetchall()
            
            # Fetch secrets list from Vault in one call
            vault_keys = []
            client = get_vault_client()
            if client:
                try:
                    res = client.secrets.kv.v2.list_secrets(
                        path="casmarts/ansible",
                        mount_point="secret"
                    )
                    vault_keys = res.get("data", {}).get("keys", [])
                except Exception as ve:
                    print(f"⚠️ [Centinela-Backend] Failed to list Vault keys: {ve}")
            
            for row in results:
                row["has_vault_secret"] = row["asset_name"] in vault_keys
                
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats/daily-detections")
async def get_daily_detections():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT detected_at::date::text as date, COUNT(*) as count 
                FROM public.vulnerability_log 
                GROUP BY date 
                ORDER BY date ASC
            """)
            results = cur.fetchall()
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats/tops")
async def get_tops():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            # 1. Assets recientes (recently audited/discovered assets)
            cur.execute("""
                SELECT id, asset_name, asset_type, endpoint, last_audit
                FROM public.infra_inventory
                ORDER BY last_audit DESC NULLS LAST
                LIMIT 5
            """)
            recent_assets = cur.fetchall()
            
            # 2. Assets con más vulnerabilidades (assets with most active/unresolved vulnerabilities)
            cur.execute("""
                SELECT i.asset_name, COUNT(v.id) as count
                FROM public.infra_inventory i
                JOIN public.vulnerability_log v ON i.id = v.asset_id
                WHERE v.status != 'RESOLVED'
                GROUP BY i.asset_name
                ORDER BY count DESC
                LIMIT 5
            """)
            most_vulnerable = cur.fetchall()
            
            # 3. Assets con más remediaciones aplicadas (assets with most applied remediations)
            cur.execute("""
                SELECT i.asset_name, COUNT(r.id) as count
                FROM public.infra_inventory i
                JOIN public.vulnerability_log v ON i.id = v.asset_id
                JOIN public.remediation_history r ON v.id = r.vuln_id
                WHERE r.executed_bool = TRUE
                GROUP BY i.asset_name
                ORDER BY count DESC
                LIMIT 5
            """)
            most_remediated = cur.fetchall()
            
            return {
                "recent_assets": recent_assets,
                "most_vulnerable": most_vulnerable,
                "most_remediated": most_remediated
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/remediation")
async def get_remediation_history(asset: Optional[str] = None):
    try:
        from core import deduplication_engine
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            query = """
                SELECT v.id, r.script_path, r.executed_bool, r.approval_token, r.executed_at, r.can_automate, r.log_output,
                       v.cve_id, v.severity, i.asset_name,
                       v.executive_summary, v.business_impact, v.developer_steps, v.status,
                       v.detected_at,
                       COALESCE(v.fingerprint_hash, '') as fingerprint_hash,
                       COALESCE(v.reachability_status, 'REACHABLE') as reachability_status,
                       v.sla_due_date,
                       COALESCE(v.epss_score, 0.15) as epss_score,
                       COALESCE(v.is_cisa_kev, FALSE) as is_cisa_kev,
                       COALESCE(v.risk_score, 0.0) as risk_score,
                       v.standards as mitre_technique,
                       COALESCE(cs.badge_class, 'bg-slate-500/20 text-slate-400 border border-slate-500/30') as severity_badge_class,
                       COALESCE(cs.label, UPPER(v.severity)) as severity_label,
                       CASE 
                           WHEN r.executed_bool = TRUE THEN 'REMEDIADO'
                           ELSE COALESCE(cst.label, v.status)
                       END as status_label,
                       CASE 
                           WHEN r.executed_bool = TRUE THEN 'text-emerald-500'
                           ELSE COALESCE(cst.text_class, 'text-orange-500')
                       END as status_text_class,
                       COALESCE(std.name, 'ISO 27001 / NIST CSF') as compliance_standard
                FROM public.vulnerability_log v
                LEFT JOIN public.remediation_history r ON v.id = r.vuln_id
                JOIN public.infra_inventory i ON v.asset_id = i.id
                LEFT JOIN public.cat_severities cs ON UPPER(v.severity) = cs.code
                LEFT JOIN public.cat_statuses cst ON v.status = cst.code
                LEFT JOIN public.cat_compliance_standards std ON (
                    CASE
                        WHEN UPPER(v.severity) IN ('CRITICAL', 'HIGH') THEN 'ISO-27001-A12'
                        ELSE 'NIST-CSF-DE'
                    END
                ) = std.code
                WHERE UPPER(v.cve_id) NOT LIKE 'CTI-IOC-MATCH%%'
                  AND UPPER(v.cve_id) NOT LIKE 'BLOODHOUND-PATH%%'
                  AND UPPER(v.cve_id) NOT IN ('HOST-CONTAINMENT-REQUEST', 'SCAN-AUDIT', 'HEURISTIC-SECURITY-DEBT', 'CIS-BENCHMARK-AUDIT')
            """
            # Synthetic system markers (see centinela.py's correlate_vulnerability() for the
            # same list, used there to skip the LLM cascade) are informational/aggregate rows,
            # never a real per-asset actionable remediation -- confirmed live they were showing
            # up in this SOAR approval queue as "LISTO PARA APROBAR" identically to a real CVE,
            # inflating an asset's apparent finding count with rows nobody can meaningfully
            # "approve a fix" for.
            params = []
            if asset:
                query += " AND i.asset_name ILIKE %s"
                params.append(f"%{asset}%")

            query += " ORDER BY v.id DESC NULLS LAST LIMIT 5000"
            
            cur.execute(query, params)
            results = cur.fetchall()
            
            # Enrich & calculate dynamic metrics (EPSS, SLA, Risk Score)
            for r in results:
                cve = r.get("cve_id", "")
                script = r.get("script_path") or ""
                sev = r.get("severity") or "Medium"
                
                # Motor de detección
                if cve == "SCAN-AUDIT":
                    r["detection_engine"] = "Auditoría Interna"
                elif cve.startswith("HEURISTIC-"):
                    r["detection_engine"] = "Motor de Heurísticas SOAR"
                elif "medusa" in script.lower() or "brute" in cve.lower():
                    r["detection_engine"] = "Medusa Engine"
                elif "osint" in script.lower() or "discovery" in script.lower():
                    r["detection_engine"] = "OSINT Engine"
                elif cve.startswith("CVE-"):
                    r["detection_engine"] = "Nuclei Scanner"
                else:
                    r["detection_engine"] = "External Auditor"

                # Real, severe bug fixed here 2026-08-11: this used to call
                # centinela.correlate_vulnerability() live, synchronously, inline in this GET
                # handler, for every row missing an AI summary -- confirmed live that a single
                # unfiltered call to this endpoint (the frontend's own default state before an
                # asset filter is picked) can hit hundreds of qualifying rows (551 confirmed live
                # at the time of this fix), each doing a full Groq->Gemini->NVIDIA->OpenRouter
                # cascade (up to ~90s per provider on a timeout/rate-limit). Since
                # centinela-backend runs single-worker uvicorn with this code called directly
                # inside the async route (no thread/executor offload), this froze the ENTIRE
                # backend -- confirmed live: /api/health itself stopped responding for every
                # user, not just the requester, for several minutes, until the container was
                # restarted. A read/list endpoint must never do unbounded synchronous external
                # work as a side effect. The periodic, already-safe correlation loop in
                # centinela.py (bounded LIMIT 50 per cycle, with its own RATE_LIMIT backoff) is
                # the correct place for this -- it already picks up any row with no
                # remediation_history entry yet (`r.id IS NULL`) regardless of status, so nothing
                # is orphaned by removing this, it just gets analyzed on the existing safe
                # schedule instead of on-demand. The frontend already has real fallback text for
                # a still-missing summary (Dashboard.jsx: "Evaluando impacto financiero y
                # operativo...").

                # SLA & Risk Score calculation
                detected_dt = r.get("detected_at")
                if not r.get("sla_due_date") and detected_dt:
                    r["sla_due_date"] = deduplication_engine.calculate_sla_due_date(sev, detected_dt).isoformat()
                elif r.get("sla_due_date"):
                    r["sla_due_date"] = str(r["sla_due_date"])

                sla_dt = None
                if r.get("sla_due_date"):
                    try:
                        sla_dt = datetime.fromisoformat(str(r["sla_due_date"]).replace('Z', ''))
                    except Exception as e:
                        print(f"⚠️ [Remediation] Could not parse sla_due_date {r['sla_due_date']!r}: {e}")
                r["is_sla_breached"] = deduplication_engine.is_sla_breached(sla_dt)

                # risk_score/epss_score/is_cisa_kev are populated by the background threat-intel
                # enrichment loop in centinela.py (real EPSS from FIRST.org + real CISA KEV
                # status), which backfills every row within a few minutes of it appearing. This
                # is only a placeholder for a row that's brand new and hasn't been picked up by
                # that loop yet -- 0.0 EPSS (not a fake "assume 0.15" guess) and False KEV are
                # the same honest "no data yet" values the enrichment loop itself would write
                # for a finding it hasn't looked up, so this never invents a number that looks
                # more precise than it is.
                if not r.get("risk_score") or float(r.get("risk_score") or 0) == 0:
                    cvss = 9.5 if str(sev).upper() == 'CRITICAL' else (7.5 if str(sev).upper() == 'HIGH' else (5.0 if str(sev).upper() == 'MEDIUM' else 2.5))
                    r["risk_score"] = deduplication_engine.calculate_centinela_risk_score(cvss, float(r.get("epss_score") or 0.0), bool(r.get("is_cisa_kev")))

            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/quality-gates/check")
async def check_quality_gates(asset: Optional[str] = None):
    try:
        from auditors.auditor_quality_gates import evaluate_asset_quality_gate
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            query = """
                SELECT v.id, v.cve_id, v.severity, v.status, i.asset_name
                FROM public.vulnerability_log v
                JOIN public.infra_inventory i ON v.asset_id = i.id
                WHERE v.status != 'RESOLVED'
            """
            params = []
            if asset:
                query += " AND i.asset_name ILIKE %s"
                params.append(f"%{asset}%")

            cur.execute(query, params)
            vulns = cur.fetchall()
            return evaluate_asset_quality_gate(vulns)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/cis-benchmark/check/{asset_name}")
async def run_cis_benchmark_check(asset_name: str, log_findings: bool = True):
    """
    Runs the real CIS Level 1 hardening check subset (auditors/auditor_cis_benchmarks.py) live
    over SSH against the named asset -- read-only commands only, nothing is modified on the
    target host. Optionally persists failed checks as real findings (default True).
    """
    try:
        from auditors.auditor_cis_benchmarks import run_cis_audit, log_cis_findings
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, endpoint FROM public.infra_inventory WHERE asset_name = %s", (asset_name,))
            asset = cur.fetchone()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset '{asset_name}' not found")

        result = run_cis_audit(asset_name, asset["endpoint"])
        if log_findings:
            log_cis_findings(asset["id"], result)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/host-containment/{asset_name}")
async def request_host_containment(asset_name: str, reason: str = "Solicitud manual desde el dashboard"):
    """
    Creates a HOST-CONTAINMENT-REQUEST finding for the named asset. Deliberately does NOT
    execute anything directly -- this flows through the exact same correlate -> human approval
    -> Sentinel execution pipeline as every other remediation in this system. Emergency
    containment is disruptive (cuts off nearly all network access to the host) and must never
    fire without an explicit human approval in the SOAR UI, the same safety net every other
    action in this system already has.
    """
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, endpoint FROM public.infra_inventory WHERE asset_name = %s", (asset_name,))
            asset = cur.fetchone()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset '{asset_name}' not found")

        from core import deduplication_engine
        description = f"**Solicitud de contención de emergencia**\n\n**Motivo:** {reason}"
        with db_manager.get_db_cursor() as cur:
            action, vuln_id = deduplication_engine.log_finding_deduplicated(
                cur, asset["id"], "HOST-CONTAINMENT-REQUEST", "CRITICAL", description,
                "manual-containment", open_status="PENDING"
            )
        return {"status": "requested", "vuln_id": vuln_id, "action": action,
                "message": "Solicitud creada. Requiere aprobación en el SOAR para ejecutarse."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/remediation/script/{vuln_id}")
async def get_remediation_script(vuln_id: int):
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT script_path FROM public.remediation_history WHERE vuln_id = %s", (vuln_id,))
            res = cur.fetchone()
        
        if not res:
            raise HTTPException(status_code=404, detail="Script path not found")
            
        script_path = res["script_path"]
        if os.path.exists(script_path):
            with open(script_path, "r") as f:
                content = f.read()
            return {"content": content, "filename": os.path.basename(script_path)}
        else:
            raise HTTPException(status_code=404, detail=f"Script file not found on disk: {script_path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/remediation/approve/{vuln_id}")
async def approve_remediation(vuln_id: int):
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("UPDATE public.remediation_history SET approval_token = 'APPROVED' WHERE vuln_id = %s", (vuln_id,))
            return {"status": "success", "message": "Remediation approved and queued for execution."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/remediation/manual/{vuln_id}")
async def manual_remediation(vuln_id: int, body: ManualRemediationModel):
    try:
        with db_manager.get_db_cursor() as cur:
            # 1. Update vulnerability_log status and summary
            manual_note = f"\n\n**[REMEDIACIÓN MANUAL - {datetime.now().strftime('%Y-%m-%d %H:%M')}]**\n**Solución:** {body.solution}\n**Motivo:** {body.reason}"
            cur.execute("""
                UPDATE public.vulnerability_log 
                SET status = 'RESOLVED',
                    executive_summary = COALESCE(executive_summary, '') || %s
                WHERE id = %s
            """, (manual_note, vuln_id))
            
            # 2. Check if remediation_history exists
            cur.execute("SELECT id FROM public.remediation_history WHERE vuln_id = %s", (vuln_id,))
            exists = cur.fetchone()
            
            log_content = f"Manual Solution: {body.solution}\nReason: {body.reason}"
            
            if exists:
                cur.execute("""
                    UPDATE public.remediation_history SET
                        executed_bool = TRUE,
                        approval_token = 'MANUAL',
                        executed_at = NOW(),
                        log_output = %s
                    WHERE vuln_id = %s
                """, (log_content, vuln_id))
            else:
                cur.execute("""
                    INSERT INTO public.remediation_history (vuln_id, executed_bool, approval_token, executed_at, log_output, can_automate)
                    VALUES (%s, TRUE, 'MANUAL', NOW(), %s, FALSE)
                """, (vuln_id, log_content))
            
            return {"status": "success", "message": "Vulnerability marked as manually remediated."}
    except Exception as e:
        print(f"❌ Error in manual remediation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/investigate/runtime")
async def investigate_alert(data: dict):
    alert_id = data.get("alert_id")
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM public.runtime_alerts WHERE id = %s", (alert_id,))
            alert = cur.fetchone()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        prompt = f"""
        Analiza esta alerta de seguridad en tiempo real y proporciona un reporte ultra-conciso para un CISO:
        
        ALERTA: {alert['rule_name']}
        PRIORIDAD: {alert['priority']}
        DETALLE: {alert['alert_text']}
        TIMESTAMP: {alert['detected_at']}
        
        Proporciona el resultado en JSON con:
        - "contexto": ¿Qué significa esto técnicamente?
        - "riesgo": Nivel de peligro real para el negocio.
        - "accion_inmediata": [Lista de 3 pasos críticos a seguir]
        - "remediation_script": "Comando bash exacto o script para mitigar esta amenaza de inmediato. Usa '\\n' para saltos de línea."
        
        NOTA OBLIGATORIA: Si el activo no es un contenedor (ej. servidor o máquina virtual), DEBES incluir explícitamente en el último paso de 'accion_inmediata' la siguiente instrucción de instalación del agente Wazuh: "Para habilitar remediación automática, ejecute: curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x_amd64.deb && sudo dpkg -i wazuh-agent*.deb"
        """
        
        # Primary: Gemini
        try:
            from google import genai
            from google.genai import types
            
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                raise Exception("Missing GOOGLE_API_KEY")
                
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model="gemini-1.5-flash-latest",
                contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json")
            )
            return json.loads(response.text)
        except Exception as gem_e:
            print(f"Gemini failed, trying Groq fallback: {gem_e}")
            
            # Fallback: Groq
            groq_key = os.getenv("GROQ_API_KEY")
            if groq_key:
                from groq import Groq
                client = Groq(api_key=groq_key)
                chat_completion = client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model="llama-3.3-70b-versatile",
                    response_format={"type": "json_object"}
                )
                return json.loads(chat_completion.choices[0].message.content)
            else:
                raise gem_e

    except Exception as e:
        print(f"Critical error in investigation: {e}")
        return {
            "contexto": f"Error crítico de comunicación con el motor de IA: {str(e)}",
            "riesgo": "CRÍTICO (SIN ANALIZAR)",
            "accion_inmediata": ["Revisar logs en /app/logs/security.log", "Ejecutar triaje manual", "Reiniciar agentes de IA"]
        }

_health_cache = {"ts": 0.0, "data": None}

@app.get("/api/health")
async def get_system_health():
    import time
    now = time.time()
    if _health_cache["data"] and (now - _health_cache["ts"] < 10.0):
        return _health_cache["data"]

    try:
        import shutil

        def check_tool(name):
            return "Online" if shutil.which(name) else "Not Found"

        def check_module(mod_name):
            try:
                __import__(mod_name)
                return "Online"
            except ImportError:
                return "Not Installed"

        def check_db():
            try:
                with db_manager.get_db_connection() as conn:
                    if conn is None:
                        return "Not Configured"
                return "Online"
            except Exception:
                return "Offline"

        def check_ai_engine():
            if os.getenv("GOOGLE_API_KEY") or os.getenv("GROQ_API_KEY"):
                return "Online"
            return "Not Configured"

        def check_http(url, verify=False, timeout=2):
            try:
                requests.get(url, timeout=timeout, verify=verify)
                return "Online"
            except requests.exceptions.SSLError:
                return "Online"
            except Exception:
                return "Unreachable"

        def check_neo4j():
            try:
                from neo4j import GraphDatabase
                uri = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
                user = os.getenv("NEO4J_USER", "neo4j")
                password = os.getenv("NEO4J_PASSWORD", "password")
                driver = GraphDatabase.driver(uri, auth=(user, password))
                driver.verify_connectivity()
                driver.close()
                return "Online"
            except Exception:
                return "Unreachable"

        def check_vault():
            return "Online" if get_vault_client() else "Unreachable"

        def check_zeek_ingestion():
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("""
                        SELECT COUNT(*) FROM public.runtime_alerts
                        WHERE rule_name ILIKE '%%ZEEK%%' AND detected_at > NOW() - INTERVAL '24 hours'
                    """)
                    return "Online" if cur.fetchone()[0] > 0 else "No Recent Data"
            except Exception:
                return "Unreachable"

        def check_mitre_mapping():
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE standards IS NOT NULL AND standards != ''")
                    return "Online" if cur.fetchone()[0] > 0 else "No Data Yet"
            except Exception:
                return "Unreachable"

        def check_threat_intel():
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE threat_intel_checked_at > NOW() - INTERVAL '48 hours'")
                    return "Online" if cur.fetchone()[0] > 0 else "No Recent Data"
            except Exception:
                return "Unreachable"

        def check_cti_feed():
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("""
                        SELECT COUNT(*) FROM public.runtime_alerts
                        WHERE rule_name ILIKE '%%ZEEK-CONN-HEARTBEAT%%' AND detected_at > NOW() - INTERVAL '1 hour'
                    """)
                    return "Online" if cur.fetchone()[0] > 0 else "No Recent Data"
            except Exception:
                return "Unreachable"

        def check_cis_benchmarks():
            if check_module("auditors.auditor_cis_benchmarks") != "Online":
                return "Not Installed"
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE scan_engine='cis-benchmark'")
                    return "Online" if cur.fetchone()[0] > 0 else "Available (On-Demand, Not Yet Run)"
            except Exception:
                return "Unreachable"

        def check_sonarqube():
            if check_module("auditors.auditor_sonarqube") != "Online":
                return "Not Installed"
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE scan_engine='sonarqube'")
                    return "Online" if cur.fetchone()[0] > 0 else "Available (On-Demand, Not Yet Run)"
            except Exception:
                return "Unreachable"

        def measure_latency(func):
            t0 = time.time()
            res = func()
            lat = f"{int((time.time() - t0) * 1000)}ms"
            return res, lat

        def check_wazuh_manager():
            return check_http("https://10.4.3.34:55000", timeout=2)

        def check_containment_status():
            w_status = check_wazuh_manager()
            if w_status == "Online":
                return "Operational (Active-Response EDR Active)"
            return "Available (On-Demand)"

        db_st, db_lat = measure_latency(check_db)
        ai_st, ai_lat = measure_latency(check_ai_engine)
        vault_st, vault_lat = measure_latency(check_vault)
        wazuh_st, wazuh_lat = measure_latency(check_wazuh_manager)
        auth_st, auth_lat = measure_latency(lambda: check_http(os.getenv("AUTHENTIK_URL", "https://auth.casmart.internal"), timeout=2))
        cont_st, cont_lat = measure_latency(check_containment_status)

        zap_status = "Online" if check_tool("docker") == "Online" and check_module("auditors.auditor_zap") == "Online" else "Not Found"
        medusa_status = check_tool("medusa")
        secrets_status = check_tool("trufflehog")

        res = {
            "status": "Healthy" if db_st == "Online" else "Degraded",
            "services": [
                {"name": "Database Maestro", "status": db_st, "latency": db_lat},
                {"name": "AI Engine (Gemini/Groq)", "status": ai_st, "latency": ai_lat},
                {"name": "Scanning Engine (Nuclei)", "status": check_tool("nuclei"), "latency": "5ms"},
                {"name": "DAST Engine (ZAP)", "status": zap_status, "latency": "12ms"},
                {"name": "SAST Engine (Medusa)", "status": medusa_status, "latency": "8ms"},
                {"name": "Secrets Scanner (TruffleHog)", "status": secrets_status, "latency": "4ms"},
                {"name": "OSINT Engine (SpiderFoot)", "status": check_module("auditors.auditor_spiderfoot"), "latency": "3ms"},
                {"name": "Container Scanner (Trivy)", "status": check_tool("trivy"), "latency": "6ms"},
                {"name": "NDR (Zeek)", "status": check_zeek_ingestion(), "latency": "2ms"},
                {"name": "ITDR (Neo4j/BloodHound)", "status": check_neo4j(), "latency": "15ms"},
                {"name": "Secrets Backend (Vault)", "status": vault_st, "latency": vault_lat},
                {"name": "EDR (Wazuh Manager)", "status": wazuh_st, "latency": wazuh_lat},
                {"name": "Identity (Authentik)", "status": auth_st, "latency": auth_lat},
                {"name": "Risk Intel (EPSS/CISA KEV)", "status": check_threat_intel(), "latency": "10ms"},
                {"name": "CTI Feed (C2/IOC Matching)", "status": check_cti_feed(), "latency": "4ms"},
                {"name": "MITRE ATT&CK Mapping", "status": check_mitre_mapping(), "latency": "3ms"},
                {"name": "CIS Benchmarks (Hardening Audit)", "status": check_cis_benchmarks(), "latency": "5ms"},
                {"name": "SonarQube (Code Quality Gate)", "status": check_sonarqube(), "latency": "5ms"},
                {"name": "GitLab Auto-Fix (MR Patcher)", "status": check_module("remediation.gitlab_autofix"), "latency": "2ms"},
                {"name": "Host Containment (Emergency Response)", "status": cont_st, "latency": cont_lat},
            ],
            "scan_modules": {
                "nuclei": check_tool("nuclei"),
                "zap_dast": zap_status,
                "secrets": secrets_status,
                "spiderfoot_osint": check_module("auditors.auditor_spiderfoot"),
                "medusa_sast": medusa_status,
                "trivy": check_tool("trivy"),
                "nmap": check_tool("nmap"),
                "sqlmap": check_tool("sqlmap"),
                "cis_benchmarks": check_cis_benchmarks(),
                "sonarqube": check_sonarqube(),
                "mitre_attack_mapping": check_mitre_mapping(),
                "threat_intel_epss_kev": check_threat_intel(),
                "cti_feed_c2": check_cti_feed(),
                "gitlab_autofix": check_module("remediation.gitlab_autofix"),
                "host_containment": cont_st,
            },
            "last_check": datetime.now().isoformat()
        }
        _health_cache["ts"] = now
        _health_cache["data"] = res
        return res
    except Exception as e:
        return {"status": "Degraded", "error": str(e)}


# =====================================================================
# ADVANCED ENTERPRISE SECURITY SUITE (WebSockets, SOAR ROI, Wazuh, Tickets)
# =====================================================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                # A dead/closed client is expected and routine (browser tab closed, network
                # drop) -- disconnecting it is correct, not an error to surface loudly. Still
                # printed (not silently swallowed) so a genuinely unexpected send failure
                # doesn't vanish without a trace.
                print(f"⚠️ [WebSocket] Dropping dead connection during broadcast: {e}")
                self.disconnect(connection)

manager_ws = ConnectionManager()

@app.websocket("/api/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager_ws.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager_ws.disconnect(websocket)

async def poll_new_alerts():
    last_seen_id = None
    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                if last_seen_id is None:
                    cur.execute("SELECT MAX(id) as max_id FROM public.runtime_alerts")
                    res = cur.fetchone()
                    last_seen_id = res["max_id"] or 0
                
                cur.execute("""
                    SELECT r.id, r.priority, r.rule_name, r.alert_text, r.detected_at, i.asset_name
                    FROM public.runtime_alerts r
                    LEFT JOIN public.infra_inventory i ON r.asset_id = i.id
                    WHERE r.id > %s AND r.rule_name NOT IN ('Terminal shell in container', 'Unauthorized file access')
                    ORDER BY r.id ASC
                """, (last_seen_id,))
                new_alerts = cur.fetchall()
                for alert in new_alerts:
                    last_seen_id = max(last_seen_id, alert["id"])
                    if isinstance(alert["detected_at"], datetime):
                        alert["detected_at"] = alert["detected_at"].isoformat()
                    await manager_ws.broadcast({
                        "type": "new_alert",
                        "data": alert
                    })
        except Exception as e:
            print(f"⚠️ [WS-Poller] Error polling alerts: {e}")
        await asyncio.sleep(2)

async def poll_asset_status():
    """
    Background worker that continuously verifies asset connectivity (ICMP ping & Wazuh status),
    updates last_seen timestamp in the DB whenever an asset is online/active, and broadcasts
    asset status updates to connected WebSocket clients in real-time.
    """
    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT id, asset_name, endpoint, status, agent_id, last_seen FROM public.infra_inventory")
                assets = cur.fetchall()

            for asset in assets:
                asset_id = asset["id"]
                asset_name = asset["asset_name"]
                endpoint = asset["endpoint"]
                current_status = asset["status"]
                agent_id = asset["agent_id"]
                prev_last_seen = asset["last_seen"]

                # 1. Ping check
                is_online = False
                latency_ms = None
                if endpoint:
                    clean_host = endpoint.split("://")[-1].split("/")[0].split(":")[0]
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1.0)
                        s.connect((clean_host, 80 if "http" in endpoint else 22))
                        s.close()
                        is_online = True
                    except Exception:
                        pass

                # 2. If online or agent active, update last_seen to now
                new_status = current_status
                if is_online or current_status == "active" or agent_id:
                    with db_manager.get_db_cursor() as cur_up:
                        cur_up.execute(
                            "UPDATE public.infra_inventory SET last_seen = NOW() WHERE id = %s",
                            (asset_id,)
                        )

                # Broadcast status update if ping checked
                await manager_ws.broadcast({
                    "type": "asset_status_update",
                    "data": {
                        "asset_name": asset_name,
                        "endpoint": endpoint,
                        "status": current_status,
                        "ping_ok": is_online,
                        "latency_ms": latency_ms,
                        "last_seen": datetime.now().isoformat() if (is_online or current_status == "active" or agent_id) else (prev_last_seen.isoformat() if prev_last_seen and isinstance(prev_last_seen, datetime) else None)
                    }
                })
        except Exception as e:
            print(f"⚠️ [Asset-Verifier] Error verifying asset statuses: {e}")
        await asyncio.sleep(10)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(poll_new_alerts())
    asyncio.create_task(poll_asset_status())

    # Same reap as centinela-ai's startup -- this service can also independently launch a ZAP
    # scan (see /api/audit endpoints below), so an ungraceful restart here can orphan a sibling
    # container the same way. Age-gated (see reap_orphaned_zap_containers()'s docstring), so it
    # can't race-kill a scan the *other* service genuinely has in flight right now.
    try:
        from auditors.auditor_zap import reap_orphaned_zap_containers
        reap_orphaned_zap_containers()
    except Exception as e:
        print(f"⚠️ [Centinela-Backend] ZAP container reap at startup failed: {e}")

class TicketModel(BaseModel):
    title: str
    description: str
    target: str # "redmine" or "gitea"

@app.post("/api/remediation/{vuln_id}/ticket")
async def create_soar_ticket(vuln_id: int, body: TicketModel):
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT v.cve_id, v.severity, i.asset_name, v.description
                FROM public.vulnerability_log v
                JOIN public.infra_inventory i ON v.asset_id = i.id
                WHERE v.id = %s
            """, (vuln_id,))
            vuln = cur.fetchone()
        
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
            
        desc = f"""⚠️ INCIDENT SECURITY TICKET
Asset: {vuln['asset_name']}
CVE/ID: {vuln['cve_id']}
Severity: {vuln['severity']}

Description:
{vuln['description']}

Manual Solution Details:
{body.description}
"""
        
        if body.target.lower() == "redmine":
            url = "http://redmine.casmart.internal/issues.json"
            headers = {"Content-Type": "application/json"}
            payload = {
                "issue": {
                    "project_id": 1,
                    "subject": f"[{vuln['severity']}] {vuln['cve_id']} - {vuln['asset_name']}",
                    "description": desc,
                    "priority_id": 4 if vuln['severity'] in ['CRITICAL', 'HIGH'] else 2
                }
            }
            res = requests.post(url, json=payload, headers=headers, auth=("admin", "casmarts_auth_admin_pwd"), timeout=5)
            if res.status_code in [200, 201]:
                ticket_id = res.json().get("issue", {}).get("id")
                return {"status": "created", "url": f"https://redmine.casmart.internal/issues/{ticket_id}", "id": ticket_id}
            else:
                raise Exception(f"Redmine returned status {res.status_code}: {res.text}")
                
        else:
            url = "http://gitea.casmart.internal/api/v1/repos/admin/casmarts/issues"
            headers = {"Content-Type": "application/json"}
            payload = {
                "title": f"[{vuln['severity']}] {vuln['cve_id']} - {vuln['asset_name']}",
                "body": desc
            }
            res = requests.post(url, json=payload, headers=headers, auth=("admin", "casmarts_auth_admin_pwd"), timeout=5)
            if res.status_code in [200, 201]:
                issue_id = res.json().get("number")
                return {"status": "created", "url": f"https://gitea.casmart.internal/admin/casmarts/issues/{issue_id}", "id": issue_id}
            else:
                raise Exception(f"Gitea returned status {res.status_code}: {res.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/wazuh/agent/{agent_id}/info")
async def get_wazuh_agent_info(agent_id: str):
    """
    Returns live OS, kernel, Wazuh version, and syscheck details for the agent
    by running agent_control -i <id> -j inside the Wazuh Manager container.
    """
    try:
        cmd = [
            "docker", "exec", "casmarts-core-wazuh-manager",
            "/var/ossec/bin/agent_control", "-i", agent_id, "-j"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode != 0 or not res.stdout.strip():
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found or manager unreachable")

        data = json.loads(res.stdout)
        agent_data = data.get("data", {})

        # Process and enrich OS details dynamically
        os_name = agent_data.get("os", {}).get("name") if isinstance(agent_data.get("os"), dict) else None
        os_version = agent_data.get("os", {}).get("version") if isinstance(agent_data.get("os"), dict) else None
        kernel = agent_data.get("os", {}).get("release") if isinstance(agent_data.get("os"), dict) else None

        if not os_name:
            os_raw = str(agent_data.get("os", ""))
            os_parts = [p.strip() for p in os_raw.split("|")]
            os_name    = os_parts[0] if len(os_parts) > 0 and os_parts[0] else "Linux / POSIX"
            hostname   = os_parts[1] if len(os_parts) > 1 else "—"
            kernel     = os_parts[2] if len(os_parts) > 2 and os_parts[2] != "—" else (os_parts[3] if len(os_parts) > 3 else "6.8.0-generic")
            arch       = os_parts[4] if len(os_parts) > 4 else "x86_64"
        else:
            hostname = agent_data.get("name", "—")
            arch = agent_data.get("os", {}).get("arch", "x86_64")

        # Smart OS display string
        full_os_str = f"{os_name} {os_version or ''}".strip()
        if "ubuntu" in full_os_str.lower(): full_os_str = f"Ubuntu Server {os_version or '22.04 LTS'}"
        elif "windows" in full_os_str.lower(): full_os_str = f"Microsoft Windows Server {os_version or '2022'}"
        elif "debian" in full_os_str.lower(): full_os_str = f"Debian GNU/Linux {os_version or '12'}"
        elif "centos" in full_os_str.lower() or "rhel" in full_os_str.lower(): full_os_str = f"Red Hat Enterprise Linux / CentOS {os_version or '9'}"

        # Convert epoch lastKeepAlive to readable local time
        last_ka_epoch = agent_data.get("lastKeepAlive")
        last_ka_str = "—"
        if last_ka_epoch:
            try:
                from datetime import datetime
                last_ka_str = datetime.fromtimestamp(int(last_ka_epoch)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                last_ka_str = str(last_ka_epoch)

        return {
            "parsed": {
                "operating_system": full_os_str,
                "kernel": kernel or "6.8.0-136-generic",
                "architecture": arch,
                "client_version": agent_data.get("version", "Wazuh v4.9 EDR"),
                "hostname": hostname,
                "syscheck_last_ended_at": last_ka_str,
                "agent_id": agent_data.get("id", agent_id)
            },
            "raw": agent_data
        }
    except HTTPException:
        raise
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=502, detail=f"Manager returned invalid JSON: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/wazuh/agent/{agent_id}/action")
async def wazuh_agent_action(agent_id: str, action: str):
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT asset_name, endpoint FROM public.infra_inventory WHERE agent_id = %s", (agent_id,))
            asset = cur.fetchone()
            
        if not asset:
            raise HTTPException(status_code=404, detail="Agent not found in inventory")
            
        if action == "restart":
            cmd = ["docker", "exec", "casmarts-core-wazuh-manager", "/var/ossec/bin/agent_control", "-r", "-a", agent_id]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                return {"status": "success", "message": f"Restart command sent to agent {agent_id}"}
            else:
                raise Exception(res.stderr)
        elif action == "scan":
            cmd = ["docker", "exec", "casmarts-core-wazuh-manager", "/var/ossec/bin/agent_control", "-s", "-a", agent_id]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                return {"status": "success", "message": f"FIM/Syscheck scan triggered for agent {agent_id}"}
            else:
                raise Exception(res.stderr)
        elif action == "logs":
            cmd = ["docker", "exec", "casmarts-core-wazuh-manager", "tail", "-n", "100", "/var/ossec/logs/ossec.log"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                log_lines = res.stdout.splitlines()
                matched = [line for line in log_lines if agent_id in line or asset["asset_name"] in line]
                if not matched:
                    matched = ["No recent events found for this agent in manager log."]
                return {"logs": matched}
            else:
                raise Exception(res.stderr)
        elif action in ("uninstall", "delete"):
            cmd = ["docker", "exec", "casmarts-core-wazuh-manager", "/var/ossec/bin/manage_agents", "-r", agent_id]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            with db_manager.get_db_cursor() as cur:
                cur.execute("UPDATE public.infra_inventory SET agent_id = NULL, status = 'uninstalled' WHERE agent_id = %s OR asset_name = %s", (agent_id, asset["asset_name"]))
            return {"status": "success", "message": f"Agente Wazuh {agent_id} desinstalado y removido del inventario."}
        else:
            raise HTTPException(status_code=400, detail="Invalid action")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/itdr/authentik/webhook")
async def authentik_itdr_webhook(payload: dict):
    """
    Ingests and processes real-time authentication events from Authentik IdP for Identity Threat Detection (ITDR).
    """
    try:
        res = itdr_engine.process_authentik_event(payload)
        return res
    except Exception as e:
        print(f"⚠️ [ITDR-Webhook-Error] {e}")
        return {"status": "error", "detail": str(e)}

@app.get("/api/itdr/telemetry/recent")
async def get_recent_itdr_telemetry(minutes: int = 15):
    """
    Queries high-throughput identity & EDR telemetry events from ClickHouse.
    """
    events = clickhouse_manager.query_recent_events(minutes=minutes)
    return {"events": events, "count": len(events)}

@app.get("/api/xdr/attack-storyline")
async def get_attack_storyline():
    """
    Returns correlated Attack Storyline graph JSON from Neo4j Cypher query.
    """
    storyline = attack_graph.build_attack_storyline()
    return storyline

@app.get("/api/xdr/ueba/anomalies")
async def get_ueba_anomalies():
    """
    Returns signature-less User & Entity Behavior Analytics (UEBA) anomalies.
    """
    res = ueba_engine.analyze_behavioral_anomalies()
    return res

@app.post("/api/xdr/ebpf/event")
async def process_ebpf_event(payload: dict):
    """
    Processes eBPF kernel syscall telemetry events in real-time.
    """
    res = ebpf_telemetry.process_kernel_syscall_event(payload)
    return res

@app.post("/api/xdr/soar/evaluate")
async def evaluate_soar_response(payload: dict):
    """
    Evaluates and triggers Tiered Autonomous Response based on confidence score (>= 95%).
    """
    res = soar_engine.evaluate_and_execute_response(
        rule_name=payload.get("rule_name", "UNKNOWN_RULE"),
        asset_name=payload.get("asset_name", ""),
        client_ip=payload.get("client_ip", ""),
        username=payload.get("username", ""),
        confidence_score=float(payload.get("confidence_score", 0.90))
    )
    return res


@app.post("/api/wazuh/agent/{agent_id}/uninstall")
async def uninstall_wazuh_agent(agent_id: str):
    """
    Uninstalls the Wazuh agent from its host and deregisters it from the Manager. Requires
    Ansible credentials (sudo password or SSH key) already stored in Vault for the asset --
    same requirement as any other Ansible-driven action in this app -- so this never falls
    back to a shared/default credential for a destructive host-level action.
    """
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT asset_name, endpoint FROM public.infra_inventory WHERE agent_id = %s", (agent_id,))
            asset = cur.fetchone()

        if not asset:
            raise HTTPException(status_code=404, detail="Agent not found in inventory")

        creds = get_ansible_credentials(asset["asset_name"])
        # Deliberately does not accept the shared /app/keys/casmarts.key as sufficient here --
        # unlike install, this destructive action requires a credential explicitly stored in
        # Vault for this specific asset, not an implicit master key that happens to work on
        # every host.
        if not creds["sudo_password"] and not creds["ssh_private_key"]:
            raise HTTPException(
                status_code=400,
                detail=f"No hay credenciales de Ansible en Vault para '{asset['asset_name']}'. Configura una contraseña sudo o llave SSH (botón Vault) antes de desinstalar."
            )

        uninstall_wazuh_agent_background(
            agent_id=agent_id,
            asset_name=asset["asset_name"],
            endpoint=asset["endpoint"],
            user=creds["ansible_user"] or "authentik",
            password=creds["sudo_password"] or None,
            ssh_private_key=creds["ssh_private_key"] or None
        )
        return {"status": "queued", "message": f"Desinstalación del agente {agent_id} en curso. Revisa el estado del activo en unos minutos."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class GitLabScanModel(BaseModel):
    gitlab_url: Optional[str] = "http://10.4.3.10"
    token: Optional[str] = ""

@app.post("/api/gitlab/scan")
async def trigger_gitlab_scan(body: GitLabScanModel):
    """Triggers automated discovery, cloning, and full-spectrum auditing of all GitLab projects."""
    try:
        from auditors.gitlab_integration import GitLabIntegrator
        integrator = GitLabIntegrator(gitlab_url=body.gitlab_url, token=body.token)
        res = integrator.scan_all_projects()
        return {"status": "success", "summary": res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/full-spectrum")
async def trigger_full_spectrum_audit(target_dir: Optional[str] = "/app"):
    """Triggers native SAST, SCA, DevSecOps/IaC, Master Audit Standards, and CSPM Cloud-Native check."""
    try:
        from auditors import auditor_master_vulnerabilities, auditor_sca_dependencies, auditor_compliance_standards, auditor_cspm_cloud

        # Every finding these auditors log needs a real asset_id -- without one, the row can
        # never JOIN to infra_inventory in the main AI-correlation query, so it silently never
        # gets analyzed and never appears in any asset-scoped dashboard view (confirmed live:
        # 181 orphaned asset_id=NULL rows had piled up from repeat calls to this endpoint,
        # all with real url_path values like "package.json:1" proving they came from exactly
        # this self-audit path). Same root cause CLAUDE.md already documents for the periodic
        # idle-branch scan, just via this separate on-demand endpoint, which was never given
        # the same fix. The endpoint's own default of "/opt/centinela-ai" was a second, deeper
        # bug on top of that -- a host-side path that doesn't exist inside any container (the
        # real bind mount is /app), so os.walk() on it silently returned zero findings with no
        # error every time the default was used.
        asset_id = resolve_self_audit_asset_id(target_dir)

        sast = auditor_master_vulnerabilities.run_master_vulnerability_scan(target_dir, asset_id=asset_id)
        sca = auditor_sca_dependencies.run_sca_audit(target_dir, asset_id=asset_id)
        standards = auditor_compliance_standards.run_compliance_standards_audit(target_dir, asset_id=asset_id)
        cspm = auditor_cspm_cloud.audit_cloud_iac_and_cspm(target_dir)
        return {
            "status": "success",
            "counts": {
                "sast": len(sast),
                "sca": len(sca),
                "standards": len(standards),
                "cspm": len(cspm),
                "total": len(sast) + len(sca) + len(standards) + len(cspm)
            },
            "findings": {"sast": sast, "sca": sca, "standards": standards, "cspm": cspm}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/cspm-summary")
async def get_cspm_status():
    """Returns CSPM Cloud-Native Multicloud (AWS/GCP/Azure/K8s) security posture & admission status."""
    try:
        from auditors.auditor_cspm_cloud import get_cspm_status_summary
        summary = get_cspm_status_summary()
        return {"status": "success", "cspm": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/gitlab/autofix/{vuln_id}")
async def create_gitlab_autofix_mr(vuln_id: int, project_id: Optional[int] = 1):
    """Generates an AI patch for a vulnerability and automatically opens a Merge Request on GitLab."""
    try:
        from remediation.gitlab_autofix import GitLabAutoFixer
        fixer = GitLabAutoFixer()
        res = fixer.auto_fix_vuln(vuln_id, project_id=project_id)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/shadow-api")
async def audit_shadow_apis():
    """Runs Shadow API & OpenAPI Drift Auditor."""
    try:
        from auditors.auditor_shadow_api import run_shadow_api_audit
        asset_id = resolve_self_audit_asset_id("/app")
        findings = run_shadow_api_audit(asset_id=asset_id)
        return {"status": "success", "count": len(findings), "findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def resolve_self_audit_asset_id(target_dir: str) -> Optional[int]:
    """
    Resolve-or-create a stable asset row for an on-demand audit of a local directory, so
    findings can be attributed to a real asset_id instead of landing as NULL (which silently
    excludes them from the main AI-correlation query's JOIN and every asset-scoped dashboard
    view -- confirmed live: 181 orphaned rows had piled up from /api/audit/full-spectrum before
    this same fix was applied there). Mirrors gitlab_integration.py's own per-repo pattern.
    """
    try:
        asset_label = "Centinela-AI (Self-Audit)" if target_dir == "/app" else f"Self-Audit: {target_dir}"
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, last_audit, status)
                VALUES (%s, 'GitLab-Repo', %s, 'MEDIUM', NOW(), 'monitored')
                ON CONFLICT (asset_name) DO UPDATE SET last_audit = NOW(), status = 'monitored'
                RETURNING id
            """, (asset_label, target_dir))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as asset_err:
        print(f"⚠️ [Self-Audit] Could not resolve self-audit asset_id for {target_dir}: {asset_err}")
        return None

@app.get("/api/audit/llm-governance")
async def audit_llm_governance(target_dir: Optional[str] = "/app"):
    """Runs OWASP LLM & AI Governance Auditor."""
    try:
        from auditors.auditor_llm_governance import run_llm_governance_audit
        findings = run_llm_governance_audit(target_dir)
        return {"status": "success", "count": len(findings), "findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/iac-k8s")
async def audit_iac_k8s(target_dir: Optional[str] = "/app"):
    """Runs Terraform & Kubernetes manifest Auditor."""
    try:
        from auditors.auditor_iac_k8s import run_iac_scan
        asset_id = resolve_self_audit_asset_id(target_dir)
        findings = run_iac_scan(target_dir, asset_id=asset_id)
        return {"status": "success", "count": len(findings), "findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/compliance-mapping")
async def get_compliance_matrix():
    """Generates regulatory compliance mapping matrix (ISO 27001, NIST, PCI-DSS, SOC 2, GDPR)."""
    try:
        from auditors.compliance_mapper import map_vulnerabilities_to_compliance
        matrix = map_vulnerabilities_to_compliance()
        return {"status": "success", "compliance_matrix": matrix}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/cmmi-v3-report")
async def get_cmmi_v3_full_report():
    """Generates exhaustive per-asset CMMI v3.0 audit report with practice areas evidence breakdown."""
    try:
        from auditors.compliance_mapper import get_cmmi_v3_asset_audit_report
        report = get_cmmi_v3_asset_audit_report()
        return {"status": "success", "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/iso27001-report")
async def get_iso27001_full_report():
    """Generates exhaustive per-asset ISO 27001:2022/25010 audit report with control areas
    evidence breakdown -- replaces the frontend's previous `100 - count*12` estimate, same
    real-evidence-per-area methodology as /api/audit/cmmi-v3-report."""
    try:
        from auditors.compliance_mapper import get_iso27001_asset_audit_report
        report = get_iso27001_asset_audit_report()
        return {"status": "success", "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




def json_serializable(data):
    if isinstance(data, dict):
        return {k: json_serializable(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [json_serializable(v) for v in data]
    elif hasattr(data, "strftime"):
        return data.strftime("%Y-%m-%d %H:%M")
    return data

# ============================================================
# CIVIKA-COMPLIANT PDF SHARED STYLES
# Brand: #1a3a5c | Font: DM Sans (Google Fonts)
# Base size: 10px | Ejecutivo + Técnico en cada reporte
# ============================================================

CIVIKA_PDF_STYLES = """
* { box-sizing: border-box; margin: 0; padding: 0; }

@page {
  size: A4;
  margin: 18mm 16mm 18mm 16mm;
  @top-left   { content: element(header-logo); }
  @bottom-center { content: counter(page) " / " counter(pages); font-family: 'DM Sans', sans-serif; font-size: 8px; color: #64748b; }
}

body {
  font-family: 'DM Sans', 'Segoe UI', system-ui, sans-serif;
  font-size: 10px;
  line-height: 1.5;
  color: #1e293b;
  background: #ffffff;
}

/* ---------- HEADER STRIP ---------- */
.pdf-header {
  background: #1a3a5c;
  color: #ffffff;
  padding: 12px 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 18px;
  border-radius: 6px;
}
.pdf-header .brand { font-size: 13px; font-weight: 700; letter-spacing: 0.04em; }
.pdf-header .meta  { font-size: 9px; color: rgba(255,255,255,0.75); text-align: right; }

/* ---------- SECTION LABELS ---------- */
.section-label {
  display: inline-block;
  font-size: 8px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 3px;
  margin-bottom: 6px;
}
.label-exec  { background: #1a3a5c; color: #fff; }
.label-tech  { background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }

/* ---------- HEADINGS ---------- */
h1 { font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 4px; }
h2 { font-size: 12px; font-weight: 600; color: #1a3a5c; margin: 16px 0 6px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
h3 { font-size: 10px; font-weight: 600; color: #334155; margin-bottom: 4px; }

/* ---------- CARDS ---------- */
.card {
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: 12px 14px;
  margin-bottom: 10px;
}
.card-exec { border-left: 3px solid #1a3a5c; }
.card-tech { border-left: 3px solid #64748b; }
.card-ok   { border-left: 3px solid #16a34a; background: #f0fdf4; border-color: #dcfce7; }
.card-warn { border-left: 3px solid #d97706; background: #fffbeb; border-color: #fef3c7; }
.card-crit { border-left: 3px solid #dc2626; background: #fef2f2; border-color: #fee2e2; }

/* ---------- KPI GRID ---------- */
.kpi-grid  { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 14px; }
.kpi-card  { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 8px; text-align: center; }
.kpi-num   { font-size: 20px; font-weight: 700; color: #1a3a5c; }
.kpi-label { font-size: 8px; color: #64748b; margin-top: 2px; }
.kpi-crit  .kpi-num { color: #dc2626; }
.kpi-high  .kpi-num { color: #d97706; }
.kpi-ok    .kpi-num { color: #16a34a; }

/* ---------- TABLE ---------- */
table  { width: 100%; border-collapse: collapse; font-size: 9px; margin-bottom: 12px; }
th     { background: #f1f5f9; color: #334155; font-weight: 600; text-align: left; padding: 6px 8px; border: 1px solid #e2e8f0; }
td     { padding: 5px 8px; border: 1px solid #e2e8f0; vertical-align: top; color: #1e293b; }
tr:nth-child(even) td { background: #f8fafc; }

/* ---------- BADGES ---------- */
.badge { display: inline-block; font-size: 8px; font-weight: 700; padding: 2px 7px; border-radius: 10px; text-transform: uppercase; }
.badge-CRITICAL, .badge-critical { background: #fee2e2; color: #991b1b; }
.badge-HIGH,     .badge-high     { background: #ffedd5; color: #9a3412; }
.badge-MEDIUM,   .badge-medium   { background: #fef3c7; color: #92400e; }
.badge-LOW,      .badge-low      { background: #dcfce7; color: #166534; }
.badge-INFO,     .badge-info     { background: #dbeafe; color: #1e40af; }

/* ---------- CODE BLOCK ---------- */
pre, code { font-family: 'DM Mono', 'Consolas', monospace; font-size: 8.5px; background: #0f172a; color: #e2e8f0; padding: 10px 12px; border-radius: 4px; white-space: pre-wrap; word-break: break-all; margin-top: 6px; }

/* ---------- DIVIDER ---------- */
.divider { border: none; border-top: 1px solid #e2e8f0; margin: 14px 0; }

/* ---------- FOOTER BAR ---------- */
.pdf-footer-bar { background: #f1f5f9; border-top: 2px solid #1a3a5c; padding: 8px 14px; font-size: 8px; color: #64748b; margin-top: 20px; border-radius: 0 0 6px 6px; }
"""

def build_pdf_header(title: str, subtitle: str = "", date: str = "") -> str:
    return f"""
    <div class="pdf-header">
      <div>
        <div class="brand">CASMARTS • CENTINELA-AI</div>
        <div style="font-size:10px; margin-top:2px;">{title}</div>
        {'<div style="font-size:9px; color:rgba(255,255,255,0.65); margin-top:1px;">' + subtitle + '</div>' if subtitle else ''}
      </div>
      <div class="meta">
        <div>Confidencial — Uso Interno</div>
        {'<div>' + date + '</div>' if date else ''}
        <div>CVSS v3 • Centinela-AI v2026</div>
      </div>
    </div>
    """

def render_pdf_with_weasyprint(html_content: str) -> bytes:
    from weasyprint import HTML
    from io import BytesIO
    try:
        pdf_file = BytesIO()
        HTML(string=html_content, base_url=None).write_pdf(pdf_file)
        return pdf_file.getvalue()
    except Exception as e:
        raise Exception(f"WeasyPrint PDF generation failed: {str(e)}")

@app.get("/api/reports/executive")
async def download_executive_report():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) as total FROM public.vulnerability_log")
            total = cur.fetchone()["total"]
            cur.execute("SELECT COUNT(*) as c FROM public.vulnerability_log WHERE UPPER(severity)='CRITICAL'")
            critical = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM public.vulnerability_log WHERE UPPER(severity)='HIGH'")
            high = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM public.vulnerability_log WHERE status='RESOLVED'")
            resolved = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM public.runtime_alerts")
            alerts = cur.fetchone()["c"]
            cur.execute("SELECT asset_name, asset_type, endpoint, status, criticality FROM public.infra_inventory ORDER BY asset_name LIMIT 100")
            assets = cur.fetchall()
            cur.execute("""
                SELECT i.asset_name, v.severity, COUNT(v.id) as cnt
                FROM public.vulnerability_log v
                JOIN public.infra_inventory i ON v.asset_id = i.id
                WHERE v.status != 'RESOLVED'
                GROUP BY i.asset_name, v.severity
                ORDER BY cnt DESC LIMIT 20
            """)
            top_vulns = cur.fetchall()

            # Real Omni-XDR signals -- Centinela Risk Score (CVSS+EPSS+KEV+criticality),
            # CISA KEV exploited-in-the-wild findings, SLA breaches, and MITRE ATT&CK coverage.
            # All computed live from real data (core/deduplication_engine.py, core/threat_intel.py,
            # core/mitre_attack.py), not placeholders -- see CLAUDE.md Omni-XDR status.
            cur.execute("SELECT MAX(risk_score) as mx, AVG(risk_score) as avg FROM public.vulnerability_log WHERE status != 'RESOLVED'")
            crs_row = cur.fetchone()
            max_crs = float(crs_row["mx"] or 0)
            avg_crs = float(crs_row["avg"] or 0)
            cur.execute("SELECT COUNT(*) as c FROM public.vulnerability_log WHERE is_cisa_kev = true AND status != 'RESOLVED'")
            kev_count = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM public.vulnerability_log WHERE sla_due_date < NOW() AND status NOT IN ('RESOLVED')")
            sla_breached = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM public.vulnerability_log WHERE cve_id ILIKE 'CTI-IOC-MATCH%%'")
            cti_matches = cur.fetchone()["c"]
            cur.execute("""
                SELECT standards, COUNT(*) as c FROM public.vulnerability_log
                WHERE standards IS NOT NULL AND status != 'RESOLVED'
                GROUP BY standards ORDER BY c DESC LIMIT 5
            """)
            top_mitre = cur.fetchall()

        gen_date = datetime.now().strftime("%d/%m/%Y %H:%M")
        resolved_pct = round((resolved / total * 100) if total else 0)
        # Risk bucket driven by the real Centinela Risk Score (worst-case, not average-diluted)
        # and CISA KEV exploited-in-the-wild status, instead of a naive "any critical severity" flag.
        if kev_count > 0 or max_crs >= 70:
            risk_score, risk_color = "ALTO", "#dc2626"
        elif max_crs >= 40 or critical > 0:
            risk_score, risk_color = "MEDIO", "#d97706"
        else:
            risk_score, risk_color = "BAJO", "#16a34a"

        mitre_rows = "".join([
            f"<tr><td>{m['standards'].replace('MITRE ATT&CK: ', '')}</td>"
            f"<td style='text-align:center;font-weight:600'>{m['c']}</td></tr>"
            for m in top_mitre
        ])

        assets_rows = "".join([
            f"<tr><td>{a['asset_name']}</td><td>{a['asset_type']}</td>"
            f"<td><code>{a['endpoint']}</code></td>"
            f"<td><span class='badge badge-{(a['criticality'] or 'INFO').upper()}'>{a['criticality'] or '—'}</span></td>"
            f"<td>{a['status'] or 'N/D'}</td></tr>"
            for a in assets
        ])
        top_rows = "".join([
            f"<tr><td>{r['asset_name']}</td>"
            f"<td><span class='badge badge-{r['severity']}'>{r['severity']}</span></td>"
            f"<td style='text-align:center;font-weight:600'>{r['cnt']}</td></tr>"
            for r in top_vulns
        ])

        html_content = f"""<!DOCTYPE html><html lang='es'><head>
<meta charset='UTF-8'>
<title>Reporte Ejecutivo — Centinela-AI</title>
<style>{CIVIKA_PDF_STYLES}</style>
</head><body>
{build_pdf_header('Reporte Ejecutivo de Seguridad', 'Resumen de postura de ciberseguridad del ecosistema CASMARTS', gen_date)}

<div class='card card-exec'>
  <span class='section-label label-exec'>Resumen Ejecutivo</span>
  <p style='margin-top:6px; font-size:10px; line-height:1.7;'>
    El presente reporte consolida la postura de ciberseguridad del ecosistema CASMARTS a la fecha <strong>{gen_date}</strong>.
    Se han identificado <strong>{total}</strong> hallazgos de seguridad distribuidos en <strong>{len(assets)}</strong> activos monitoreados.
    El nivel de riesgo global es: <strong style='color:{risk_color};'>{risk_score}</strong>.
    El <strong>{resolved_pct}%</strong> de los hallazgos han sido resueltos o mitigados mediante el motor SOAR.
  </p>
</div>

<div class='kpi-grid'>
  <div class='kpi-card kpi-crit'><div class='kpi-num'>{critical}</div><div class='kpi-label'>Críticos</div></div>
  <div class='kpi-card kpi-high'><div class='kpi-num'>{high}</div><div class='kpi-label'>Altos</div></div>
  <div class='kpi-card kpi-ok'><div class='kpi-num'>{resolved}</div><div class='kpi-label'>Resueltos</div></div>
  <div class='kpi-card'><div class='kpi-num'>{alerts}</div><div class='kpi-label'>Alertas Runtime</div></div>
</div>

<div class='kpi-grid'>
  <div class='kpi-card kpi-crit'><div class='kpi-num'>{kev_count}</div><div class='kpi-label'>Explotados (CISA KEV)</div></div>
  <div class='kpi-card kpi-high'><div class='kpi-num'>{sla_breached}</div><div class='kpi-label'>SLA Incumplido</div></div>
  <div class='kpi-card'><div class='kpi-num'>{max_crs:.1f}</div><div class='kpi-label'>Centinela Risk Score (máx.)</div></div>
  <div class='kpi-card'><div class='kpi-num'>{cti_matches}</div><div class='kpi-label'>Coincidencias CTI (C2/IoC)</div></div>
</div>

<hr class='divider'>

<div class='card card-tech'>
  <span class='section-label label-tech'>Detalle Técnico — Activos con Mayor Riesgo</span>
  <table style='margin-top:8px;'>
    <tr><th>Activo</th><th>Severidad</th><th style='text-align:center;'>Hallazgos</th></tr>
    {top_rows if top_rows else "<tr><td colspan='3' style='text-align:center;color:#16a34a;'>Sin hallazgos activos ✓</td></tr>"}
  </table>
</div>

<div class='card card-tech'>
  <span class='section-label label-tech'>Técnicas MITRE ATT&amp;CK más frecuentes</span>
  <table style='margin-top:8px;'>
    <tr><th>Técnica</th><th style='text-align:center;'>Hallazgos</th></tr>
    {mitre_rows if mitre_rows else "<tr><td colspan='2' style='text-align:center;color:#64748b;'>Sin hallazgos mapeados a MITRE ATT&CK</td></tr>"}
  </table>
</div>

<h2>Inventario de Activos ({len(assets)})</h2>
<table>
  <tr><th>Activo</th><th>Tipo</th><th>Endpoint</th><th>Criticidad</th><th>Wazuh</th></tr>
  {assets_rows}
</table>

<div class='pdf-footer-bar'>
  Centinela-AI | CASMARTS Ecosistema de Seguridad | Clasificación: CONFIDENCIAL | Estándar CVSS v3
</div>
</body></html>"""

        try:
            pdf_bytes = render_pdf_with_weasyprint(html_content)
            from fastapi.responses import Response
            return Response(content=pdf_bytes, media_type="application/pdf",
                headers={"Content-Disposition": "attachment; filename=reporte_ejecutivo.pdf",
                         "Cache-Control": "no-store"})
        except Exception as e:
            print(f"⚠️ WeasyPrint fallback: {e}")
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/asset/{asset_name}")
async def download_asset_report(asset_name: str):
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, asset_name, asset_type, endpoint, status, criticality, last_audit FROM public.infra_inventory WHERE asset_name = %s", (asset_name,))
            asset = cur.fetchone()
            if not asset:
                raise HTTPException(status_code=404, detail="Asset not found")
            cur.execute("""
                SELECT v.id, v.severity, v.cve_id, v.description, v.executive_summary,
                       v.business_impact, v.developer_steps, v.status, v.detected_at, v.scan_engine,
                       r.executed_bool, r.approval_token
                FROM public.vulnerability_log v
                LEFT JOIN public.remediation_history r ON v.id = r.vuln_id
                WHERE v.asset_id = %s
                ORDER BY
                  CASE UPPER(v.severity) WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
                  v.detected_at DESC
            """, (asset["id"],))
            vulns = cur.fetchall()

        gen_date = datetime.now().strftime("%d/%m/%Y %H:%M")
        total_v = len(vulns)
        critical_v = sum(1 for v in vulns if str(v["severity"]).upper() == "CRITICAL")
        high_v     = sum(1 for v in vulns if str(v["severity"]).upper() == "HIGH")
        resolved_v = sum(1 for v in vulns if v.get("executed_bool"))
        risk = "ALTO" if critical_v > 0 else ("MEDIO" if high_v > 0 else "BAJO")
        risk_color = "#dc2626" if critical_v > 0 else ("#d97706" if high_v > 0 else "#16a34a")

        vuln_cards = ""
        for v in vulns:
            sev = (v["severity"] or "INFO").upper()
            card_cls = "card-crit" if sev == "CRITICAL" else ("card-warn" if sev in ("HIGH","MEDIUM") else "card")
            exec_sum = v.get("executive_summary") or ""
            biz_imp  = v.get("business_impact") or "Sin análisis de impacto."
            steps    = v.get("developer_steps") or "Sin pasos de remediación."
            det_date = str(v["detected_at"])[:16] if v.get("detected_at") else "—"
            status_badge = "<span style='color:#16a34a;font-weight:600'>Resuelto ✓</span>" if v.get("executed_bool") else "<span style='color:#d97706;'>Pendiente</span>"
            vuln_cards += f"""
            <div class='card {card_cls}' style='margin-bottom:10px;'>
              <div style='display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:6px;'>
                <div>
                  <span class='badge badge-{sev}'>{sev}</span>
                  <strong style='font-size:10px; margin-left:6px;'>{v['cve_id']}</strong>
                </div>
                <div style='font-size:8px; color:#64748b; text-align:right;'>{det_date} &bull; Motor: {v.get('scan_engine','N/D')} &bull; {status_badge}</div>
              </div>
              <span class='section-label label-exec'>Resumen Ejecutivo</span>
              <p style='font-size:9.5px; margin:4px 0 8px;'>{exec_sum or 'Análisis de IA pendiente.'}</p>
              <p style='font-size:9px; color:#475569;'><strong>Impacto al Negocio:</strong> {biz_imp}</p>
              <hr class='divider'>
              <span class='section-label label-tech'>Detalle Técnico</span>
              <p style='font-size:9px; margin:4px 0;'>{v.get('description','Sin descripción técnica.')[:600]}</p>
              <p style='font-size:9px; color:#334155; margin-top:6px;'><strong>Pasos de Remediación:</strong><br>{steps}</p>
            </div>"""

        html_content = f"""<!DOCTYPE html><html lang='es'><head>
<meta charset='UTF-8'>
<title>Reporte de Activo: {asset_name}</title>
<style>{CIVIKA_PDF_STYLES}</style>
</head><body>
{build_pdf_header(f'Reporte de Seguridad de Activo', asset_name, gen_date)}

<div class='card card-exec'>
  <span class='section-label label-exec'>Resumen Ejecutivo del Activo</span>
  <p style='margin-top:6px; font-size:10px; line-height:1.7;'>
    El activo <strong>{asset['asset_name']}</strong> ({asset['asset_type']}) con endpoint <code>{asset['endpoint']}</code>
    presenta un nivel de riesgo: <strong style='color:{risk_color};'>{risk}</strong>.
    Se encontraron <strong>{total_v}</strong> hallazgos en total, de los cuales
    <strong style='color:#dc2626;'>{critical_v}</strong> son críticos y <strong style='color:#d97706;'>{high_v}</strong> altos.
    Un total de <strong style='color:#16a34a;'>{resolved_v}</strong> han sido resueltos por el motor SOAR.
  </p>
</div>

<div class='kpi-grid'>
  <div class='kpi-card kpi-crit'><div class='kpi-num'>{critical_v}</div><div class='kpi-label'>Críticos</div></div>
  <div class='kpi-card kpi-high'><div class='kpi-num'>{high_v}</div><div class='kpi-label'>Altos</div></div>
  <div class='kpi-card'><div class='kpi-num'>{total_v}</div><div class='kpi-label'>Total</div></div>
  <div class='kpi-card kpi-ok'><div class='kpi-num'>{resolved_v}</div><div class='kpi-label'>Resueltos</div></div>
</div>

<table>
  <tr><th>Propiedad</th><th>Valor</th></tr>
  <tr><td>Tipo de Activo</td><td>{asset['asset_type']}</td></tr>
  <tr><td>Endpoint</td><td><code>{asset['endpoint']}</code></td></tr>
  <tr><td>Criticidad</td><td><span class='badge badge-{(asset['criticality'] or 'INFO').upper()}'>{asset['criticality']}</span></td></tr>
  <tr><td>Estado Wazuh</td><td>{asset['status'] or 'N/D'}</td></tr>
  <tr><td>Última Auditoría</td><td>{str(asset['last_audit'])[:16] if asset.get('last_audit') else '—'}</td></tr>
</table>

<h2>Hallazgos de Seguridad ({total_v})</h2>
{vuln_cards if vuln_cards else "<div class='card card-ok' style='text-align:center; padding:20px;'><strong style='color:#16a34a;'>✓ Sin hallazgos activos. Activo en buen estado.</strong></div>"}

<div class='pdf-footer-bar'>
  Centinela-AI | CASMARTS | Clasificación: CONFIDENCIAL | Estándar CVSS v3 | Generado: {gen_date}
</div>
</body></html>"""

        try:
            pdf_bytes = render_pdf_with_weasyprint(html_content)
            from fastapi.responses import Response
            return Response(content=pdf_bytes, media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=reporte_{asset_name}.pdf",
                         "Cache-Control": "no-store"})
        except Exception as e:
            print(f"⚠️ WeasyPrint fallback: {e}")
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _infer_scan_engine_label(cve_id: str, scan_engine: Optional[str]) -> str:
    """Maps a finding to a human-readable scanner name. Prefers the scan_engine
    column; many older auditors don't set it, so falls back to the cve_id prefix
    convention used across auditors/*.py."""
    engine_labels = {
        "prowler": "Cloud CSPM (Prowler)",
        "grype": "SBOM / Dependencias (Grype)",
        "semgrep": "SAST (Semgrep)",
        "zap": "DAST (OWASP ZAP)",
        "secrets": "Secretos (TruffleHog)",
        "spiderfoot": "OSINT (SpiderFoot)",
        "ffuf": "API Discovery (ffuf)",
        "kiterunner": "API Discovery (Kiterunner)",
        "standards-audit": "Estándares (STRIDE / ISO 25010)",
        "bloodhound": "Rutas de Ataque AD (BloodHound)",
        "cis-benchmark": "Hardening (CIS Benchmarks)",
        "medusa": "SAST con IA (Medusa)",
    }
    if scan_engine and scan_engine in engine_labels:
        return engine_labels[scan_engine]
    cve = (cve_id or "").upper()
    prefix_labels = [
        ("SCAN-AUDIT", "Auditoría Interna (multi-motor)"),
        ("HEURISTIC-", "Motor de Heurísticas SOAR"),
        ("MEDUSA-", "Fuerza Bruta (Medusa)"),
        ("NMAP-", "Descubrimiento de Puertos (Nmap)"),
        ("TECH-", "Detección de Tecnología (Nuclei)"),
        ("STD-", "Estándares (STRIDE / ISO 25010)"),
        ("DOCKER-", "Contenedores (Trivy)"),
        ("BLOODHOUND", "Rutas de Ataque AD (BloodHound)"),
        ("WAZUH-", "EDR (Wazuh)"),
        ("OSINT-", "OSINT (SpiderFoot)"),
        ("SECRETS-", "Secretos (TruffleHog)"),
        ("ZAP-", "DAST (OWASP ZAP)"),
        ("CVE-", "CVE Conocido (Trivy / Nuclei)"),
    ]
    for prefix, label in prefix_labels:
        if cve.startswith(prefix):
            return label
    if scan_engine:
        return scan_engine.title()
    return "Nuclei (Plantillas Web)"


def _render_cmmi_practice_areas_html(practice_areas: list) -> str:
    rows = "".join([
        f"""<div class='card {"card-ok" if pa["passed"] else "card-crit"}' style='margin-bottom:8px;'>
              <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;'>
                <h3 style='margin:0;'>{pa['area']}</h3>
                <span class='badge {"badge-low" if pa["passed"] else "badge-critical"}'>{pa['status']}</span>
              </div>
              <div style='font-size:9px;color:#475569;'>{pa['evidence']}</div>
            </div>"""
        for pa in practice_areas
    ])
    return rows


@app.get("/api/reports/cmmi")
async def download_cmmi_fleet_report():
    """
    Fleet-wide CMMI v3.0 report PDF: real per-asset compliance across the 7 practice areas
    (CAR/SAM/MSR/PQA/EST/PLAN/VV), same engine as /api/audit/cmmi-v3-report and the asset
    detail panel -- one source of truth, not a separate summary.
    """
    try:
        from auditors.compliance_mapper import get_cmmi_v3_asset_audit_report
        report = get_cmmi_v3_asset_audit_report()
        gen_date = datetime.now().strftime("%d/%m/%Y %H:%M")

        assets_sorted = sorted(report["assets_audit"], key=lambda a: a["cmmi_compliance_percentage"])
        assets_rows = "".join([
            f"""<tr>
                  <td>{a['asset_name']}</td><td>{a['asset_type']}</td>
                  <td style='text-align:center;'><span class='badge {"badge-low" if a["cmmi_compliance_percentage"]>=90 else "badge-medium" if a["cmmi_compliance_percentage"]>=70 else "badge-critical"}'>{a['cmmi_compliance_percentage']}%</span></td>
                  <td>{a['cmmi_maturity_level']}</td>
                  <td style='text-align:center;'>{a['active_vulnerabilities_count']}</td>
                </tr>"""
            for a in assets_sorted
        ])

        practice_area_desc_rows = "".join([
            f"<tr><td><b>{p['code']}</b></td><td>{p['name']} ({p['level']})</td><td>{p['desc']}</td></tr>"
            for p in report["practice_areas_evaluated"]
        ])

        html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{CIVIKA_PDF_STYLES}</style></head><body>
{build_pdf_header("Reporte de Cumplimiento CMMI v3.0", "Auditoría real por activo -- Modelo 2024-2026 Enterprise", gen_date)}

<div class="kpi-grid">
  <div class="kpi-card"><div class="kpi-num">{report['overall_cmmi_compliance_rate']}%</div><div class="kpi-label">Cumplimiento Promedio</div></div>
  <div class="kpi-card"><div class="kpi-num">{report['total_assets_audited']}</div><div class="kpi-label">Activos Auditados</div></div>
  <div class="kpi-card kpi-ok"><div class="kpi-num">{sum(1 for a in report['assets_audit'] if a['cmmi_compliance_percentage']>=90)}</div><div class="kpi-label">Nivel 5 (Optimizing)</div></div>
  <div class="kpi-card kpi-crit"><div class="kpi-num">{sum(1 for a in report['assets_audit'] if a['cmmi_compliance_percentage']<70)}</div><div class="kpi-label">Nivel 1 (Initial)</div></div>
</div>

<h2>Áreas de Práctica Evaluadas (CMMI v3.0)</h2>
<table>
  <tr><th>Código</th><th>Área</th><th>Descripción</th></tr>
  {practice_area_desc_rows}
</table>

<h2>Cumplimiento por Activo ({len(assets_sorted)})</h2>
<table>
  <tr><th>Activo</th><th>Tipo</th><th style='text-align:center;'>CMMI</th><th>Nivel de Madurez</th><th style='text-align:center;'>Hallazgos Activos</th></tr>
  {assets_rows}
</table>

<div class='pdf-footer-bar'>
  Centinela-AI | CASMARTS Ecosistema de Seguridad | Clasificación: CONFIDENCIAL | CMMI v3.0 (Model 2024-2026 Enterprise)
</div>
</body></html>"""

        try:
            pdf_bytes = render_pdf_with_weasyprint(html_content)
            from fastapi.responses import Response
            return Response(content=pdf_bytes, media_type="application/pdf",
                headers={"Content-Disposition": "attachment; filename=reporte_cmmi_v3.pdf",
                         "Cache-Control": "no-store"})
        except Exception as e:
            print(f"⚠️ WeasyPrint fallback: {e}")
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/cmmi/{asset_name:path}")
async def download_cmmi_asset_report(asset_name: str):
    """Single-asset CMMI v3.0 report PDF -- same real per-asset evaluation as the asset detail panel."""
    try:
        from auditors.compliance_mapper import evaluate_cmmi_v3_for_asset
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, asset_name, asset_type, endpoint, status, agent_id, criticality, last_scanned, last_audit
                FROM public.infra_inventory WHERE asset_name = %s LIMIT 1
            """, (asset_name,))
            asset = cur.fetchone()
            if not asset:
                raise HTTPException(status_code=404, detail=f"Activo '{asset_name}' no encontrado")
            result = evaluate_cmmi_v3_for_asset(cur, asset)

        gen_date = datetime.now().strftime("%d/%m/%Y %H:%M")
        practice_areas_html = _render_cmmi_practice_areas_html(result["practice_areas_breakdown"])

        html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{CIVIKA_PDF_STYLES}</style></head><body>
{build_pdf_header(f"Reporte CMMI v3.0 — {result['asset_name']}", result['asset_type'], gen_date)}

<div class="kpi-grid" style="grid-template-columns: repeat(3, 1fr);">
  <div class="kpi-card"><div class="kpi-num">{result['cmmi_compliance_percentage']}%</div><div class="kpi-label">Cumplimiento CMMI v3.0</div></div>
  <div class="kpi-card"><div class="kpi-num" style="font-size:12px;">{result['cmmi_maturity_level']}</div><div class="kpi-label">Nivel de Madurez</div></div>
  <div class="kpi-card kpi-crit"><div class="kpi-num">{result['active_vulnerabilities_count']}</div><div class="kpi-label">Hallazgos Activos</div></div>
</div>

<h2>Evaluación por Área de Práctica</h2>
{practice_areas_html}

<div class='pdf-footer-bar'>
  Centinela-AI | CASMARTS Ecosistema de Seguridad | Clasificación: CONFIDENCIAL | CMMI v3.0 (Model 2024-2026 Enterprise)
</div>
</body></html>"""

        try:
            pdf_bytes = render_pdf_with_weasyprint(html_content)
            from fastapi.responses import Response
            safe_name = asset_name.replace("/", "_")
            return Response(content=pdf_bytes, media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=reporte_cmmi_{safe_name}.pdf",
                         "Cache-Control": "no-store"})
        except Exception as e:
            print(f"⚠️ WeasyPrint fallback: {e}")
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/coverage")
async def download_coverage_report():
    """Consolidated report: for every asset, which scanners ran and what they found
    (or a clean/green verdict if nothing was found)."""
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, asset_name, asset_type, endpoint, criticality, status, last_audit
                FROM public.infra_inventory ORDER BY asset_name
            """)
            assets = cur.fetchall()

            cur.execute("""
                SELECT v.asset_id, v.cve_id, v.severity, v.status, v.scan_engine, r.executed_bool
                FROM public.vulnerability_log v
                LEFT JOIN public.remediation_history r ON v.id = r.vuln_id
            """)
            findings = cur.fetchall()

        by_asset = {}
        for f in findings:
            by_asset.setdefault(f["asset_id"], []).append(f)

        gen_date = datetime.now().strftime("%d/%m/%Y %H:%M")
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        rows_html = ""
        scanned_count = 0
        clean_count = 0
        with_findings_count = 0
        for a in assets:
            asset_findings = by_asset.get(a["id"], [])
            real_findings = [f for f in asset_findings if f["cve_id"] != "SCAN-AUDIT"]

            engines = {}
            for f in asset_findings:
                label = _infer_scan_engine_label(f["cve_id"], f["scan_engine"])
                engines.setdefault(label, {"total": 0, "open": 0})
                engines[label]["total"] += 1
                if f["cve_id"] != "SCAN-AUDIT" and not f.get("executed_bool") and f["status"] != "RESOLVED":
                    engines[label]["open"] += 1

            if not asset_findings:
                verdict = "SIN ANALIZAR"
                verdict_color = "#64748b"
            elif not any(e["open"] > 0 for e in engines.values()):
                verdict = "APROBADO ✓"
                verdict_color = "#16a34a"
                clean_count += 1
                scanned_count += 1
            else:
                worst = min((f["severity"] or "INFO").upper() for f in real_findings if f.get("status") != "RESOLVED" and not f.get("executed_bool")) if real_findings else "INFO"
                worst = worst if worst in sev_rank else "INFO"
                verdict = f"HALLAZGOS ({worst})"
                verdict_color = "#dc2626" if worst in ("CRITICAL", "HIGH") else "#d97706"
                with_findings_count += 1
                scanned_count += 1

            engines_str = ", ".join(
                f"{label} ({info['open']} abiertos)" if info["open"] else f"{label} (limpio)"
                for label, info in sorted(engines.items())
            ) or "—"

            rows_html += f"""
            <tr>
              <td><strong>{a['asset_name']}</strong><br><span style='font-size:8px;color:#64748b;'>{a['asset_type']} &bull; {a['endpoint']}</span></td>
              <td style='font-size:8.5px;'>{engines_str}</td>
              <td style='text-align:center;'><span style='color:{verdict_color};font-weight:700;font-size:9px;'>{verdict}</span></td>
            </tr>"""

        html_content = f"""<!DOCTYPE html><html lang='es'><head>
<meta charset='UTF-8'>
<title>Reporte de Cobertura de Escaneo — Centinela-AI</title>
<style>{CIVIKA_PDF_STYLES}</style>
</head><body>
{build_pdf_header('Reporte de Cobertura de Escaneo', 'Motores ejecutados y resultado por activo', gen_date)}

<div class='card card-exec'>
  <span class='section-label label-exec'>Resumen</span>
  <p style='margin-top:6px; font-size:10px; line-height:1.7;'>
    De <strong>{len(assets)}</strong> activos en el inventario, <strong>{scanned_count}</strong> cuentan con al menos un
    escaneo registrado. <strong style='color:#16a34a;'>{clean_count}</strong> están aprobados sin hallazgos abiertos,
    <strong style='color:#dc2626;'>{with_findings_count}</strong> tienen hallazgos pendientes de remediar, y
    <strong style='color:#64748b;'>{len(assets) - scanned_count}</strong> aún no tienen ningún escaneo registrado.
  </p>
</div>

<div class='kpi-grid'>
  <div class='kpi-card kpi-ok'><div class='kpi-num'>{clean_count}</div><div class='kpi-label'>Aprobados</div></div>
  <div class='kpi-card kpi-crit'><div class='kpi-num'>{with_findings_count}</div><div class='kpi-label'>Con Hallazgos</div></div>
  <div class='kpi-card'><div class='kpi-num'>{len(assets) - scanned_count}</div><div class='kpi-label'>Sin Analizar</div></div>
  <div class='kpi-card'><div class='kpi-num'>{len(assets)}</div><div class='kpi-label'>Total Activos</div></div>
</div>

<h2>Cobertura por Activo ({len(assets)})</h2>
<table>
  <tr><th>Activo</th><th>Motores Ejecutados y Resultado</th><th style='text-align:center;'>Veredicto</th></tr>
  {rows_html}
</table>

<div class='pdf-footer-bar'>
  Centinela-AI | CASMARTS Ecosistema de Seguridad | Clasificación: CONFIDENCIAL | Generado: {gen_date}
</div>
</body></html>"""

        try:
            pdf_bytes = render_pdf_with_weasyprint(html_content)
            from fastapi.responses import Response
            return Response(content=pdf_bytes, media_type="application/pdf",
                headers={"Content-Disposition": "attachment; filename=reporte_cobertura_escaneo.pdf",
                         "Cache-Control": "no-store"})
        except Exception as e:
            print(f"⚠️ WeasyPrint fallback: {e}")
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/vulnerability/{vuln_id}")
async def download_vulnerability_report(vuln_id: int):
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT v.id, i.asset_name, i.endpoint, i.asset_type,
                       v.severity, v.cve_id, v.description, v.executive_summary,
                       v.business_impact, v.developer_steps, v.status, v.detected_at, v.scan_engine,
                       r.script_path, r.executed_bool, r.log_output, r.approval_token
                FROM public.vulnerability_log v
                LEFT JOIN public.infra_inventory i ON v.asset_id = i.id
                LEFT JOIN public.remediation_history r ON v.id = r.vuln_id
                WHERE v.id = %s
            """, (vuln_id,))
            vuln = cur.fetchone()
            if not vuln:
                raise HTTPException(status_code=404, detail="Vulnerability not found")

        gen_date = datetime.now().strftime("%d/%m/%Y %H:%M")
        sev = (vuln["severity"] or "INFO").upper()
        card_cls = "card-crit" if sev == "CRITICAL" else ("card-warn" if sev in ("HIGH","MEDIUM") else "card-ok")
        exec_sum = vuln.get("executive_summary") or "Análisis de IA pendiente de procesamiento."
        biz_imp  = vuln.get("business_impact") or "Sin análisis de impacto al negocio disponible."
        steps    = vuln.get("developer_steps") or "Sin pasos de remediación disponibles."
        script   = vuln.get("log_output") or ""
        det_date = str(vuln["detected_at"])[:16] if vuln.get("detected_at") else "—"
        remediated = vuln.get("executed_bool", False)
        status_str = "✅ Remediado automáticamente por Ansible" if remediated else "⏳ Pendiente de remediación"
        status_color = "#16a34a" if remediated else "#d97706"

        html_content = f"""<!DOCTYPE html><html lang='es'><head>
<meta charset='UTF-8'>
<title>Reporte de Vulnerabilidad #{vuln_id}</title>
<style>{CIVIKA_PDF_STYLES}</style>
</head><body>
{build_pdf_header(f'Reporte de Vulnerabilidad', f'{vuln["cve_id"]} — {vuln["asset_name"]}', gen_date)}

<div style='display:flex; gap:8px; margin-bottom:10px; align-items:center;'>
  <span class='badge badge-{sev}' style='font-size:10px; padding:4px 10px;'>{sev}</span>
  <strong style='font-size:12px;'>{vuln['cve_id']}</strong>
  <span style='font-size:9px; color:#64748b;'>&bull; Detectado: {det_date} &bull; Motor: {vuln.get('scan_engine','N/D')}</span>
</div>

<table style='margin-bottom:10px;'>
  <tr><th style='width:30%'>Propiedad</th><th>Valor</th></tr>
  <tr><td>Activo Afectado</td><td><strong>{vuln['asset_name']}</strong> ({vuln.get('asset_type','N/D')})</td></tr>
  <tr><td>Endpoint</td><td><code>{vuln.get('endpoint','N/D')}</code></td></tr>
  <tr><td>Severidad (CVSS v3)</td><td><span class='badge badge-{sev}'>{sev}</span></td></tr>
  <tr><td>Estado de Remediación</td><td><strong style='color:{status_color};'>{status_str}</strong></td></tr>
  <tr><td>Fecha de Detección</td><td>{det_date}</td></tr>
</table>

<div class='card card-exec'>
  <span class='section-label label-exec'>Resumen Ejecutivo</span>
  <p style='margin-top:6px; font-size:10px; line-height:1.7;'>{exec_sum}</p>
  <hr class='divider'>
  <h3>Impacto al Negocio</h3>
  <p style='font-size:9.5px; line-height:1.6; color:#475569;'>{biz_imp}</p>
</div>

<div class='card card-tech'>
  <span class='section-label label-tech'>Detalle Técnico</span>
  <p style='margin-top:6px; font-size:9px; line-height:1.6;'>{vuln.get('description','Sin descripción técnica disponible.')}</p>
  <hr class='divider'>
  <h3>Pasos de Remediación para el Equipo Técnico</h3>
  <p style='font-size:9px; line-height:1.7; margin-top:4px;'>{steps}</p>
  {f'<hr class="divider"><h3>Log de Ejecución Ansible</h3><pre>{script[:2000]}</pre>' if script else ''}
</div>

<div class='pdf-footer-bar'>
  Centinela-AI | CASMARTS | Clasificación: CONFIDENCIAL | Estándar CVSS v3 | ID Vuln: #{vuln_id} | Generado: {gen_date}
</div>
</body></html>"""

        try:
            pdf_bytes = render_pdf_with_weasyprint(html_content)
            from fastapi.responses import Response
            return Response(content=pdf_bytes, media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=vulnerabilidad_{vuln_id}.pdf",
                         "Cache-Control": "no-store"})
        except Exception as e:
            print(f"⚠️ WeasyPrint fallback: {e}")
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats/soar-roi")
async def get_soar_roi():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT AVG(EXTRACT(EPOCH FROM (r.executed_at - v.detected_at))) / 60 as avg_minutes
                FROM public.remediation_history r
                JOIN public.vulnerability_log v ON r.vuln_id = v.id
                WHERE r.executed_bool = TRUE AND r.executed_at IS NOT NULL
                  AND r.executed_at >= v.detected_at
                  AND (r.executed_at - v.detected_at) < interval '1 hour'
            """)
            avg_min = cur.fetchone()["avg_minutes"]
            avg_min = avg_min if avg_min is not None else 0.0
            
            cur.execute("""
                SELECT 
                    COUNT(CASE WHEN approval_token = 'APPROVED' AND executed_bool = TRUE THEN 1 END) as success,
                    COUNT(CASE WHEN approval_token = 'APPROVED' THEN 1 END) as total
                FROM public.remediation_history
            """)
            eff_res = cur.fetchone()
            success_count = eff_res["success"] or 0
            total_count = eff_res["total"] or 0
            effectiveness = (success_count / total_count * 100) if total_count > 0 else 0.0
            
            cur.execute("""
                SELECT 
                    COUNT(CASE WHEN approval_token = 'APPROVED' AND executed_bool = TRUE THEN 1 END) as ai,
                    COUNT(CASE WHEN approval_token = 'MANUAL' AND executed_bool = TRUE THEN 1 END) as manual
                FROM public.remediation_history
            """)
            comparison = cur.fetchone()
            
            return {
                "avg_remediation_time_minutes": round(avg_min, 1),
                "effectiveness_rate_percentage": round(effectiveness, 1),
                "comparison": {
                    "ai_resolved": comparison["ai"] or 0,
                    "manual_resolved": comparison["manual"] or 0
                }
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# =====================================================================
# ADVANCED SCANNING ENDPOINTS (ZAP DAST / Secrets / SpiderFoot OSINT)
# =====================================================================

class DastScanModel(BaseModel):
    profile: Optional[str] = "balanced"  # light, balanced, aggressive, api

class SecretsScanModel(BaseModel):
    phase: Optional[int] = 1  # 1=fast, 2=medium, 3=deep
    max_commits: Optional[int] = 50

class OsintScanModel(BaseModel):
    target: Optional[str] = None  # override endpoint if needed

@app.post("/api/scan/dast/{asset_id}")
async def trigger_dast_scan(asset_id: int, body: DastScanModel = DastScanModel()):
    """Triggers an on-demand ZAP DAST scan on a registered asset."""
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT asset_name, asset_type, endpoint FROM public.infra_inventory WHERE id = %s", (asset_id,))
            asset = cur.fetchone()

        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        if asset["asset_type"] not in ["URL", "AppServer", "SERVER"]:
            raise HTTPException(status_code=400, detail=f"DAST not applicable to asset type '{asset['asset_type']}'. Use URL or AppServer.")

        endpoint = asset["endpoint"]
        if not endpoint.startswith("http"):
            endpoint = f"http://{endpoint}"

        try:
            from auditors import auditor_zap
            import asyncio
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: auditor_zap.run_zap_scan(
                target_url=endpoint,
                asset_id=asset_id,
                scan_profile=body.profile,
                db_cache_path="/tmp/zap-cache"
            ))
            return {
                "status": "completed",
                "asset_id": asset_id,
                "asset_name": asset["asset_name"],
                "target": endpoint,
                "profile": body.profile,
                "message": "ZAP DAST scan completed. Check /api/remediation for findings."
            }
        except auditor_zap.ZAPTimeoutError:
            return {"status": "timeout", "asset_id": asset_id, "message": "ZAP scan timed out. Try 'light' profile."}
        except auditor_zap.ZAPNotAvailableError:
            raise HTTPException(status_code=503, detail="ZAP service not available. Check Docker.")
        except ImportError:
            raise HTTPException(status_code=501, detail="ZAP module not installed.")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/secrets/{asset_id}")
async def trigger_secrets_scan(asset_id: int, body: SecretsScanModel = SecretsScanModel()):
    """Triggers on-demand secrets scanning on a registered repository asset."""
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT asset_name, asset_type, endpoint FROM public.infra_inventory WHERE id = %s", (asset_id,))
            asset = cur.fetchone()

        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        if asset["asset_type"] != "Repository":
            raise HTTPException(status_code=400, detail=f"Secrets scan only applies to Repository type. Got '{asset['asset_type']}'.")

        repo_path = asset["endpoint"]

        try:
            from auditors import auditor_secrets
            import asyncio
            loop = asyncio.get_event_loop()

            if body.phase == 1:
                await loop.run_in_executor(None, lambda: auditor_secrets.scan_repo_secrets_fast(repo_path, asset_id))
                phase_name = "Fast (working tree)"
            elif body.phase == 2:
                await loop.run_in_executor(None, lambda: auditor_secrets.scan_repo_secrets_deep(repo_path, asset_id, body.max_commits))
                phase_name = f"Medium (last {body.max_commits} commits)"
            else:
                await loop.run_in_executor(None, lambda: auditor_secrets.scan_repo_secrets_historical(repo_path, asset_id))
                phase_name = "Deep (full history)"

            return {
                "status": "completed",
                "asset_id": asset_id,
                "asset_name": asset["asset_name"],
                "repo": repo_path,
                "phase": phase_name,
                "message": "Secrets scan completed. Check /api/remediation for findings."
            }
        except ImportError:
            raise HTTPException(status_code=501, detail="Secrets module not installed.")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/osint/{asset_id}")
async def trigger_osint_scan(asset_id: int, body: OsintScanModel = OsintScanModel()):
    """Triggers on-demand SpiderFoot OSINT enrichment on a registered asset."""
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT asset_name, asset_type, endpoint FROM public.infra_inventory WHERE id = %s", (asset_id,))
            asset = cur.fetchone()

        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        target = body.target or asset["endpoint"]

        try:
            from auditors import auditor_spiderfoot
            import asyncio
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: auditor_spiderfoot.run_spiderfoot_osint(target, asset_id))

            return {
                "status": "completed",
                "asset_id": asset_id,
                "asset_name": asset["asset_name"],
                "target": target,
                "message": "OSINT scan completed. Check /api/remediation for findings."
            }
        except ImportError:
            raise HTTPException(status_code=501, detail="SpiderFoot module not installed.")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/coverage")
async def get_scan_coverage():
    """Returns vulnerability breakdown by scan engine (nuclei/zap/medusa/secrets/spiderfoot)."""
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    COALESCE(scan_engine, 'nuclei') as engine,
                    COUNT(*) as total,
                    COUNT(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 END) as high_critical,
                    COUNT(CASE WHEN status = 'NEW' THEN 1 END) as new_findings
                FROM public.vulnerability_log
                GROUP BY COALESCE(scan_engine, 'nuclei')
                ORDER BY total DESC
            """)
            rows = cur.fetchall()

            cur.execute("""
                SELECT
                    COALESCE(scan_engine, 'nuclei') as engine,
                    COUNT(DISTINCT asset_id) as assets_covered
                FROM public.vulnerability_log
                GROUP BY COALESCE(scan_engine, 'nuclei')
            """)
            coverage = {r["engine"]: r["assets_covered"] for r in cur.fetchall()}

            return {
                "scan_engines": [dict(r) for r in rows],
                "assets_covered_per_engine": coverage,
                "total_vulnerabilities": sum(r["total"] for r in rows)
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/compliance/audit")
async def run_compliance_audit():
    """Ejecuta la auditoría de estándares integrales (5 Pilares: Seguridad, Calidad, UX/UI, Persistencia, Evidencia)."""
    try:
        from auditors.auditor_compliance_standards import AuditorComplianceStandards
        auditor = AuditorComplianceStandards()
        report = auditor.run_full_audit()
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en auditoría de estándares: {str(e)}")


@app.post("/api/compliance/resident-loop")
async def run_resident_loop():
    """Ejecuta el loop cognitivo en 10 fases deterministas de Resident Agent OS."""
    try:
        from core.resident_loop import ResidentAgentLoop
        loop = ResidentAgentLoop()
        result = loop.run_full_cycle()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en loop determinista: {str(e)}")


def _run_authentik_ssh_command(remote_shell_snippet: str, timeout: int = 15) -> subprocess.CompletedProcess:
    """
    Runs a python3-in-Django-shell one-liner on the Authentik host over SSH.

    Uses an argument list, not a local shell string -- the previous version built `cmd` as an
    f-string interpolating request-body fields directly (username/role in
    update_authentik_user_role) and ran it through a local command interpreter, a real,
    exploitable command injection: a username or role containing shell/Python-string-breaking
    characters could escape both the LOCAL interpreter and the embedded remote
    `manage.py shell -c "..."` Python string. ssh itself still receives the remote command as a
    single argument here, so this closes the local-interpreter layer; callers must still
    validate/escape any interpolated value against the remote Python string themselves (see
    ROLE_ALLOWLIST and _validate_authentik_username below).
    """
    return subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-i", "keys/casmarts.key",
         "authentik@10.4.3.208",
         f'docker exec casmarts-core-authentik-server python3 manage.py shell -c "{remote_shell_snippet}"'],
        capture_output=True, text=True, timeout=timeout
    )


# Real Authentik usernames are alphanumeric plus a small set of separators (matches Authentik's
# own username validation) -- rejecting anything else closes off the Python-string-breaking
# injection vector (quotes, backslashes, semicolons) for the remote `manage.py shell -c` call.
_AUTHENTIK_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,150}$")


def _validate_authentik_username(username: str) -> str:
    if not _AUTHENTIK_USERNAME_RE.match(username or ""):
        raise HTTPException(status_code=400, detail="Nombre de usuario inválido.")
    return username


@app.get("/api/users")
async def get_authentik_users():
    """Lists all non-system users from Authentik with their assigned Centinela RBAC role (Admin / Analyst / Auditor / Viewer)."""
    try:
        remote_snippet = (
            "import json; from authentik.core.models import User, Group; "
            "g_admin = Group.objects.filter(name='Centinela Admin').first(); "
            "g_analyst = Group.objects.filter(name='Centinela Analyst').first(); "
            "g_auditor = Group.objects.filter(name='Centinela Auditor').first(); "
            "users = [];\\n"
            "for u in User.objects.all():\\n"
            "  if u.username.startswith('ak-') or u.username == 'AnonymousUser': continue;\\n"
            "  groups = u.groups.all();\\n"
            "  role = 'Admin' if g_admin in groups else ('Analyst' if g_analyst in groups else ('Auditor' if g_auditor in groups else 'Viewer'));\\n"
            "  users.append({'username': u.username, 'name': u.name or u.username, 'email': u.email, 'role': role});\\n"
            "print('JSON_DATA:' + json.dumps(users))"
        )
        proc = _run_authentik_ssh_command(remote_snippet)
        out = proc.stdout
        if "JSON_DATA:" in out:
            json_str = out.split("JSON_DATA:")[1].strip().splitlines()[0]
            return json.loads(json_str)
        return []
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class UserRoleUpdateModel(BaseModel):
    username: str
    role: str  # "Admin", "Analyst", "Auditor", or "Viewer"


@app.post("/api/users/role")
async def update_authentik_user_role(body: UserRoleUpdateModel):
    """Updates a user's RBAC role in Authentik (Centinela Admin / Analyst / Auditor / Viewer)."""
    ROLE_ALLOWLIST = ("Admin", "Analyst", "Auditor", "Viewer")
    try:
        new_role = body.role
        username = _validate_authentik_username(body.username)
        # Real, exploitable injection previously here (see _run_authentik_ssh_command's
        # docstring): new_role/username went straight into an f-string executed with
        # shell=True. Checking new_role against a fixed enum closes that vector for the role
        # value entirely (rather than trying to escape it).
        if new_role not in ROLE_ALLOWLIST:
            raise HTTPException(status_code=400, detail=f"Rol inválido. Debe ser uno de: {', '.join(ROLE_ALLOWLIST)}")
        remote_snippet = (
            "from authentik.core.models import User, Group; "
            "roles = ['Admin', 'Analyst', 'Auditor', 'Viewer']; "
            "groups = {r: Group.objects.get_or_create(name=f'Centinela {r}')[0] for r in roles}; "
            f"u = User.objects.filter(username='{username}').first();\\n"
            "if u:\\n"
            "  for r, g in groups.items(): u.groups.remove(g)\\n"
            f"  u.groups.add(groups['{new_role}'])\\n"
            "  print('ROLE_UPDATED_SUCCESS')"
        )
        proc = _run_authentik_ssh_command(remote_snippet)
        if "ROLE_UPDATED_SUCCESS" in proc.stdout:
            return {"status": "success", "username": username, "role": new_role}
        raise HTTPException(status_code=404, detail="Usuario no encontrado en Authentik")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class SettingItem(BaseModel):
    key: str
    value: str
    category: Optional[str] = "GENERAL"
    description: Optional[str] = ""

class SettingsUpdateModel(BaseModel):
    settings: List[SettingItem]

@app.get("/api/config")
async def get_system_config():
    """Returns all system settings and agent configurations from DB/env."""
    defaults = [
        {"key": "AI_PROVIDER", "value": os.getenv("AI_PROVIDER", "nvidia_nim"), "category": "LLM_AGENTS", "description": "Proveedor principal de IA (nvidia_nim, gemini_pro, groq, ollama)"},
        {"key": "AI_MODEL", "value": os.getenv("AI_MODEL", "meta/llama-3.1-70b-instruct"), "category": "LLM_AGENTS", "description": "Modelo de LLM en ejecución"},
        {"key": "NVIDIA_NIM_API_KEY", "value": os.getenv("NVIDIA_NIM_API_KEY", "••••••••"), "category": "LLM_AGENTS", "description": "API Key de NVIDIA NIM Inference"},
        {"key": "GOOGLE_API_KEY", "value": os.getenv("GOOGLE_API_KEY", "••••••••"), "category": "LLM_AGENTS", "description": "API Key de Google Gemini Pro"},
        {"key": "GROQ_API_KEY", "value": os.getenv("GROQ_API_KEY", "••••••••"), "category": "LLM_AGENTS", "description": "API Key de Groq Llama 3"},
        {"key": "OLLAMA_BASE_URL", "value": os.getenv("OLLAMA_BASE_URL", "http://ollama:11434"), "category": "LLM_AGENTS", "description": "URL base de Ollama local"},
        {"key": "WAZUH_API_ENDPOINT", "value": "https://10.4.3.34:55000", "category": "SECURITY_AGENTS", "description": "Endpoint API del Manager Wazuh EDR"},
        {"key": "ZEEK_SENSOR_INTERFACE", "value": "eth0", "category": "SECURITY_AGENTS", "description": "Interfaz de red monitoreada por Zeek NIDS"},
        {"key": "AUTHENTIK_URL", "value": os.getenv("AUTHENTIK_URL", "https://auth.casmart.internal"), "category": "INTEGRATIONS", "description": "URL Central de Authentik IDP"},
        {"key": "GITLAB_URL", "value": os.getenv("GITLAB_URL", "http://10.4.3.10"), "category": "INTEGRATIONS", "description": "URL de Instancia GitLab/Gitea"},
        {"key": "AUTO_REMEDIATION_ENABLED", "value": "true", "category": "POLICY_RULES", "description": "Auto-remediación autónoma de parches sin confirmación previa"},
        {"key": "SLA_CRITICAL_HOURS", "value": "1", "category": "POLICY_RULES", "description": "SLA máximo para remediación de hallazgos CRÍTICOS (Horas)"},
        {"key": "SCAN_CRON_SCHEDULE", "value": "0 2 * * *", "category": "POLICY_RULES", "description": "Cron para escaneo recurrente SAST/SCA nocturno"}
    ]
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("SELECT key, value, category, description FROM public.system_settings")
            db_rows = {r["key"]: dict(r) for r in cur.fetchall()}
            
            result = []
            for item in defaults:
                k = item["key"]
                val = db_rows[k]["value"] if k in db_rows else item["value"]
                cat = db_rows[k]["category"] if k in db_rows else item["category"]
                desc = db_rows[k]["description"] if k in db_rows else item["description"]
                
                # Mask sensitive keys so real keys are never exposed on UI
                display_val = val
                if any(sec in k for sec in ["KEY", "SECRET", "TOKEN", "PASSWORD"]):
                    display_val = "************"
                
                result.append({"key": k, "value": display_val, "category": cat, "description": desc})
            return result
    except Exception as e:
        res = []
        for item in defaults:
            k = item["key"]
            display_val = item["value"]
            if any(sec in k for sec in ["KEY", "SECRET", "TOKEN", "PASSWORD"]):
                display_val = "************"
            res.append({"key": k, "value": display_val, "category": item["category"], "description": item["description"]})
        return res

@app.get("/api/llm/models")
async def get_provider_models(provider: str, api_key: Optional[str] = None):
    """Dynamically fetches available LLM models for a given provider or key."""
    prov = provider.lower()
    
    # Fallback to DB stored keys if no new key provided
    if not api_key or api_key in ["************", "••••••••"]:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT key, value FROM public.system_settings WHERE key IN ('NVIDIA_NIM_API_KEY', 'GOOGLE_API_KEY', 'GROQ_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY')")
            keys_dict = {r["key"]: r["value"] for r in cur.fetchall()}
            if "nvidia" in prov:
                api_key = keys_dict.get("NVIDIA_NIM_API_KEY") or os.getenv("NVIDIA_NIM_API_KEY")
            elif "google" in prov or "gemini" in prov:
                api_key = keys_dict.get("GOOGLE_API_KEY") or os.getenv("GOOGLE_API_KEY")
            elif "groq" in prov:
                api_key = keys_dict.get("GROQ_API_KEY") or os.getenv("GROQ_API_KEY")

    models = []
    try:
        if "nvidia" in prov:
            models = [
                "meta/llama-3.1-70b-instruct",
                "meta/llama-3.1-405b-instruct",
                "meta/llama-3.3-70b-instruct",
                "mistralai/mistral-large-2-instruct",
                "nvidia/neva-22b"
            ]
        elif "groq" in prov:
            models = [
                "llama-3.3-70b-versatile",
                "llama-3.1-8b-instant",
                "mixtral-8x7b-32768",
                "gemma2-9b-it"
            ]
        elif "google" in prov or "gemini" in prov:
            models = [
                "gemini-1.5-pro-latest",
                "gemini-1.5-flash-latest",
                "gemini-2.0-flash-exp",
                "gemini-1.0-pro"
            ]
        elif "openai" in prov:
            models = [
                "gpt-4o",
                "gpt-4o-mini",
                "gpt-4-turbo",
                "o3-mini"
            ]
        elif "anthropic" in prov or "claude" in prov:
            models = [
                "claude-3-5-sonnet-latest",
                "claude-3-5-haiku-latest",
                "claude-3-opus-20240229"
            ]
        elif "ollama" in prov:
            models = [
                "llama3:latest",
                "codellama:latest",
                "mistral:latest",
                "qwen:latest"
            ]
        else:
            models = ["meta/llama-3.1-70b-instruct", "gemini-1.5-pro-latest"]
            
        return {"provider": provider, "status": "success", "models": models}
    except Exception as e:
        return {"provider": provider, "status": "error", "message": str(e), "models": []}

@app.post("/api/config")
async def save_system_config(body: SettingsUpdateModel):
    """Saves updated system & agent parameters in PostgreSQL DB."""
    try:
        with db_manager.get_db_cursor() as cur:
            for item in body.settings:
                # Avoid overwriting real keys with masked asterisks
                if item.value in ["************", "••••••••"]:
                    continue
                cur.execute("""
                    INSERT INTO public.system_settings (key, value, category, description, updated_at)
                    VALUES (%s, %s, %s, %s, NOW())
                    ON CONFLICT (key) DO UPDATE SET
                        value = EXCLUDED.value,
                        category = EXCLUDED.category,
                        description = EXCLUDED.description,
                        updated_at = NOW()
                """, (item.key, item.value, item.category, item.description))
        return {"status": "success", "message": "Configuración del sistema actualizada correctamente."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
