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
from core import db_manager
from pydantic import BaseModel
from typing import Optional
import requests
import re
import hvac
import threading
import subprocess


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

def install_wazuh_agent_background(endpoint: str, user: str, password: Optional[str] = None, ssh_key: Optional[str] = "/app/keys/casmarts.key"):
    """Executes Ansible to install and configure Wazuh Agent on the remote host via Password or SSH Key in a background thread."""
    def target():
        manager_ip = get_wazuh_manager_ip()
        print(f"🚀 [Centinela-Backend] Background Ansible Wazuh Agent deployment started for {endpoint} pointing to Manager {manager_ip}...")
        
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
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("UPDATE public.infra_inventory SET status = 'active' WHERE endpoint = %s", (endpoint,))
                print(f"🔄 [Centinela-Backend] Database status set to active for {endpoint}.")
            except Exception as db_e:
                print(f"⚠️ [Centinela-Backend] Failed to update status for {endpoint}: {db_e}")
        else:
            print(f"❌ [Ansible] Could not install Wazuh Agent on {endpoint}. Both Password and SSH Key auth failed or were unavailable.")

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
    gitlab_token: Optional[str] = None  # Personal Access Token (PAT) for GitLab/Gitea
    gitlab_user: Optional[str] = None  # GitLab/Gitea username

class VaultSecretModel(BaseModel):
    sudo_password: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ansible_user: Optional[str] = None

class ManualRemediationModel(BaseModel):
    solution: str
    reason: str

app = FastAPI(title="Centinela-AI Security API")

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

        # Si viene clave sudo, token GitLab o SSH Private Key, guardarla en Vault (nunca en la BD)
        vault_stored = False
        if item.vault_sudo_token or item.gitlab_token or item.ssh_private_key:
            vault_stored = store_vault_secret(
                asset_name=item.asset_name,
                sudo_password=item.vault_sudo_token or "",
                ansible_user=item.vault_ansible_user or item.gitlab_user or "",
                ssh_private_key=item.ssh_private_key or ""
            )

        # Iniciar instalación del agente Wazuh mediante Ansible para cualquier Servidor de Aplicación
        if item.asset_type in ("SERVER", "Servidor de Aplicación"):
            ansible_user = item.vault_ansible_user or "authentik"
            install_wazuh_agent_background(
                endpoint=item.endpoint,
                user=ansible_user,
                password=item.vault_sudo_token,
                ssh_key="/app/keys/casmarts.key"
            )

        return {
            "status": "success",
            "message": f"Asset {item.asset_name} registered.",
            "vault_secret_stored": vault_stored
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
            
            # Críticos y Altos
            cur.execute("SELECT COUNT(*) as count FROM public.vulnerability_log WHERE severity = 'CRITICAL'")
            critical = cur.fetchone()["count"]
            
            cur.execute("SELECT COUNT(*) as count FROM public.vulnerability_log WHERE severity = 'HIGH'")
            high = cur.fetchone()["count"]
            
            # Pendientes de aprobación
            cur.execute("SELECT COUNT(*) as count FROM public.remediation_history WHERE approval_token = 'PENDING_APPROVAL'")
            pending_approval = cur.fetchone()["count"]
            
            return {
                "total": total,
                "pending_ia": pending_ia,
                "critical": critical,
                "high": high,
                "pending_approval": pending_approval
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
            
            # Endpoints
            cur.execute("SELECT COUNT(*) as count FROM public.infra_inventory")
            endpoints_count = cur.fetchone()["count"]
            
            # Query Authentik for real active users via the management SSH channel
            # (Authentik's Postgres lives on 10.4.3.208, not on the Centinela DB host)
            users_count = 26 # Fallback real user count
            try:
                cmd = """ssh -o StrictHostKeyChecking=no -i keys/casmarts.key authentik@10.4.3.208 "docker exec casmarts-core-authentik-server python3 manage.py shell -c \\"from authentik.core.models import User; print('JSON_DATA:' + str(User.objects.filter(is_active=True).exclude(username__startswith='ak-').exclude(username='AnonymousUser').count()))\\"" """
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                if "JSON_DATA:" in proc.stdout:
                    users_count = int(proc.stdout.split("JSON_DATA:")[1].strip().splitlines()[0])
                else:
                    raise Exception(proc.stderr.strip() or "sin salida JSON_DATA")
            except Exception as auth_e:
                print(f"⚠️ [Centinela-Backend] Could not fetch user count from Authentik: {auth_e}")
            
            private_hosts = endpoints_count
            public_hosts = 0 # Placeholder
            
            return {
                "alerts": alerts_count,
                "endpoints": endpoints_count,
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
                SELECT r.id, r.priority, r.rule_name, r.alert_text, r.detected_at, i.asset_name
                FROM public.runtime_alerts r
                LEFT JOIN public.infra_inventory i ON r.asset_id = i.id
                WHERE r.rule_name NOT IN ('Terminal shell in container', 'Unauthorized file access')
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
            cur.execute("SELECT severity, COUNT(id) as value FROM public.vulnerability_log GROUP BY severity")
            results = cur.fetchall()
            return results
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
                    COALESCE(COUNT(DISTINCT v.id), 0) as vulnerability_count,
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
                GROUP BY i.asset_name, i.asset_type, cat.label, cat.badge_class, i.endpoint, i.status, i.agent_id
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
            """
            params = []
            if asset:
                query += " WHERE i.asset_name ILIKE %s"
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
                    except Exception:
                        pass
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

@app.get("/api/health")
async def get_system_health():
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

        def check_http(url, verify=False, timeout=3):
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
            # standards is COALESCE'd in by log_finding_deduplicated() whenever
            # core/mitre_attack.py's map_finding() recognizes a cve_id -- real DB evidence
            # that the mapping is actually being applied, not just importable.
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE standards IS NOT NULL AND standards != ''")
                    return "Online" if cur.fetchone()[0] > 0 else "No Data Yet"
            except Exception:
                return "Unreachable"

        def check_threat_intel():
            # run_threat_intel_enrichment_loop() re-checks every row every 24h -- 48h window
            # gives slack for a slow cycle without ever masking a genuinely stalled loop.
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE threat_intel_checked_at > NOW() - INTERVAL '48 hours'")
                    return "Online" if cur.fetchone()[0] > 0 else "No Recent Data"
            except Exception:
                return "Unreachable"

        def check_cti_feed():
            # process_zeek_conn_log() checks every connection against cti_feed's IP set and
            # logs a heartbeat every 5 minutes regardless of whether a match occurred -- a real
            # C2 match (CTI-IOC-MATCH-RUNTIME) is a hoped-for-empty result, not a health signal,
            # so liveness has to come from the heartbeat, same reasoning as the Zeek fix.
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
            # On-demand (SSH-triggered per asset via /api/cis-benchmark/check/{asset_name}),
            # no background loop -- "Online" would be a lie before it's ever been run against
            # anything, so report that honestly instead of defaulting to a fake positive.
            if check_module("auditors.auditor_cis_benchmarks") != "Online":
                return "Not Installed"
            try:
                with db_manager.get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE scan_engine='cis-benchmark'")
                    return "Online" if cur.fetchone()[0] > 0 else "Available (On-Demand, Not Yet Run)"
            except Exception:
                return "Unreachable"

        db_status = check_db()
        zap_status = "Online" if check_tool("docker") == "Online" and check_module("auditors.auditor_zap") == "Online" else "Not Found"
        medusa_status = check_tool("medusa")
        secrets_status = check_tool("trufflehog")

        return {
            "status": "Healthy" if db_status == "Online" else "Degraded",
            "services": [
                {"name": "Database Maestro", "status": db_status, "latency": "2ms" if db_status == "Online" else "N/A"},
                {"name": "AI Engine (Gemini/Groq)", "status": check_ai_engine(), "latency": "N/A"},
                {"name": "Scanning Engine (Nuclei)", "status": check_tool("nuclei"), "latency": "N/A"},
                {"name": "DAST Engine (ZAP)", "status": zap_status, "latency": "N/A"},
                {"name": "SAST Engine (Medusa)", "status": medusa_status, "latency": "N/A"},
                {"name": "Secrets Scanner (TruffleHog)", "status": secrets_status, "latency": "N/A"},
                {"name": "OSINT Engine (SpiderFoot)", "status": check_module("auditors.auditor_spiderfoot"), "latency": "N/A"},
                {"name": "Container Scanner (Trivy)", "status": check_tool("trivy"), "latency": "N/A"},
                {"name": "NDR (Zeek)", "status": check_zeek_ingestion(), "latency": "N/A"},
                {"name": "ITDR (Neo4j/BloodHound)", "status": check_neo4j(), "latency": "N/A"},
                {"name": "Secrets Backend (Vault)", "status": check_vault(), "latency": "N/A"},
                # Wazuh's API genuinely takes longer than the default 3s to respond even to an
                # unauthenticated request -- confirmed live: it reliably answers (401, meaning
                # it's actually up, just requires auth -- check_http() doesn't inspect status
                # codes, so this was never about the response itself) within ~15s but times out
                # at 3s. The manager was never actually down; the check was just too impatient.
                {"name": "EDR (Wazuh Manager)", "status": check_http("https://10.4.3.34:55000", timeout=12), "latency": "N/A"},
                {"name": "Identity (Authentik)", "status": check_http(os.getenv("AUTHENTIK_URL", "https://auth.casmart.internal")), "latency": "N/A"},
                {"name": "Risk Intel (EPSS/CISA KEV)", "status": check_threat_intel(), "latency": "N/A"},
                {"name": "CTI Feed (C2/IOC Matching)", "status": check_cti_feed(), "latency": "N/A"},
                {"name": "MITRE ATT&CK Mapping", "status": check_mitre_mapping(), "latency": "N/A"},
                {"name": "CIS Benchmarks (Hardening Audit)", "status": check_cis_benchmarks(), "latency": "N/A"},
                {"name": "GitLab Auto-Fix (MR Patcher)", "status": check_module("remediation.gitlab_autofix"), "latency": "N/A"},
                {"name": "Host Containment (Emergency Response)", "status": "Available (On-Demand)", "latency": "N/A"},
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
                "mitre_attack_mapping": check_mitre_mapping(),
                "threat_intel_epss_kev": check_threat_intel(),
                "cti_feed_c2": check_cti_feed(),
                "gitlab_autofix": check_module("remediation.gitlab_autofix"),
                "host_containment": "Available (On-Demand)",
            },
            "last_check": datetime.now().isoformat()
        }
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
            except Exception:
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

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(poll_new_alerts())

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
        else:
            raise HTTPException(status_code=400, detail="Invalid action")
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
async def trigger_full_spectrum_audit(target_dir: Optional[str] = "/opt/centinela-ai"):
    """Triggers native SAST, SCA, DevSecOps/IaC, and Master Audit Standards check."""
    try:
        from auditors import auditor_master_vulnerabilities, auditor_sca_dependencies, auditor_compliance_standards
        sast = auditor_master_vulnerabilities.run_master_vulnerability_scan(target_dir)
        sca = auditor_sca_dependencies.run_sca_audit(target_dir)
        standards = auditor_compliance_standards.run_compliance_standards_audit(target_dir)
        return {
            "status": "success",
            "counts": {
                "sast": len(sast),
                "sca": len(sca),
                "standards": len(standards),
                "total": len(sast) + len(sca) + len(standards)
            },
            "findings": {"sast": sast, "sca": sca, "standards": standards}
        }
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
        findings = run_shadow_api_audit()
        return {"status": "success", "count": len(findings), "findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/llm-governance")
async def audit_llm_governance(target_dir: Optional[str] = "/opt/centinela-ai"):
    """Runs OWASP LLM & AI Governance Auditor."""
    try:
        from auditors.auditor_llm_governance import run_llm_governance_audit
        findings = run_llm_governance_audit(target_dir)
        return {"status": "success", "count": len(findings), "findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/iac-k8s")
async def audit_iac_k8s(target_dir: Optional[str] = "/opt/centinela-ai"):
    """Runs Terraform & Kubernetes manifest Auditor."""
    try:
        from auditors.auditor_iac_k8s import run_iac_k8s_audit
        findings = run_iac_k8s_audit(target_dir)
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
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,600;0,9..40,700;1,9..40,400&family=DM+Mono:wght@400;500&display=swap');

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
            cur.execute("SELECT COUNT(*) as c FROM public.vulnerability_log WHERE severity='CRITICAL'")
            critical = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) as c FROM public.vulnerability_log WHERE severity='HIGH'")
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
                  CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
                  v.detected_at DESC
            """, (asset["id"],))
            vulns = cur.fetchall()

        gen_date = datetime.now().strftime("%d/%m/%Y %H:%M")
        total_v = len(vulns)
        critical_v = sum(1 for v in vulns if v["severity"] == "CRITICAL")
        high_v     = sum(1 for v in vulns if v["severity"] == "HIGH")
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


@app.get("/api/users")
async def get_authentik_users():
    """Lists all non-system users from Authentik with their assigned Centinela role (Admin / Viewer)."""
    try:
        cmd = """ssh -o StrictHostKeyChecking=no -i keys/casmarts.key authentik@10.4.3.208 "docker exec casmarts-core-authentik-server python3 manage.py shell -c \\"import json; from authentik.core.models import User, Group; admin_group = Group.objects.filter(name='Centinela Admin').first(); users = [{'username': u.username, 'name': u.name or u.username, 'email': u.email, 'role': 'Admin' if admin_group in u.groups.all() else 'Viewer'} for u in User.objects.all() if not u.username.startswith('ak-') and u.username != 'AnonymousUser']; print('JSON_DATA:' + json.dumps(users))\\"" """
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        out = proc.stdout
        if "JSON_DATA:" in out:
            json_str = out.split("JSON_DATA:")[1].strip().splitlines()[0]
            return json.loads(json_str)
        return []
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class UserRoleUpdateModel(BaseModel):
    username: str
    role: str  # "Admin" or "Viewer"


@app.post("/api/users/role")
async def update_authentik_user_role(body: UserRoleUpdateModel):
    """Updates a user's role in Authentik (Centinela Admin vs Centinela Viewer)."""
    try:
        new_role = body.role
        username = body.username
        cmd = f"""ssh -o StrictHostKeyChecking=no -i keys/casmarts.key authentik@10.4.3.208 "docker exec casmarts-core-authentik-server python3 manage.py shell -c \\"from authentik.core.models import User, Group; admin_group, _ = Group.objects.get_or_create(name='Centinela Admin'); viewer_group, _ = Group.objects.get_or_create(name='Centinela Viewer'); u = User.objects.filter(username='{username}').first(); u.groups.add(admin_group) if '{new_role}' == 'Admin' else u.groups.add(viewer_group); u.groups.remove(viewer_group) if '{new_role}' == 'Admin' else u.groups.remove(admin_group); print('ROLE_UPDATED_SUCCESS')\\"" """
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        if "ROLE_UPDATED_SUCCESS" in proc.stdout:
            return {"status": "success", "username": username, "role": new_role}
        raise HTTPException(status_code=404, detail="Usuario no encontrado en Authentik")
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
