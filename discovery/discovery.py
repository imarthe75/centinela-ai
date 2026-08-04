import docker
import os
import yaml
import psycopg2
from core import db_manager
from psycopg2.extras import RealDictCursor

# Initialize Docker Client
docker_client = docker.from_env()

def discover_core_assets():
    print("🔍 [Centinela-AI] Starting Core Asset Discovery...")
    
    # Path to core compose (mounted in container)
    core_compose_path = "/app/core-casmarts/docker-compose.yml" 
    
    if not os.path.exists(core_compose_path):
        print(f"⚠️ Core compose not found at {core_compose_path}. Skipping discovery.")
        return

    with open(core_compose_path, 'r') as f:
        compose_data = yaml.safe_load(f)

    services = compose_data.get('services', {})
    
    for service_name, config in services.items():
        image_name = config.get('image')
        if not image_name:
            try:
                # Get image from container inspect
                container = docker_client.containers.get(f"casmarts-core-{service_name}")
                image_name = container.image.tags[0] if container.image.tags else container.image.id
            except:
                image_name = "local-build"

        print(f"📦 Found service: {service_name} (Image: {image_name})")
        
        if "wazuh" in service_name:
            print(f"⏭️ Skipping security stack component: {service_name}")
            continue
            
        criticality = "Medium"
        if any(keyword in service_name for keyword in ["db", "vault", "auth", "gateway"]):
            criticality = "High"
        
        try:
            with db_manager.get_db_cursor() as cur:
                cur.execute("""
                    INSERT INTO infra_inventory (asset_name, asset_type, endpoint, criticality, last_audit, status)
                    VALUES (%s, %s, %s, %s, NOW(), 'discovered')
                    ON CONFLICT (asset_name) DO UPDATE 
                    SET endpoint = %s, last_audit = NOW(), status = 'rediscovered';
                """, (service_name, "Container", image_name, criticality, image_name))
        except Exception as e:
            print(f"❌ Error inserting service {service_name}: {e}")

    print("✅ Discovery complete.")

def discover_wazuh_agents():
    print("🔍 [Centinela-AI] Starting Wazuh Agent Discovery...")
    try:
        container = docker_client.containers.get("casmarts-core-wazuh-manager")
        result = container.exec_run("/var/ossec/bin/agent_control -l")
        
        if result.exit_code == 0:
            lines = result.output.decode().splitlines()
            
            with db_manager.get_db_cursor() as cur:
                for line in lines:
                    if "ID:" in line and "Name:" in line:
                        # Parse: ID: 001, Name: pmcp, IP: any, Active
                        parts = [p.strip() for p in line.split(",")]
                        agent_id = parts[0].split(":")[1].strip()
                        agent_name = parts[1].split(":")[1].strip()
                        agent_ip = parts[2].split(":")[1].strip()
                        status = parts[3].strip()
                        
                        if agent_name.startswith("wazuh-manager"): continue
                        
                        print(f"🕵️ Found agent: {agent_name} (IP: {agent_ip})")
                        
                        # Check if an asset with this IP or matching name already exists
                        existing = None
                        if agent_ip and agent_ip != "any":
                            cur.execute("SELECT id FROM infra_inventory WHERE endpoint = %s", (agent_ip,))
                            existing = cur.fetchone()
                        
                        if not existing:
                            # Try to match by asset_name (case-insensitive: agent hostnames
                            # and inventory asset_name casing frequently differ)
                            cur.execute("SELECT id FROM infra_inventory WHERE LOWER(asset_name) = LOWER(%s) OR LOWER(asset_name) = LOWER(%s)", (agent_name, f"{agent_name}-server"))
                            existing = cur.fetchone()

                        if not existing and agent_name and len(agent_name) >= 5:
                            # Last-resort fuzzy match: asset_name contains the agent hostname
                            # or vice versa (e.g. agent "authentik" <-> asset "casmart_authentik").
                            # Avoids spawning duplicate assets when naming conventions differ
                            # slightly between the OS hostname and the inventory record.
                            # Restricted to SERVER/AppServer assets and a minimum name length —
                            # short/generic agent hostnames (e.g. "kiwi") can otherwise spuriously
                            # substring-match unrelated rows (a GitLab repo path containing the
                            # word "compramex" once matched a Wazuh agent named "compramex").
                            # (Wildcard built in Python, not SQL: literal '%' in the query
                            # string clashes with psycopg2's %s parameter substitution.)
                            name_pattern = f"%{agent_name.lower()}%"
                            cur.execute("""
                                SELECT id FROM infra_inventory
                                WHERE asset_type IN ('SERVER', 'AppServer')
                                  AND (LOWER(asset_name) LIKE %s
                                       OR %s LIKE '%%' || LOWER(asset_name) || '%%')
                                LIMIT 1
                            """, (name_pattern, agent_name.lower()))
                            existing = cur.fetchone()

                        if existing:
                            cur.execute("""
                                UPDATE infra_inventory 
                                SET agent_id = %s,
                                    status = %s,
                                    last_audit = NOW()
                                WHERE id = %s
                            """, (agent_id, status.lower(), existing[0]))
                        else:
                            cur.execute("""
                                INSERT INTO infra_inventory (asset_name, asset_type, endpoint, criticality, last_audit, status, agent_id)
                                VALUES (%s, %s, %s, %s, NOW(), %s, %s)
                                ON CONFLICT (asset_name) DO UPDATE 
                                SET status = EXCLUDED.status, 
                                    last_audit = NOW(),
                                    agent_id = EXCLUDED.agent_id;
                            """, (agent_name, "AppServer", agent_ip if agent_ip != "any" else "remote-agent", "High", status.lower(), agent_id))
            
            print("✅ Wazuh discovery complete.")
    except Exception as e:
        print(f"❌ Error in Wazuh discovery: {e}")

if __name__ == "__main__":
    discover_core_assets()
    discover_wazuh_agents()
