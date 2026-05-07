import os
import yaml
import psycopg2
import db_manager
import subprocess
from psycopg2.extras import RealDictCursor

# DB Config moved to db_manager.py

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
        # Try to get image from compose, if local-build, try to get it from running container
        image_name = config.get('image')
        if not image_name:
            try:
                # Get image ID of running container
                inspect_cmd = ["docker", "inspect", "--format", "{{.Image}}", f"casmarts-core-{service_name}"]
                result = subprocess.run(inspect_cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    image_name = result.stdout.strip() # This will be the sha256 ID
                else:
                    image_name = "local-build"
            except:
                image_name = "local-build"

        print(f"📦 Found service: {service_name} (Image: {image_name})")
        
        # Skip Wazuh stack to avoid self-auditing noise
        if "wazuh" in service_name:
            print(f"⏭️ Skipping security stack component: {service_name}")
            continue
            
        # Determine criticality (basic logic for now)
        criticality = "Medium"
        if any(keyword in service_name for keyword in ["db", "vault", "auth", "gateway"]):
            criticality = "High"
        
        # Insert or update in inventory
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
        # We can use the docker exec to the manager to get agent list
        cmd = ["docker", "exec", "casmarts-core-wazuh-manager", "/var/ossec/bin/agent_control", "-l"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            
            with db_manager.get_db_cursor() as cur:
                for line in lines:
                    if "ID:" in line and "Name:" in line:
                        # Parse: ID: 001, Name: pmcp, IP: any, Active
                        parts = [p.strip() for p in line.split(",")]
                        agent_id = parts[0].split(":")[1].strip()
                        agent_name = parts[1].split(":")[1].strip()
                        agent_ip = parts[2].split(":")[1].strip()
                        status = parts[3].strip()
                        
                        if agent_name == "wazuh-manager": continue
                        
                        print(f"🕵️ Found agent: {agent_name} (IP: {agent_ip})")
                        
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
