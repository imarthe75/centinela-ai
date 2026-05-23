import os
import time
import json
import redis
import psycopg2
from psycopg2.extras import RealDictCursor
import db_manager
from langchain_core.prompts import ChatPromptTemplate
# Providers
from langchain_openai import ChatOpenAI # For Groq (OpenAI compatible)
from langchain_community.chat_models import ChatOllama
from google import genai

import hvac

def get_vault_secrets():
    """Fetch secrets from Vault if configured"""
    vault_addr = os.getenv("VAULT_ADDR")
    vault_token = os.getenv("VAULT_TOKEN")
    
    if not vault_addr or not vault_token:
        print("ℹ️ [Centinela-AI] Vault not configured, using environment variables.")
        return {}
        
    try:
        client = hvac.Client(url=vault_addr, token=vault_token)
        # Try KV v2 path first
        read_response = client.secrets.kv.v2.read_secret_version(path='casmarts/security')
        secrets = read_response['data']['data']
        print("🔒 [Centinela-AI] Secrets fetched from Vault successfully.")
        return secrets
    except Exception as e:
        print(f"⚠️ [Centinela-AI] Could not fetch secrets from Vault: {e}")
        return {}

# Load Secrets
VAULT_SECRETS = get_vault_secrets()

def get_secret(key, default=None):
    # Check env first for easier debugging
    env_val = os.getenv(key)
    if env_val:
        return env_val
    return VAULT_SECRETS.get(key, default)

# DB_CONFIG moved to db_manager.py

VALKEY_CONFIG = {
    "host": get_secret("VALKEY_HOST", "casmarts-core-cache"),
    "port": 6379,
    "db": 0
}

# Initialize AI based on Provider
provider = get_secret("AI_PROVIDER", "google_genai").lower()
model_name = get_secret("AI_MODEL", "gemini-1.5-flash-latest")
llm = None
genai_client = None

try:
    print(f"🤖 [Centinela-AI] Initializing AI: Provider={provider}, Model={model_name}")
    if provider == "google_genai" or provider == "vertex_ai":
        api_key = get_secret("GOOGLE_API_KEY")
        project = get_secret("GOOGLE_CLOUD_PROJECT")
        location = get_secret("GCP_LOCATION", "us-central1")
        
        if provider == "vertex_ai" and project:
            genai_client = genai.Client(vertexai=True, project=project, location=location)
            print(f"✨ [Centinela-AI] Using NEW GenAI SDK with Vertex AI (GCP)")
        elif api_key:
            genai_client = genai.Client(api_key=api_key)
            print(f"✨ [Centinela-AI] Using NEW GenAI SDK (Google AI Studio)")
            
    elif provider == "groq":
        api_key = get_secret("GROQ_API_KEY")
        if api_key:
            llm = ChatOpenAI(
                openai_api_base="https://api.groq.com/openai/v1",
                openai_api_key=api_key,
                model_name=model_name
            )
    elif provider == "ollama":
        base_url = get_secret("OLLAMA_BASE_URL", "http://ollama:11434")
        llm = ChatOllama(base_url=base_url, model=model_name)
    elif provider == "nvidia_nim":
        api_key = get_secret("NVIDIA_NIM_API_KEY")
        base_url = get_secret("NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
        if api_key:
            llm = ChatOpenAI(
                openai_api_base=base_url,
                openai_api_key=api_key,
                model_name=model_name
            )
    
    if not llm and not genai_client:
        print(f"⚠️ [Centinela-AI] AI Provider '{provider}' not configured correctly. Correlation disabled.")
    else:
        print(f"✅ [Centinela-AI] AI Provider '{provider}' initialized successfully.")
except Exception as e:
    print(f"❌ [Centinela-AI] Error initializing AI provider '{provider}': {e}")

# get_db_connection moved to db_manager.py

def get_valkey_connection():
    return redis.Redis(**VALKEY_CONFIG)

def correlate_vulnerability(vuln):
    """
    Use AI to correlate vulnerability data and suggest remediation.
    """
    if not llm and not genai_client:
        return None
        
    print(f"🤖 [Centinela-AI] Senior Audit analysis for {vuln['cve_id']} on {vuln['asset_name']}...")
    
    # Prompt mejorado basado en CAI Senior Auditor
    # Prompt mejorado basado en CAI Senior Auditor
    prompt_text = f"""
        Actúa como el Auditor Senior de Ciberseguridad de CASMARTS, experto en infraestructura crítica, 
        entornos Linux, seguridad en la nube y servidores de aplicaciones / middleware (WildFly, Tomcat, Nginx, JBoss). 
        Tu objetivo es realizar un análisis exhaustivo de la vulnerabilidad detectada.

        VULNERABILIDAD A ANALIZAR:
        - ID: {vuln['cve_id']}
        - Activo: {vuln['asset_name']}
        - Tipo: {vuln.get('asset_type', 'unknown')}
        - Ubicación: {vuln.get('endpoint', 'unknown')}
        - Descripción inicial: {vuln.get('description', 'Sin descripción')}
        - Severidad reportada: {vuln['severity']}

        REGLAS DE ANÁLISIS:
        1. METODOLOGÍA: Clasifica el hallazgo usando el estándar CVSS v3.
        2. CORRELACIÓN: Identifica patrones específicos de middleware (ej. JMX expuesto, consola admin sin pass, CVEs de Java Deserialization).
        3. REMEDIACIÓN: Proporciona el comando exacto para mitigarla. Si es WildFly, usa 'jboss-cli.sh'. Si es Tomcat, sugiere cambios en 'server.xml'.
        4. INTEGRIDAD: No inventes datos. Si falta información, indícalo en la evidencia.

        FORMATO DE SALIDA (JSON ESTRICTO):
        {{
            "riesgo_detectado": "Nombre técnico de la vulnerabilidad",
            "nivel_severidad": "Bajo/Medio/Alto/Crítico",
            "evidencia_tecnica": "Extracto del log, puerto o configuración afectada",
            "impacto_negocio": "Descripción del riesgo para la operación de CASMARTS",
            "accion_remediacion": "Pasos simples para un desarrollador",
            "remediation_script": "Comando técnico exacto o script en bash para ejecutar y corregir el problema",
            "can_automate": true/false
        }}

        REGLAS DE SCRIPTS:
        - El campo 'remediation_script' DEBE contener un script bash completo, autónomo y ejecutable.
        - IDEMPOTENCIA: El script debe poder ejecutarse varias veces sin causar errores (ej. usar 'mkdir -p', 'grep' antes de añadir líneas).
        - VERIFICACIÓN: El script DEBE incluir comandos para verificar que la corrección funcionó (ej. 'netstat -tuln | grep 9990' para confirmar cierre).
        - DETECCIÓN UNIVERSAL: Los scripts DEBEN detectar si el servicio es WildFly, Tomcat o Nginx y actuar en consecuencia.
        - Si el activo es 'CONTAINER', el script se ejecutará DENTRO del contenedor. NO uses 'sudo'.
        - Si el activo es 'SERVER', asume que tienes permisos de 'root' o 'sudo' (pero el script debe ser agnóstico al método de elevación).
        - Si el activo es 'AppServer', intenta usar las herramientas de gestión integradas (como jboss-cli.sh --connect --command=...).
        - NOTA OBLIGATORIA: Para activos no automatizables (can_automate: false), añade SIEMPRE como paso final en 'accion_remediacion' la instrucción para instalar el agente de Wazuh de forma agnóstica:
          "Para habilitar monitoreo continuo, instale el Agente Wazuh: curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x_amd64.deb && sudo dpkg -i wazuh-agent*.deb"
    """
    
    content = ""
    try:
        if genai_client:
            from google.genai import types
            response = genai_client.models.generate_content(
                model=model_name,
                contents=prompt_text,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )
            content = response.text.strip()
        else:
            prompt = ChatPromptTemplate.from_template("{text}")
            chain = prompt | llm
            response = chain.invoke({"text": prompt_text})
            content = response.content.strip()
        
        import re
        json_match = re.search(r'(\{.*\})', content, re.DOTALL)
        if json_match:
            content = json_match.group(1)
            
        try:
            analysis = json.loads(content)
            
            # Mapeo al esquema de la DB para mantener compatibilidad con el dashboard
            # Pero enriqueciendo el contenido con el formato solicitado
            processed_analysis = {
                "executive_summary": f"**Riesgo:** {analysis.get('riesgo_detectado')}\n\n**Evidencia:** {analysis.get('evidencia_tecnica')}",
                "business_impact": analysis.get('impacto_negocio', 'No impact analysis available'),
                "developer_steps": analysis.get('accion_remediacion', 'No steps provided'),
                "remediation_script": analysis.get('remediation_script', '# No script provided'),
                "can_automate": analysis.get('can_automate', False)
            }
            return processed_analysis
        except json.JSONDecodeError:
            print(f"❌ Failed to parse JSON from AI. Raw content: {content}")
            return None
    except Exception as e:
        print(f"❌ Error in correlation call: {str(e)}")
        import traceback
        traceback.print_exc()
        if "429" in str(e) or "rate_limit" in str(e).lower():
            # Attempt fallback to Groq if available
            groq_key = os.getenv('GROQ_API_KEY')
            if groq_key and os.getenv('AI_PROVIDER') != 'groq':
                print(f"🔄 [Centinela-AI] Vertex limit reached. Falling back to Groq for speed...")
                try:
                    from groq import Groq
                    groq_client = Groq(api_key=groq_key)
                    # Use a stable Llama 3 model for fallback
                    chat_completion = groq_client.chat.completions.create(
                        messages=[{"role": "user", "content": prompt}],
                        model="llama-3.3-70b-versatile",
                    )
                    content = chat_completion.choices[0].message.content
                    # Reuse JSON parsing logic
                    try:
                        if "```json" in content:
                            content = content.split("```json")[1].split("```")[0].strip()
                        return json.loads(content)
                    except:
                        return None
                except Exception as groq_e:
                    print(f"❌ Groq fallback also failed: {groq_e}")
            
            print(f"⏳ [Centinela-AI] Rate limit hit details: {e}")
            return "RATE_LIMIT"
        return None

def generate_ai_remediation_report(cve_id, log_output):
    """
    Use AI to generate a professional remediation report based on the technical execution log.
    """
    if not llm and not genai_client:
        return f"Remediation for {cve_id} completed.\n\nTechnical Log:\n{log_output}"
        
    print(f"🤖 [Centinela-AI] Generating final remediation report for {cve_id}...")
    
    prompt_text = f"""
        Actúa como el CISO de CASMARTS. Redacta un reporte ejecutivo de remediación técnica.
        VULNERABILIDAD: {cve_id}
        LOG TÉCNICO DE EJECUCIÓN:
        {log_output}

        FORMATO DEL REPORTE:
        1. RESUMEN EJECUTIVO: Qué se hizo y por qué.
        2. DETALLE TÉCNICO: Acciones realizadas (iptables, configuración, etc).
        3. ESTADO FINAL: Confirmación de cierre de brecha.
        4. RECOMENDACIÓN: Próximos pasos.

        Mantén un tono profesional, tecnológico y minimalista.
    """
    
    try:
        if genai_client:
            from google.genai import types
            response = genai_client.models.generate_content(
                model=model_name,
                contents=prompt_text
            )
            return response.text.strip()
        else:
            prompt = ChatPromptTemplate.from_template("{text}")
            chain = prompt | llm
            response = chain.invoke({"text": prompt_text})
            return response.content.strip()
    except Exception as e:
        print(f"⚠️ [Centinela-AI] AI Report generation failed: {e}")
        return f"Remediation for {cve_id} completed successfully.\n\nTechnical Log:\n{log_output}"

def process_falco_alerts():
    """Consume Falco alerts from Valkey and store in DB"""
    r = get_valkey_connection()
    while True:
        try:
            alert_raw = r.lpop("centinela:falco")
            if alert_raw:
                alert = json.loads(alert_raw)
                print(f"🚨 [Centinela-AI] Falco Alert: {alert.get('rule')}")
                
                with db_manager.get_db_cursor() as cur:
                    container_name = alert.get('output_fields', {}).get('container.name')
                    asset_id = None
                    if container_name:
                        cur.execute("SELECT id FROM infra_inventory WHERE asset_name LIKE %s", (f"%{container_name}%",))
                        res = cur.fetchone()
                        if res:
                            asset_id = res[0]
                    
                    cur.execute("""
                        INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        asset_id,
                        alert.get('priority'),
                        alert.get('rule'),
                        alert.get('output'),
                        json.dumps(alert.get('output_fields', {}))
                    ))
        except Exception as e:
            print(f"❌ [Centinela-AI] Error processing Falco alert: {e}")
        
        time.sleep(1)

def run_heuristics_loop():
    """Runs the temporal correlation engine every 60 seconds."""
    import heuristics_engine
    while True:
        try:
            heuristics_engine.run_heuristics_correlation()
        except Exception as e:
            print(f"❌ [Centinela-AI] Error running heuristics correlation: {e}")
        time.sleep(60)

def main_loop():
    print("🚀 [Centinela-AI] Aura-Guard v2026.4.2 active.")
    
    import threading
    falco_thread = threading.Thread(target=process_falco_alerts, daemon=True)
    falco_thread.start()
    
    # Start real-time Heuristics Engine thread
    heuristics_thread = threading.Thread(target=run_heuristics_loop, daemon=True)
    heuristics_thread.start()
    
    # External Auditor Thread
    import auditor_ext
    threading.Thread(target=auditor_ext.main, daemon=True).start()

    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT v.id, v.cve_id, v.severity, v.description, i.asset_name, i.asset_type, i.endpoint
                    FROM vulnerability_log v
                    JOIN infra_inventory i ON v.asset_id = i.id
                    LEFT JOIN remediation_history r ON v.id = r.vuln_id
                    WHERE (r.id IS NULL OR v.status IN ('PENDING', 'NEW', 'AI_FAILED', 'AI_ERROR'))
                    AND v.status != 'QUEUED_BACKLOG'
                    ORDER BY (CASE WHEN i.id IN (131, 137, 138, 139) THEN 0 ELSE 1 END) ASC, v.id DESC
                    LIMIT 50;
                """)
                
                pending_vulns = cur.fetchall()
                
                if not pending_vulns:
                    time.sleep(30)
                    continue

                for vuln in pending_vulns:
                    try:
                        analysis = correlate_vulnerability(vuln)
                        if analysis == "RATE_LIMIT":
                            print(f"⏳ [Centinela-AI] Respecting API quota. Waiting 30s before next batch...")
                            time.sleep(30) # Increased wait for Vertex AI quota reset
                            break 
                        
                        if analysis:
                            script_path = f"/app/data/remediation/{vuln['cve_id']}_{vuln['id']}.sh"
                            remediation_content = analysis.get('remediation_script', '# No script provided')
                            
                            with open(script_path, "w") as f:
                                f.write(str(remediation_content))
                            
                            cur.execute("""
                                UPDATE vulnerability_log 
                                SET status = 'CORRELATED', 
                                    executive_summary = %s,
                                    business_impact = %s,
                                    developer_steps = %s
                                WHERE id = %s
                            """, (
                                analysis.get('executive_summary', 'No summary available'),
                                analysis.get('business_impact', 'No impact analysis available'),
                                analysis.get('developer_steps', 'No steps provided'),
                                vuln['id']
                            ))
                            
                            cur.execute("""
                                INSERT INTO remediation_history (vuln_id, script_path, approval_token, can_automate)
                                VALUES (%s, %s, %s, %s);
                            """, (vuln['id'], script_path, "PENDING_APPROVAL", analysis.get('can_automate', True)))
                            
                            # Commit happens automatically in context manager
                            print(f"✅ Analysis complete for {vuln['cve_id']}. Script saved.")
                            time.sleep(3) # Delay between successful requests to prevent 429
                        else:
                            cur.execute("UPDATE vulnerability_log SET status = 'AI_FAILED' WHERE id = %s", (vuln['id'],))
                    except Exception as e:
                        print(f"❌ Critical error processing vuln {vuln['id']}: {e}")
                        # If it's a connection error or something transient, don't mark as error
                        if "conn" in str(e).lower() or "429" in str(e):
                            continue
                        cur.execute("UPDATE vulnerability_log SET status = 'AI_ERROR' WHERE id = %s", (vuln['id'],))
        except Exception as e:
            print(f"❌ [Centinela-AI] Error in main loop: {e}")
            time.sleep(10)
        
        time.sleep(10) # Wait 10s between query cycles

if __name__ == "__main__":
    main_loop()
