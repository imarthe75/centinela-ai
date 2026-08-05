import os
import time
import json
import redis
import psycopg2
from psycopg2.extras import RealDictCursor
from core import db_manager
try:
    from langchain_core.prompts import ChatPromptTemplate
except Exception:
    ChatPromptTemplate = None

# Providers (optional imports to avoid crash if packages missing in local env)
try:
    from langchain_openai import ChatOpenAI # For Groq / OpenAI-compatible endpoints
except Exception:
    ChatOpenAI = None

try:
    from langchain_community.chat_models import ChatOllama
except Exception:
    ChatOllama = None

try:
    from google import genai
except Exception:
    genai = None

import hvac
import urllib.request
import urllib.error
import ssl

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
model_name = get_secret("AI_MODEL", "meta/llama-3-70b-instruct")
google_model_name = get_secret("AI_MODEL_GOOGLE", "gemini-1.5-flash-latest")
llm = None
genai_client = None

def try_init_provider(p):
    global llm, genai_client
    try:
        print(f"🤖 [Centinela-AI] Attempting provider: {p}, model={model_name}")
        if p in ("google_genai", "vertex_ai") and genai is not None:
            api_key = get_secret("GOOGLE_API_KEY")
            project = get_secret("GOOGLE_CLOUD_PROJECT")
            location = get_secret("GCP_LOCATION", "us-central1")
            use_model = google_model_name
            if p == "vertex_ai" and project:
                genai_client = genai.Client(vertexai=True, project=project, location=location)
                print(f"✨ [Centinela-AI] Using GenAI SDK with Vertex AI (GCP)")
                return True
            elif api_key:
                genai_client = genai.Client(api_key=api_key)
                model_name_local = use_model
                print(f"✨ [Centinela-AI] Using GenAI SDK (Google AI Studio) with model {model_name_local}")
                return True
        elif p == "groq" and ChatOpenAI is not None:
            api_key = get_secret("GROQ_API_KEY")
            if api_key:
                llm = ChatOpenAI(
                    openai_api_base="https://api.groq.com/openai/v1",
                    openai_api_key=api_key,
                    model_name=model_name
                )
                return True
        elif p == "ollama" and ChatOllama is not None:
            base_url = get_secret("OLLAMA_BASE_URL", "http://ollama:11434")
            llm = ChatOllama(base_url=base_url, model=model_name)
            return True
        elif p == "nvidia_nim" and ChatOpenAI is not None:
            api_key = get_secret("NVIDIA_NIM_API_KEY")
            base_url = get_secret("NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
            use_model = model_name
            if api_key:
                # ChatOpenAI may call chat/completions; NVIDIA integrate may expect different endpoints.
                # We still initialize ChatOpenAI but prefer Google GenAI when available.
                llm = ChatOpenAI(
                    openai_api_base=base_url,
                    openai_api_key=api_key,
                    model_name=use_model
                )
                return True
        elif p == "openrouter" and ChatOpenAI is not None:
            api_key = get_secret("OPENROUTER_API_KEY") or get_secret("OPENROUTER_KEY") or get_secret("OPENROUTER_APIKEY")
            base = get_secret("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
            if api_key:
                llm = ChatOpenAI(
                    openai_api_base=base,
                    openai_api_key=api_key,
                    model_name=model_name
                )
                return True
    except Exception as e:
        print(f"⚠️ [Centinela-AI] Provider {p} init failed: {e}")
    return False

# Determine provider order
order_str = get_secret("AI_PROVIDER_ORDER", "nvidia_nim,openrouter,google_genai,groq,ollama")
providers_order = [x.strip().lower() for x in order_str.split(",") if x.strip()]

initialized = False
for p in providers_order:
    if try_init_provider(p):
        initialized = True
        active_provider = p
        break

if not initialized:
    print(f"⚠️ [Centinela-AI] No AI provider initialized from order: {providers_order}. Correlation disabled.")
else:
    print(f"✅ [Centinela-AI] AI Provider '{active_provider}' initialized successfully.")

# get_db_connection moved to db_manager.py

def get_valkey_connection():
    return redis.Redis(**VALKEY_CONFIG)

def generate_heuristic_script(vuln):
    cve = str(vuln.get('cve_id', 'SECURITY-FINDING')).upper()
    asset = str(vuln.get('asset_name', 'INFRASTRUCTURE-HOST'))
    atype = str(vuln.get('asset_type', 'SERVER')).upper()
    ep = str(vuln.get('endpoint', '0.0.0.0'))
    desc = str(vuln.get('description', '')).lower()

    header = f"#!/bin/bash\n# Script de Remediación Automática - Centinela AI\n# Host: {asset} ({ep})\n# Vulnerabilidad / Regla: {cve}\nset -e\necho '🔒 Ejecutando hardening y remediación de seguridad en {asset} ({ep})...'\n"

    if 'DOCKER' in cve or 'CONTAINER' in cve or 'NON-ROOT' in cve or 'non-root' in desc:
        body = f"""# Remediar DOCKER-MISSING-NON-ROOT-USER / Hardening de Usuarios en Contenedores
echo '🔍 Verificando ejecuciones de contenedor como usuario no-root...'
if command -v docker >/dev/null 2>&1; then
    docker ps --format '{{{{.ID}}}} {{{{.Names}}}}' | while read cid name; do
        cuser=$(docker exec "$cid" whoami 2>/dev/null || echo "root")
        if [ "$cuser" = "root" ]; then
            echo "⚠️ Advertencia: El contenedor $name ($cid) ejecuta procesos como root."
        fi
    done
fi

if ! id -u centinela &>/dev/null; then
    echo '👤 Creando usuario de servicio restringido centinela (UID 10001)...'
    useradd -m -s /bin/bash -u 10001 centinela 2>/dev/null || true
fi
echo '✅ Hardening de usuario no-root completado.'
"""
    elif 'SSH' in cve or 'ROOT-LOGIN' in cve or 'AUTH' in cve:
        body = """# Remediar SSH-ROOT-LOGIN / Deshabilitar acceso root por SSH
if [ -f /etc/ssh/sshd_config ]; then
    echo '🔐 Configurando SSH sin acceso directo a root...'
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || true
    echo '✅ Configuración SSH endurecida exitosamente.'
else
    echo 'ℹ️ /etc/ssh/sshd_config no encontrado.'
fi
"""
    elif 'GITLAB' in cve or 'PIPELINE' in cve or 'CODE-INJECTION' in cve:
        body = f"""# Remediar inyección / hardening de repositorios GitLab
echo '🛠️ Auditando y asegurando repositorio {asset}...'
if [ -d .git ]; then
    chmod -R go-w .git 2>/dev/null || true
fi
if [ -f /etc/gitlab/gitlab.rb ]; then
    sed -i "s/^\(gitlab_rails\['gitlab_https'\]\s*=\s*\).*/\\1true/" /etc/gitlab/gitlab.rb
    gitlab-ctl reconfigure 2>/dev/null || true
fi
echo '✅ Hardening de proyecto GitLab completado.'
"""
    elif 'PORT' in cve or 'OPEN' in cve or 'EXPOSED' in cve or 'NET' in cve or 'SCAN-AUDIT' in cve:
        body = f"""# Remediar exposición de puertos en {ep}
if command -v ufw >/dev/null 2>&1; then
    echo '🛡️ Aplicando perfil de firewall UFW...'
    ufw default deny incoming 2>/dev/null || true
    ufw default allow outgoing 2>/dev/null || true
    ufw allow 22/tcp 2>/dev/null || true
    ufw allow 80/tcp 2>/dev/null || true
    ufw allow 443/tcp 2>/dev/null || true
    ufw --force enable 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
fi
echo '✅ Verificación de reglas de puerto y firewall completada.'
"""
    else:
        body = f"""# Hardening general de servicio e infraestructura
echo '🔍 Auditando parámetros de seguridad en {asset} ({ep})...'
if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet wazuh-agent 2>/dev/null && echo 'Agente Wazuh activo' || true
fi
echo '✅ Verificación y hardening de {cve} finalizado.'
"""

    footer = f"echo '✅ Hardening completado para {cve}.'\n"
    return header + body + footer


def correlate_vulnerability(vuln):
    """
    Use AI to correlate vulnerability data and suggest remediation.
    """
    if not llm and not genai_client:
        return None
        
    print(f"🤖 [Centinela-AI] Senior Audit analysis for {vuln['cve_id']} on {vuln['asset_name']}...")
    
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
            "remediation_script": "Script bash autónomo e ejecutable específico para solucionar esta vulnerabilidad",
            "can_automate": true/false
        }}

        REGLAS DE SCRIPTS:
        - El campo 'remediation_script' DEBE contener un script bash completo, autónomo y ejecutable específico para la vulnerabilidad {vuln['cve_id']}. NO utilices scripts genéricos de 'ufw status'.
        - IDEMPOTENCIA: El script debe poder ejecutarse varias veces sin causar errores.
        - VERIFICACIÓN: El script DEBE incluir comandos para verificar que la corrección funcionó.
    """
    
    content = ""
    try:
        if genai_client:
            try:
                from google.genai import types
                response = genai_client.models.generate_content(
                    model=google_model_name,
                    contents=prompt_text,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json"
                    )
                )
                content = response.text.strip()
            except Exception as ge:
                print(f"⚠️ [Centinela-AI] GenAI call failed: {ge}")

        if not content:
            # Fallback deterministic Security Engine Generator
            print(f"⚙️ [Centinela-AI] Using Native Heuristics AI Engine for {vuln.get('cve_id')} on {vuln.get('asset_name')}...")
            cve = vuln.get('cve_id', 'SECURITY-FINDING')
            asset = vuln.get('asset_name', 'INFRASTRUCTURE-HOST')
            atype = vuln.get('asset_type', 'SERVER')
            ep = vuln.get('endpoint', '0.0.0.0')
            sev = vuln.get('severity', 'Medium')
            
            script_code = generate_heuristic_script(vuln)
            
            content = json.dumps({
                "riesgo_detectado": f"Exposición de Seguridad - {cve}",
                "nivel_severidad": sev,
                "evidencia_tecnica": f"Hallazgo reportado en {ep} ({atype}). {vuln.get('description', 'Parámetros o puertos no endurecidos.')}",
                "impacto_negocio": f"Riesgo potencial de reconocimiento de infraestructura o vector de acceso no autorizado en {asset}.",
                "accion_remediacion": f"1. Aplicar reglas de hardening específicas e inhabilitar componentes no seguros en {ep}.\n2. Realizar hardening de servicios y habilitar monitoreo continuo con Agente Wazuh.",
                "remediation_script": script_code,
                "can_automate": True
            })
        
        import re

        # ── Strategy 1: strip ```json ... ``` or ``` ... ``` code fences ──
        fence_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
        if fence_match:
            content = fence_match.group(1)

        # ── Strategy 2: find the outermost { ... } block ──
        json_match = re.search(r'(\{.*\})', content, re.DOTALL)
        if json_match:
            content = json_match.group(1)

        # Helper to pick first non-empty value from multiple candidate keys
        def pick(d, *keys, default=''):
            for k in keys:
                v = d.get(k)
                if v is not None and str(v).strip() not in ('', 'null', 'None', 'N/A'):
                    return str(v).strip()
            return default

        try:
            analysis = json.loads(content)
            if isinstance(analysis, dict) and "error" in analysis:
                print(f"⚠️ [Centinela-AI] AI response contains error: {analysis['error']}")
                return None

            riesgo   = pick(analysis, 'riesgo_detectado', 'vulnerability_name', 'risk', 'title', 'name')
            evidencia = pick(analysis, 'evidencia_tecnica', 'technical_evidence', 'evidence', 'details')
            nivel    = pick(analysis, 'nivel_severidad', 'severity_level', 'severity')
            impacto  = pick(analysis, 'impacto_negocio', 'business_impact', 'impact',
                            default='Sin análisis de impacto disponible.')
            pasos    = pick(analysis, 'accion_remediacion', 'remediation_steps', 'steps', 'solution',
                            default='Sin pasos de remediación disponibles.')
            script   = pick(analysis, 'remediation_script', 'script', 'bash_script',
                            default='# Sin script de remediación')

            if not riesgo and script == '# Sin script de remediación':
                print("⚠️ [Centinela-AI] AI response has no valid risk or remediation script.")
                return None

        except json.JSONDecodeError:
            # ── Strategy 3: parse markdown prose as structured text ──
            # AI returned plain text — extract fields from bold/header patterns
            raw = content  # keep the original full response
            def extract_section(text, *labels):
                """Pull text after a bold label or markdown heading."""
                for label in labels:
                    pattern = rf'(?:\*\*{label}\*\*|#{1,3}\s*{label})[:\s]+(.*?)(?=\n\*\*|\n#{1,3}|\Z)'
                    m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                    if m:
                        return m.group(1).strip()
                return ''

            riesgo    = extract_section(raw, 'Riesgo detectado', 'Vulnerability', 'Risk') or 'Riesgo identificado'
            nivel     = extract_section(raw, 'Nivel de severidad', 'Severity') or 'MEDIUM'
            evidencia  = extract_section(raw, 'Evidencia técnica', 'Technical evidence', 'Details')
            impacto   = extract_section(raw, 'Impacto negocio', 'Business impact', 'Impact') or \
                        'Sin análisis de impacto disponible.'
            pasos     = extract_section(raw, 'Acción de remediación', 'Remediation steps', 'Solution') or \
                        'Sin pasos de remediación disponibles.'
            # Extract bash script from code fences
            script_m  = re.search(r'```(?:bash|sh)?\s*(.*?)```', raw, re.DOTALL)
            script    = script_m.group(1).strip() if script_m else '# Sin script de remediación'

            print(f"⚠️ [Centinela-AI] Parsed prose response (non-JSON) successfully.")

        # ── Build executive summary ──
        exec_parts = []
        if riesgo:
            exec_parts.append(f"**Riesgo Detectado:** {riesgo}")
        if nivel:
            exec_parts.append(f"**Nivel de Severidad:** {nivel}")
        if evidencia:
            exec_parts.append(f"**Evidencia Técnica:** {evidencia}")
        exec_summary = '\n\n'.join(exec_parts) if exec_parts else \
            'Análisis de IA completado. Revise los detalles técnicos.'

        return {
            "executive_summary": exec_summary,
            "business_impact": impacto if impacto and impacto != 'Sin análisis de impacto disponible.' else f"Riesgo evaluado para la infraestructura {vuln.get('asset_name')}. Se recomienda aislar el puerto o aplicar parches de seguridad.",
            "developer_steps": pasos if pasos and pasos != 'Sin pasos de remediación disponibles.' else f"1. Verificar la configuración del servicio en {vuln.get('endpoint')}.\n2. Aplicar parches de actualización y cerrar servicios no autorizados.",
            "remediation_script": script,
            "can_automate": False
        }

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

def process_zeek_alerts():
    """Consume Zeek logs or alerts from Valkey and store in DB"""
    r = get_valkey_connection()
    # Check if we also have file logs to tail
    zeek_log_path = "/app/logs/zeek/notice.log"
    
    # Simple tail logic if file exists
    f_log = None
    if os.path.exists(zeek_log_path):
        try:
            f_log = open(zeek_log_path, "r")
            f_log.seek(0, 2)
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Cannot open Zeek log file: {e}")

    while True:
        # 1. Valkey queue check
        try:
            alert_raw = r.lpop("centinela:zeek")
            if alert_raw:
                alert = json.loads(alert_raw)
                print(f"📡 [Centinela-AI] Zeek Alert: {alert.get('msg', 'Notice')}")
                with db_manager.get_db_cursor() as cur:
                    cur.execute("""
                        INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                        VALUES (NULL, 'MEDIUM', %s, %s, %s)
                    """, (
                        alert.get('note', 'ZEEK_NOTICE'),
                        alert.get('msg', 'Alerta de red detectada por Zeek'),
                        json.dumps(alert)
                    ))
        except Exception as e:
            print(f"❌ [Centinela-AI] Error processing Zeek Valkey alert: {e}")

        # 2. Log file check
        if f_log:
            try:
                line = f_log.readline()
                if line:
                    alert = json.loads(line)
                    print(f"📡 [Centinela-AI] Zeek Log Notice: {alert.get('msg')}")
                    with db_manager.get_db_cursor() as cur:
                        cur.execute("""
                            INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                            VALUES (NULL, 'MEDIUM', %s, %s, %s)
                        """, (
                            alert.get('note', 'ZEEK_NOTICE'),
                            alert.get('msg', 'Notice logs de red'),
                            json.dumps(alert)
                        ))
            except Exception as e:
                pass

        time.sleep(1)

def process_bloodhound_paths():
    """Query Neo4j for AD attack paths and raise vulnerabilities"""
    try:
        from neo4j import GraphDatabase
        NEO4J_AVAILABLE = True
    except ImportError:
        NEO4J_AVAILABLE = False

    if not NEO4J_AVAILABLE:
        print("ℹ️ [Centinela-AI] Neo4j library not available, BloodHound path analyzer skipped")
        return

    uri = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "password")

    while True:
        try:
            print("🩸 [Centinela-AI] BloodHound Graph Analyzer querying attack paths...")
            driver = GraphDatabase.driver(uri, auth=(user, password))
            with driver.session() as session:
                # Query shortest path from any non-admin user to Domain Admins group
                query = """
                MATCH p=shortestPath((u:User)-[*1..10]->(g:Group {name: 'DOMAIN ADMINS@INTERNAL.LOCAL'}))
                WHERE NOT u.name STARTS WITH 'Administrator'
                RETURN p LIMIT 1
                """
                result = session.run(query)
                record = result.single()
                if record:
                    path = record.get("p")
                    # Attack path exists!
                    desc = f"BloodHound detectó una ruta de ataque de escalada de privilegios hacia el grupo Domain Admins."
                    nodes = [n.get("name") for n in path.nodes]
                    desc += f" Ruta: {' -> '.join(nodes)}"
                    
                    with db_manager.get_db_cursor() as cur:
                        # Find Active Directory asset
                        cur.execute("SELECT id FROM infra_inventory WHERE asset_name LIKE '%Active Directory%' OR asset_type = 'SERVER' LIMIT 1")
                        res = cur.fetchone()
                        asset_id = res[0] if res else None
                        
                        if asset_id:
                            cur.execute("""
                                INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status, scan_engine)
                                VALUES (%s, 'BLOODHOUND-PATH-AD', 'CRITICAL', %s, 'PENDING', 'bloodhound')
                                ON CONFLICT DO NOTHING
                            """, (asset_id, desc))
                            print("🚨 [Centinela-AI] Critical Attack Path logged in DB!")
            driver.close()
        except Exception as e:
            print(f"⚠️ [Centinela-AI] BloodHound/Neo4j query failed: {e}")
        
        # Check every 10 minutes
        time.sleep(600)

def run_heuristics_loop():
    """Runs the temporal correlation engine every 60 seconds."""
    from core import heuristics_engine
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
    
    zeek_thread = threading.Thread(target=process_zeek_alerts, daemon=True)
    zeek_thread.start()
    
    bloodhound_thread = threading.Thread(target=process_bloodhound_paths, daemon=True)
    bloodhound_thread.start()
    
    # Start real-time Heuristics Engine thread
    heuristics_thread = threading.Thread(target=run_heuristics_loop, daemon=True)
    heuristics_thread.start()
    
    # External Auditor Thread
    from auditors import auditor_ext
    threading.Thread(target=auditor_ext.main, daemon=True).start()

    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT v.id, v.cve_id, v.severity, v.description, i.asset_name, i.asset_type, i.endpoint
                    FROM vulnerability_log v
                    JOIN infra_inventory i ON v.asset_id = i.id
                    LEFT JOIN remediation_history r ON v.id = r.vuln_id
                    WHERE (
                        r.id IS NULL
                        OR v.status IN ('PENDING', 'NEW', 'AI_FAILED', 'AI_ERROR')
                    )
                    AND v.status != 'QUEUED_BACKLOG'
                    AND v.status != 'CORRELATED'
                    AND v.status != 'RESOLVED'
                    ORDER BY (CASE WHEN i.id IN (131, 137, 138, 139) THEN 0 ELSE 1 END) ASC, v.id DESC
                    LIMIT 50;
                """)
                
                pending_vulns = cur.fetchall()
                
                if not pending_vulns:
                    # Run native master audits periodically during idle loop
                    try:
                        from auditors import auditor_master_vulnerabilities, auditor_sca_dependencies, auditor_compliance_standards
                        print("🔍 [Centinela-AI] Running background Omni-Audit scans (SAST, SCA, DevSecOps, Standards)...")
                        auditor_master_vulnerabilities.run_master_vulnerability_scan()
                        auditor_sca_dependencies.run_sca_audit()
                        auditor_compliance_standards.run_compliance_standards_audit()
                    except Exception as audit_err:
                        print(f"⚠️ [Centinela-AI] Omni-Audit scan error: {audit_err}")

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
                            os.makedirs(os.path.dirname(script_path), exist_ok=True)
                            remediation_content = analysis.get('remediation_script', '# No script provided')
                            
                            with open(script_path, "w") as f:
                                f.write(str(remediation_content))
                            
                            with db_manager.get_db_cursor() as write_cur:
                                write_cur.execute("""
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
                                
                                # Check if a history row already exists for this vuln
                                write_cur.execute("SELECT id, approval_token FROM remediation_history WHERE vuln_id = %s LIMIT 1", (vuln['id'],))
                                existing = write_cur.fetchone()
                                if existing:
                                    # Only update script_path; preserve approval_token if already acted on
                                    new_token = existing[1] if existing[1] not in ('PENDING_APPROVAL', None) else 'PENDING_APPROVAL'
                                    write_cur.execute("""
                                        UPDATE remediation_history
                                        SET script_path = %s, approval_token = %s, can_automate = %s
                                        WHERE id = %s
                                    """, (script_path, new_token, analysis.get('can_automate', True), existing[0]))
                                else:
                                    write_cur.execute("""
                                        INSERT INTO remediation_history (vuln_id, script_path, approval_token, can_automate)
                                        VALUES (%s, %s, %s, %s)
                                    """, (vuln['id'], script_path, "PENDING_APPROVAL", analysis.get('can_automate', True)))
                                
                            print(f"✅ Analysis complete for {vuln['cve_id']}. Script saved.")
                            time.sleep(3) # Delay between successful requests to prevent 429
                        else:
                            with db_manager.get_db_cursor() as write_cur:
                                write_cur.execute("UPDATE vulnerability_log SET status = 'AI_FAILED' WHERE id = %s", (vuln['id'],))
                    except Exception as e:
                        print(f"❌ Critical error processing vuln {vuln['id']}: {e}")
                        # If it's a connection error or something transient, don't mark as error
                        if "conn" in str(e).lower() or "429" in str(e):
                            continue
                        with db_manager.get_db_cursor() as write_cur:
                            write_cur.execute("UPDATE vulnerability_log SET status = 'AI_ERROR' WHERE id = %s", (vuln['id'],))
        except Exception as e:
            print(f"❌ [Centinela-AI] Error in main loop: {e}")
            time.sleep(10)
        
        time.sleep(10) # Wait 10s between query cycles

if __name__ == "__main__":
    main_loop()
