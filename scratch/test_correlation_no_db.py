import os
import json
import urllib.request
import urllib.error
import ssl
import re

vuln = {
    'id': 12844062,
    'cve_id': 'CVE-2026-46099',
    'severity': 'HIGH',
    'description': 'Vulnerabilidad crítica en opensign-server.',
    'asset_name': 'opensign-server',
    'asset_type': 'CONTAINER',
    'endpoint': '10.4.5.10:8080'
}

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

api_key = os.getenv('NVIDIA_NIM_API_KEY')
base_url = os.getenv('NVIDIA_NIM_BASE_URL')
model_name = os.getenv('AI_MODEL')

print("API_KEY length:", len(api_key) if api_key else 0)
print("BASE_URL:", base_url)
print("MODEL:", model_name)

payload = {
    "model": model_name,
    "messages": [{"role": "user", "content": prompt_text}]
}

url = base_url.rstrip('/') + '/chat/completions'
data = json.dumps(payload).encode('utf-8')
req = urllib.request.Request(url, data=data, headers={
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {api_key}'
})

def http_post_json(url, api_key, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    })
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
            return resp.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.read().decode('utf-8')
    except Exception as e:
        return json.dumps({'error': str(e)})

print("Sending request to NVIDIA NIM...")
content = http_post_json(url, api_key, payload)
print("RAW CONTENT RECEIVED:")
print(content[:1000])

try:
    resp_json = json.loads(content)
    if 'choices' in resp_json and len(resp_json['choices']) > 0:
        content = resp_json['choices'][0]['message']['content']
        print("EXTRACTED CONTENT:")
        print(content)
except Exception as e:
    print("Failed to parse response:", e)
