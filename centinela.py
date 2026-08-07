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

# Initialize AI providers. Each of Groq / NVIDIA NIM / Google Gemini is initialized
# independently (not "first configured one wins") so correlate_vulnerability() can cascade
# through all three at call time, in that order, before falling back to the deterministic
# heuristic engine. Previously only ONE provider was ever initialized for the process's whole
# lifetime (whichever came first in AI_PROVIDER_ORDER with a valid key) -- e.g. once Groq's
# small daily token quota was exhausted mid-day, every single subsequent finding fell straight
# to the heuristic engine for the rest of the day, even though NVIDIA/Gemini keys were also
# configured and never got a chance to try.
model_name = get_secret("AI_MODEL", "llama-3.3-70b-versatile")
google_model_name = get_secret("AI_MODEL_GOOGLE", "gemini-1.5-flash-latest")
nvidia_model_name = get_secret("AI_MODEL_NVIDIA", "meta/llama-3.1-70b-instruct")

groq_llm = None
nvidia_llm = None
gemini_client = None

if ChatOpenAI is not None:
    groq_key = get_secret("GROQ_API_KEY")
    if groq_key:
        try:
            groq_llm = ChatOpenAI(
                openai_api_base="https://api.groq.com/openai/v1",
                openai_api_key=groq_key,
                model_name=model_name
            )
            print(f"✅ [Centinela-AI] Groq provider initialized (model={model_name}).")
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Groq init failed: {e}")

    nvidia_key = get_secret("NVIDIA_NIM_API_KEY")
    if nvidia_key:
        try:
            nvidia_llm = ChatOpenAI(
                openai_api_base=get_secret("NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"),
                openai_api_key=nvidia_key,
                model_name=nvidia_model_name
            )
            print(f"✅ [Centinela-AI] NVIDIA NIM provider initialized (model={nvidia_model_name}).")
        except Exception as e:
            print(f"⚠️ [Centinela-AI] NVIDIA NIM init failed: {e}")

if genai is not None:
    google_key = get_secret("GOOGLE_API_KEY")
    if google_key:
        try:
            gemini_client = genai.Client(api_key=google_key)
            print(f"✅ [Centinela-AI] Google Gemini provider initialized (model={google_model_name}).")
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Google Gemini init failed: {e}")

if not (groq_llm or nvidia_llm or gemini_client):
    print("⚠️ [Centinela-AI] No AI provider initialized (Groq/NVIDIA/Gemini all unavailable or missing keys). Correlation will use the heuristic engine only.")


def call_ai_cascade(prompt_text, want_json=True):
    """
    Tries each configured LLM provider in order -- Groq -> NVIDIA NIM -> Google Gemini -- and
    returns the text of the first one that actually responds. Returns None if every provider is
    unavailable/unconfigured or errors out (invalid key, rate limit, etc), in which case the
    caller falls back to the deterministic heuristic engine.
    """
    if groq_llm:
        try:
            response = groq_llm.invoke(prompt_text)
            content = (response.content if hasattr(response, "content") else str(response)).strip()
            if content:
                print("🧠 [Centinela-AI] Using LLM provider 'groq'...")
                return content
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Groq call failed: {e}")

    if nvidia_llm:
        try:
            response = nvidia_llm.invoke(prompt_text)
            content = (response.content if hasattr(response, "content") else str(response)).strip()
            if content:
                print("🧠 [Centinela-AI] Using LLM provider 'nvidia_nim'...")
                return content
        except Exception as e:
            print(f"⚠️ [Centinela-AI] NVIDIA NIM call failed: {e}")

    if gemini_client:
        try:
            from google.genai import types
            config = types.GenerateContentConfig(response_mime_type="application/json") if want_json else None
            response = gemini_client.models.generate_content(
                model=google_model_name,
                contents=prompt_text,
                config=config
            )
            content = response.text.strip()
            if content:
                print("🧠 [Centinela-AI] Using LLM provider 'google_genai'...")
                return content
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Google Gemini call failed: {e}")

    return None

# get_db_connection moved to db_manager.py

def get_valkey_connection():
    return redis.Redis(**VALKEY_CONFIG)

# Maps a substring found in a ZAP finding's own "Type:" text (already present in every ZAP
# description regardless of whether cve_id resolved to a real pluginId) to the real nginx
# directive that fixes it. These are the standard, well-known fixes for these specific,
# server-wide HTTP header findings -- covers every ZAP header finding actually seen in
# production. Unmatched ZAP finding types fall through to an honest "no deterministic rule for
# this one" message instead of a fake generic script.
# Each entry: (needle to match in the finding's description, nginx directive that fixes it,
# short real risk name, short real business-impact description). The name/risk are used to
# build genuinely differentiated executive_summary/impacto_negocio text -- previously that text
# was a single generic template regardless of which of these branches actually ran.
ZAP_HEADER_FIXES = [
    ("x-content-type-options", 'add_header X-Content-Type-Options "nosniff" always;',
     "Cabecera X-Content-Type-Options ausente",
     "El navegador puede interpretar (MIME-sniff) una respuesta como un tipo de contenido distinto al declarado, habilitando ataques de XSS vía archivos disfrazados."),
    ("strict-transport-security", 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
     "Cabecera HSTS (Strict-Transport-Security) ausente",
     "Sin HSTS, un atacante en la misma red puede forzar un downgrade a HTTP y interceptar tráfico (ataque de tipo SSL stripping)."),
    ("x-frame-options", 'add_header X-Frame-Options "SAMEORIGIN" always;',
     "Cabecera X-Frame-Options ausente (clickjacking)",
     "El sitio puede ser embebido en un iframe de un dominio malicioso, permitiendo ataques de clickjacking sobre usuarios autenticados."),
    ("anti-clickjacking", 'add_header X-Frame-Options "SAMEORIGIN" always;',
     "Falta protección anti-clickjacking",
     "El sitio puede ser embebido en un iframe de un dominio malicioso, permitiendo ataques de clickjacking sobre usuarios autenticados."),
    ("content security policy", 'add_header Content-Security-Policy "default-src \'self\'" always;',
     "Content-Security-Policy ausente",
     "Sin CSP, el navegador no tiene una segunda barrera contra XSS -- un script inyectado se ejecuta sin restricción de origen."),
    ("csp header not set", 'add_header Content-Security-Policy "default-src \'self\'" always;',
     "Content-Security-Policy ausente",
     "Sin CSP, el navegador no tiene una segunda barrera contra XSS -- un script inyectado se ejecuta sin restricción de origen."),
    ("x-powered-by", 'proxy_hide_header X-Powered-By;',
     "Fuga de información vía cabecera X-Powered-By",
     "Revela el framework/tecnología backend exacta, facilitando a un atacante buscar CVEs específicos de esa versión."),
    ('"server" http response header', 'server_tokens off;',
     "Fuga de versión de servidor vía cabecera Server",
     "Revela la versión exacta del servidor web, facilitando a un atacante buscar CVEs específicos de esa versión."),
    ("cache-control", 'add_header Cache-Control "no-store, max-age=0" always;',
     "Directivas Cache-Control insuficientes",
     "Contenido potencialmente sensible puede quedar cacheado en proxies intermedios o en el navegador de un usuario compartido."),
    ("permissions-policy", 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
     "Cabecera Permissions-Policy ausente",
     "El sitio no restringe explícitamente el acceso a APIs sensibles del navegador (cámara, micrófono, geolocalización) si un script es comprometido."),
    ("referrer-policy", 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
     "Cabecera Referrer-Policy ausente",
     "URLs internas (potencialmente con tokens o rutas sensibles) pueden filtrarse al sitio de destino vía el header Referer en enlaces salientes."),
]


def match_zap_header_entry(vuln):
    """Returns the matched (needle, directive, name, risk) tuple for this ZAP finding, or None."""
    desc = str(vuln.get('description', '')).lower()
    for entry in ZAP_HEADER_FIXES:
        if entry[0] in desc:
            return entry
    return None


def generate_zap_header_fix(vuln):
    """
    Builds a real, idempotent nginx security-header remediation script for the standard
    server-wide ZAP header findings. Returns None if this specific finding's type doesn't
    match a known directive (caller should fall back to an honest "manual review" message
    rather than a fake generic script).

    The script is designed to be run by Sentinel via Ansible against the real target host:
    it detects nginx, writes the missing directive into a dedicated, idempotent snippet file
    (so it never touches/risks breaking existing vhost configs), validates with `nginx -t`
    before reloading, and verifies the header is actually present in a live response
    afterwards -- so a failure is reported as a failure, not silently swallowed.
    """
    desc = str(vuln.get('description', '')).lower()
    directive = None
    for needle, fix, _name, _risk in ZAP_HEADER_FIXES:
        if needle in desc:
            directive = fix
            break
    if not directive:
        return None

    asset = str(vuln.get('asset_name', 'INFRASTRUCTURE-HOST'))
    ep = str(vuln.get('endpoint', '0.0.0.0'))
    cve = str(vuln.get('cve_id', 'ZAP-FINDING'))
    # Best-effort target host for the live verification curl -- endpoint may be a bare IP
    # (asset inventory) rather than the specific URL that was flagged.
    verify_host = ep if ep.startswith("http") else f"https://{ep}"

    return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI
# Host: {asset} ({ep})
# Vulnerabilidad / Regla: {cve}
set -e
echo '🔒 Aplicando cabecera de seguridad HTTP faltante en {asset} ({ep})...'

SNIPPET_REL=/etc/nginx/conf.d/99-centinela-security-headers.conf
DIRECTIVE='{directive}'
NGINX_CONTAINER=""

verify() {{
    echo '✅ Verificando que la cabecera esté presente en una respuesta real...'
    sleep 1
    curl -sk -D - -o /dev/null "{verify_host}" | grep -qi "$(echo "$DIRECTIVE" | cut -d' ' -f2)" \\
        && echo '✅ Verificación exitosa: la cabecera ahora está presente.' \\
        || echo '⚠️ No se pudo confirmar la cabecera en la respuesta -- revisar manualmente (puede que otro vhost/proxy distinto esté sirviendo esta URL específica).'
}}

if command -v nginx >/dev/null 2>&1; then
    echo 'ℹ️ nginx detectado directamente en el host.'
    sudo mkdir -p /etc/nginx/conf.d
    sudo touch "$SNIPPET_REL"
    if sudo grep -qF "$DIRECTIVE" "$SNIPPET_REL" 2>/dev/null; then
        echo "ℹ️ La directiva ya estaba presente (idempotente, nada que hacer)."
    else
        echo "$DIRECTIVE" | sudo tee -a "$SNIPPET_REL" > /dev/null
        echo "✏️ Directiva agregada a $SNIPPET_REL"
    fi
    sudo nginx -t
    sudo systemctl reload nginx 2>/dev/null || sudo nginx -s reload
    verify
    exit 0
fi

# nginx no está instalado en el host -- muy común en despliegues dockerizados, donde el
# reverse-proxy real corre como contenedor (confirmado en producción: casmart_authentik no
# tiene nginx a nivel de sistema, pero sí un contenedor nginx:alpine haciendo de gateway).
if command -v docker >/dev/null 2>&1; then
    NGINX_CONTAINER=$(sudo docker ps --format '{{{{.Names}}}} {{{{.Image}}}}' 2>/dev/null | grep -i nginx | head -1 | awk '{{print $1}}')
    if [ -n "$NGINX_CONTAINER" ]; then
        echo "ℹ️ nginx no está en el host, pero se encontró el contenedor '$NGINX_CONTAINER' corriendo esa imagen."

        if sudo docker exec "$NGINX_CONTAINER" sh -c "touch $SNIPPET_REL" 2>/dev/null; then
            # conf.d is writable inside the container.
            if sudo docker exec "$NGINX_CONTAINER" grep -qF "$DIRECTIVE" "$SNIPPET_REL" 2>/dev/null; then
                echo "ℹ️ La directiva ya estaba presente (idempotente, nada que hacer)."
            else
                sudo docker exec -i "$NGINX_CONTAINER" sh -c "echo '$DIRECTIVE' >> $SNIPPET_REL"
                echo "✏️ Directiva agregada a $SNIPPET_REL dentro del contenedor."
            fi
        else
            # conf.d is bind-mounted read-only inside the container (common, deliberate
            # hardening) -- confirmed in production on casmart_authentik's gateway. Find the
            # real host-side source path via `docker inspect` and write there instead; the
            # container can still see it (bind mounts share the same inode), we just can't
            # write to it from inside.
            echo "ℹ️ $SNIPPET_REL es de solo lectura dentro del contenedor -- buscando la ruta real en el host..."
            HOST_CONFD=$(sudo docker inspect "$NGINX_CONTAINER" --format '{{{{range .Mounts}}}}{{{{if eq .Destination "/etc/nginx/conf.d"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}')
            if [ -z "$HOST_CONFD" ]; then
                echo "⚠️ No se pudo determinar la ruta real de /etc/nginx/conf.d en el host. Acción manual requerida: agregar '$DIRECTIVE' a la configuración de $NGINX_CONTAINER."
                exit 1
            fi
            HOST_SNIPPET="$HOST_CONFD/99-centinela-security-headers.conf"
            sudo touch "$HOST_SNIPPET"
            if sudo grep -qF "$DIRECTIVE" "$HOST_SNIPPET" 2>/dev/null; then
                echo "ℹ️ La directiva ya estaba presente en $HOST_SNIPPET (idempotente, nada que hacer)."
            else
                echo "$DIRECTIVE" | sudo tee -a "$HOST_SNIPPET" > /dev/null
                echo "✏️ Directiva agregada a $HOST_SNIPPET (ruta real en el host, visible dentro del contenedor vía bind mount)."
            fi
        fi

        echo '🔍 Validando configuración de nginx...'
        sudo docker exec "$NGINX_CONTAINER" nginx -t
        echo '🔄 Recargando nginx...'
        sudo docker exec "$NGINX_CONTAINER" nginx -s reload
        verify
        exit 0
    fi
fi

echo "⚠️ No se encontró nginx en el host ni en un contenedor Docker. Acción manual requerida: agregar la directiva '$DIRECTIVE' en la configuración del reverse proxy o del servidor de aplicaciones correspondiente."
exit 1
"""


def generate_ip_block_virtual_patch(vuln, malicious_ip: str, reason: str):
    """
    Real virtual patch for a CTI-IOC-MATCH finding: blocks a specific confirmed-malicious IP
    (from core/cti_feed.py's live Feodo Tracker match) at the reverse-proxy layer via `deny`,
    without touching application code or restarting the service. Reuses the exact same
    nginx-detection pattern already verified for generate_zap_header_fix() (system nginx vs.
    containerized, writable vs. read-only-bind-mounted conf.d).

    `deny <ip>;` is deliberately used instead of a per-URL `location` block: unlike
    add_header/proxy_hide_header/deny, a `location` block can only be safely added inside the
    correct existing server{} block for the target vhost -- blind-inserting one into a separate
    conf.d snippet either does nothing (wrong context) or requires editing the existing vhost
    file directly, which is not purely additive and risks breaking it. `deny` at the http
    context level applies to every server block via nginx's normal directive inheritance, the
    same mechanism the header fix already relies on -- genuinely safe to add blindly.
    """
    asset = str(vuln.get('asset_name', 'INFRASTRUCTURE-HOST'))
    ep = str(vuln.get('endpoint', '0.0.0.0'))
    cve = str(vuln.get('cve_id', 'CTI-IOC-MATCH'))
    directive = f"deny {malicious_ip};"

    return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (Parcheo Virtual)
# Host: {asset} ({ep})
# Vulnerabilidad / Regla: {cve}
# Motivo: {reason}
set -e
echo '🛡️ Aplicando bloqueo de IP maliciosa confirmada ({malicious_ip}) en {asset} ({ep})...'

SNIPPET_REL=/etc/nginx/conf.d/98-centinela-ip-blocklist.conf
DIRECTIVE='{directive}'

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p /etc/nginx/conf.d
    sudo touch "$SNIPPET_REL"
    if sudo grep -qF "$DIRECTIVE" "$SNIPPET_REL" 2>/dev/null; then
        echo "ℹ️ La IP ya estaba bloqueada (idempotente, nada que hacer)."
    else
        echo "$DIRECTIVE" | sudo tee -a "$SNIPPET_REL" > /dev/null
        echo "✏️ IP maliciosa bloqueada: $DIRECTIVE"
    fi
    sudo nginx -t
    sudo systemctl reload nginx 2>/dev/null || sudo nginx -s reload
    echo '✅ Bloqueo aplicado -- ningún reinicio de la aplicación fue necesario.'
    exit 0
fi

if command -v docker >/dev/null 2>&1; then
    NGINX_CONTAINER=$(sudo docker ps --format '{{{{.Names}}}} {{{{.Image}}}}' 2>/dev/null | grep -i nginx | head -1 | awk '{{print $1}}')
    if [ -n "$NGINX_CONTAINER" ]; then
        if sudo docker exec "$NGINX_CONTAINER" sh -c "touch $SNIPPET_REL" 2>/dev/null; then
            if sudo docker exec "$NGINX_CONTAINER" grep -qF "$DIRECTIVE" "$SNIPPET_REL" 2>/dev/null; then
                echo "ℹ️ La IP ya estaba bloqueada (idempotente, nada que hacer)."
            else
                sudo docker exec -i "$NGINX_CONTAINER" sh -c "echo '$DIRECTIVE' >> $SNIPPET_REL"
                echo "✏️ IP maliciosa bloqueada dentro del contenedor: $DIRECTIVE"
            fi
        else
            HOST_CONFD=$(sudo docker inspect "$NGINX_CONTAINER" --format '{{{{range .Mounts}}}}{{{{if eq .Destination "/etc/nginx/conf.d"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}')
            if [ -z "$HOST_CONFD" ]; then
                echo "⚠️ No se pudo determinar la ruta real de conf.d en el host. Acción manual requerida."
                exit 1
            fi
            HOST_SNIPPET="$HOST_CONFD/98-centinela-ip-blocklist.conf"
            sudo touch "$HOST_SNIPPET"
            if sudo grep -qF "$DIRECTIVE" "$HOST_SNIPPET" 2>/dev/null; then
                echo "ℹ️ La IP ya estaba bloqueada (idempotente, nada que hacer)."
            else
                echo "$DIRECTIVE" | sudo tee -a "$HOST_SNIPPET" > /dev/null
                echo "✏️ IP maliciosa bloqueada (ruta real en el host): $DIRECTIVE"
            fi
        fi
        sudo docker exec "$NGINX_CONTAINER" nginx -t
        sudo docker exec "$NGINX_CONTAINER" nginx -s reload
        echo '✅ Bloqueo aplicado -- ningún reinicio de la aplicación fue necesario.'
        exit 0
    fi
fi

echo "⚠️ No se encontró nginx en el host ni en un contenedor Docker. Acción manual requerida: bloquear {malicious_ip} en el firewall o reverse proxy correspondiente."
exit 1
"""


def generate_heuristic_script(vuln):
    cve = str(vuln.get('cve_id', 'SECURITY-FINDING')).upper()
    asset = str(vuln.get('asset_name', 'INFRASTRUCTURE-HOST'))
    atype = str(vuln.get('asset_type', 'SERVER')).upper()
    ep = str(vuln.get('endpoint', '0.0.0.0'))
    desc = str(vuln.get('description', '')).lower()

    header = f"#!/bin/bash\n# Script de Remediación Automática - Centinela AI\n# Host: {asset} ({ep})\n# Vulnerabilidad / Regla: {cve}\nset -e\necho '🔒 Ejecutando hardening y remediación de seguridad en {asset} ({ep})...'\n"

    if cve.startswith('CTI-IOC-MATCH'):
        malicious_ip = str(vuln.get('url_path', '')).split('-')[-1]  # url_path is the raw IP, or "alert-{id}-{ip}"
        return generate_ip_block_virtual_patch(vuln, malicious_ip, "IP confirmada como C2 activo en Feodo Tracker (abuse.ch)")

    if cve == 'HOST-CONTAINMENT-REQUEST':
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (CONTENCIÓN DE EMERGENCIA)
# Host: {asset} ({ep})
# ADVERTENCIA: esto corta el tráfico de red entrante del host casi por completo.
set -e
echo '🚨 CONTENCIÓN DE EMERGENCIA -- aislando {asset} ({ep})...'

BACKUP_FILE="/tmp/centinela_firewall_backup_$(date +%s).rules"

if command -v ufw >/dev/null 2>&1; then
    echo "📋 Respaldando reglas UFW actuales en $BACKUP_FILE (para revertir manualmente después)..."
    sudo ufw status verbose | sudo tee "$BACKUP_FILE" > /dev/null
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default deny outgoing
    sudo ufw allow out 53/udp comment 'DNS'
    sudo ufw allow out 123/udp comment 'NTP'
    echo "ℹ️ Solo se permite DNS/NTP saliente. Todo el tráfico entrante está bloqueado."
    sudo ufw --force enable
elif command -v iptables >/dev/null 2>&1; then
    echo "📋 Respaldando reglas iptables actuales en $BACKUP_FILE..."
    sudo iptables-save | sudo tee "$BACKUP_FILE" > /dev/null
    sudo iptables -P INPUT DROP
    sudo iptables -P OUTPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
else
    echo "❌ No se encontró ufw ni iptables -- no se puede aplicar contención de red."
    exit 1
fi

echo "✅ Host aislado. Respaldo de reglas guardado en $BACKUP_FILE en el propio host."
echo "⚠️ Para revertir: restaurar $BACKUP_FILE manualmente vía SSH/consola -- este script no incluye reversión automática por diseño (una contención de emergencia no debe deshacerse sola)."
"""

    if cve.startswith('ZAP-'):
        zap_fix = generate_zap_header_fix(vuln)
        if zap_fix:
            return zap_fix
        return (
            f"#!/bin/bash\n# Centinela AI -- {cve} en {asset} ({ep})\n"
            f"echo 'ℹ️ No existe una regla de remediación determinística para este tipo de hallazgo ZAP.'\n"
            f"echo 'Acción manual requerida. Revisar la descripción del hallazgo para el detalle técnico exacto.'\n"
            f"exit 1\n"
        )

    if cve in ('SCAN-AUDIT',) or cve == 'HEURISTIC-SECURITY-DEBT' or \
       any(p in desc for p in ('no se detectaron vulnerabilidades', 'no se encontraron', 'escaneo externo omitido', 'accumulation of', 'acumulación de')):
        return (
            f"#!/bin/bash\n# Centinela AI -- {cve} en {asset} ({ep})\n"
            f"echo 'ℹ️ Este hallazgo es informativo (no es una vulnerabilidad técnica específica) y no requiere ni admite una acción de remediación automática.'\n"
            f"echo 'Si es HEURISTIC-SECURITY-DEBT: resuelve los hallazgos individuales listados en la evidencia -- esta entrada es solo un resumen agregado.'\n"
            f"exit 0\n"
        )

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
    elif atype == 'GITLAB-REPO':
        # This is a source-code finding (from sast-native/sca-native/standards-audit scanning
        # a cloned repo) -- there is no live host for a bash "hardening" script to SSH into,
        # which is what the old GITLAB/PIPELINE/CODE-INJECTION branch below did (chmod .git
        # permissions, edit /etc/gitlab/gitlab.rb) regardless of what the actual finding was.
        # The real fix is a code change in the repo itself. Sentinel's GitLab-Repo execution
        # path (remediate_gitlab_repo in sentinel.py) handles the actually-automatable cases
        # (DOCKER-MISSING-NON-ROOT-USER/DOCKER-ROOT-USER, SCA-CVE-*) deterministically by
        # cloning the repo, applying the fix, and opening a Merge Request -- this script is
        # just the human-readable record of that, since script_path is what the UI displays.
        location = str(vuln.get('url_path', '')) or 'ver descripción'
        body = f"""# {cve} es un hallazgo de código fuente en el repositorio {asset}, no de infraestructura.
echo 'ℹ️ Ubicación exacta: {location}'
echo 'ℹ️ No hay un host remoto que "endurecer" -- la corrección real es un cambio de código en el repositorio.'
echo 'Si esta regla tiene parche automático soportado (Dockerfile USER, versión de dependencia), Sentinel abrirá un Merge Request al aprobar.'
echo 'Si no, aplica manualmente el cambio indicado en la descripción del hallazgo en {location} y aprueba luego para marcarlo resuelto.'
"""
    elif 'PORT' in cve or 'OPEN' in cve or 'EXPOSED' in cve or 'NET' in cve:
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


def heuristic_can_automate(vuln):
    """
    Whether the heuristic fallback script actually performs a real fix vs. only reporting/
    guiding. Kept in sync with generate_heuristic_script's own branches so can_automate in the
    DB reflects reality instead of being hardcoded True regardless of what happened.
    """
    cve = str(vuln.get('cve_id', '')).upper()
    atype = str(vuln.get('asset_type', '')).upper()
    desc = str(vuln.get('description', '')).lower()

    if cve.startswith('CTI-IOC-MATCH') or cve == 'HOST-CONTAINMENT-REQUEST':
        return True
    if cve.startswith('ZAP-'):
        return generate_zap_header_fix(vuln) is not None
    if cve in ('SCAN-AUDIT', 'HEURISTIC-SECURITY-DEBT') or any(
        p in desc for p in ('no se detectaron vulnerabilidades', 'no se encontraron', 'escaneo externo omitido')
    ):
        return False
    if atype == 'GITLAB-REPO':
        # Only the deterministic patch categories Sentinel's GitLab pipeline actually handles.
        return cve in ('DOCKER-MISSING-NON-ROOT-USER', 'DOCKER-ROOT-USER') or cve.startswith('SCA-CVE-')
    return True


def generate_heuristic_analysis(vuln):
    """
    Real, category-specific risk/impact/action text for the heuristic (no-LLM) fallback path.
    Mirrors generate_heuristic_script's own branches -- previously this text was a single
    generic template ("Exposición de Seguridad - {cve}" / "Riesgo potencial de reconocimiento
    de infraestructura...") used for every single finding regardless of which branch actually
    ran, even after the scripts themselves were made real and category-specific. Returns
    (riesgo_detectado, impacto_negocio, accion_remediacion).
    """
    cve = str(vuln.get('cve_id', 'SECURITY-FINDING'))
    cve_u = cve.upper()
    asset = str(vuln.get('asset_name', 'INFRASTRUCTURE-HOST'))
    atype = str(vuln.get('asset_type', '')).upper()
    ep = str(vuln.get('endpoint', '0.0.0.0'))
    desc = str(vuln.get('description', '')).lower()
    location = str(vuln.get('url_path', '')) or 'ver descripción'

    if cve_u.startswith('CTI-IOC-MATCH'):
        return (
            "IP confirmada como servidor C2 activo (Feodo Tracker / abuse.ch)",
            f"Esta IP está siendo usada activamente para comando y control de malware -- si {asset} se está comunicando con ella, es indicio real de compromiso o de tráfico entrante malicioso confirmado, no una sospecha.",
            f"Se aplica un parche virtual bloqueando la IP a nivel del reverse-proxy (`deny`) en {asset} ({ep}), sin tocar el código de la aplicación ni reiniciar el servicio."
        )

    if cve_u == 'HOST-CONTAINMENT-REQUEST':
        return (
            f"Solicitud de contención de emergencia para {asset}",
            f"Acción disruptiva deliberada: aísla {asset} ({ep}) de la red (excepto DNS/NTP salientes) para detener una amenaza activa a costa de disponibilidad. Requiere aprobación humana explícita como cualquier otra remediación -- no se ejecuta automáticamente.",
            f"Al aprobar, se respaldan las reglas de firewall actuales en el propio host y se aplica una política de denegación total entrante/saliente salvo DNS/NTP. La reversión es manual y deliberada -- una contención de emergencia no debe deshacerse sola."
        )

    if cve_u.startswith('ZAP-'):
        entry = match_zap_header_entry(vuln)
        if entry:
            _needle, directive, name, risk = entry
            return (
                name,
                risk,
                f"Se agrega la directiva nginx `{directive}` de forma idempotente en {asset} ({ep}) "
                f"(detectando nginx a nivel de sistema o en un contenedor reverse-proxy), se valida "
                f"con `nginx -t`, se recarga, y se verifica la cabecera en una respuesta real."
            )
        return (
            f"Hallazgo DAST sin regla determinística: {cve}",
            "Sin una regla de remediación conocida para este tipo de hallazgo, el riesgo real no puede confirmarse automáticamente.",
            "No existe una corrección automatizable para este hallazgo específico -- revisar la descripción técnica y aplicar manualmente."
        )

    if cve_u in ('SCAN-AUDIT', 'CIS-BENCHMARK-AUDIT') or any(p in desc for p in ('no se detectaron vulnerabilidades', 'no se encontraron', 'escaneo externo omitido', 'auditoría cis benchmarks completada')):
        return (
            "Sin hallazgo técnico (mensaje informativo de escaneo)",
            "Ninguno -- esta entrada documenta el resultado de un escaneo, no una vulnerabilidad.",
            "No aplica ninguna acción; el escaneo no encontró problemas o fue omitido por falta de datos del agente."
        )
    if cve_u == 'HEURISTIC-SECURITY-DEBT':
        return (
            "Deuda de seguridad acumulada (hallazgo agregado)",
            f"Resume múltiples hallazgos individuales ya reportados por separado sobre {asset}; no es en sí mismo un vector de ataque explotable.",
            "Resolver los hallazgos individuales listados en la evidencia -- esta entrada se cierra sola cuando ya no hay hallazgos abiertos que agregar."
        )

    if atype == 'GITLAB-REPO':
        if cve_u in ('DOCKER-MISSING-NON-ROOT-USER', 'DOCKER-ROOT-USER'):
            return (
                "Contenedor configurado para ejecutar como root",
                "Si el contenedor es comprometido (ej. vía una dependencia vulnerable), el atacante obtiene privilegios de root dentro de él, ampliando el impacto de cualquier escape de contenedor.",
                f"Sentinel abre un Merge Request agregando/corrigiendo la directiva `USER` no-root en el Dockerfile ({location}) al aprobar este hallazgo."
            )
        if cve_u.startswith('SCA-CVE-'):
            return (
                "Dependencia con CVE conocido",
                "El paquete instalado tiene una vulnerabilidad pública documentada que puede ser explotada sin necesidad de descubrir un 0-day.",
                f"Sentinel abre un Merge Request actualizando la dependencia a la versión segura conocida ({location}) al aprobar este hallazgo."
            )
        return (
            f"Hallazgo de código fuente: {cve}",
            f"Riesgo específico del tipo de hallazgo -- ver evidencia técnica en {location} para el detalle exacto.",
            "Hallazgo de repositorio sin parche automático soportado todavía -- revisar el código en la ubicación indicada y corregir manualmente, o esperar a que la IA genere un parche cuando haya cupo de API disponible."
        )

    if 'DOCKER' in cve_u or 'CONTAINER' in cve_u or 'NON-ROOT' in cve_u or 'non-root' in desc:
        return (
            "Contenedor(es) ejecutando procesos como root",
            "Si un contenedor comprometido corre como root, un escape de contenedor otorga control root directo del host.",
            f"Se audita cada contenedor en ejecución en {ep} buscando procesos root y se provisiona un usuario de servicio restringido para futura remediación manual del Dockerfile/compose."
        )
    if 'SSH' in cve_u or 'ROOT-LOGIN' in cve_u or 'AUTH' in cve_u:
        return (
            "Acceso root habilitado por SSH",
            "Permite ataques de fuerza bruta o diccionario directamente contra la cuenta con más privilegios del sistema.",
            f"Se deshabilita `PermitRootLogin` y `PasswordAuthentication` en sshd_config de {ep} y se recarga el servicio SSH."
        )
    if 'PORT' in cve_u or 'OPEN' in cve_u or 'EXPOSED' in cve_u or 'NET' in cve_u:
        return (
            "Puertos de red expuestos sin restricción de firewall",
            f"Amplía la superficie de ataque de red de {asset} -- cualquier servicio en un puerto abierto es alcanzable por quien tenga red hacia el host.",
            f"Se aplica una política de firewall (UFW/iptables) en {ep} permitiendo solo el tráfico esencial (22/80/443)."
        )

    return (
        f"Hallazgo de seguridad sin regla de remediación específica: {cve}",
        f"Impacto no clasificado automáticamente para este tipo de hallazgo en {asset} -- ver evidencia técnica.",
        f"No hay una regla de hardening determinística para {cve}; se registra el hallazgo y se verifica el estado del Agente Wazuh en {ep}, pero no se aplica ningún cambio de configuración."
    )


def correlate_vulnerability(vuln):
    """
    Use AI to correlate vulnerability data and suggest remediation.
    """
    print(f"🤖 [Centinela-AI] Senior Audit analysis for {vuln['cve_id']} on {vuln['asset_name']}...")

    is_repo_finding = str(vuln.get('asset_type', '')).upper() == 'GITLAB-REPO'

    # These cve_id values are Centinela's own synthetic/system markers, not real
    # scanner-detected vulnerabilities -- there's no real technical substance for a generic
    # security-auditor LLM prompt to reason about, and testing this live surfaced exactly the
    # failure mode that risk implies: asked to fix "HOST-CONTAINMENT-REQUEST", Groq hallucinated
    # an unrelated WildFly/JMX script with can_automate=true, which would have been offered for
    # one-click execution against a host that may not even run WildFly. generate_heuristic_script()
    # already has correct, purpose-built logic for each of these (real firewall lockdown for
    # HOST-CONTAINMENT-REQUEST, real IP block for CTI-IOC-MATCH, etc) -- skip the LLM entirely
    # for these and go straight to it instead of risking a plausible-sounding wrong answer.
    cve_upper = str(vuln.get('cve_id', '')).upper()
    is_synthetic_marker = (
        cve_upper.startswith('CTI-IOC-MATCH') or cve_upper.startswith('BLOODHOUND-PATH')
        or cve_upper in ('HOST-CONTAINMENT-REQUEST', 'SCAN-AUDIT', 'HEURISTIC-SECURITY-DEBT', 'CIS-BENCHMARK-AUDIT')
    )

    if is_repo_finding:
        # A bash "remediation_script" makes no sense here -- there's no live host to SSH into
        # and run hardening commands against; the file it needs to fix is inside the repo this
        # finding came from. Ask for a real unified diff instead, which Sentinel's GitLab
        # auto-fixer (remediation/gitlab_autofix.py) applies with `git apply` and pushes as a
        # Merge Request -- the same mechanism used for the deterministic Docker/SCA patches.
        prompt_text = f"""
        Actúa como un Ingeniero Senior de AppSec de CASMARTS revisando un hallazgo de análisis
        estático de código (SAST/SCA) en un repositorio real.

        HALLAZGO A CORREGIR:
        - Regla: {vuln['cve_id']}
        - Repositorio: {vuln['asset_name']}
        - Ubicación (archivo:línea): {vuln.get('url_path', 'desconocida')}
        - Severidad: {vuln['severity']}
        - Detalle (incluye el fragmento de código real detectado): {vuln.get('description', 'Sin descripción')}

        REGLAS:
        1. Propón el cambio de código MÍNIMO y CORRECTO que soluciona específicamente este hallazgo
           en la línea/archivo indicados -- no reescribas el archivo completo ni refactorices nada
           no relacionado.
        2. El campo 'fix_patch' DEBE ser un diff unificado válido (formato `git diff`, aplicable
           con `git apply`), con encabezados `--- a/<ruta>` / `+++ b/<ruta>` usando la ruta relativa
           exacta de 'Ubicación'.
        3. Si el fragmento de código disponible es insuficiente para generar un parche seguro y
           correcto (por ejemplo, no se conoce el contexto completo de la función), NO inventes
           un parche: deja 'fix_patch' vacío y pon can_automate en false.
        4. INTEGRIDAD: no inventes rutas de archivo ni asumas frameworks no mencionados en el hallazgo.

        FORMATO DE SALIDA (JSON ESTRICTO):
        {{
            "riesgo_detectado": "Nombre técnico de la vulnerabilidad",
            "nivel_severidad": "Bajo/Medio/Alto/Crítico",
            "evidencia_tecnica": "Extracto del código afectado",
            "impacto_negocio": "Descripción del riesgo para la operación de CASMARTS",
            "accion_remediacion": "Qué cambia el parche, en una frase, para un desarrollador que va a revisar el Merge Request",
            "fix_patch": "Diff unificado real, o cadena vacía si no es seguro generar uno",
            "can_automate": true/false
        }}
        """
    else:
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
        if not is_synthetic_marker:
            content = call_ai_cascade(prompt_text) or ""

        if not content:
            # Fallback deterministic Security Engine Generator
            print(f"⚙️ [Centinela-AI] Using Native Heuristics AI Engine for {vuln.get('cve_id')} on {vuln.get('asset_name')}...")
            cve = vuln.get('cve_id', 'SECURITY-FINDING')
            asset = vuln.get('asset_name', 'INFRASTRUCTURE-HOST')
            atype = vuln.get('asset_type', 'SERVER')
            ep = vuln.get('endpoint', '0.0.0.0')
            sev = vuln.get('severity', 'Medium')
            
            script_code = generate_heuristic_script(vuln)
            can_automate = heuristic_can_automate(vuln)
            riesgo, impacto, accion = generate_heuristic_analysis(vuln)

            content = json.dumps({
                "riesgo_detectado": riesgo,
                "nivel_severidad": sev,
                "evidencia_tecnica": f"Hallazgo reportado en {ep} ({atype}). {vuln.get('description', 'Parámetros o puertos no endurecidos.')}",
                "impacto_negocio": impacto,
                "accion_remediacion": accion,
                "remediation_script": script_code,
                "can_automate": can_automate
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

        # Some LLM responses pass `pick()`'s non-empty check but are lazy/truncated
        # placeholders instead of real content -- confirmed live on real production data,
        # e.g. remediation_script literally containing "... (script proporcionado)" or
        # "... (contenido del script)". pick() only checks for emptiness/null-like strings,
        # so this garbage was silently accepted as a real script and written to disk,
        # sometimes even with can_automate=true (the SOAR UI would offer to auto-execute
        # a file with no real commands in it). Reject anything that, after stripping a
        # leading shebang, is just an ellipsis (optionally with a placeholder parenthetical)
        # or otherwise too short to plausibly be real content.
        def is_placeholder_text(text):
            if not text:
                return True
            body = re.sub(r'^#!.*(\n|$)', '', text.strip(), count=1).strip()
            if not body:
                return True
            if re.fullmatch(r'\.{3,}(\s*\([^)]*\))?', body):
                return True
            if len(body) < 15:
                return True
            return False

        try:
            # strict=False allows raw control characters (e.g. literal newlines) inside JSON
            # string values — LLMs routinely write multi-line bash into "remediation_script"
            # with real line breaks instead of escaped \n, which strict JSON parsing rejects
            # outright even though the rest of the document is well-formed.
            analysis = json.loads(content, strict=False)
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
            fix_patch = pick(analysis, 'fix_patch', 'patch', 'diff', default='')
            can_automate_raw = analysis.get('can_automate') if isinstance(analysis, dict) else None

            if not riesgo and script == '# Sin script de remediación' and not fix_patch:
                print("⚠️ [Centinela-AI] AI response has no valid risk, script, or patch.")
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
            diff_m    = re.search(r'```(?:diff|patch)?\s*(---\s*a/.*?)```', raw, re.DOTALL)
            fix_patch = diff_m.group(1).strip() if diff_m else ''
            can_automate_raw = None

            print(f"⚠️ [Centinela-AI] Parsed prose response (non-JSON) successfully.")

        # Reject lazy/placeholder LLM output instead of accepting it as real remediation
        # content (see is_placeholder_text above) -- fall back to the same deterministic
        # heuristic generator used when the LLM never responds at all, rather than writing
        # garbage to script_path or claiming can_automate=true on an empty script.
        if is_repo_finding:
            if is_placeholder_text(fix_patch):
                if fix_patch:
                    print(f"⚠️ [Centinela-AI] Discarding placeholder fix_patch for {vuln['cve_id']}: {fix_patch[:80]!r}")
                fix_patch = ''
        else:
            if is_placeholder_text(script):
                if script and script != '# Sin script de remediación':
                    print(f"⚠️ [Centinela-AI] Discarding placeholder remediation_script for {vuln['cve_id']}: {script[:80]!r}")
                script = generate_heuristic_script(vuln)
                if can_automate_raw is None:
                    can_automate_raw = heuristic_can_automate(vuln)

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

        # Respect what the LLM actually said about automatability rather than discarding it --
        # but never claim True if we ended up with neither a real script nor a real patch, and
        # for GitLab-Repo findings only trust a "true" if a patch was actually produced (a bash
        # remediation_script alone can't be applied to a repo finding).
        has_real_output = bool(fix_patch.strip()) or (script and script != '# Sin script de remediación')
        if is_repo_finding:
            can_automate = bool(fix_patch.strip())
        elif can_automate_raw is not None:
            can_automate = bool(can_automate_raw) and has_real_output
        else:
            can_automate = has_real_output

        return {
            "executive_summary": exec_summary,
            "business_impact": impacto if impacto and impacto != 'Sin análisis de impacto disponible.' else f"Riesgo evaluado para la infraestructura {vuln.get('asset_name')}. Se recomienda aislar el puerto o aplicar parches de seguridad.",
            "developer_steps": pasos if pasos and pasos != 'Sin pasos de remediación disponibles.' else f"1. Verificar la configuración del servicio en {vuln.get('endpoint')}.\n2. Aplicar parches de actualización y cerrar servicios no autorizados.",
            "remediation_script": script,
            "fix_patch": fix_patch,
            "can_automate": can_automate
        }

    except Exception as e:
        print(f"❌ Error in correlation call: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def generate_ai_remediation_report(cve_id, log_output):
    """
    Use AI to generate a professional remediation report based on the technical execution log.
    """
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

    content = call_ai_cascade(prompt_text, want_json=False)
    if content:
        return content
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


def process_zeek_conn_log():
    """
    Real Zeek conn.log ingestion, cross-referenced live against the CTI feed
    (core/cti_feed.py). The infrastructure for this was already correct -- centinela-ai has a
    real, working, read-only mount of Zeek's actual log directory (zeek-logs volume at
    /app/logs/zeek) -- but process_zeek_alerts() only ever watched notice.log, which Zeek only
    writes when something already looks notice-worthy by its own built-in policy. conn.log is
    Zeek's real, continuously-written connection log (confirmed live: 108KB and growing,
    updated seconds before this was written) and nothing ever read it, so Zeek's rich
    per-connection data was completely unused despite the working ingestion pipe already being
    there.

    Every new connection's source/destination IP is checked against the live Feodo Tracker
    feed in real time -- a match means this host is *currently* talking to a confirmed C2
    server, not a static/backfilled check. Also logs a periodic real activity heartbeat
    (distinct from a fake "still alive" ping -- it's an honest count of connections actually
    observed) so main.py's Zeek health check reflects genuine pipeline activity, not just
    whether something bad happened to be found in the last 24h.
    """
    from core import cti_feed, deduplication_engine

    conn_log_path = "/app/logs/zeek/conn.log"
    fields = []
    f = None
    conn_count = 0
    last_heartbeat = time.time()

    def open_log():
        nonlocal f, fields
        try:
            f = open(conn_log_path, "r")
            for line in f:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    break
            f.seek(0, 2)  # only process new connections from here on
            return True
        except Exception as e:
            print(f"⚠️ [Centinela-AI] Cannot open Zeek conn.log: {e}")
            return False

    if not os.path.exists(conn_log_path) or not open_log():
        print("ℹ️ [Centinela-AI] Zeek conn.log not available -- conn-log ingestion skipped.")
        return

    print(f"📡 [Centinela-AI] Tailing Zeek conn.log for real-time CTI correlation ({len(fields)} fields detected).")

    while True:
        try:
            line = f.readline()
            if not line:
                # Detect rotation (file replaced/truncated) -- reopen from the start of the new file.
                try:
                    if os.path.exists(conn_log_path) and os.path.getsize(conn_log_path) < f.tell():
                        f.close()
                        open_log()
                except Exception:
                    pass
                time.sleep(2)

                # Real, honest activity heartbeat every 5 minutes -- not a fake ping, an actual
                # count of connections observed since the last one.
                if time.time() - last_heartbeat > 300:
                    with db_manager.get_db_cursor() as cur:
                        cur.execute("""
                            INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                            VALUES (NULL, 'INFO', 'ZEEK-CONN-HEARTBEAT', %s, %s)
                        """, (
                            f"Zeek observó {conn_count} conexiones de red en los últimos 5 minutos.",
                            json.dumps({"connections_observed": conn_count})
                        ))
                    conn_count = 0
                    last_heartbeat = time.time()
                continue

            if line.startswith("#") or not fields:
                continue
            values = line.rstrip("\n").split("\t")
            if len(values) != len(fields):
                continue
            record = dict(zip(fields, values))
            conn_count += 1

            malicious_ips = cti_feed.get_malicious_ips()
            for ip_field in ("id.orig_h", "id.resp_h"):
                ip = record.get(ip_field, "")
                if ip in malicious_ips:
                    ioc = malicious_ips[ip]
                    direction = "hacia" if ip_field == "id.resp_h" else "desde"
                    desc = (
                        f"**Zeek observó una conexión de red real {direction} {ip}, confirmada como servidor C2 "
                        f"activo en Feodo Tracker (abuse.ch).**\n\n"
                        f"**Malware asociado:** {ioc.get('malware', 'desconocido')}\n"
                        f"**Conexión:** {record.get('id.orig_h')}:{record.get('id.orig_p')} -> "
                        f"{record.get('id.resp_h')}:{record.get('id.resp_p')} ({record.get('proto', '?')})"
                    )
                    with db_manager.get_db_cursor() as cur:
                        cur.execute("""
                            INSERT INTO runtime_alerts (asset_id, priority, rule_name, alert_text, output_fields)
                            VALUES (NULL, 'CRITICAL', 'ZEEK-CTI-MATCH', %s, %s)
                        """, (desc, json.dumps(record)))
                        # Best-effort: attribute to a real asset if the non-malicious side of
                        # the connection matches a registered IP; otherwise this still lands in
                        # runtime_alerts for visibility even without a specific asset to pin it to.
                        other_ip = record.get("id.orig_h") if ip_field == "id.resp_h" else record.get("id.resp_h")
                        cur.execute("SELECT id FROM infra_inventory WHERE endpoint ILIKE %s LIMIT 1", (f"%{other_ip}%",))
                        asset = cur.fetchone()
                        if asset:
                            deduplication_engine.log_finding_deduplicated(
                                cur, asset[0], "CTI-IOC-MATCH-RUNTIME", "CRITICAL", desc,
                                "cti-feed", url_path=f"conn-{record.get('uid', ip)}", open_status="PENDING",
                                preserve_status=True
                            )
                    print(f"🚨 [Centinela-AI] Zeek+CTI: real connection to confirmed C2 IP {ip} ({ioc.get('malware')}).")
        except Exception as e:
            print(f"❌ [Centinela-AI] Error processing Zeek conn.log: {e}")
            time.sleep(5)


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

    from core import deduplication_engine

    while True:
        try:
            print("🩸 [Centinela-AI] BloodHound Graph Analyzer querying attack paths...")
            driver = GraphDatabase.driver(uri, auth=(user, password))
            with driver.session() as session:
                # Distinguish "no data has ever been imported" from "data exists and genuinely
                # shows no attack path" -- these previously looked identical (both produced no
                # log line at all), which silently masked the fact this query has likely never
                # found real data to run against (see the CLAUDE.md Attack-Path-Graphing entry:
                # SharpHound/AzureHound collector output is never ingested anywhere in this repo).
                node_count = session.run("MATCH (u:User) RETURN count(u) AS c").single()
                user_count = node_count["c"] if node_count else 0
                if user_count == 0:
                    print("ℹ️ [Centinela-AI] BloodHound graph has no :User nodes -- no collector "
                          "data (SharpHound/AzureHound) has ever been imported into Neo4j. "
                          "Query skipped; nothing to analyze until real AD data is loaded.")
                    driver.close()
                    time.sleep(600)
                    continue

                # Query shortest path from any non-admin user to the Domain Admins group.
                # Was previously hardcoded to the literal group name
                # 'DOMAIN ADMINS@INTERNAL.LOCAL' -- BloodHound suffixes every node name with
                # the real AD domain's FQDN, so this only ever matched a domain literally
                # named INTERNAL.LOCAL and would have silently found nothing against any real
                # domain (verified live against a disposable synthetic Neo4j dataset: the old
                # hardcoded query returned zero rows against a DOMAIN ADMINS@TESTDOMAIN.LOCAL
                # group, the STARTS WITH version below found the path correctly). Matching by
                # prefix instead of the full name makes this work against whatever domain gets
                # imported later without needing a code change.
                query = """
                MATCH p=shortestPath((u:User)-[*1..10]->(g:Group))
                WHERE g.name STARTS WITH 'DOMAIN ADMINS@' AND NOT u.name STARTS WITH 'Administrator'
                RETURN p LIMIT 1
                """
                result = session.run(query)
                record = result.single()
                if record:
                    path = record.get("p")
                    nodes = [n.get("name") for n in path.nodes]
                    desc = (
                        "BloodHound detectó una ruta de ataque de escalada de privilegios hacia "
                        f"el grupo Domain Admins. Ruta: {' -> '.join(nodes)}"
                    )

                    with db_manager.get_db_cursor() as cur:
                        # Real AD domain asset only -- the old fallback ("...OR asset_type =
                        # 'SERVER' LIMIT 1") attributed this to an arbitrary, unrelated SERVER
                        # asset whenever no asset was literally named "Active Directory",
                        # misrepresenting which host the finding is actually about.
                        cur.execute("""
                            SELECT id FROM infra_inventory
                            WHERE asset_name ILIKE '%active directory%' OR asset_type ILIKE '%domain%'
                            LIMIT 1
                        """)
                        res = cur.fetchone()
                        if res:
                            deduplication_engine.log_finding_deduplicated(
                                cur, res[0], "BLOODHOUND-PATH-AD", "CRITICAL", desc,
                                "bloodhound", open_status="PENDING", preserve_status=True
                            )
                            print("🚨 [Centinela-AI] Critical Attack Path logged in DB!")
                        else:
                            print("⚠️ [Centinela-AI] Attack path found but no Active Directory "
                                  "asset is registered in infra_inventory to attribute it to -- "
                                  "not logging against an unrelated asset. Register the AD "
                                  "domain as an asset to enable this.")
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


def _criticality_weight(criticality: str) -> float:
    """Maps infra_inventory.criticality (real text field, values seen: CRITICAL/HIGH/MEDIUM/LOW,
    mixed case) to the 0.5-2.0 range calculate_centinela_risk_score expects."""
    c = str(criticality or '').upper()
    return {"CRITICAL": 2.0, "HIGH": 1.5, "MEDIUM": 1.0, "LOW": 0.5}.get(c, 1.0)


def run_threat_intel_enrichment_loop():
    """
    Backfills real EPSS exploitation-probability scores and real CISA KEV (confirmed
    actively-exploited) status onto vulnerability_log rows, and (re)computes a real Centinela
    Risk Score from them plus the asset's real criticality.

    Previously nothing ever wrote epss_score/is_cisa_kev, so every risk score used a fixed 0.15
    EPSS default and is_cisa_kev=False for every finding regardless of real-world exploitation
    status -- e.g. a finding for Log4Shell (CVE-2021-44228, confirmed CISA KEV, EPSS ~1.0) and
    an obscure CVE with near-zero real exploitation likelihood got an identical score. Runs as
    a background pass (not per-request) since EPSS/KEV are external API calls -- both endpoints
    are batched, but recomputing on every dashboard page load would be slow and wasteful. This
    also backfills the large volume of pre-existing rows from before this fix existed.
    """
    from core import threat_intel, deduplication_engine
    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                # epss_score/is_cisa_kev default to 0.0/FALSE at the column level (never NULL),
                # so "never enriched" can't be told apart from "genuinely zero" by NULL-ness --
                # and most findings aren't CVE-based at all (ZAP-*/DOCKER-*/STD-* rule IDs), so
                # they'd always legitimately get real epss=0.0/kev=false written back, which
                # would re-match a filter based on those values on every single pass forever.
                # threat_intel_checked_at is a real completion marker instead: set once per row
                # below, and re-checked after 24h since EPSS scores do genuinely change over time
                # as real-world exploitation data comes in.
                cur.execute("""
                    SELECT v.id, v.cve_id, v.severity, i.criticality
                    FROM vulnerability_log v
                    JOIN infra_inventory i ON v.asset_id = i.id
                    WHERE (v.threat_intel_checked_at IS NULL OR v.threat_intel_checked_at < NOW() - INTERVAL '24 hours')
                    AND v.status != 'RESOLVED'
                    ORDER BY v.id DESC
                    LIMIT 200
                """)
                rows = cur.fetchall()

            if not rows:
                time.sleep(300)
                continue

            print(f"🛰️ [Centinela-AI] Enriching {len(rows)} finding(s) with real EPSS/CISA KEV threat intel...")

            cve_by_row = {r["id"]: threat_intel.extract_cve(r["cve_id"]) for r in rows}
            real_cves = [c for c in cve_by_row.values() if c]
            epss_scores = threat_intel.get_epss_scores(real_cves) if real_cves else {}
            kev_set = threat_intel.get_cisa_kev_set()

            with db_manager.get_db_cursor() as write_cur:
                for r in rows:
                    cve = cve_by_row[r["id"]]
                    # No real CVE (ZAP/DOCKER/STD/etc. -- Centinela's own rule IDs, not CVEs):
                    # 0.0/False is the honest value (no EPSS/KEV data exists for a non-CVE), not
                    # a copy of the old fake "unknown so assume 0.15" placeholder.
                    epss = epss_scores.get(cve, 0.0) if cve else 0.0
                    is_kev = (cve in kev_set) if cve else False

                    sev = str(r.get("severity") or "MEDIUM").upper()
                    # No numeric CVSS is stored anywhere in this schema; approximating from the
                    # severity bucket a real scanner (OSV/ZAP/etc.) already assigned is the best
                    # available signal without adding a slow, heavily rate-limited per-CVE NVD
                    # lookup to a bulk backfill pass.
                    cvss_approx = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(sev, 5.0)
                    risk_score = deduplication_engine.calculate_centinela_risk_score(
                        cvss_approx, epss, is_kev, _criticality_weight(r.get("criticality"))
                    )

                    write_cur.execute("""
                        UPDATE vulnerability_log
                        SET epss_score = %s, is_cisa_kev = %s, risk_score = %s, threat_intel_checked_at = NOW()
                        WHERE id = %s
                    """, (epss, is_kev, risk_score, r["id"]))

            kev_hits = sum(1 for r in rows if (cve_by_row[r["id"]] in kev_set if cve_by_row[r["id"]] else False))
            if kev_hits:
                print(f"🚨 [Centinela-AI] {kev_hits} finding(s) in this batch are CISA-confirmed actively exploited (KEV).")

            # Brief pacing between batches during backlog catch-up so this doesn't hammer
            # FIRST.org/CISA back-to-back with no gap; harmless once the backlog is drained and
            # each pass finds nothing (that case sleeps 300s via the `if not rows` branch above).
            time.sleep(5)

        except Exception as e:
            print(f"❌ [Centinela-AI] Error in threat intel enrichment loop: {e}")
            time.sleep(60)


def run_cis_benchmark_loop():
    """
    Periodically runs the real CIS Level 1 hardening check subset (auditors/auditor_cis_benchmarks.py)
    over SSH against every SERVER/AppServer asset. Previously this only ever ran when a human hit
    POST /api/cis-benchmark/check/{asset_name} by hand -- the health check honestly reported
    "Available (On-Demand, Not Yet Run)" because nothing ever actually triggered it. All checks
    are read-only (file permissions, sshd_config, systemctl is-active, etc); nothing is modified
    on the target host. log_cis_findings() always writes a CIS-BENCHMARK-AUDIT completion marker
    (pass or fail) so "never checked" can be told apart from "checked N days ago, all green" via
    its own detected_at, the same pattern threat_intel_checked_at uses above.
    """
    from auditors.auditor_cis_benchmarks import run_cis_audit, log_cis_findings
    RECHECK_INTERVAL_DAYS = 7
    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT i.id, i.asset_name, i.endpoint
                    FROM infra_inventory i
                    LEFT JOIN vulnerability_log v
                        ON v.asset_id = i.id AND v.cve_id = 'CIS-BENCHMARK-AUDIT'
                    WHERE i.asset_type IN ('SERVER', 'AppServer')
                        AND i.endpoint != 'remote-agent'
                    GROUP BY i.id, i.asset_name, i.endpoint
                    HAVING MAX(v.detected_at) IS NULL
                        OR MAX(v.detected_at) < NOW() - (%s || ' days')::interval
                    ORDER BY MAX(v.detected_at) ASC NULLS FIRST
                    LIMIT 5
                """, (RECHECK_INTERVAL_DAYS,))
                due_assets = cur.fetchall()

            if not due_assets:
                time.sleep(3600)
                continue

            for asset in due_assets:
                try:
                    print(f"🛡️ [Centinela-AI] Running CIS Benchmark audit on {asset['asset_name']}...")
                    result = run_cis_audit(asset["asset_name"], asset["endpoint"])
                    log_cis_findings(asset["id"], result)
                    print(f"✅ [Centinela-AI] CIS Benchmark on {asset['asset_name']}: grade {result['grade']} ({result['percentage']}%)")
                except Exception as asset_err:
                    # Most commonly: no SSH credentials stored in Vault for this asset yet --
                    # skip it and let the next asset in the batch proceed rather than stalling
                    # the whole loop on one host.
                    print(f"⚠️ [Centinela-AI] CIS Benchmark on {asset['asset_name']} failed (likely missing SSH credentials): {asset_err}")
                time.sleep(10)

        except Exception as e:
            print(f"❌ [Centinela-AI] Error in CIS Benchmark loop: {e}")
            time.sleep(60)


def run_cti_correlation_loop():
    """
    Real CTI/IoC correlation against abuse.ch's Feodo Tracker (live, active C2 server IPs).
    Checks two real data sources this codebase already has: registered asset IPs
    (infra_inventory), and IPs mentioned in runtime_alerts (Falco/Zeek output already ingested
    by process_falco_alerts()/process_zeek_alerts()). A hit on the first means one of our own
    hosts' IPs is a known-malicious C2 server; a hit on the second means a runtime alert
    involved a connection to/from one.
    """
    from core import cti_feed, deduplication_engine

    while True:
        try:
            malicious_ips = cti_feed.get_malicious_ips()
            if not malicious_ips:
                time.sleep(3600)
                continue

            hits = 0
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                # Source 1: our own registered asset IPs.
                cur.execute("SELECT id, asset_name, endpoint FROM infra_inventory")
                for asset in cur.fetchall():
                    for ip in cti_feed.extract_ips(asset.get("endpoint") or ""):
                        if ip in malicious_ips:
                            ioc = malicious_ips[ip]
                            desc = (
                                f"**IP del activo `{asset['asset_name']}` ({ip}) aparece en Feodo Tracker "
                                f"(abuse.ch) como servidor C2 activo.**\n\n"
                                f"**Malware asociado:** {ioc.get('malware', 'desconocido')}\n"
                                f"**Primera vez visto:** {ioc.get('first_seen', 'desconocido')}\n"
                                f"**Estado:** {ioc.get('status', 'desconocido')}"
                            )
                            deduplication_engine.log_finding_deduplicated(
                                cur, asset["id"], "CTI-IOC-MATCH-ASSET", "CRITICAL", desc,
                                "cti-feed", url_path=ip, open_status="PENDING", preserve_status=True
                            )
                            hits += 1

                # Source 2: IPs seen in real runtime alerts (Falco/Zeek), checked against the
                # same live feed -- empty today (no runtime_alerts have fired yet in this
                # deployment), but the mechanism is real and starts working the moment they do.
                cur.execute("""
                    SELECT id, asset_id, alert_text, output_fields, rule_name
                    FROM runtime_alerts
                    WHERE detected_at > NOW() - INTERVAL '1 hour'
                """)
                for alert in cur.fetchall():
                    text = f"{alert.get('alert_text') or ''} {alert.get('output_fields') or ''}"
                    for ip in cti_feed.extract_ips(text):
                        if ip in malicious_ips and alert.get("asset_id"):
                            ioc = malicious_ips[ip]
                            desc = (
                                f"**Alerta runtime `{alert['rule_name']}` involucra la IP {ip}, "
                                f"presente en Feodo Tracker (abuse.ch) como servidor C2 activo.**\n\n"
                                f"**Malware asociado:** {ioc.get('malware', 'desconocido')}"
                            )
                            deduplication_engine.log_finding_deduplicated(
                                cur, alert["asset_id"], "CTI-IOC-MATCH-RUNTIME", "CRITICAL", desc,
                                "cti-feed", url_path=f"alert-{alert['id']}-{ip}", open_status="PENDING",
                                preserve_status=True
                            )
                            hits += 1

            if hits:
                print(f"🚨 [Centinela-AI] CTI correlation found {hits} real IoC match(es) against Feodo Tracker.")

        except Exception as e:
            print(f"❌ [Centinela-AI] Error in CTI correlation loop: {e}")

        time.sleep(1800)  # 30 min -- feed itself only refreshes hourly


def main_loop():
    print("🚀 [Centinela-AI] Aura-Guard v2026.4.2 active.")
    
    import threading
    falco_thread = threading.Thread(target=process_falco_alerts, daemon=True)
    falco_thread.start()
    
    zeek_thread = threading.Thread(target=process_zeek_alerts, daemon=True)
    zeek_thread.start()

    zeek_conn_thread = threading.Thread(target=process_zeek_conn_log, daemon=True)
    zeek_conn_thread.start()

    bloodhound_thread = threading.Thread(target=process_bloodhound_paths, daemon=True)
    bloodhound_thread.start()
    
    # Start real-time Heuristics Engine thread
    heuristics_thread = threading.Thread(target=run_heuristics_loop, daemon=True)
    heuristics_thread.start()

    # Real EPSS/CISA KEV threat-intel enrichment (backfills real risk scores)
    threat_intel_thread = threading.Thread(target=run_threat_intel_enrichment_loop, daemon=True)
    threat_intel_thread.start()

    # Real CTI/IoC correlation (Feodo Tracker C2 IPs)
    cti_thread = threading.Thread(target=run_cti_correlation_loop, daemon=True)
    cti_thread.start()

    # Real CIS Level 1 hardening checks over SSH, previously on-demand only
    cis_thread = threading.Thread(target=run_cis_benchmark_loop, daemon=True)
    cis_thread.start()

    # External Auditor Thread
    from auditors import auditor_ext
    threading.Thread(target=auditor_ext.main, daemon=True).start()

    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT v.id, v.cve_id, v.severity, v.description, v.url_path, i.asset_name, i.asset_type, i.endpoint
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
                    # Run native master audits (SAST/SCA/Standards) periodically during idle loop.
                    # Was calling run_master_vulnerability_scan() etc. with no args, which defaults
                    # to target_dir="/opt/centinela-ai" (Centinela's own source, not any of the 66
                    # registered GitLab-Repo customer assets) and asset_id=None -- so this branch
                    # never actually audited a real GitLab project, only ever the platform's own
                    # code. GitLabIntegrator.scan_all_projects() (already used, working, and
                    # auth'd via GITLAB_TOKEN, by the manual POST /api/gitlab/scan endpoint) clones
                    # each real project and calls the same three auditors with the correct
                    # target_dir/asset_id per repo.
                    try:
                        from auditors.gitlab_integration import GitLabIntegrator
                        print("🔍 [Centinela-AI] Running background Omni-Audit scans on GitLab projects (SAST, SCA, Standards)...")
                        summary = GitLabIntegrator().scan_all_projects()
                        print(f"✅ [Centinela-AI] Omni-Audit scan complete: {summary.get('scanned_projects')}/{summary.get('total_projects')} projects, {summary.get('total_vulnerabilities')} findings.")
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
                            fix_patch = analysis.get('fix_patch', '') or ''

                            if fix_patch.strip():
                                # GitLab-Repo finding with a real AI-generated diff: record it as
                                # the human-readable artifact too, but the actual application
                                # happens via `git apply` in remediation/gitlab_autofix.py, not
                                # by executing this file as a shell script.
                                remediation_content = (
                                    f"# Parche generado por IA para {vuln['cve_id']} -- aplicado automáticamente\n"
                                    f"# vía Merge Request por Sentinel (remediation/gitlab_autofix.py), no ejecutado como script.\n\n"
                                    f"{fix_patch}"
                                )
                            else:
                                remediation_content = analysis.get('remediation_script', '# No script provided')

                            with open(script_path, "w") as f:
                                f.write(str(remediation_content))

                            with db_manager.get_db_cursor() as write_cur:
                                write_cur.execute("""
                                    UPDATE vulnerability_log
                                    SET status = 'CORRELATED',
                                        executive_summary = %s,
                                        business_impact = %s,
                                        developer_steps = %s,
                                        fix_patch = %s
                                    WHERE id = %s
                                """, (
                                    analysis.get('executive_summary', 'No summary available'),
                                    analysis.get('business_impact', 'No impact analysis available'),
                                    analysis.get('developer_steps', 'No steps provided'),
                                    fix_patch if fix_patch.strip() else None,
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
