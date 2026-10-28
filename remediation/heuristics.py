"""Moved verbatim from centinela.py (ADR-0008 #3)."""
import os
import re
import logging
import threading
import time
import json
import redis
import psycopg2
import concurrent.futures
from psycopg2.extras import RealDictCursor
from core import db_manager
from core import agent_ledger
from core import deduplication_engine

import hvac
import urllib.request
import urllib.error
import ssl


from core.ip_block_script import generate_ip_block_virtual_patch, generate_ip_unblock_script  # noqa: E402  (shared with core/soar_engine.py)
import logging
logger = logging.getLogger("centinela")



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
# reverse-proxy real corre como contenedor (confirmado en producción: un host de identidad no
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
            # hardening) -- confirmed in production on an identity-provider host's gateway. Find the
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



def _authz_fix_guidance(cve_u: str):
    """
    Real, mechanical fix guidance per AUTHZ-* family (from auditors/auditor_authz.py /
    auditor_authz_dast.py) -- for the heuristic (no-LLM) fallback path. These are the same
    fixes documented in the proyecto-k retest report (user-nonadmin / 403->200 tampering / privilege
    escalation): a missing Spring Security rule or client-side-only enforcement, always a
    deterministic, well-known correction -- no LLM reasoning needed to describe it.
    Returns (titulo, impacto, accion, code_snippet) or None if cve_u isn't an AUTHZ-* family
    this function has real guidance for.
    """
    if cve_u.startswith('AUTHZ-INCONSISTENT-FAMILY'):
        return (
            "Escalación de privilegios -- endpoint de identidad sin control de rol",
            "Un endpoint que administra identidad (usuarios/roles/permisos) solo exige sesión "
            "iniciada mientras endpoints hermanos exigen rol admin -- cualquier cuenta autenticada "
            "sin privilegios llega a una función administrativa (el patrón del retest de proyecto-k, "
            "cuenta user-nonadmin: 403->200 por manipulación de respuesta).",
            "Añadir la regla de rol que falta ANTES del catch-all `.antMatchers(\"/v1/**\").authenticated()`, "
            "o -mejor- una anotación a nivel de método.",
            '.antMatchers("/v1/usr/**").access("@roleSecurity.isAdmin(authentication)")\n'
            '// o: @PreAuthorize("hasRole(\'ADMIN\')") sobre el método del controlador'
        )
    if cve_u.startswith('AUTHZ-PERMITALL-WRITE'):
        return (
            "Operación de escritura pública (permitAll)",
            "Un verbo POST/PUT/DELETE queda cubierto por una regla permitAll() -- cualquiera sin "
            "autenticarse puede invocarlo.",
            "Cambiar la decisión de la regla o sacar el endpoint del bloque permitAll.",
            '.antMatchers(HttpMethod.POST, "/ruta/afectada").authenticated()   // o .access("...isAdmin...")'
        )
    if cve_u.startswith('AUTHZ-ONLY-AUTHENTICATED-WRITE'):
        return (
            "Escritura sensible sin verificación de rol",
            "El endpoint muta datos sensibles y solo exige .authenticated(); falta el chequeo de rol.",
            "Añadir rol en la regla de URL o @PreAuthorize en el método.",
            '@PreAuthorize("hasRole(\'ADMIN\')")   // o hasAnyRole(\'ADMIN\',\'GESTOR\') según el negocio'
        )
    if cve_u.startswith('AUTHZ-CLIENT-SIDE-ONLY') or cve_u.startswith('AUTHZ-CLIENT-SIDE-UI-GATE') or cve_u.startswith('AUTHZ-ADMIN-BUNDLE-EXPOSED'):
        return (
            "Módulo/función administrativa protegida solo en el cliente",
            "La ruta/función admin se protege únicamente con un guard o *ngIf de Angular; el backend "
            "no verifica rol -- interceptar y reescribir la respuesta (403->200) la habilita igual. CWE-602.",
            "El guard del front puede quedarse por UX, pero el control real debe estar en el backend: "
            "cada endpoint que consume el módulo/función admin necesita @PreAuthorize o regla de rol.",
            '@PreAuthorize("hasRole(\'ADMIN\')")   // en CADA endpoint que consume el módulo admin, no solo algunos'
        )
    if cve_u.startswith('AUTHZ-CSRF-DISABLED'):
        return (
            "Protección CSRF deshabilitada",
            ".csrf().disable() en la configuración; si la app usa cookie de sesión o form-login, "
            "queda expuesta a CSRF (aceptable solo si TODO el acceso es Bearer token en cabecera).",
            "Si el API es 100% stateless, forzar STATELESS y documentarlo; si usa sesión, reactivar CSRF.",
            'http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);\n'
            '// o: http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());'
        )
    if cve_u.startswith('AUTHZ-IDOR-PARAM-REVIEW') or cve_u.startswith('AUTHZ-DAST-IDOR'):
        return (
            "Posible IDOR / BOLA -- id del sujeto en la ruta",
            "El endpoint recibe el id del sujeto como parámetro de ruta con solo .authenticated(); "
            "sin comprobación de pertenencia, un usuario lee/modifica datos de otro cambiando el id.",
            "Comprobar en el servicio que el recurso pertenece a quien lo pide.",
            'if (!idToken.equals(idUsuarioRuta) && !esAdmin())\n'
            '    return new ResponseEntity<>(HttpStatus.FORBIDDEN);'
        )
    if cve_u.startswith('AUTHZ-NAMESPACE-GAP'):
        return (
            "Prefijo de rutas sin cobertura de seguridad",
            "Los antMatchers cubren un prefijo (p.ej. /v1/**) pero hay controladores o llamadas del "
            "front bajo otro (/api/**) sin regla -- un rewrite de proxy evita el control de acceso.",
            "Unificar el prefijo o añadir un catch-all defensivo.",
            '.anyRequest().authenticated();   // red de seguridad final, además de cubrir el prefijo faltante'
        )
    if cve_u.startswith('AUTHZ-NO-METHOD-AUTHZ') or cve_u.startswith('AUTHZ-PREAUTHORIZE-COMMENTED-OUT'):
        return (
            "Endpoint sin autorización por método (@PreAuthorize)",
            "El proyecto decide la autorización por permiso en cada método, pero este endpoint no la exige: "
            "cualquier usuario con un token válido, aunque no tenga el permiso, puede ejecutarlo.",
            "Añadir `@PreAuthorize(\"hasAuthority('<RECURSO>_<ACCION>')\")` igual que el resto del controlador, "
            "darlo de alta en el catálogo de permisos y cubrirlo con una prueba de 403. Si la anotación estaba "
            "comentada, reactivarla.",
            '@PreAuthorize("hasAuthority(\'RECURSO_ACCION\')")   // ajustar al permiso real del catálogo'
        )
    if cve_u.startswith('AUTHZ-PUBLIC-SENSITIVE-READ'):
        return (
            "Lectura pública de datos de identidad/permisos",
            "Un GET sin autenticación expone usuarios, roles o privilegios y facilita la escalada de privilegios.",
            "Quitar la ruta de las reglas `permitAll()` y exigir autenticación + `@PreAuthorize` con el permiso de consulta.",
            '// SecurityConfig: eliminar .requestMatchers("<ruta>").permitAll() y proteger con @PreAuthorize'
        )
    if cve_u.startswith('AUTHZ-TEST-ENDPOINT-EXPOSED'):
        return (
            "Controlador de prueba desplegado en producción",
            "Un controlador de ejemplo/prueba dentro de src/main se publica con la aplicación y amplía la superficie de ataque.",
            "Moverlo a src/test o limitarlo con `@Profile(\"dev\")`/`@ConditionalOnProperty`, y verificar que ningún cliente lo use.",
            '@Profile("dev")   // sobre la clase del controlador'
        )
    if cve_u.startswith('AUTHZ-NO-RULE') or cve_u.startswith('AUTHZ-NO-METHOD-ANNOTATIONS'):
        return (
            "Endpoint sin autorización definida / autorización frágil por lista de URLs",
            "Sin regla de URL ni anotación de método, la autorización real depende del orden de "
            "filtros o queda indefinida.",
            "Añadir una regla explícita o anotación de método; considerar "
            "@EnableGlobalMethodSecurity(prePostEnabled = true) para defensa en profundidad.",
            '@PreAuthorize("isAuthenticated()")   // punto de partida mínimo, ajustar el rol real requerido'
        )
    if cve_u.startswith('AUTHZ-DAST-BROKEN-FUNCTION-LEVEL'):
        return (
            "Escalación de privilegios confirmada en vivo (rol no-admin obtuvo 2xx)",
            "La sonda autenticada multi-rol reprodujo el acceso real de un rol sin privilegios a un "
            "endpoint solo-admin -- no es una sospecha estática, es la explotación confirmada.",
            "La corrección va en el código del repositorio (regla de rol faltante), no en este host -- "
            "ver el hallazgo AUTHZ-INCONSISTENT-FAMILY correspondiente en el repositorio de origen.",
            None
        )
    if cve_u.startswith('AUTHZ-DAST-DENY-LEAKS-BODY'):
        return (
            "Un 401/403 todavía devuelve el cuerpo con datos",
            "Habilita el bypass exacto del retest de proyecto-k: reescribir solo la línea de estado "
            "(403->200) ya expone datos que el servidor de hecho envió.",
            "Asegurar que el filtro de autorización corte la respuesta ANTES de serializar el cuerpo, "
            "no solo cambie el código de estado.",
            None
        )
    if cve_u.startswith('AUTHZ-DAST-NO-CREDS'):
        return (
            "Sonda de autorización multi-rol no ejecutada (sin credenciales)",
            "Este motor confirma en vivo la escalación de privilegios pero necesita credenciales de "
            "al menos 2 roles distintos configuradas en Vault para poder correr.",
            "Aprovisionar credenciales en secret/<namespace>/authz/{activo} (ver DECISIONS/0005) -- no es "
            "una vulnerabilidad en sí, es un estado 'pendiente de configurar'.",
            None
        )

def generate_wstg_remediation(vuln):
    """
    Builds concrete, idempotent remediation scripts for OWASP WSTG v4.2 findings.
    Targets Nginx reverse proxy configuration, strict transport policies, and
    application-level settings (e.g. Apache Superset superset_config.py).
    """
    cve = str(vuln.get('cve_id', '')).upper()
    asset = str(vuln.get('asset_name', 'INFRASTRUCTURE-HOST'))
    ep = str(vuln.get('endpoint', '0.0.0.0'))

    if 'CLEARTEXT-LOGIN' in cve or 'UNENCRYPTED-CHANNEL' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-ATHN-02 / WSTG-CRYP-03)
# Host: {asset} ({ep})
# Objetivo: Forzar redirección estricta HTTP -> HTTPS y habilitar HSTS / cookies seguras
set -e
echo '🔒 Aplicando hardening de transporte seguro (HTTPS / HSTS / Secure Cookies) en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
SNIPPET_FILE="$NGINX_CONF_DIR/centinela_ssl_redirect.conf"

if command -v nginx >/dev/null 2>&1; then
    echo "⚙️ Configurando redirección 301 de HTTP a HTTPS y directiva HSTS en Nginx..."
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$SNIPPET_FILE" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-ATHN-02 / WSTG-CRYP-03
server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}}
EOF

    HSTS_FILE="$NGINX_CONF_DIR/centinela_hsts.conf"
    sudo tee "$HSTS_FILE" > /dev/null << 'EOF'
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
EOF

    echo "🔍 Validando sintaxis de configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx para aplicar cambios..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Redirección HTTPS y HSTS aplicadas exitosamente."
else
    echo "⚠️ Nginx no encontrado en el host local. Si la app corre en contenedor Docker:"
    echo "   Configure SESSION_COOKIE_SECURE = True en superset_config.py y active SSL en el ingress."
fi
"""

    if 'HOST-HEADER-INJECTION' in cve or 'OPEN-REDIRECT' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-INPV-17 / WSTG-CLNT-04)
# Host: {asset} ({ep})
# Objetivo: Sanitizar encabezados Host / X-Forwarded-Host y prevenir redirecciones abiertas
set -e
echo '🛡️ Aplicando mitigación contra Host Header Injection y Open Redirect en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
PROXY_SNIPPET="$NGINX_CONF_DIR/centinela_proxy_hardening.conf"

if command -v nginx >/dev/null 2>&1; then
    echo "⚙️ Configurando descarte de X-Forwarded-Host externo y allowlist en Nginx..."
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$PROXY_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-INPV-17 / WSTG-CLNT-04
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
EOF

    echo "🔍 Validando sintaxis de configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Protección contra manipulación de Host / Open Redirect activada en Nginx."
fi

echo "ℹ️ En caso de entornos Apache Superset, verificar en superset_config.py:"
echo "   ENABLE_PROXY_FIX = True"
echo "   PREFERRED_URL_SCHEME = 'https'"
echo "   OVERRIDE_HTTP_HEADERS = {{}}"
"""

    if 'DANGEROUS-HTTP-METHOD' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-CONF-06)
# Host: {asset} ({ep})
# Objetivo: Bloquear métodos HTTP no autorizados (CONNECT, TRACE, TRACK)
set -e
echo '🔒 Deshabilitando métodos HTTP no seguros (CONNECT / TRACE) en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
METHODS_SNIPPET="$NGINX_CONF_DIR/centinela_allowed_methods.conf"

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$METHODS_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-CONF-06
if ($request_method !~ ^(GET|POST|HEAD|OPTIONS|PUT|DELETE)$) {{
    return 405 "Method Not Allowed";
}}
EOF

    echo "🔍 Validando configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Métodos peligrosos bloqueados con código HTTP 405."
fi
"""

    if 'SERVER-BANNER-LEAK' in cve or 'FRAMEWORK-FINGERPRINT' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-INFO-02 / WSTG-INFO-08)
# Host: {asset} ({ep})
# Objetivo: Ocultar versión del servidor web y banners de error
set -e
echo '🛡️ Aplicando minimización de banners tecnológicos (Information Disclosure) en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
TOKENS_SNIPPET="$NGINX_CONF_DIR/centinela_hide_tokens.conf"

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$TOKENS_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-INFO-02
server_tokens off;
proxy_hide_header X-Powered-By;
proxy_hide_header Server;
EOF

    echo "🔍 Validando configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Banners y tokens de versión ocultos exitosamente."
fi
"""

    if 'VERBOSE-BACKEND-ERROR' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-ERRH-01)
# Host: {asset} ({ep})
# Objetivo: Interceptar errores de backend y devolver respuestas neutrales
set -e
echo '🛡️ Configurando manejo seguro de errores e intercepción de proxy en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
ERRORS_SNIPPET="$NGINX_CONF_DIR/centinela_custom_errors.conf"

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$ERRORS_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-ERRH-01
proxy_intercept_errors on;
error_page 400 403 404 405 500 502 503 504 /centinela_generic_error.json;

location = /centinela_generic_error.json {{
    internal;
    default_type application/json;
    return 200 '{{"status": "error", "message": "Solicitud no procesable o recurso no disponible."}}';
}}
EOF

    echo "🔍 Validando configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Intercepción de errores de backend configurada en Nginx."
fi

echo "ℹ️ En caso de entornos Apache Superset / Flask, configurar en superset_config.py:"
echo "   SHOW_STACKTRACE = False"
"""

    if 'INSECURE-CORS' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-CLNT-07)
# Host: {asset} ({ep})
# Objetivo: Restringir CORS a orígenes autorizados y deshabilitar reflexión de Origin
set -e
echo '🔒 Aplicando hardening de cabeceras CORS en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
CORS_SNIPPET="$NGINX_CONF_DIR/centinela_cors_hardening.conf"

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$CORS_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-CLNT-07
proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Credentials;
add_header Access-Control-Allow-Origin "$scheme://$host" always;
add_header Access-Control-Allow-Credentials "true" always;
EOF

    echo "🔍 Validando sintaxis de configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Política CORS estricta aplicada."
fi
"""

    if 'SENSITIVE-FILES' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-CONF-04)
# Host: {asset} ({ep})
# Objetivo: Bloquear acceso a archivos sensibles, dotfiles y backups (.env, .git, .bak, .yml)
set -e
echo '🔒 Bloqueando acceso perimetral a archivos de configuración y dotfiles en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
BLOCK_SNIPPET="$NGINX_CONF_DIR/centinela_block_sensitive_files.conf"

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$BLOCK_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-CONF-04
location ~ /\\.(env|git|svn|hg|bzr) {{
    deny all;
    return 404;
}}
location ~ \\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|yml|yaml)$ {{
    deny all;
    return 404;
}}
EOF

    echo "🔍 Validando sintaxis de configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Reglas de bloqueo de dotfiles y backups activadas."
fi
"""

    if 'DEBUG-ENDPOINTS' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-CONF-05)
# Host: {asset} ({ep})
# Objetivo: Restringir acceso público a endpoints de métricas, diagnóstico y Swagger
set -e
echo '🔒 Protegiendo interfaces de métricas y debug en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
DEBUG_SNIPPET="$NGINX_CONF_DIR/centinela_restrict_debug.conf"

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$DEBUG_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-CONF-05
location ~ ^/(actuator|metrics|debug|server-status) {{
    allow 127.0.0.1;
    allow 192.0.2.1/8;
    deny all;
    return 404;
}}
EOF

    echo "🔍 Validando configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Endpoints de métricas y debug restringidos a redes internas."
fi
"""

    if 'COOKIE-SAMESITE' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-SESS-02)
# Host: {asset} ({ep})
# Objetivo: Forzar atributos SameSite=Lax y Secure en cookies
set -e
echo '🔒 Configurando SameSite=Lax en cookies de sesión en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
COOKIE_SNIPPET="$NGINX_CONF_DIR/centinela_cookie_flags.conf"

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$COOKIE_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-SESS-02
proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";
EOF

    echo "🔍 Validando configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Directiva de atributos de cookies aplicada en Nginx."
fi

echo "ℹ️ En Apache Superset, configurar en superset_config.py:"
echo "   SESSION_COOKIE_SAMESITE = 'Lax'"
echo "   SESSION_COOKIE_HTTPONLY = True"
echo "   SESSION_COOKIE_SECURE = True"
"""

    if 'INCOMPLETE-HSTS' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-CONF-07)
# Host: {asset} ({ep})
# Objetivo: Habilitar HSTS estricto con max-age de 1 año e includeSubDomains
set -e
echo '🔒 Aplicando HSTS completo y preload en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
HSTS_SNIPPET="$NGINX_CONF_DIR/centinela_strict_hsts.conf"

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$HSTS_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-CONF-07
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
EOF

    echo "🔍 Validando configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Política HSTS completa aplicada."
fi
"""

    if 'DUPLICATE-OR-WEAK-FRAME-OPTIONS' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-CLNT-09)
# Host: {asset} ({ep})
# Objetivo: Deduplicar X-Frame-Options y configurar CSP frame-ancestors
set -e
echo '🔒 Deduplicando X-Frame-Options y configurando CSP anti-clickjacking en {asset}...'

NGINX_CONF_DIR="/etc/nginx/conf.d"
FRAME_SNIPPET="$NGINX_CONF_DIR/centinela_frame_options.conf"

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p "$NGINX_CONF_DIR"
    sudo tee "$FRAME_SNIPPET" > /dev/null << 'EOF'
# Generado por Centinela AI - Hardening WSTG-CLNT-09
proxy_hide_header X-Frame-Options;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Content-Security-Policy "frame-ancestors 'self';" always;
EOF

    echo "🔍 Validando configuración de Nginx..."
    sudo nginx -t
    echo "🔄 Recargando Nginx..."
    sudo systemctl reload nginx || sudo service nginx reload
    echo "✅ Protección anti-clickjacking estandarizada."
fi
"""

    if 'DEFAULT-CREDENTIALS' in cve:
        return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (OWASP WSTG-AUTH-02)
# Host: {asset} ({ep})
# Objetivo: Rotación urgente de credenciales por defecto de fábrica
set -e
echo '🚨 ALERTA CRÍTICA: Rotando credenciales por defecto de fábrica en {asset}...'

if command -v superset >/dev/null 2>&1; then
    NEW_PASS=$(openssl rand -base64 24)
    echo "🔑 Generando nueva contraseña aleatoria de alta entropía para admin..."
    superset fab reset-password --username admin --password "$NEW_PASS" || true
    echo "✅ Contraseña del usuario admin de Superset actualizada en el host."
else
    echo "⚠️ Por favor acceda de inmediato a la interfaz administrativa y cambie la contraseña del usuario 'admin'."
fi
"""

    return None



def generate_heuristic_script(vuln):
    cve = str(vuln.get('cve_id', 'SECURITY-FINDING')).upper()
    asset = str(vuln.get('asset_name', 'INFRASTRUCTURE-HOST'))
    atype = str(vuln.get('asset_type', 'SERVER')).upper()
    ep = str(vuln.get('endpoint', '0.0.0.0'))
    desc = str(vuln.get('description', '')).lower()

    header = f"#!/bin/bash\n# Script de Remediación Automática - Centinela AI\n# Host: {asset} ({ep})\n# Vulnerabilidad / Regla: {cve}\nset -e\necho '🔒 Ejecutando hardening y remediación de seguridad en {asset} ({ep})...'\n"

    _hyg = _infra_hygiene_guidance(vuln)
    if _hyg is not None:
        return _hyg[3]

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

    if cve.startswith('WSTG-'):
        wstg_fix = generate_wstg_remediation(vuln)
        if wstg_fix:
            return wstg_fix
        return (
            f"#!/bin/bash\n# Centinela AI -- {cve} en {asset} ({ep})\n"
            f"echo 'ℹ️ No existe un script de remediación automática aplicable directamente en el host para {cve}.'\n"
            f"echo 'Revisar la configuración del aplicativo y del proxy para el ajuste manual.'\n"
            f"exit 1\n"
        )

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
    elif cve.startswith('AUTHZ'):
        # Real bug found live 2026-09-01: the next branch's `'AUTH' in cve` substring test
        # matched every single AUTHZ-* cve_id (they all contain "AUTH"), hijacking every
        # broken-access-control finding -- including the exact proyecto-k privilege-escalation
        # pattern -- into an irrelevant SSH-root-login hardening script, before this function
        # ever reached the atype=='GITLAB-REPO' branch below. Caught by manually correlating a
        # real AUTHZ-INCONSISTENT-FAMILY finding with all 4 LLM providers exhausted (forcing the
        # heuristic path) and seeing an SSH script come back for a Spring Security finding.
        guidance = _authz_fix_guidance(cve)
        location = str(vuln.get('url_path', '')) or 'ver descripción'
        if atype == 'GITLAB-REPO':
            if guidance:
                titulo, impacto, accion, code = guidance
                code_block = f"\n# Corrección sugerida:\n# {code}\n" if code else ""
                body = f"""# {cve}: {titulo}
echo 'ℹ️ Ubicación exacta: {location}'
echo 'ℹ️ {impacto}'
echo 'ℹ️ Cómo se resuelve (NO requiere actualizar librerías): {accion}'
echo 'Al aprobar en SOAR, Centinela clonará el repositorio, creará una rama de corrección y abrirá un Merge Request en GitLab con el parche generado por IA.'
{code_block}"""
            else:
                body = f"""# {cve} es un hallazgo de control de acceso en el repositorio {asset}.
echo 'ℹ️ Ubicación exacta: {location}'
echo 'ℹ️ No hay un host remoto que "endurecer" -- la corrección real es un cambio de código en el repositorio.'
echo 'Al aprobar en SOAR, Centinela clonará el repositorio y abrirá un Merge Request con el parche generado por IA.'
"""
        else:
            # AUTHZ-DAST-* against a live URL/AppServer/SERVER asset: this engine only
            # *confirms* the vulnerability at runtime -- the fix always lives in the source
            # repo (a Spring Security rule / method annotation), never on this host.
            if guidance:
                titulo, impacto, accion, _code = guidance
                body = f"""# {cve}: {titulo}
echo 'ℹ️ {impacto}'
echo 'ℹ️ Esta sonda CONFIRMA la vulnerabilidad en vivo contra {ep} -- la corrección no se aplica en este host.'
echo 'ℹ️ {accion}'
echo 'Buscar el hallazgo AUTHZ-INCONSISTENT-FAMILY / AUTHZ-* correspondiente en el repositorio de origen y corregirlo ahí.'
"""
            else:
                body = f"""# {cve} en {asset} ({ep}): hallazgo de control de acceso confirmado en vivo.
echo 'ℹ️ La corrección se aplica en el repositorio de origen, no en este host.'
"""
    elif 'SSH' in cve or 'ROOT-LOGIN' in cve:
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
echo 'Al aprobar en SOAR, Centinela clonará el repositorio, creará una rama de corrección y abrirá un Merge Request en GitLab.'
echo 'Soporta parches automáticos para Dockerfile USER, actualización de dependencias SCA y prevención de Command Injection (shell=True).'
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
    elif cve.startswith('CIS-') or 'CIS' in cve:
        if '1.1' in cve or 'ROOT-LOGIN' in cve or 'ROOT' in cve:
            body = """# Remediar CIS-1.1: Deshabilitar acceso root por SSH
if [ -f /etc/ssh/sshd_config ]; then
    echo '🔐 Configurando SSH sin acceso directo a root (PermitRootLogin no)...'
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || true
    echo '✅ SSH PermitRootLogin configurado en no.'
else
    echo 'ℹ️ /etc/ssh/sshd_config no encontrado.'
fi
"""
        elif '1.2' in cve or 'PASSWORD' in cve:
            body = """# Remediar CIS-1.2: Deshabilitar autenticación SSH por contraseña
if [ -f /etc/ssh/sshd_config ]; then
    echo '🔐 Configurando SSH para requerir autenticación por clave pública (PasswordAuthentication no)...'
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || true
    echo '✅ SSH PasswordAuthentication configurado en no.'
else
    echo 'ℹ️ /etc/ssh/sshd_config no encontrado.'
fi
"""
        elif '2.1' in cve or 'PASSWD' in cve:
            body = """# Remediar CIS-2.1: Permisos estrictos en /etc/passwd (644)
echo '🔒 Ajustando permisos y propietario en /etc/passwd...'
chmod 644 /etc/passwd
chown root:root /etc/passwd
echo '✅ Permisos de /etc/passwd ajustados a 644 (root:root).'
"""
        elif '2.2' in cve or 'SHADOW' in cve:
            body = """# Remediar CIS-2.2: Permisos estrictos en /etc/shadow (600)
echo '🔒 Ajustando permisos y propietario en /etc/shadow...'
chmod 600 /etc/shadow
chown root:root /etc/shadow
echo '✅ Permisos de /etc/shadow ajustados a 600 (root:root).'
"""
        elif '3.1' in cve or 'MIN_LEN' in cve:
            body = """# Remediar CIS-3.1: Longitud mínima de contraseña >= 14 en /etc/login.defs
if [ -f /etc/login.defs ]; then
    echo '🔐 Configurando PASS_MIN_LEN 14 en /etc/login.defs...'
    if grep -q '^PASS_MIN_LEN' /etc/login.defs; then
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN   14/' /etc/login.defs
    else
        echo 'PASS_MIN_LEN   14' >> /etc/login.defs
    fi
    echo '✅ PASS_MIN_LEN establecido a 14 en /etc/login.defs.'
else
    echo 'ℹ️ /etc/login.defs no encontrado.'
fi
"""
        elif '4.1' in cve or 'FIREWALL' in cve:
            body = """# Remediar CIS-4.1: Activación y endurecimiento de Firewall (UFW / firewalld)
echo '🛡️ Verificando y activando servicio de firewall...'
if command -v ufw >/dev/null 2>&1; then
    echo 'Activando UFW con políticas defensivas...'
    ufw default deny incoming 2>/dev/null || true
    ufw default allow outgoing 2>/dev/null || true
    ufw allow 22/tcp 2>/dev/null || true
    ufw allow 80/tcp 2>/dev/null || true
    ufw allow 443/tcp 2>/dev/null || true
    ufw --force enable 2>/dev/null || true
    echo '✅ UFW activado correctamente.'
elif command -v firewalld >/dev/null 2>&1; then
    echo 'Activando firewalld...'
    systemctl enable --now firewalld 2>/dev/null || true
    echo '✅ firewalld activado correctamente.'
else
    echo '📦 Instalando ufw como solución de firewall estándar...'
    apt-get update -qq && apt-get install -y ufw 2>/dev/null || yum install -y ufw 2>/dev/null || true
    if command -v ufw >/dev/null 2>&1; then
        ufw default deny incoming 2>/dev/null || true
        ufw default allow outgoing 2>/dev/null || true
        ufw allow 22/tcp 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
        echo '✅ UFW instalado y activado.'
    fi
fi
"""
        elif '5.1' in cve or 'EMPTY' in cve:
            body = """# Remediar CIS-5.1: Bloqueo de cuentas sin contraseña definida
echo '🔒 Auditando cuentas con contraseña vacía en /etc/shadow...'
empty_users=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || true)
if [ -n "$empty_users" ]; then
    echo "⚠️ Bloqueando usuarios sin contraseña: $empty_users"
    for u in $empty_users; do
        passwd -l "$u" 2>/dev/null || true
    done
    echo '✅ Cuentas sin contraseña bloqueadas exitosamente.'
else
    echo '✅ No se encontraron cuentas con contraseña vacía.'
fi
"""
        elif '5.2' in cve or 'AUDITD' in cve:
            body = """# Remediar CIS-5.2: Instalación y activación de auditd (Auditoría del Sistema)
echo '🔍 Verificando servicio de auditoría de kernel (auditd)...'
if ! command -v auditd >/dev/null 2>&1 && ! systemctl status auditd >/dev/null 2>&1; then
    echo '📦 Instalando paquete auditd...'
    apt-get update -qq && apt-get install -y auditd auditd-plugins 2>/dev/null || yum install -y audit 2>/dev/null || true
fi
if systemctl enable --now auditd 2>/dev/null || service auditd start 2>/dev/null; then
    echo '✅ Servicio auditd activado e iniciado.'
else
    echo '⚠️ No se pudo iniciar auditd automáticamente; verificar módulo de kernel audit.'
fi
"""
        elif '6.1' in cve or 'IP_FORWARD' in cve:
            body = """# Remediar CIS-6.1: Deshabilitar IP Forwarding (net.ipv4.ip_forward=0)
echo '🛡️ Deshabilitando enrutamiento de paquetes IP (IP Forwarding)...'
sysctl -w net.ipv4.ip_forward=0 2>/dev/null || true
mkdir -p /etc/sysctl.d
echo 'net.ipv4.ip_forward = 0' > /etc/sysctl.d/99-cis-ip-forward.conf
sysctl --system 2>/dev/null || true
echo '✅ IP Forwarding configurado en 0 persistentemente.'
"""
        elif '6.2' in cve or 'CORE' in cve or 'SUID' in cve:
            body = """# Remediar CIS-6.2: Restricción de Core Dumps (fs.suid_dumpable=0)
echo '🛡️ Restringiendo generación de core dumps de binarios SUID/SGID...'
sysctl -w fs.suid_dumpable=0 2>/dev/null || true
mkdir -p /etc/sysctl.d
echo 'fs.suid_dumpable = 0' > /etc/sysctl.d/99-cis-coredump.conf
sysctl --system 2>/dev/null || true
if [ -f /etc/security/limits.conf ]; then
    if ! grep -q '^\*\s*hard\s*core\s*0' /etc/security/limits.conf; then
        echo '* hard core 0' >> /etc/security/limits.conf
    fi
fi
echo '✅ Restricción de core dumps (fs.suid_dumpable=0) configurada correctamente.'
"""
        elif '7.1' in cve or 'TIME' in cve or 'NTP' in cve:
            body = """# Remediar CIS-7.1: Activación de servicio de sincronización horaria (NTP)
echo '⏱️ Verificando servicios de sincronización de tiempo...'
if systemctl enable --now systemd-timesyncd 2>/dev/null; then
    echo '✅ systemd-timesyncd activado.'
elif systemctl enable --now chrony 2>/dev/null || systemctl enable --now ntp 2>/dev/null; then
    echo '✅ Servicio NTP (chrony/ntp) activado.'
else
    echo '📦 Instalando y activando chrony...'
    apt-get update -qq && apt-get install -y chrony 2>/dev/null || yum install -y chrony 2>/dev/null || true
    systemctl enable --now chrony 2>/dev/null || true
    echo '✅ chrony instalado y activado.'
fi
"""
        else:
            body = f"""# Hardening general CIS Benchmark para {cve}
echo '🔍 Ejecutando hardening defensivo CIS en {asset} ({ep})...'
if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet wazuh-agent 2>/dev/null && echo 'Agente Wazuh activo' || true
fi
echo '✅ Verificación CIS completada.'
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



def _infra_hygiene_guidance(vuln):
    """
    Deterministic, real guidance for the OS-patch (auditors/auditor_os_patches.py) and TLS
    (auditors/auditor_tls.py) finding families. Returns None for any other cve_id, else
    (riesgo, impacto, accion, script, can_automate). Scripts that change a host are only ever run
    after human approval (Sentinel) and are meant for a maintenance window; TLS/EOL/cert findings
    are guidance-only (can_automate=False) because a blind config rewrite of a shared proxy or an
    OS migration is not something a script can do safely.
    """
    cve_u = str(vuln.get('cve_id', '')).upper()
    asset = str(vuln.get('asset_name', 'HOST'))
    ep = str(vuln.get('endpoint', ''))
    loc = str(vuln.get('url_path', '')) or ep
    hdr = f"#!/bin/bash\n# Centinela AI - {cve_u}\n# Host: {asset} ({ep})\nset -e\n"

    if cve_u == 'OS-PATCH-SECURITY-UPDATES-PENDING':
        script = hdr + (
            "# REQUIERE VENTANA DE MANTENIMIENTO: puede reiniciar servicios.\n"
            "if command -v apt-get >/dev/null 2>&1; then\n"
            "  sudo apt-get update\n  sudo unattended-upgrade -v || sudo apt-get -y upgrade\n"
            "elif command -v dnf >/dev/null 2>&1; then sudo dnf -y upgrade --security\n"
            "elif command -v yum >/dev/null 2>&1; then sudo yum -y update --security\n"
            "else echo 'Gestor de paquetes no soportado'; exit 1; fi\n"
            "echo '✅ Actualizaciones de seguridad aplicadas. Verifique si se requiere reinicio.'\n")
        return ("Actualizaciones de seguridad del sistema operativo pendientes",
                "Cada parche pendiente corresponde a una vulnerabilidad ya publicada y explotable en los paquetes del host.",
                "Aplicar las actualizaciones de seguridad en una ventana de mantenimiento y validar los servicios.", script, True)
    if cve_u == 'OS-REBOOT-REQUIRED':
        script = hdr + ("# Programa el reinicio a las 02:00 (cancelable con `shutdown -c`); no reinicia de inmediato.\n"
                        "sudo shutdown -r 02:00 'Reinicio programado por Centinela para activar parches del kernel'\n"
                        "echo '🕑 Reinicio programado a las 02:00.'\n")
        return ("Reinicio pendiente: parche del kernel no activo",
                "El host sigue ejecutando el kernel vulnerable hasta reiniciar, aunque el paquete corregido ya esté instalado.",
                "Reiniciar el host en una ventana de mantenimiento (script: reinicio programado, cancelable).", script, True)
    if cve_u == 'OS-AUTO-UPDATES-DISABLED':
        script = hdr + (
            "if command -v apt-get >/dev/null 2>&1; then\n"
            "  sudo apt-get install -y unattended-upgrades && sudo systemctl enable --now unattended-upgrades\n"
            "elif command -v dnf >/dev/null 2>&1; then\n"
            "  sudo dnf install -y dnf-automatic && sudo sed -i 's/^upgrade_type.*/upgrade_type = security/;s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf && sudo systemctl enable --now dnf-automatic.timer\n"
            "else echo 'Configure actualizaciones automáticas manualmente'; exit 1; fi\n"
            "echo '✅ Actualizaciones automáticas de seguridad habilitadas.'\n")
        return ("Sin actualizaciones automáticas de seguridad",
                "Los parches dependen de intervención manual y se aplican tarde o nunca.",
                "Habilitar unattended-upgrades (Debian/Ubuntu) o dnf-automatic (RHEL) limitado a seguridad.", script, True)
    if cve_u == 'OS-PACKAGE-INDEX-STALE':
        script = hdr + "if command -v apt-get >/dev/null 2>&1; then sudo apt-get update; else sudo dnf -y makecache || sudo yum -y makecache; fi\necho '✅ Índice de paquetes actualizado.'\n"
        return ("Índice de paquetes desactualizado",
                "El host desconoce los parches recientes; el conteo de actualizaciones pendientes no es confiable.",
                "Refrescar el índice de paquetes y revisar la conectividad a los repositorios.", script, True)
    if cve_u == 'OS-EOL':
        msg = hdr + "echo '⚠️ Sistema operativo fuera de soporte: no existe un parche automático. Planifique migración/actualización de versión.'\nexit 1\n"
        return ("Sistema operativo fuera de soporte del fabricante",
                "Sin parches de seguridad nuevos: toda vulnerabilidad futura del sistema base permanecerá abierta.",
                "Migrar a una versión soportada (o contratar soporte extendido del fabricante) y reconstruir el servicio sobre ella.", msg, False)
    tls = {
        'TLS-NOT-ENABLED': ("Servicio expuesto solo por HTTP sin cifrar", "Credenciales y tokens de sesión viajan en texto claro y pueden ser interceptados o alterados en la red.", f"Publicar {loc} detrás de un reverse proxy con TLS (nginx `listen 443 ssl`) y redirigir HTTP a HTTPS."),
        'TLS-CERT-EXPIRED': ("Certificado TLS vencido", "Los clientes rechazan la conexión o aprenden a ignorar advertencias (habilita MITM).", f"Renovar el certificado de {loc} con la CA correspondiente y recargar el servicio."),
        'TLS-CERT-EXPIRING-SOON': ("Certificado TLS próximo a vencer", "Al vencer, el servicio dejará de ser confiable para los clientes.", f"Renovar el certificado de {loc} antes de su fecha de vencimiento y automatizar la renovación."),
        'TLS-CERT-WEAK-KEY': ("Certificado TLS con llave débil", "Una llave corta puede ser factorizada, permitiendo suplantar el servicio.", f"Emitir un nuevo certificado para {loc} con llave RSA >= 2048 (recomendado 3072) o ECDSA P-256."),
        'TLS-CERT-WEAK-SIGNATURE': ("Certificado TLS firmado con algoritmo roto (SHA-1/MD5)", "La firma puede falsificarse mediante colisiones.", f"Reemitir el certificado de {loc} firmado con SHA-256 o superior."),
        'TLS-CERT-SELF-SIGNED': ("Certificado TLS autofirmado", "Los clientes no pueden validar la identidad del servidor.", f"Emitir el certificado de {loc} desde la CA interna de la organización e instalar su cadena en los clientes."),
        'TLS-LEGACY-PROTOCOL-ENABLED': ("Protocolos TLS obsoletos habilitados (TLS 1.0/1.1/SSLv3)", "Vulnerables a ataques conocidos (BEAST, POODLE); PCI DSS los prohíbe.", f"Configurar `ssl_protocols TLSv1.2 TLSv1.3;` en el servidor/proxy de {loc} y recargar."),
        'TLS-WEAK-CIPHER-ENABLED': ("Suites de cifrado débiles habilitadas", "Permiten descifrar o degradar el tráfico protegido.", f"Restringir `ssl_ciphers` en {loc} a suites AEAD con ECDHE (p. ej. `ECDHE+AESGCM:ECDHE+CHACHA20`)."),
        'TLS-STATIC-RSA-KEX-ENABLED': ("Intercambio de llaves RSA estático (sin forward secrecy)", "Si la llave privada se compromete, el tráfico pasado grabado queda descifrable.", f"Reemplazar `ssl_ciphers HIGH:!aNULL:!MD5` en {loc} por una lista solo ECDHE (p. ej. `ECDHE+AESGCM:ECDHE+CHACHA20`)."),
    }
    if cve_u in tls:
        riesgo, impacto, accion = tls[cve_u]
        script = hdr + f"echo 'Sin automatización segura: {accion}'\nexit 1\n"
        return (riesgo, impacto, accion, script, False)
    return None



_GITLAB_HYGIENE_GUIDANCE = {
    'GITLAB-PROJECT-DEFAULT-BRANCH-UNPROTECTED': ("Rama por defecto sin protección en GitLab",
        "Cualquier Developer puede empujar directo o reescribir el historial de la rama productiva sin revisión, invalidando el control de cambios.",
        "En GitLab: Settings > Repository > Protected branches: proteger la rama por defecto (push: Maintainers, merge: Developers+Maintainers, sin force-push)."),
    'GITLAB-PROJECT-BRANCH-FORCE-PUSH': ("Force-push permitido en rama protegida",
        "El historial auditado puede reescribirse, borrando evidencia de cambios.", "Desactivar 'Allow force push' en la regla de la rama protegida."),
    'GITLAB-PROJECT-BRANCH-DEVELOPER-PUSH': ("Push directo permitido a Developers en la rama protegida",
        "Los cambios llegan a la rama principal sin Merge Request ni revisión por pares.", "Cambiar 'Allowed to push' a Maintainers y exigir Merge Request."),
    'GITLAB-PROJECT-PUBLIC-VISIBILITY': ("Repositorio con visibilidad excesiva",
        "El código fuente e historial (posibles secretos, lógica de negocio) es legible fuera del equipo del proyecto.", "Settings > General > Visibility: establecer 'Private' y otorgar acceso solo a los miembros del equipo."),
    'GITLAB-PROJECT-MR-NO-PIPELINE-GATE': ("Merge Requests integrables con pipeline fallido",
        "Código que no pasa pruebas ni escaneos puede llegar a la rama principal.", "Settings > Merge requests: activar 'Pipelines must succeed'."),
    'GITLAB-PROJECT-WEBHOOK-INSECURE': ("Webhook de GitLab inseguro",
        "El contenido del repositorio y eventos viajan sin cifrar o sin verificar el destino.", "Usar HTTPS con verificación de certificado y un secret token en el webhook."),
    'GITLAB-PROJECT-CI-VARIABLE-UNMASKED': ("Variable de CI con secreto sin enmascarar",
        "El valor puede quedar impreso en claro en los logs de los jobs.", "Settings > CI/CD > Variables: marcar la variable como 'Masked' (y 'Protected' si solo se usa en ramas protegidas)."),
    'GITLAB-PROJECT-CI-VARIABLE-UNPROTECTED': ("Variable secreta disponible en ramas no protegidas",
        "Cualquier rama o MR puede leer el secreto desde un job.", "Marcar la variable como 'Protected' para restringirla a ramas/tags protegidos."),
    'CICD-NO-PIPELINE': ("Proyecto sin pipeline de CI/CD",
        "No corre ningún control automático (pruebas, SAST, SCA) antes de integrar cambios.", "Crear `.gitlab-ci.yml` con etapas mínimas de build, test y escaneo de seguridad."),
    'CICD-CURL-PIPE-SHELL': ("Pipeline descarga y ejecuta código remoto sin verificar",
        "Si el origen se compromete, el runner ejecuta código del atacante con acceso a los secretos del pipeline.", "Descargar el script, verificar su checksum/firma y ejecutarlo después; o usar una imagen con la herramienta preinstalada."),
    'CICD-UNPINNED-IMAGE': ("Imagen de CI sin versión fija",
        "El build no es reproducible y una imagen alterada se ejecutaría con los secretos del pipeline.", "Fijar la imagen a una versión concreta (o a su digest `@sha256:`)."),
    'CICD-HARDCODED-SECRET': ("Secreto literal en .gitlab-ci.yml",
        "El secreto queda en el repositorio y en todo su historial.", "Mover el valor a variables de CI enmascaradas/protegidas, rotar el secreto expuesto y limpiar el historial si aplica."),
    'CICD-TLS-VERIFICATION-DISABLED': ("Pipeline con verificación TLS desactivada",
        "Las descargas del build pueden ser interceptadas o alteradas.", "Eliminar `-k`/`GIT_SSL_NO_VERIFY`/`strict-ssl false` e instalar la CA interna en la imagen del runner."),
    'CICD-DOCKER-PRIVILEGED': ("Contenedores privilegiados en el pipeline",
        "Un job comprometido obtiene acceso equivalente a root en el host del runner.", "Evitar `privileged: true`; usar builders sin privilegios (Kaniko/BuildKit rootless)."),
    'CICD-REMOTE-INCLUDE-INSECURE': ("Pipeline incluye definición remota por HTTP",
        "La definición del pipeline puede alterarse en tránsito.", "Usar `include: project:` con ref fija o HTTPS con verificación."),
}



def _gitlab_hygiene_guidance(vuln):
    """Guidance-only (never auto-fixable by script) for the GitLab-config / CI families. Returns
    (riesgo, impacto, accion) or None."""
    return _GITLAB_HYGIENE_GUIDANCE.get(str(vuln.get('cve_id', '')).upper())



def heuristic_can_automate(vuln):
    """
    Whether the heuristic fallback script actually performs a real fix vs. only reporting/
    guiding. Kept in sync with generate_heuristic_script's own branches so can_automate in the
    DB reflects reality instead of being hardcoded True regardless of what happened.
    """
    cve = str(vuln.get('cve_id', '')).upper()
    atype = str(vuln.get('asset_type', '')).upper()
    desc = str(vuln.get('description', '')).lower()

    if cve.startswith('CTI-IOC-MATCH') or cve == 'HOST-CONTAINMENT-REQUEST' or cve.startswith('CIS-') or 'CIS' in cve:
        return True
    _hyg = _infra_hygiene_guidance(vuln)
    if _hyg is not None:
        return _hyg[4]
    if cve.startswith('WSTG-'):
        return generate_wstg_remediation(vuln) is not None
    if cve.startswith('ZAP-'):
        return generate_zap_header_fix(vuln) is not None
    if cve in ('SCAN-AUDIT', 'HEURISTIC-SECURITY-DEBT', 'SONARQUBE-QUALITY-GATE') or any(
        p in desc for p in ('no se detectaron vulnerabilidades', 'no se encontraron', 'escaneo externo omitido')
    ):
        return False
    if atype == 'GITLAB-REPO':
        # Only the deterministic patch categories Sentinel's GitLab pipeline actually handles.
        return cve in ('DOCKER-MISSING-NON-ROOT-USER', 'DOCKER-ROOT-USER') or cve.startswith('SCA-CVE-')
    if cve.startswith('AUTHZ'):
        # AUTHZ-DAST-* runs against a live URL/AppServer/SERVER asset but only *confirms* the
        # vulnerability -- the real fix is a code change in the source repo, never an action on
        # this host. Without this, the old blanket `return True` below would mark it
        # can_automate=True with no real automated action behind it.
        return False
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

    _hyg = _infra_hygiene_guidance(vuln)
    if _hyg is not None:
        return _hyg[0], _hyg[1], _hyg[2]
    _gl = _gitlab_hygiene_guidance(vuln)
    if _gl is not None:
        return _gl

    if cve_u.startswith('WSTG-'):
        if 'CLEARTEXT-LOGIN' in cve_u:
            return (
                "Formulario de autenticación transmitido en HTTP texto claro (WSTG-ATHN-02)",
                "Permite la intercepción de credenciales de usuario y tokens de sesión en tránsito mediante escuchas en red local o MitM.",
                f"Configurar redirección obligatoria 301 a HTTPS y directiva HSTS en Nginx para {ep} y aplicar SESSION_COOKIE_SECURE=True."
            )
        if 'UNENCRYPTED-CHANNEL' in cve_u:
            return (
                "Información sensible y sesión transmitida sin cifrado (WSTG-CRYP-03)",
                "El tráfico web y las cookies de autenticación viajan desprotegidos por HTTP sin garantía de confidencialidad ni HSTS.",
                f"Habilitar TLS de extremo a extremo, forzar HTTPS y configurar HSTS (Strict-Transport-Security) en {ep}."
            )
        if 'HOST-HEADER-INJECTION' in cve_u:
            return (
                "Inyección de cabecera Host reflejada en redirección (WSTG-INPV-17)",
                "Permite a un atacante manipular cabeceras Host/X-Forwarded-Host para provocar redirecciones hacia sitios maliciosos o envenenar cachés.",
                f"Configurar Nginx en {ep} con proxy_set_header Host $host y descartar cabeceras X-Forwarded-Host no validadas."
            )
        if 'DANGEROUS-HTTP-METHOD' in cve_u:
            return (
                "Método HTTP peligroso no restringido (CONNECT/TRACE) (WSTG-CONF-06)",
                "Aceptación innecesaria del método CONNECT permite abusos de tunneling a través del proxy inverso y amplía la superficie de ataque.",
                f"Restringir métodos HTTP en Nginx de {ep} permitiendo solo los requeridos (GET, POST, HEAD, OPTIONS, PUT, DELETE)."
            )
        if 'OPEN-REDIRECT' in cve_u:
            return (
                "Redirección abierta controlada por el usuario (WSTG-CLNT-04)",
                "El parámetro de retorno o next permite especificar URLs externas arbitrarias, facilitando campañas de phishing e ingeniería social.",
                f"Validar y restringir los destinos de redirección a rutas relativas o allowlist de dominios autorizados en {ep}."
            )
        if 'SERVER-BANNER-LEAK' in cve_u:
            return (
                "Exposición de versión del servidor web en cabeceras o páginas de error (WSTG-INFO-02)",
                "Revela la versión exacta de Nginx/Apache facilitando al atacante perfilar el entorno e identificar CVEs específicos.",
                f"Configurar `server_tokens off;` y personalizar páginas de error en Nginx de {ep}."
            )
        if 'FRAMEWORK-FINGERPRINT' in cve_u:
            return (
                "Exposición de versiones de frameworks y dependencias en recursos estáticos (WSTG-INFO-08)",
                "Facilita a atacantes identificar librerías de frontend con fin de soporte o vulnerabilidades públicas.",
                f"Minificar recursos JavaScript, remover comentarios de versión y actualizar dependencias a versiones con soporte activo."
            )
        if 'VERBOSE-BACKEND-ERROR' in cve_u:
            return (
                "Manejo inadecuado de errores con fuga de información interna (WSTG-ERRH-01)",
                "Respuestas HTTP 4xx/5xx revelan estructuras JSON con identificadores internos, frameworks o códigos de error del backend (ej. Superset 1011).",
                f"Habilitar `proxy_intercept_errors on;` en Nginx de {ep} y retornar respuestas de error genéricas sin trazas ni identificadores internos."
            )
        if 'INSECURE-CORS' in cve_u:
            return (
                "Reflexión arbitraria de origen CORS con credenciales (WSTG-CLNT-07)",
                "El servidor permite a cualquier origen externo leer datos autenticados del usuario mediante peticiones XHR.",
                f"Definir una allowlist estricta de dominios autorizados para CORS en Nginx de {ep} y nunca reflejar cabeceras Origin arbitrarias."
            )
        if 'SENSITIVE-FILES' in cve_u:
            return (
                "Exposición pública de archivos sensibles o de respaldo (WSTG-CONF-04)",
                "Archivos como .env, .git o copias de respaldo son descargables directamente exponiendo secretos y código fuente.",
                f"Bloquear en Nginx de {ep} el acceso a dotfiles (`/\\..*`) y extensiones sensibles (`.env`, `.bak`, `.sql`, `.yml`)."
            )
        if 'DEBUG-ENDPOINTS' in cve_u:
            return (
                "Interfaces de métricas, diagnóstico o Swagger expuestas (WSTG-CONF-05)",
                "Endpoints como /actuator, /metrics o /swagger-ui son accesibles sin autenticación permitiendo el perfilado del sistema.",
                f"Restringir acceso a endpoints de diagnóstico exclusivamente a redes internas autorizadas en {ep}."
            )
        if 'COOKIE-SAMESITE' in cve_u:
            return (
                "Atributos de cookie inseguros o ausencia de SameSite (WSTG-SESS-02)",
                "Las cookies de sesión carecen de SameSite=Lax/Strict o utilizan SameSite=None sin Secure, facilitando CSRF.",
                f"Configurar `proxy_cookie_path` en Nginx de {ep} para forzar atributos Secure, HttpOnly y SameSite=Lax."
            )
        if 'INCOMPLETE-HSTS' in cve_u:
            return (
                "Directiva HSTS ausente o incompleta (WSTG-CONF-07)",
                "Falta de HSTS o max-age insuficiente permite ataques de SSL Stripping y degradación a HTTP no cifrado.",
                f"Configurar `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` en Nginx de {ep}."
            )
        if 'DUPLICATE-OR-WEAK-FRAME-OPTIONS' in cve_u:
            return (
                "Protección anti-clickjacking duplicada o ausente (WSTG-CLNT-09)",
                "Cabeceras X-Frame-Options duplicadas o falta de directiva frame-ancestors en Content-Security-Policy.",
                f"Consolidar X-Frame-Options en Nginx de {ep} y añadir directiva `frame-ancestors 'self'` en la cabecera CSP."
            )
        if 'DEFAULT-CREDENTIALS' in cve_u:
            return (
                "Credenciales por defecto de fábrica activas (WSTG-AUTH-02)",
                "La aplicación permite el acceso con credenciales estándar out-of-the-box (`admin:admin`), comprometiendo el control total del activo.",
                f"Rotar inmediatamente la contraseña de la cuenta administrativa en {ep} y forzar cambio obligatorio tras la instalación."
            )

    if cve_u.startswith('CIS-') or 'CIS' in cve_u:
        if '1.1' in cve_u:
            return (
                "Acceso directo de superusuario root por SSH activado (CIS-1.1)",
                "Permite intentos de autenticación directa y ataques de fuerza bruta contra el usuario de máxima autoridad (root) en el servidor.",
                f"Se actualiza `/etc/ssh/sshd_config` con `PermitRootLogin no` en {ep} y se recarga el servicio SSH para forzar acceso mediante usuarios no privilegiados y elevación con sudo."
            )
        if '1.2' in cve_u:
            return (
                "Autenticación SSH mediante contraseña habilitada (CIS-1.2)",
                "Expone el servicio de administración remota SSH a ataques de fuerza bruta y diccionario contra credenciales del sistema.",
                f"Se establece `PasswordAuthentication no` en `/etc/ssh/sshd_config` en {ep} y se recarga el daemon SSH obligando el uso exclusivo de llaves criptográficas."
            )
        if '2.1' in cve_u:
            return (
                "Permisos de escritura inseguros en /etc/passwd (CIS-2.1)",
                "Permite a usuarios locales o procesos comprometidos modificar las cuentas del sistema y escalar privilegios creando usuarios root arbitrarios.",
                f"Se aplican permisos estrictos `chmod 644 /etc/passwd` y propiedad `chown root:root /etc/passwd` en {ep}."
            )
        if '2.2' in cve_u:
            return (
                "Permisos de lectura no restringidos en /etc/shadow (CIS-2.2)",
                "Permite la lectura no autorizada de hashes de contraseñas de usuarios del sistema para ataques de cracking de credenciales offline.",
                f"Se aplican permisos restringidos `chmod 600 /etc/shadow` y propiedad `chown root:root /etc/shadow` en {ep}."
            )
        if '3.1' in cve_u:
            return (
                "Longitud mínima de contraseña inferior a 14 caracteres (CIS-3.1)",
                "Contraseñas débiles o cortas facilitan el descubrimiento de credenciales por ataques de fuerza bruta o diccionarios.",
                f"Se establece `PASS_MIN_LEN 14` en `/etc/login.defs` en {ep} para reforzar la política global de complejidad de credenciales."
            )
        if '4.1' in cve_u:
            return (
                "Firewall de red deshabilitado o inactivo (CIS-4.1)",
                "El host no filtra tráfico de red entrante, exponiendo todos los puertos locales y servicios no autorizados a la red externa.",
                f"Se habilita y configura el servicio de firewall (UFW/firewalld) en {ep} estableciendo denegación por defecto e ingress únicamente en puertos declarados (22/80/443)."
            )
        if '5.1' in cve_u:
            return (
                "Existencia de cuentas de usuario sin contraseña definida (CIS-5.1)",
                "Permite autenticación inmediata y sin requerimiento de credenciales a usuarios locales o interactivos.",
                f"Se audita `/etc/shadow` en {ep} buscando cuentas sin contraseña y se aplica `passwd -l` para bloquear su acceso."
            )
        if '5.2' in cve_u:
            return (
                "Servicio de auditoría del kernel auditd inactivo (CIS-5.2)",
                "Falta de visibilidad y registro persistente ante modificaciones de archivos críticos o comandos sospechosos en el sistema.",
                f"Se instala y activa el servicio `auditd` en {ep} habilitando la auditoría de eventos de kernel a nivel de sistema operativo."
            )
        if '6.1' in cve_u:
            return (
                "Enrutamiento IP (IP Forwarding) habilitado en el host (CIS-6.1)",
                "Permite que el servidor sea utilizado como router o pivote no autorizado para canalizar tráfico malicioso entre subredes.",
                f"Se deshabilita `net.ipv4.ip_forward = 0` en caliente vía `sysctl` y se persiste en `/etc/sysctl.d/99-cis-ip-forward.conf` en {ep}."
            )
        if '6.2' in cve_u:
            return (
                "Generación de core dumps no restringida para binarios SUID (CIS-6.2)",
                "Los volcados de memoria (core dumps) de procesos privilegiados pueden exponer contraseñas, claves privadas y tokens en texto plano accesibles localmente.",
                f"Se configura `fs.suid_dumpable = 0` vía `sysctl`, se persiste en `/etc/sysctl.d/99-cis-coredump.conf` y se bloquea el límite `core` a 0 en `/etc/security/limits.conf` en {ep}."
            )
        if '7.1' in cve_u:
            return (
                "Sincronización de tiempo (NTP) inactiva (CIS-7.1)",
                "La desincronización horaria compromete la validez legal y forense de marcas de tiempo en auditorías, trazabilidad e inspección de logs.",
                f"Se activa y arranca el servicio de sincronización de tiempo (`systemd-timesyncd`, `chrony` o `ntp`) en {ep}."
            )
        return (
            f"Control de hardening CIS incumplido: {cve}",
            f"El control {cve} no cumple con los estándares recomendados de CIS Benchmark en {asset} -- ver evidencia técnica.",
            f"Se aplica script de hardening defensivo específico para {cve} en {ep}."
        )

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

    if cve_u in ('SCAN-AUDIT', 'CIS-BENCHMARK-AUDIT', 'SONARQUBE-QUALITY-GATE') or any(p in desc for p in ('no se detectaron vulnerabilidades', 'no se encontraron', 'escaneo externo omitido', 'auditoría cis benchmarks completada', 'auditoría sonarqube completada')):
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
        if cve_u.startswith('AUTHZ'):
            _g = _authz_fix_guidance(cve_u)
            if _g:
                _titulo, _impacto, _accion, _code = _g
                return (_titulo, _impacto, f"{_accion} Ubicación: {location}.")
        return (
            f"Hallazgo de código fuente: {cve}",
            f"Riesgo específico del tipo de hallazgo -- ver evidencia técnica en {location} para el detalle exacto.",
            "Hallazgo de repositorio sin parche automático soportado todavía -- revisar el código en la ubicación indicada y corregir manualmente, o esperar a que la IA genere un parche cuando haya cupo de API disponible."
        )

    if cve_u.startswith('AUTHZ'):
        # Not a GitLab-Repo asset: this is an AUTHZ-DAST-* live confirmation against a real
        # URL/AppServer/SERVER host. Placed before the 'SSH'/'AUTH' substring check below --
        # every AUTHZ-* cve_id contains "AUTH" as a substring and was being mis-classified as
        # an SSH-root-login finding (found live 2026-09-01 correlating a real
        # AUTHZ-INCONSISTENT-FAMILY finding with all 4 LLM providers exhausted).
        _g = _authz_fix_guidance(cve_u)
        if _g:
            _titulo, _impacto, _accion, _code = _g
            return (_titulo, f"{_impacto} Confirmado en vivo contra {ep}.",
                   f"La corrección no se aplica en este host: {_accion} Buscar y corregir el hallazgo "
                   f"correspondiente en el repositorio de origen.")
        return (
            f"Hallazgo de control de acceso: {cve}",
            f"Confirmado en vivo contra {ep}.",
            "La corrección se aplica en el repositorio de origen, no en este host."
        )
    if 'DOCKER' in cve_u or 'CONTAINER' in cve_u or 'NON-ROOT' in cve_u or 'non-root' in desc:
        return (
            "Contenedor(es) ejecutando procesos como root",
            "Si un contenedor comprometido corre como root, un escape de contenedor otorga control root directo del host.",
            f"Se audita cada contenedor en ejecución en {ep} buscando procesos root y se provisiona un usuario de servicio restringido para futura remediación manual del Dockerfile/compose."
        )
    if 'SSH' in cve_u or 'ROOT-LOGIN' in cve_u:
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
        f"Exposición de Seguridad o Mala Configuración en {cve}",
        f"Riesgo de Seguridad en la Infraestructura ({asset}): La exposición de la regla o vulnerabilidad {cve} en {ep} permite a actores maliciosos o malware realizar movimientos laterales, extraer información confidencial o interrumpir la continuidad operativa de los servicios corporativos.",
        f"Pasos de Resolución para el Equipo de Desarrollo e Infraestructura:\n1. Revisar la ubicación exacta ({location}) o la configuración del servicio en {ep}.\n2. Aplicar las políticas de hardening específicas del fabricante, cerrar puertos no autorizados o actualizar las dependencias vulnerables a versiones estables.\n3. Ejecutar de nuevo el escáner de Centinela-AI para verificar la mitigación de la brecha."
    )
