"""
Reverse-proxy IP block / unblock remediation scripts (virtual patching).

Shared by the heuristic remediation generator (centinela.py, human-approved path) and the SOAR
autoresponse engine (core/soar_engine.py, policy-gated path). Both are executed by Sentinel through
Ansible with the target asset's real credentials -- there is no other execution channel.
"""


def generate_ip_block_virtual_patch(vuln, malicious_ip: str, reason: str, expires_ts: int = None):
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
    # Autonomous (SOAR) blocks carry an expiry marker so a reaper can lift exactly those lines and
    # never touch a block a human added by hand.
    line = f"{directive} # centinela-auto expires={int(expires_ts)}" if expires_ts else directive

    return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (Parcheo Virtual)
# Host: {asset} ({ep})
# Vulnerabilidad / Regla: {cve}
# Motivo: {reason}
set -e
echo '🛡️ Aplicando bloqueo de IP maliciosa confirmada ({malicious_ip}) en {asset} ({ep})...'

SNIPPET_REL=/etc/nginx/conf.d/98-centinela-ip-blocklist.conf
DIRECTIVE='{directive}'
LINE='{line}'

if command -v nginx >/dev/null 2>&1; then
    sudo mkdir -p /etc/nginx/conf.d
    sudo touch "$SNIPPET_REL"
    if sudo grep -qF "$DIRECTIVE" "$SNIPPET_REL" 2>/dev/null; then
        echo "ℹ️ La IP ya estaba bloqueada (idempotente, nada que hacer)."
    else
        echo "$LINE" | sudo tee -a "$SNIPPET_REL" > /dev/null
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
                sudo docker exec -i "$NGINX_CONTAINER" sh -c "echo '$LINE' >> $SNIPPET_REL"
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
                echo "$LINE" | sudo tee -a "$HOST_SNIPPET" > /dev/null
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


def generate_ip_unblock_script(vuln, blocked_ip: str):
    """Lift ONLY a block that SOAR itself added (line tagged `# centinela-auto`)."""
    asset = str(vuln.get('asset_name', 'INFRASTRUCTURE-HOST'))
    ep = str(vuln.get('endpoint', '0.0.0.0'))
    return f"""#!/bin/bash
# Script de Remediación Automática - Centinela AI (Expiración de bloqueo SOAR)
# Host: {asset} ({ep})
set -e
IP='{blocked_ip}'
SNIPPET_REL=/etc/nginx/conf.d/98-centinela-ip-blocklist.conf
PATTERN="^deny ${{IP//./\\.}}; # centinela-auto"
echo "🔓 Levantando bloqueo temporal SOAR de $IP en {asset} ({ep})..."

if command -v nginx >/dev/null 2>&1; then
    if [ -f "$SNIPPET_REL" ]; then sudo sed -i -E "/$PATTERN/d" "$SNIPPET_REL"; fi
    sudo nginx -t
    sudo systemctl reload nginx 2>/dev/null || sudo nginx -s reload
    echo '✅ Bloqueo levantado.'
    exit 0
fi

if command -v docker >/dev/null 2>&1; then
    NGINX_CONTAINER=$(sudo docker ps --format '{{{{.Names}}}} {{{{.Image}}}}' 2>/dev/null | grep -i nginx | head -1 | awk '{{print $1}}')
    if [ -n "$NGINX_CONTAINER" ]; then
        HOST_CONFD=$(sudo docker inspect "$NGINX_CONTAINER" --format '{{{{range .Mounts}}}}{{{{if eq .Destination "/etc/nginx/conf.d"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}')
        if [ -n "$HOST_CONFD" ] && [ -f "$HOST_CONFD/98-centinela-ip-blocklist.conf" ]; then
            sudo sed -i -E "/$PATTERN/d" "$HOST_CONFD/98-centinela-ip-blocklist.conf"
        else
            sudo docker exec "$NGINX_CONTAINER" sh -c "[ -f $SNIPPET_REL ] && sed -i -E '/$PATTERN/d' $SNIPPET_REL || true"
        fi
        sudo docker exec "$NGINX_CONTAINER" nginx -t
        sudo docker exec "$NGINX_CONTAINER" nginx -s reload
        echo '✅ Bloqueo levantado.'
        exit 0
    fi
fi
echo "⚠️ No se encontró nginx; nada que levantar."
exit 1
"""
