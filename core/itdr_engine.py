"""
Módulo ITDR (Identity Threat Detection & Response) para Centinela Omni-XDR.
Analiza eventos de autenticación en tiempo real provenientes del IdP Authentik
y detecta ataques a nivel de identidad (Password Spraying, Fuerza Bruta, Alteraciones de MFA y Escalamiento).
"""

import os
import requests
import json
from datetime import datetime, timedelta
from core import db_manager, clickhouse_manager

AUTHENTIK_URL = os.getenv("AUTHENTIK_INTERNAL_URL", os.getenv("AUTHENTIK_URL", "https://auth.casmart.internal"))
AUTHENTIK_TOKEN = os.getenv("AUTHENTIK_CLIENT_SECRET", "")

# Bitácora en memoria para análisis de frecuencia de intentos fallidos
FAILED_LOGINS = {} # { (username, client_ip): [timestamps] }

def process_authentik_event(payload: dict):
    """
    Procesa un evento de autenticación enviado por Authentik vía Webhook o Syslog.
    Detecta:
    - Fuerza Bruta / Password Spraying
    - Eliminación / Alteración de Dispositivos MFA
    - Escalamiento de Privilegios no autorizado
    """
    event_type = payload.get("action", payload.get("event", "desconocido"))
    username = payload.get("user", {}).get("username") or payload.get("username", "desconocido")
    client_ip = payload.get("client_ip") or payload.get("ip_address") or "0.0.0.0"
    timestamp = datetime.utcnow()

    alerts_generated = []

    # 1. Detección de Fuerza Bruta y Password Spraying
    if "login_failed" in event_type.lower() or "auth_failed" in event_type.lower():
        key = (username, client_ip)
        if key not in FAILED_LOGINS:
            FAILED_LOGINS[key] = []
        FAILED_LOGINS[key].append(timestamp)
        
        # Filtrar intentos en la última ventana de 60 segundos
        recent = [t for t in FAILED_LOGINS[key] if timestamp - t <= timedelta(seconds=60)]
        FAILED_LOGINS[key] = recent

        if len(recent) >= 5:
            confidence = 0.96 # Alta Confianza >= 95% -> Desencadena respuesta autónoma
            alert = {
                "rule_name": "ITDR-AUTHENTIK-BRUTE-FORCE",
                "severity": "CRITICAL",
                "asset_name": f"Authentik-User ({username})",
                "alert_text": f"Detección ITDR: Ataque de Fuerza Bruta / Password Spraying desde IP {client_ip} contra el usuario '{username}' ({len(recent)} intentos fallidos en 60s).",
                "confidence_score": confidence,
                "autonomous_action_executed": True
            }
            alerts_generated.append(alert)

            # Ejecutar Respuesta Autónoma Escalonada (Revocación de Sesión)
            revoke_authentik_user_sessions(username)

    # 2. Eliminación / Alteración de MFA
    elif "mfa" in event_type.lower() and ("remove" in event_type.lower() or "delete" in event_type.lower()):
        confidence = 0.90
        alert = {
            "rule_name": "ITDR-AUTHENTIK-MFA-BYPASS",
            "severity": "HIGH",
            "asset_name": f"Authentik-User ({username})",
            "alert_text": f"Detección ITDR: Dispositivo MFA eliminado o alterado para la cuenta '{username}' desde IP {client_ip}.",
            "confidence_score": confidence,
            "autonomous_action_executed": False
        }
        alerts_generated.append(alert)

    # 3. Escalamiento de Privilegios
    elif "group" in event_type.lower() and ("add" in event_type.lower() or "admin" in event_type.lower()):
        confidence = 0.95
        alert = {
            "rule_name": "ITDR-AUTHENTIK-PRIVILEGE-ESCALATION",
            "severity": "CRITICAL",
            "asset_name": f"Authentik-User ({username})",
            "alert_text": f"Detección ITDR: Asignación de rol administrativo o superusuario detectada para '{username}' desde IP {client_ip}.",
            "confidence_score": confidence,
            "autonomous_action_executed": True
        }
        alerts_generated.append(alert)
        revoke_authentik_user_sessions(username)

    # Registrar alertas en ClickHouse y PostgreSQL
    for a in alerts_generated:
        clickhouse_manager.insert_telemetry_event(
            source="authentik_itdr",
            event_type=a["rule_name"],
            username=username,
            client_ip=client_ip,
            severity=a["severity"],
            details=a,
            confidence=a["confidence_score"]
        )

        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                INSERT INTO public.runtime_alerts (asset_id, rule_name, priority, alert_text)
                VALUES (
                    (SELECT id FROM public.infra_inventory WHERE asset_name = %s LIMIT 1),
                    %s, %s, %s
                );
            """, (a["asset_name"], a["rule_name"], a["severity"], a["alert_text"]))

    return {"processed": True, "alerts_count": len(alerts_generated), "alerts": alerts_generated}

def revoke_authentik_user_sessions(username: str):
    """
    Ejecuta la Respuesta Autónoma Escalonada: Invalida tokens OIDC y cierra sesiones activas del usuario comprometido en Authentik.
    """
    if not AUTHENTIK_TOKEN:
        print(f"⚠️ [ITDR-Engine] No se pudo revocar la sesión de {username}: AUTHENTIK_CLIENT_SECRET no está configurado.")
        return False

    try:
        headers = {
            "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
            "Content-Type": "application/json"
        }
        url = f"{AUTHENTIK_URL}/api/v3/core/users/?username={username}"
        r = requests.get(url, headers=headers, verify=False, timeout=5)
        if r.status_code == 200:
            users = r.json().get("results", [])
            if users:
                user_id = users[0]["pk"]
                deactivate_url = f"{AUTHENTIK_URL}/api/v3/core/users/{user_id}/deactivate/"
                r_deact = requests.post(deactivate_url, headers=headers, verify=False, timeout=5)
                print(f"🔒 [ITDR-Respuesta-Autónoma] Sesiones del usuario '{username}' (ID: {user_id}) revocadas en Authentik ({r_deact.status_code}).")
                return True
    except Exception as e:
        print(f"⚠️ [ITDR-Engine] Error al revocar sesión para el usuario {username}: {e}")
    return False
