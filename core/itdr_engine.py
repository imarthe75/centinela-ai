"""
Módulo ITDR (Identity Threat Detection & Response) para Centinela Omni-XDR.
Analiza eventos de autenticación en tiempo real provenientes del IdP Authentik
y detecta ataques a nivel de identidad (Password Spraying, Fuerza Bruta, Alteraciones de MFA y Escalamiento).
"""

import os
import requests
import json
import traceback
from datetime import datetime, timedelta
from core import db_manager, clickhouse_manager

AUTHENTIK_URL = os.getenv("AUTHENTIK_INTERNAL_URL", os.getenv("AUTHENTIK_URL", "https://auth.example.internal"))

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
    # Normalize across the several shapes Authentik can send:
    #  - a raw Event ({"action": "login_failed", "user": {...}, "client_ip": "...", "context": {...}})
    #  - a generic-webhook Notification ({"body": "...", "severity": "...",
    #    "event_user_username": "...", ...})
    #  - a hand-crafted test payload ({"action"/"event", "username", "ip_address"})
    context = payload.get("context") or {}
    http_request = context.get("http_request") or {}

    event_type = (
        payload.get("action")
        or payload.get("event")
        or payload.get("event_action")
        or context.get("action")
        or ""
    )
    # Fall back to sniffing the rendered notification body when no structured action is present.
    if not event_type:
        body_txt = str(payload.get("body", "")).lower()
        if "login failed" in body_txt or "failed login" in body_txt or "invalid credentials" in body_txt:
            event_type = "login_failed"
        elif "mfa" in body_txt and ("remove" in body_txt or "delete" in body_txt):
            event_type = "mfa_device_delete"
        elif ("added to group" in body_txt or "group membership" in body_txt) and "admin" in body_txt:
            event_type = "group_add_admin"
        else:
            event_type = "desconocido"

    username = (
        (payload.get("user") or {}).get("username")
        or payload.get("username")
        or payload.get("event_user_username")
        or context.get("username")
        or (context.get("user") or {}).get("username")
        or "desconocido"
    )

    client_ip = (
        payload.get("client_ip")
        or payload.get("ip_address")
        or context.get("client_ip")
        or http_request.get("client_ip")
        or (context.get("geo") or {}).get("ip")
        or "0.0.0.0"
    )
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

        # >= 5 fallos en 60s para el mismo (usuario, IP). Un evento aislado, aunque el IdP lo
        # marque "critical", NO es fuerza bruta y no debe disparar respuesta autónoma.
        if len(recent) >= 5:
            confidence = 0.96 # Alta Confianza >= 95% -> elegible para respuesta autónoma (según política)
            alert = {
                "rule_name": "ITDR-AUTHENTIK-BRUTE-FORCE",
                "severity": "CRITICAL",
                "asset_name": f"Authentik-User ({username})",
                "alert_text": f"Detección ITDR: Ataque de Fuerza Bruta / Password Spraying desde IP {client_ip} contra la cuenta '{username}' ({len(recent)} intentos fallidos en 60s).",
                "confidence_score": confidence,
                "autonomous_action_executed": False
            }
            _apply_response(alert, client_ip, username)
            alerts_generated.append(alert)

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
        _apply_response(alert, client_ip, username)
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
            "autonomous_action_executed": False
        }
        _apply_response(alert, client_ip, username)
        alerts_generated.append(alert)

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
                INSERT INTO public.runtime_alerts (asset_id, rule_name, priority, alert_text, output_fields)
                VALUES (
                    (SELECT id FROM public.infra_inventory WHERE asset_name = %s LIMIT 1),
                    %s, %s, %s, %s::jsonb
                );
            """, (a["asset_name"], a["rule_name"], a["severity"], a["alert_text"],
                  json.dumps({"username": username, "client_ip": client_ip,
                              "confidence_score": a["confidence_score"],
                              "response_mode": a.get("response_mode")})))

    return {"processed": True, "alerts_count": len(alerts_generated), "alerts": alerts_generated}

def _apply_response(alert: dict, client_ip: str, username: str) -> None:
    """Route the detection through the policy-gated SOAR engine and record what REALLY happened
    (dry-run / manual / executed / failed) instead of claiming an action was taken."""
    from core import soar_engine  # lazy: soar_engine imports this module
    cti_hit = False
    try:
        from core import cti_feed
        cti_hit = client_ip in cti_feed.get_malicious_ips()
    except Exception:
        print("❌ [ITDR-Engine] CTI lookup failed; treating IP as not CTI-confirmed:")
        traceback.print_exc()
    result = soar_engine.evaluate_and_execute_response(
        alert["rule_name"], alert["asset_name"], client_ip, username,
        alert["confidence_score"], cti_hit=cti_hit, severity=alert["severity"])
    alert["autonomous_action_executed"] = bool(result["executed"])
    alert["response_mode"] = result["mode"]
    alert["response_detail"] = result["message"]


def revoke_authentik_user_sessions(username: str) -> dict:
    """
    Terminate the user's ACTIVE SESSIONS in Authentik (DELETE core/authenticated_sessions).

    Deliberately does NOT deactivate the account: deactivation is an account-lockout DoS
    primitive (an attacker who can provoke failed logins could disable any user, admins included).
    Returns {"status": "revoked" | "no_credentials" | "user_not_found" | "api_error", "revoked_count": n}.
    Requires AUTHENTIK_API_TOKEN (a real API token; the OAuth client secret is NOT accepted).
    """
    token = os.getenv("AUTHENTIK_API_TOKEN", "")
    if not token:
        print(f"⚠️ [ITDR-Engine] No se pudo revocar sesiones de {username}: AUTHENTIK_API_TOKEN no está configurado.")
        return {"status": "no_credentials", "revoked_count": 0}
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base = f"{AUTHENTIK_URL}/api/v3/core"
    try:
        r = requests.get(f"{base}/users/", params={"username": username}, headers=headers, verify=False, timeout=10)
        if r.status_code != 200:
            print(f"❌ [ITDR-Engine] Authentik user lookup HTTP {r.status_code}: {r.text[:200]}")
            return {"status": "api_error", "revoked_count": 0}
        users = r.json().get("results", [])
        if not users:
            return {"status": "user_not_found", "revoked_count": 0}
        user_pk = users[0]["pk"]
        s = requests.get(f"{base}/authenticated_sessions/", params={"user__id": user_pk}, headers=headers, verify=False, timeout=10)
        if s.status_code != 200:
            print(f"❌ [ITDR-Engine] Authentik sessions lookup HTTP {s.status_code}: {s.text[:200]}")
            return {"status": "api_error", "revoked_count": 0}
        revoked = 0
        for sess in s.json().get("results", []):
            d = requests.delete(f"{base}/authenticated_sessions/{sess['uuid']}/", headers=headers, verify=False, timeout=10)
            if d.status_code in (200, 204):
                revoked += 1
            else:
                print(f"❌ [ITDR-Engine] Could not delete session {sess.get('uuid')}: HTTP {d.status_code}")
        print(f"🔒 [ITDR-Engine] {revoked} sesión(es) de '{username}' revocadas en Authentik.")
        return {"status": "revoked", "revoked_count": revoked}
    except Exception:
        print(f"❌ [ITDR-Engine] Error revocando sesiones de {username}:")
        traceback.print_exc()
        return {"status": "api_error", "revoked_count": 0}
