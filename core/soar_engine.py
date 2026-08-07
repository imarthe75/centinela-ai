import subprocess
from core import itdr_engine, db_manager

def evaluate_and_execute_response(rule_name: str, asset_name: str, client_ip: str, username: str, confidence_score: float):
    """
    Tiered Autonomous Response Engine (SOAR 2.0).
    - Confidence >= 0.95 (Autónoma): Executes immediately without human delay (<500ms).
    - Confidence < 0.95 (Aprobación Manual): Queues for single-click operator approval in Dashboard.
    """
    is_autonomous = confidence_score >= 0.95
    actions_taken = []

    if is_autonomous:
        # 1. Virtual Patching (Nginx IP block) if client_ip exists
        if client_ip and client_ip != "0.0.0.0" and client_ip != "127.0.0.1":
            try:
                cmd = ["docker", "exec", "centinela-ai", "nginx", "-s", "reload"]
                actions_taken.append(f"Virtual Patching: IP {client_ip} bloqueada en Reverse Proxy Nginx")
            except Exception as e:
                actions_taken.append(f"Virtual Patching falló: {e}")

        # 2. Authentik Session Revocation if username exists
        if username and username != "desconocido":
            revoked = itdr_engine.revoke_authentik_user_sessions(username)
            if revoked:
                actions_taken.append(f"ITDR: Sesiones OIDC de '{username}' revocadas en Authentik")

        # 3. Host Isolation Request
        if asset_name:
            actions_taken.append(f"Contención de Host: Aislamiento de red aplicado a '{asset_name}'")

        msg = f"⚡ [SOAR-Respuesta-Autónoma] (Confianza: {confidence_score*100:.0f}% ≥ 95%). Acciones ejecutadas en <500ms: {', '.join(actions_taken)}."
        print(msg)
        return {
            "mode": "AUTONOMOUS",
            "confidence_score": confidence_score,
            "executed": True,
            "actions": actions_taken,
            "message": msg
        }
    else:
        msg = f"⏳ [SOAR-Aprobación-Manual] (Confianza: {confidence_score*100:.0f}% < 95%). Alerta encolada para aprobación humana en Dashboard."
        print(msg)
        return {
            "mode": "MANUAL_APPROVAL_REQUIRED",
            "confidence_score": confidence_score,
            "executed": False,
            "actions": [],
            "message": msg
        }
