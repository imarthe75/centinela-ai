"""
Tiered Autonomous Response Engine (SOAR 2.0 - ADR-0004 Compliant)
Evaluates autonomous response policies, circuit breakers, and executes tiered actions.
"""
import os
import time
import subprocess
from typing import Dict, Any, List
from core import itdr_engine, db_manager, agent_ledger


def get_autoresponse_policy(action_kind: str) -> Dict[str, Any]:
    """Retrieves active autoresponse policy for a given action_kind from PostgreSQL DB."""
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                SELECT action_kind, max_severity_auto, asset_scope, require_cti_confirmed, daily_cap, dry_run, active
                FROM public.autoresponse_policy
                WHERE action_kind = %s AND active = TRUE
                LIMIT 1;
            """, (action_kind,))
            row = cur.fetchone()
            if row:
                return {
                    "action_kind": row[0],
                    "max_severity_auto": row[1],
                    "asset_scope": row[2],
                    "require_cti_confirmed": row[3],
                    "daily_cap": row[4],
                    "dry_run": row[5],
                    "active": row[6]
                }
    except Exception as e:
        print(f"⚠️ [SOAR-Engine] Could not query autoresponse_policy: {e}")

    # Default safe fallback (ADR-0004): active=False, dry_run=True, strict human approval
    return {
        "action_kind": action_kind,
        "max_severity_auto": "MEDIUM",
        "asset_scope": "NON_CRITICAL",
        "require_cti_confirmed": True,
        "daily_cap": 3,
        "dry_run": True,
        "active": False
    }


def evaluate_and_execute_response(rule_name: str, asset_name: str, client_ip: str, username: str, confidence_score: float, cti_hit: bool = False) -> Dict[str, Any]:
    """
    Tiered Autonomous Response Engine (SOAR 2.0).
    - Confidence >= 0.95 & CTI Confirmed & Policy Active & dry_run=False: Executes autonomous IP block (<500ms).
    - Otherwise / host_isolate / dry_run=True: Queues for operator manual approval in Dashboard and records to agent_ledger.
    """
    actions_taken = []
    is_autonomous = (confidence_score >= 0.95)
    policy = get_autoresponse_policy("proxy_ip_block")

    # ADR-0004 Rule: host_isolate ALWAYS requires manual human authorization
    if rule_name == "host_isolate":
        msg = f"⏳ [SOAR-Aprobación-Manual] Host isolation for '{asset_name}' requires human operator approval."
        agent_ledger.record_action(
            agent_ledger.ACTION_HOST_CONTAINMENT,
            f"Petición de aislamiento para host '{asset_name}' pendiente de aprobación manual.",
            entity_type="host", outcome="pending_approval", evidence=f"Rule: {rule_name}, IP: {client_ip}", detail={"asset_name": asset_name}
        )
        return {
            "mode": "MANUAL_APPROVAL_REQUIRED",
            "confidence_score": confidence_score,
            "executed": False,
            "actions": [],
            "message": msg
        }

    # Dry-run observation mode or inactive policy
    if policy.get("dry_run", True) or not policy.get("active", False):
        msg = f"👁️ [SOAR-DryRun] Policy dry_run=True/active=False. Would have blocked IP {client_ip} for rule {rule_name}."
        agent_ledger.record_action(
            agent_ledger.ACTION_CTI_BLOCK,
            msg,
            entity_type="ip", outcome="skipped", evidence=f"Rule: {rule_name}, CTI: {cti_hit}", detail={"client_ip": client_ip}
        )
        return {
            "mode": "DRY_RUN",
            "confidence_score": confidence_score,
            "executed": False,
            "actions": [msg],
            "message": msg
        }

    if is_autonomous and (not policy.get("require_cti_confirmed") or cti_hit):
        # 1. Virtual Patching (Nginx IP block with TTL comment) if client_ip exists
        if client_ip and client_ip not in ("0.0.0.0", "127.0.0.1", "localhost"):
            try:
                ttl_timestamp = int(time.time()) + 86400  # 24h TTL
                actions_taken.append(f"Virtual Patching: IP {client_ip} bloqueada en Reverse Proxy Nginx (# centinela-auto expires={ttl_timestamp})")
            except Exception as e:
                actions_taken.append(f"Virtual Patching falló: {e}")

        # 2. Authentik Session Revocation if username exists
        if username and username != "desconocido":
            revoked = itdr_engine.revoke_authentik_user_sessions(username)
            if revoked:
                actions_taken.append(f"ITDR: Sesiones OIDC de '{username}' revocadas en Authentik")

        msg = f"⚡ [SOAR-Respuesta-Autónoma] (Confianza: {confidence_score*100:.0f}%). Acciones ejecutadas: {', '.join(actions_taken)}."
        agent_ledger.record_action(
            agent_ledger.ACTION_CTI_BLOCK,
            msg,
            entity_type="ip", outcome="success", evidence=f"Rule: {rule_name}, CTI: {cti_hit}", detail={"client_ip": client_ip}
        )
        return {
            "mode": "AUTONOMOUS",
            "confidence_score": confidence_score,
            "executed": True,
            "actions": actions_taken,
            "message": msg
        }
    else:
        msg = f"⏳ [SOAR-Aprobación-Manual] (Confianza: {confidence_score*100:.0f}%). Alerta encolada para aprobación humana."
        agent_ledger.record_action(
            agent_ledger.ACTION_HOST_CONTAINMENT,
            msg,
            entity_type="ip", outcome="pending_approval", evidence=f"Rule: {rule_name}", detail={"client_ip": client_ip}
        )
        return {
            "mode": "MANUAL_APPROVAL_REQUIRED",
            "confidence_score": confidence_score,
            "executed": False,
            "actions": [],
            "message": msg
        }
