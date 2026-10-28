"""
Tiered autonomous response engine (SOAR 2.0 -- ADR-0004).

A *policy layer* over the execution channel that already exists (Sentinel + Ansible, with the
target asset's real credentials). Nothing here shells out or "pretends": an autonomous
`proxy_ip_block` is a pre-approved remediation row that Sentinel really executes; a
`session_revoke` is a real Authentik API call. Everything else is manual or dry-run.

Guard rails (all evaluated BEFORE dry-run, so the ledger shows what would really happen):
  * host_isolate NEVER auto-executes (ADR-0004).
  * policy row must exist and be active; dry_run defaults to TRUE (observation mode).
  * confidence >= 0.95, CTI-confirmed when the policy requires it.
  * a blocked IP must be public (never RFC1918/loopback/reserved), never one of our own assets'
    IPs, never in SOAR_NEVER_BLOCK; a session-revoke target must not be a protected account.
  * per-kind daily cap; every block carries a TTL and is lifted by reap_expired_ip_blocks().
"""
import ipaddress
import os
import re
import time
import traceback
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core import agent_ledger, db_manager, itdr_engine

KIND_PROXY_IP_BLOCK = "proxy_ip_block"
KIND_SESSION_REVOKE = "session_revoke"
KIND_HOST_ISOLATE = "host_isolate"
KNOWN_KINDS = (KIND_PROXY_IP_BLOCK, KIND_SESSION_REVOKE, KIND_HOST_ISOLATE)

AUTONOMY_MIN_CONFIDENCE = 0.95
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
BLOCK_TTL_SECONDS = int(os.getenv("SOAR_BLOCK_TTL_SECONDS", "86400"))


def _default_policy(kind: str) -> Dict[str, Any]:
    """Safe fallback when no policy row exists / DB unreachable: inactive, dry-run, strict."""
    return {"action_kind": kind, "max_severity_auto": "MEDIUM", "asset_scope": "NON_CRITICAL",
            "require_cti_confirmed": True, "daily_cap": 3, "dry_run": True, "active": False}


def get_autoresponse_policy(action_kind: str) -> Dict[str, Any]:
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                SELECT action_kind, max_severity_auto, asset_scope, require_cti_confirmed, daily_cap, dry_run, active
                FROM public.autoresponse_policy WHERE action_kind = %s LIMIT 1
            """, (action_kind,))
            row = cur.fetchone()
        if row:
            return {"action_kind": row[0], "max_severity_auto": row[1], "asset_scope": row[2],
                    "require_cti_confirmed": row[3], "daily_cap": row[4], "dry_run": row[5], "active": row[6]}
    except Exception:
        print(f"❌ [SOAR-Engine] Could not read autoresponse_policy for {action_kind!r}; using safe default:")
        traceback.print_exc()
    return _default_policy(action_kind)


# --------------------------------------------------------------------------- guards
def _never_block_networks() -> List[Any]:
    nets = []
    for tok in os.getenv("SOAR_NEVER_BLOCK", "").split(","):
        tok = tok.strip()
        if tok:
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                print(f"⚠️ [SOAR-Engine] Ignoring invalid SOAR_NEVER_BLOCK entry {tok!r}")
    return nets


def is_blockable_ip(ip: str) -> Tuple[bool, str]:
    """A block may only ever target a public address that is not ours."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False, "invalid_ip"
    if not addr.is_global:
        return False, "not_a_public_ip"
    for net in _never_block_networks():
        if addr in net:
            return False, "in_SOAR_NEVER_BLOCK"
    try:
        pattern = re.compile(r"(?<![0-9.])" + re.escape(str(addr)) + r"(?![0-9])")
        with db_manager.get_db_cursor() as cur:
            cur.execute("SELECT endpoint FROM public.infra_inventory WHERE endpoint IS NOT NULL")
            if any(pattern.search(row[0] or "") for row in cur.fetchall()):
                return False, "is_own_asset"
    except Exception:
        print("❌ [SOAR-Engine] Could not check own-asset IPs; refusing to block (fail-safe):")
        traceback.print_exc()
        return False, "own_asset_check_failed"
    return True, "ok"


def is_protected_user(username: str) -> bool:
    protected = {u.strip().lower() for u in os.getenv("SOAR_PROTECTED_USERS", "akadmin,admin,root").split(",") if u.strip()}
    return (username or "").strip().lower() in protected


def _executed_today(kind: str) -> int:
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                SELECT count(*) FROM public.agent_actions
                WHERE action_type = %s AND outcome IN ('success', 'pending_approval') AND detail->>'kind' = %s
                  AND detail->>'phase' = 'executed' AND created_at >= date_trunc('day', NOW())
            """, (agent_ledger.ACTION_SOAR_AUTORESPONSE, kind))
            return cur.fetchone()[0]
    except Exception:
        print("❌ [SOAR-Engine] Could not read the daily action count; treating cap as reached (fail-safe):")
        traceback.print_exc()
        return 10 ** 9


# --------------------------------------------------------------------------- execution
def _resolve_proxy_asset(asset_name: str) -> Optional[Dict[str, Any]]:
    """The asset whose reverse proxy receives the deny rule: SOAR_PROXY_ASSET, else the alert's asset."""
    candidates = [c for c in (os.getenv("SOAR_PROXY_ASSET", ""), asset_name) if c]
    with db_manager.get_db_cursor() as cur:
        for name in candidates:
            cur.execute("SELECT id, asset_name, endpoint, asset_type FROM public.infra_inventory WHERE asset_name = %s LIMIT 1", (name,))
            row = cur.fetchone()
            if row:
                return {"id": row[0], "asset_name": row[1], "endpoint": row[2], "asset_type": row[3]}
    return None


def _queue_remediation(cur, asset: Dict[str, Any], cve_id: str, severity: str, description: str,
                       url_path: str, script: str) -> Tuple[int, int]:
    """Create/refresh the finding + a PRE-APPROVED remediation row; Sentinel executes it."""
    from core import deduplication_engine
    _, vuln_id = deduplication_engine.log_finding_deduplicated(
        cur, asset["id"], cve_id, severity, description, "soar-autoresponse",
        url_path=url_path, open_status="CORRELATED", preserve_status=True)
    script_path = f"/app/data/remediation/{cve_id}_{vuln_id}.sh"
    os.makedirs(os.path.dirname(script_path), exist_ok=True)
    with open(script_path, "w") as fh:
        fh.write(script)
    cur.execute("SELECT id FROM public.remediation_history WHERE vuln_id = %s LIMIT 1", (vuln_id,))
    row = cur.fetchone()
    if row:
        cur.execute("""UPDATE public.remediation_history
                       SET script_path = %s, approval_token = 'APPROVED', can_automate = 'true', executed_bool = FALSE
                       WHERE id = %s""", (script_path, row[0]))
        return vuln_id, row[0]
    cur.execute("""INSERT INTO public.remediation_history (vuln_id, script_path, approval_token, can_automate)
                   VALUES (%s, %s, 'APPROVED', 'true') RETURNING id""", (vuln_id, script_path))
    return vuln_id, cur.fetchone()[0]


def _queue_ip_block(asset_name: str, ip: str, rule_name: str) -> Dict[str, Any]:
    from core.ip_block_script import generate_ip_block_virtual_patch
    asset = _resolve_proxy_asset(asset_name)
    if not asset:
        return {"ok": False, "reason": "no_proxy_asset (set SOAR_PROXY_ASSET to an inventory asset name)"}
    expires_ts = int(time.time()) + BLOCK_TTL_SECONDS
    cve_id = f"CTI-IOC-MATCH-SOAR-{ip}"
    desc = (f"Bloqueo temporal autónomo (SOAR) de {ip} por regla {rule_name}. "
            f"Expira {datetime.utcfromtimestamp(expires_ts).isoformat()}Z.")
    vuln = {"asset_name": asset["asset_name"], "endpoint": asset["endpoint"], "cve_id": cve_id}
    script = generate_ip_block_virtual_patch(vuln, ip, f"Regla {rule_name} (SOAR, TTL {BLOCK_TTL_SECONDS}s)", expires_ts=expires_ts)
    with db_manager.get_db_cursor() as cur:
        vuln_id, rem_id = _queue_remediation(cur, asset, cve_id, "HIGH", desc, ip, script)
        cur.execute("""INSERT INTO public.soar_ip_blocks (ip, asset_id, vuln_id, remediation_id, rule_name, expires_at)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (ip, asset["id"], vuln_id, rem_id, rule_name, datetime.utcfromtimestamp(expires_ts)))
    return {"ok": True, "asset": asset["asset_name"], "vuln_id": vuln_id, "remediation_id": rem_id, "expires_ts": expires_ts}


def reap_expired_ip_blocks() -> Dict[str, int]:
    """Lift blocks SOAR added once their TTL passes -- through the same Sentinel channel."""
    from core.ip_block_script import generate_ip_unblock_script
    stats = {"unblock_queued": 0, "unblocked": 0, "never_applied": 0}
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("""
                SELECT b.id, b.ip, b.asset_id, rb.approval_token, b.unblock_remediation_id, ru.approval_token,
                       i.asset_name, i.endpoint, b.expires_at < NOW()
                FROM public.soar_ip_blocks b
                JOIN public.infra_inventory i ON i.id = b.asset_id
                LEFT JOIN public.remediation_history rb ON rb.id = b.remediation_id
                LEFT JOIN public.remediation_history ru ON ru.id = b.unblock_remediation_id
                WHERE b.unblocked_at IS NULL
            """)
            rows = cur.fetchall()
            for bid, ip, asset_id, block_state, unblock_rem, unblock_state, aname, aendpoint, expired in rows:
                if unblock_rem:
                    if unblock_state == "COMPLETED":
                        cur.execute("UPDATE public.soar_ip_blocks SET unblocked_at = NOW() WHERE id = %s", (bid,))
                        stats["unblocked"] += 1
                    continue
                if not expired:
                    continue
                if block_state != "COMPLETED":
                    # The deny rule was never applied (Sentinel failed/never ran): nothing to lift.
                    if block_state in ("FAILED", "REJECTED"):
                        cur.execute("UPDATE public.soar_ip_blocks SET unblocked_at = NOW() WHERE id = %s", (bid,))
                        stats["never_applied"] += 1
                    continue
                asset = {"id": asset_id, "asset_name": aname, "endpoint": aendpoint}
                script = generate_ip_unblock_script({"asset_name": aname, "endpoint": aendpoint}, ip)
                uv, ur = _queue_remediation(cur, asset, f"CTI-IOC-UNBLOCK-SOAR-{ip}", "LOW",
                                            f"Expiración del bloqueo temporal SOAR de {ip}.", ip, script)
                cur.execute("UPDATE public.soar_ip_blocks SET unblock_vuln_id = %s, unblock_remediation_id = %s WHERE id = %s",
                            (uv, ur, bid))
                stats["unblock_queued"] += 1
    except Exception:
        print("❌ [SOAR-Engine] reap_expired_ip_blocks failed:")
        traceback.print_exc()
    return stats


# --------------------------------------------------------------------------- decision
def _ledger(kind: str, outcome: str, phase: str, summary: str, asset_name: str, extra: Dict[str, Any]) -> None:
    agent_ledger.record_action(
        agent_ledger.ACTION_SOAR_AUTORESPONSE, summary, outcome=outcome,
        entity_type="response", detail={"kind": kind, "phase": phase, "asset_name": asset_name, **extra})


def _evaluate_kind(kind: str, rule_name: str, asset_name: str, client_ip: str, username: str,
                   confidence: float, cti_hit: bool, severity: str) -> Dict[str, Any]:
    base = {"kind": kind, "executed": False}
    if kind == KIND_HOST_ISOLATE:
        msg = f"Aislamiento de '{asset_name}' requiere aprobación humana (ADR-0004)."
        _ledger(kind, "pending_approval", "manual", msg, asset_name, {"rule": rule_name})
        return {**base, "mode": "MANUAL_APPROVAL_REQUIRED", "message": msg}

    policy = get_autoresponse_policy(kind)
    manual = lambda why: (_ledger(kind, "pending_approval", "manual", f"{kind}: {why}", asset_name,  # noqa: E731
                                  {"rule": rule_name, "reason": why}),
                          {**base, "mode": "MANUAL_APPROVAL_REQUIRED", "message": f"{kind}: {why}"})[1]

    if not policy["active"]:
        return manual("política inactiva")
    if confidence < AUTONOMY_MIN_CONFIDENCE:
        return manual(f"confianza {confidence:.2f} < {AUTONOMY_MIN_CONFIDENCE}")
    if _SEVERITY_RANK.get(severity.upper(), 3) > _SEVERITY_RANK.get((policy["max_severity_auto"] or "CRITICAL").upper(), 4):
        return manual(f"severidad {severity} supera el máximo autónomo {policy['max_severity_auto']}")

    target = ""
    if kind == KIND_PROXY_IP_BLOCK:
        ok, why = is_blockable_ip(client_ip)
        if not ok:
            return manual(f"IP no bloqueable ({why})")
        if policy["require_cti_confirmed"] and not cti_hit:
            return manual("IP sin confirmación CTI")
        target = client_ip
    elif kind == KIND_SESSION_REVOKE:
        if not username or username == "desconocido":
            return manual("usuario desconocido")
        if is_protected_user(username):
            return manual(f"cuenta protegida '{username}'")
        target = username

    if _executed_today(kind) >= policy["daily_cap"]:
        return manual(f"tope diario ({policy['daily_cap']}) alcanzado")

    if policy["dry_run"]:
        msg = f"[DRY-RUN] {kind} sobre '{target}' se habría ejecutado (regla {rule_name}, confianza {confidence:.2f})."
        _ledger(kind, "skipped", "dry_run", msg, asset_name, {"rule": rule_name, "target": target})
        return {**base, "mode": "DRY_RUN", "message": msg, "target": target}

    try:
        if kind == KIND_PROXY_IP_BLOCK:
            res = _queue_ip_block(asset_name, client_ip, rule_name)
            if not res["ok"]:
                _ledger(kind, "failed", "executed", f"No se pudo encolar el bloqueo: {res['reason']}", asset_name, {"rule": rule_name})
                return {**base, "mode": "FAILED", "message": res["reason"]}
            msg = (f"Bloqueo de {client_ip} pre-aprobado por política y encolado a Sentinel sobre "
                   f"'{res['asset']}' (expira en {BLOCK_TTL_SECONDS}s).")
            _ledger(kind, "success", "executed", msg, asset_name, {"rule": rule_name, "target": target, **res})
            return {**base, "mode": "AUTONOMOUS", "executed": True, "message": msg, "target": target, **res}
        res = itdr_engine.revoke_authentik_user_sessions(username)
        if res["status"] != "revoked":
            _ledger(kind, "failed", "executed", f"Revocación no completada: {res['status']}", asset_name, {"rule": rule_name, **res})
            return {**base, "mode": "FAILED", "message": res["status"], "target": target, **res}
        msg = f"{res['revoked_count']} sesión(es) de '{username}' revocadas en Authentik."
        _ledger(kind, "success", "executed", msg, asset_name, {"rule": rule_name, "target": target, **res})
        return {**base, "mode": "AUTONOMOUS", "executed": True, "message": msg, "target": target, **res}
    except Exception as e:
        print(f"❌ [SOAR-Engine] {kind} execution failed:")
        traceback.print_exc()
        _ledger(kind, "failed", "executed", f"Excepción ejecutando {kind}: {e}", asset_name, {"rule": rule_name})
        return {**base, "mode": "FAILED", "message": str(e)}


def default_kinds_for_rule(rule_name: str) -> Sequence[str]:
    r = (rule_name or "").lower()
    if r in KNOWN_KINDS:
        return (r,)
    if "privilege" in r or "mfa" in r:
        return (KIND_SESSION_REVOKE,)
    return (KIND_PROXY_IP_BLOCK,)


def evaluate_and_execute_response(rule_name: str, asset_name: str, client_ip: str, username: str,
                                  confidence_score: float, cti_hit: bool = False,
                                  severity: str = "HIGH", kinds: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Decide (and, if policy allows, dispatch) the tiered response for one detection."""
    kinds = tuple(kinds) if kinds else tuple(default_kinds_for_rule(rule_name))
    results = [_evaluate_kind(k, rule_name, asset_name, client_ip, username, float(confidence_score), bool(cti_hit), severity)
               for k in kinds]
    modes = [r["mode"] for r in results]
    if "AUTONOMOUS" in modes:
        mode = "AUTONOMOUS"
    elif "FAILED" in modes:
        mode = "FAILED"
    elif "DRY_RUN" in modes:
        mode = "DRY_RUN"
    else:
        mode = "MANUAL_APPROVAL_REQUIRED"
    return {
        "mode": mode,
        "confidence_score": confidence_score,
        "executed": any(r["executed"] for r in results),
        "actions": [r["message"] for r in results],
        "message": " | ".join(r["message"] for r in results),
        "results": results,
    }
