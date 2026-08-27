"""
Item 4 (2026-08-27): unified autonomous-action ledger.

Before this, "what has the AI actually done" was scattered across remediation_history rows,
free-text log lines, and -- for most background loops -- nothing at all. KIO's "The Rock"
agentic SOC headlines "30,000+ autonomous actions" as an accountability figure; Centinela had
no single queryable record of its own agent activity to show, audit, or measure MTTR against.

record_action() is the single write path. Every autonomous step that changes state (AI
correlation, GitLab auto-fix MR, orphaned-container reap, threat-intel enrichment pass, CTI
block, analyst suppression) calls it. It NEVER raises: a ledger write failing must not break
the real work it is only recording. Per Rule #6 the failure is still logged with a full
traceback -- never a silent `pass`.
"""
import json
import traceback
from typing import Optional

from core import db_manager

# Canonical action_type values, kept here so call sites and the dashboard agree on spelling.
ACTION_AI_CORRELATION      = "ai_correlation"
ACTION_AI_CORRELATION_FAIL = "ai_correlation_failed"
ACTION_GITLAB_AUTOFIX_MR   = "gitlab_autofix_mr"
ACTION_MR_REVIEW           = "mr_review"
ACTION_ZAP_REAP            = "zap_container_reap"
ACTION_THREAT_INTEL_ENRICH = "threat_intel_enrichment"
ACTION_CTI_BLOCK           = "cti_ip_block"
ACTION_SUPPRESSION_CREATED = "suppression_created"
ACTION_FINDING_SUPPRESSED  = "finding_suppressed"
ACTION_HOST_CONTAINMENT    = "host_containment_request"
ACTION_INCIDENT_CORRELATION = "incident_correlation"

VALID_OUTCOMES = {"success", "failed", "skipped", "pending_approval"}


def record_action(action_type: str, summary: str, *, outcome: str = "success",
                  actor: str = "centinela-ai", entity_type: Optional[str] = None,
                  entity_id: Optional[int] = None, asset_id: Optional[int] = None,
                  detail: Optional[dict] = None, evidence: Optional[str] = None,
                  cur=None) -> Optional[int]:
    """
    Insert one ledger row.

    cur: if given, the caller owns the transaction and this write joins it (use inside an
         already-open get_db_cursor() block so the ledger row commits/rolls back atomically
         with the state change it describes). If None, a short-lived own cursor is opened and
         committed independently.

    Returns the new row id, or None on any failure (never raises).
    """
    if outcome not in VALID_OUTCOMES:
        outcome = "success"

    params = (
        action_type, actor, entity_type, entity_id, asset_id, summary,
        json.dumps(detail, default=str) if detail is not None else None, evidence, outcome,
    )
    sql = """
        INSERT INTO public.agent_actions
        (action_type, actor, entity_type, entity_id, asset_id, summary, detail, evidence, outcome)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """
    try:
        if cur is not None:
            cur.execute(sql, params)
            row = cur.fetchone()
            return row[0] if row else None
        with db_manager.get_db_cursor() as own:
            if own is None:
                return None
            own.execute(sql, params)
            row = own.fetchone()
            return row[0] if row else None
    except Exception:
        print(f"⚠️ [AgentLedger] Failed to record action {action_type!r} -- swallowed to protect caller:")
        traceback.print_exc()
        return None
