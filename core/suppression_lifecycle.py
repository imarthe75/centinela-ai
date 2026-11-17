"""
Lifecycle of finding suppressions (ADR-0022 §1): an accepted risk is a decision with an owner and an end date, not a
permanent mute.

Two gaps this closes, both measured in the code on 2026-11-12:
  * `ACCEPTED_RISK` could be created with no `expires_at`, i.e. accepted forever.
  * When a suppression expired or was deactivated (`DELETE /api/suppressions/{id}`), the findings it had parked in
    `SUPPRESSED` stayed there for good: `log_finding_deduplicated(preserve_status=True)` leaves any status it does not
    own untouched, so a re-detection never brought them back. The expiry date was cosmetic.

Rules:
  * `validate_expiry(scope, expires_at)` -- ACCEPTED_RISK requires an expiry no more than `ACCEPTED_RISK_MAX_DAYS`
    (365 by default) in the future; WONT_FIX is a permanent product decision and FALSE_POSITIVE is a fact about the code,
    so for those an expiry stays optional.
  * `release_findings(cur, suppression_ids)` -- findings parked by those suppressions go back to `OPEN` unless another
    active, unexpired suppression still covers them. They keep their previous AI analysis (nothing is re-sent to a
    provider); the next scan reconciles them like any open finding.
  * `expire_due(cur)` -- deactivates every suppression whose `expires_at` passed and releases its findings. Run by the
    periodic loop (workers/periodic.run_soar_expiry_loop).
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

ACCEPTED_RISK_MAX_DAYS = int(os.getenv("ACCEPTED_RISK_MAX_DAYS", "365"))


class SuppressionPolicyError(ValueError):
    """A suppression request that breaks the lifecycle policy (mapped to HTTP 400 by the API)."""


def _parse_ts(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        ts = value
    else:
        try:
            ts = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise SuppressionPolicyError(f"expires_at no es una fecha ISO-8601 válida: {value!r}") from exc
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def validate_expiry(scope: str, expires_at: Any, now: Optional[datetime] = None) -> Optional[datetime]:
    """Returns the normalized expiry (UTC-aware) or None; raises SuppressionPolicyError when the policy is broken."""
    now = now or datetime.now(timezone.utc)
    ts = _parse_ts(expires_at)
    if ts is not None and ts <= now:
        raise SuppressionPolicyError("expires_at debe estar en el futuro.")
    if str(scope or "").upper() == "ACCEPTED_RISK":
        if ts is None:
            raise SuppressionPolicyError(
                "Un riesgo aceptado necesita fecha de vencimiento (expires_at): al vencer, los hallazgos vuelven a abrirse "
                f"para decidir de nuevo. Máximo {ACCEPTED_RISK_MAX_DAYS} días.")
        if ts > now + timedelta(days=ACCEPTED_RISK_MAX_DAYS):
            raise SuppressionPolicyError(f"Un riesgo aceptado no puede durar más de {ACCEPTED_RISK_MAX_DAYS} días.")
    return ts


def release_findings(cur, suppression_ids: Iterable[Any]) -> List[str]:
    """Reopens the SUPPRESSED findings matched by these (already inactive or expired) suppressions, unless another active
    suppression still covers each one. Returns the reopened finding ids."""
    from core import deduplication_engine
    ids = [str(i) for i in suppression_ids if i]
    if not ids:
        return []
    cur.execute("""
        SELECT DISTINCT v.id, v.asset_id, v.cve_id, v.fingerprint_hash, COALESCE(v.url_path, v.description)
        FROM public.finding_suppressions s
        JOIN public.vulnerability_log v
          ON v.status = 'SUPPRESSED'
         AND (s.asset_id IS NULL OR v.asset_id IS NOT DISTINCT FROM s.asset_id)
         AND (s.cve_id IS NULL OR v.cve_id = s.cve_id)
         AND (s.fingerprint_hash IS NULL OR v.fingerprint_hash = s.fingerprint_hash)
         AND (s.url_path_pattern IS NULL OR COALESCE(v.url_path, v.description, '') LIKE s.url_path_pattern)
        WHERE s.id = ANY(%s::uuid[])
    """, (ids,))
    reopened: List[str] = []
    for vid, asset_id, cve_id, fp, loc in cur.fetchall():
        if deduplication_engine.find_active_suppression(cur, asset_id, cve_id, fp, loc):
            continue
        cur.execute("UPDATE public.vulnerability_log SET status = 'OPEN' WHERE id = %s AND status = 'SUPPRESSED'", (vid,))
        if cur.rowcount:
            reopened.append(str(vid))
    return reopened


def expire_due(cur) -> Dict[str, int]:
    """Deactivates suppressions past their expiry and reopens what they were hiding."""
    cur.execute("""
        UPDATE public.finding_suppressions SET active = FALSE
        WHERE active = TRUE AND expires_at IS NOT NULL AND expires_at <= NOW()
        RETURNING id
    """)
    expired = [r[0] for r in cur.fetchall()]
    reopened = release_findings(cur, expired)
    return {"expired": len(expired), "reopened": len(reopened)}
