"""
Centinela Omni-XDR 2.0 - Deduplication, Risk Scoring & SLA Management Engine
Inspired by DefectDojo, Vicarius vRx, and Aikido Security.
"""
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

def calculate_fingerprint(asset_id: Any, cve_id: str, location_or_desc: str) -> str:
    """
    Generates a deterministic fingerprint hash to deduplicate findings
    across multiple scanners (Nuclei, Semgrep, Grype, ZAP, etc.).
    """
    normalized_cve = str(cve_id or '').strip().upper()
    normalized_loc = str(location_or_desc or '').strip().lower()[:120]
    raw = f"{asset_id}:{normalized_cve}:{normalized_loc}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]

def get_sla_delta(severity: str) -> timedelta:
    """
    Maps severity to its SLA remediation window.
    - CRITICAL: 24 hours
    - HIGH: 7 days
    - MEDIUM: 30 days
    - LOW / INFO: 90 days
    """
    sev = str(severity or '').upper()

    if sev in ('CRITICAL', 'CRÍTICO'):
        return timedelta(hours=24)
    elif sev in ('HIGH', 'ALTO'):
        return timedelta(days=7)
    elif sev in ('MEDIUM', 'MEDIO'):
        return timedelta(days=30)
    else:
        return timedelta(days=90)

def calculate_sla_due_date(severity: str, detected_at: Optional[datetime] = None) -> datetime:
    """Calculates SLA remediation deadline based on severity, relative to detected_at (or now)."""
    start_time = detected_at or datetime.utcnow()
    return start_time + get_sla_delta(severity)

def calculate_centinela_risk_score(cvss_score: float, epss_score: float, is_cisa_kev: bool, asset_criticality: float = 1.0) -> float:
    """
    Calculates Centinela Risk Score (CRS 0 - 100) combining CVSS, EPSS, CISA KEV, and Asset Weight.
    Formula:
      Base CVSS Weight (40%) + EPSS Probability (30%) + CISA KEV Exploited Boost (20%) + Asset Weight (10%)
    """
    cvss_component = (min(max(cvss_score, 0.0), 10.0) / 10.0) * 40.0
    epss_component = (min(max(epss_score, 0.0), 1.0)) * 30.0
    kev_component = 20.0 if is_cisa_kev else 0.0
    asset_component = (min(max(asset_criticality, 0.5), 2.0) / 2.0) * 10.0

    total_score = cvss_component + epss_component + kev_component + asset_component
    return round(min(total_score, 100.0), 1)

def is_sla_breached(sla_due_date: Optional[datetime]) -> bool:
    if not sla_due_date:
        return False
    return datetime.utcnow() > sla_due_date


def log_finding_deduplicated(cur, asset_id: int, cve_id: str, severity: str, description: str,
                              scan_engine: str, url_path: Optional[str] = None,
                              open_status: str = "OPEN",
                              reachability_status: Optional[str] = None,
                              preserve_status: bool = False) -> "tuple[str, int]":
    """
    Central, cross-tool-aware finding logger. calculate_fingerprint() existed since this
    module's original commit but nothing ever called it -- fingerprint_hash was empty on every
    row in production. This is the real wiring, modeled on DefectDojo's documented dedup
    approach (prefer an exact match, fall back to a broader one) extended with an actual
    cross-tool merge, which per-engine dedup (each auditor only ever checked its own previous
    rows) never provided: if Nuclei and the native SCA engine both independently flag the same
    real CVE on the same asset, per-engine dedup alone creates two separate tickets for the same
    underlying vulnerability.

    Three tiers, in order:
      1. Same fingerprint (asset + cve_id + location) already open, from ANY engine -> this is
         the same finding being re-detected (e.g. a re-scan) -> update in place.
      2. No exact fingerprint match, but the same *real* CVE (extracted from cve_id, e.g.
         "SCA-CVE-2024-29041" -> "CVE-2024-29041") is already open on this asset from a
         *different* scan_engine -> genuine cross-tool duplicate -> merge: note the extra
         detection source on the existing row instead of opening a second ticket.
      3. Otherwise: genuinely new finding -> insert, with fingerprint_hash stored so future
         calls can find it.

    Takes an already-open cursor (matches the existing pattern where each auditor manages its
    own transaction across a whole batch of findings) rather than opening its own.

    preserve_status: when True, matches auditor_ext.py's original (and genuinely good) nuance --
    a re-detected finding that was previously RESOLVED becomes REOPENED (not silently ignored,
    not silently duplicated), while a re-detected finding in any other status keeps that status
    untouched rather than being forced back to open_status. When False (default, matches every
    other caller's existing tested behavior), Tier 1 only matches non-RESOLVED rows and always
    sets status to open_status on update.

    Returns (action, row_id) where action is 'updated' | 'merged' | 'inserted'.
    """
    from core import threat_intel, mitre_attack

    # Normalized once, here, rather than trusting every one of the ~10 call sites across the
    # codebase to pass consistent casing. Confirmed live this was a real, not just cosmetic,
    # bug: 'Info' vs 'INFO' currently split 44 identical findings into two separate
    # /api/risk-distribution chart segments, AND several exact-match severity filters elsewhere
    # (main.py's HIGH-count health stat, PDF report KPI cards) silently undercounted anything
    # that wasn't exactly 'HIGH'/'CRITICAL'.
    severity = str(severity or '').strip().upper()

    fingerprint = calculate_fingerprint(asset_id, cve_id, url_path or description)
    real_cve = threat_intel.extract_cve(cve_id)

    mitre = mitre_attack.map_finding(cve_id, description)
    standards_value = f"MITRE ATT&CK: {mitre[0]} - {mitre[1]} ({mitre[2]})" if mitre else None

    # Tier 1: exact same finding (same fingerprint), any engine. "asset_id IS NOT DISTINCT FROM
    # %s" (not "asset_id = %s") -- plain "=" against a NULL asset_id (a legitimate, intentional
    # value for aggregate/org-wide findings like HEURISTIC-SECURITY-DEBT's "no single asset"
    # bucket) is SQL NULL, never TRUE, so this tier could never find its own previously-inserted
    # row for any asset_id=None finding and fell through to Tier 3 on every single call --
    # confirmed live: 983 duplicate rows for one such alert, vs. real dedup (a handful of rows)
    # for every properly asset-attributed finding using the exact same code path.
    if preserve_status:
        cur.execute("""
            SELECT id FROM public.vulnerability_log
            WHERE asset_id IS NOT DISTINCT FROM %s AND fingerprint_hash = %s
        """, (asset_id, fingerprint))
    else:
        cur.execute("""
            SELECT id FROM public.vulnerability_log
            WHERE asset_id IS NOT DISTINCT FROM %s AND fingerprint_hash = %s AND status != 'RESOLVED'
        """, (asset_id, fingerprint))
    existing = cur.fetchone()
    if existing:
        if preserve_status:
            cur.execute("""
                UPDATE public.vulnerability_log
                SET severity = %s, description = %s, detected_at = NOW(),
                    status = CASE WHEN status = 'RESOLVED' THEN 'REOPENED' ELSE status END,
                    reachability_status = COALESCE(%s, reachability_status),
                    standards = COALESCE(%s, standards)
                WHERE id = %s
            """, (severity, description, reachability_status, standards_value, existing[0]))
        else:
            cur.execute("""
                UPDATE public.vulnerability_log
                SET severity = %s, description = %s, detected_at = NOW(), status = %s,
                    reachability_status = COALESCE(%s, reachability_status),
                    standards = COALESCE(%s, standards)
                WHERE id = %s
            """, (severity, description, open_status, reachability_status, standards_value, existing[0]))
        return "updated", existing[0]

    # Tier 2: same real CVE, already open, from a genuinely different engine -> cross-tool merge.
    if real_cve:
        cur.execute("""
            SELECT id, description, scan_engine FROM public.vulnerability_log
            WHERE asset_id IS NOT DISTINCT FROM %s AND cve_id LIKE %s AND scan_engine != %s AND status != 'RESOLVED'
            LIMIT 1
        """, (asset_id, f"%{real_cve}%", scan_engine))
        cross_tool_match = cur.fetchone()
        if cross_tool_match:
            merge_id, existing_desc, other_engine = cross_tool_match
            note = f"\n\n**También detectado por:** `{scan_engine}` (fusionado por deduplicación cross-tool, {real_cve})"
            if note.split("\n")[-1] not in (existing_desc or ""):
                # Only refresh detected_at/description -- leave status untouched. This row
                # belongs to `other_engine`'s own lifecycle convention (e.g. ZAP-originated rows
                # use 'NEW', not 'OPEN'); a merge should annotate, not change lifecycle state.
                cur.execute("""
                    UPDATE public.vulnerability_log
                    SET description = description || %s, detected_at = NOW()
                    WHERE id = %s
                """, (note, merge_id))
            return "merged", merge_id

    # Tier 3: genuinely new. sla_due_date is set here at insert time (fixed severity->deadline
    # mapping, not touched again on re-detection/update above) -- previously this column was
    # only ever populated by a narrow legacy insert path elsewhere, so the shared logger every
    # other engine funnels through left ~96% of unresolved findings (including every
    # CRITICAL/HIGH row) with no SLA deadline at all, making the SLA-breach KPI structurally
    # blind to almost the entire real backlog. Computed as "NOW() + interval" in the same SQL
    # statement (not Python's datetime.utcnow() + timedelta beforehand) because this DB server's
    # session timezone is America/Mexico_City, not UTC -- a Python-side UTC calculation compared
    # against Postgres' own NOW()-based detected_at silently drifted by 6 hours (confirmed live:
    # a CRITICAL insert got a ~30h window instead of the intended 24h).
    sla_delta = get_sla_delta(severity)

    # ON CONFLICT (fingerprint_hash) DO UPDATE, backed by a real unique index
    # (idx_vulnerability_log_fingerprint_unique, added after a real incident this fixes) --
    # Tier 1's SELECT-then-branch above is a plain read with no locking, so two calls racing
    # for the *same brand-new* fingerprint (neither having inserted yet when the other's SELECT
    # runs) could both fall through to here and both INSERT, since nothing before this ever
    # actually enforced fingerprint_hash uniqueness at the database level (see gotcha #3 in
    # CLAUDE.md: no unique constraint ever existed beyond the `id` primary key). Confirmed live:
    # a backfill script produced 61 duplicate rows for a single ZAP finding in one batch (all
    # sharing the same fingerprint, inserted within the same transaction's NOW()), each with its
    # own separate PENDING_APPROVAL remediation_history row -- 839 duplicate rows total across
    # 171 groups, cleaned up as part of this fix. ON CONFLICT makes the insert-or-update
    # atomic at the database level regardless of how many callers race for the same fingerprint,
    # closing the gap Tier 1's plain SELECT can't. `(xmax = 0)` is the standard Postgres idiom
    # to tell an actual INSERT apart from a row returned via the ON CONFLICT UPDATE path.
    if preserve_status:
        cur.execute("""
            INSERT INTO public.vulnerability_log
            (asset_id, cve_id, severity, description, status, scan_engine, detected_at, url_path, fingerprint_hash, reachability_status, standards, sla_due_date)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, COALESCE(%s, 'REACHABLE'), %s, NOW() + %s)
            ON CONFLICT (fingerprint_hash) WHERE fingerprint_hash IS NOT NULL DO UPDATE SET
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                detected_at = NOW(),
                status = CASE WHEN public.vulnerability_log.status = 'RESOLVED' THEN 'REOPENED' ELSE public.vulnerability_log.status END,
                reachability_status = COALESCE(EXCLUDED.reachability_status, public.vulnerability_log.reachability_status),
                standards = COALESCE(EXCLUDED.standards, public.vulnerability_log.standards)
            RETURNING id, (xmax = 0) AS was_inserted
        """, (asset_id, cve_id, severity, description, open_status, scan_engine, url_path, fingerprint, reachability_status, standards_value, sla_delta))
    else:
        cur.execute("""
            INSERT INTO public.vulnerability_log
            (asset_id, cve_id, severity, description, status, scan_engine, detected_at, url_path, fingerprint_hash, reachability_status, standards, sla_due_date)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, COALESCE(%s, 'REACHABLE'), %s, NOW() + %s)
            ON CONFLICT (fingerprint_hash) WHERE fingerprint_hash IS NOT NULL DO UPDATE SET
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                detected_at = NOW(),
                status = EXCLUDED.status,
                reachability_status = COALESCE(EXCLUDED.reachability_status, public.vulnerability_log.reachability_status),
                standards = COALESCE(EXCLUDED.standards, public.vulnerability_log.standards)
            RETURNING id, (xmax = 0) AS was_inserted
        """, (asset_id, cve_id, severity, description, open_status, scan_engine, url_path, fingerprint, reachability_status, standards_value, sla_delta))
    new_id, was_inserted = cur.fetchone()
    return ("inserted" if was_inserted else "updated"), new_id
