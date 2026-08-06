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

def calculate_sla_due_date(severity: str, detected_at: Optional[datetime] = None) -> datetime:
    """
    Calculates SLA remediation deadline based on severity.
    - CRITICAL: 24 hours
    - HIGH: 7 days
    - MEDIUM: 30 days
    - LOW / INFO: 90 days
    """
    start_time = detected_at or datetime.utcnow()
    sev = str(severity or '').upper()

    if sev in ('CRITICAL', 'CRÍTICO'):
        delta = timedelta(hours=24)
    elif sev in ('HIGH', 'ALTO'):
        delta = timedelta(days=7)
    elif sev in ('MEDIUM', 'MEDIO'):
        delta = timedelta(days=30)
    else:
        delta = timedelta(days=90)

    return start_time + delta

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
                              reachability_status: Optional[str] = None) -> "tuple[str, int]":
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

    Returns (action, row_id) where action is 'updated' | 'merged' | 'inserted'.
    """
    from core import threat_intel, mitre_attack

    fingerprint = calculate_fingerprint(asset_id, cve_id, url_path or description)
    real_cve = threat_intel.extract_cve(cve_id)

    mitre = mitre_attack.map_finding(cve_id, description)
    standards_value = f"MITRE ATT&CK: {mitre[0]} - {mitre[1]} ({mitre[2]})" if mitre else None

    # Tier 1: exact same finding (same fingerprint), any engine.
    cur.execute("""
        SELECT id FROM public.vulnerability_log
        WHERE asset_id = %s AND fingerprint_hash = %s AND status != 'RESOLVED'
    """, (asset_id, fingerprint))
    existing = cur.fetchone()
    if existing:
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
            WHERE asset_id = %s AND cve_id LIKE %s AND scan_engine != %s AND status != 'RESOLVED'
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

    # Tier 3: genuinely new.
    cur.execute("""
        INSERT INTO public.vulnerability_log
        (asset_id, cve_id, severity, description, status, scan_engine, detected_at, url_path, fingerprint_hash, reachability_status, standards)
        VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, COALESCE(%s, 'REACHABLE'), %s)
        RETURNING id
    """, (asset_id, cve_id, severity, description, open_status, scan_engine, url_path, fingerprint, reachability_status, standards_value))
    new_id = cur.fetchone()[0]
    return "inserted", new_id
