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
    across multiple scanners (Nuclei, Semgrep, ZAP, etc.).
    """
    normalized_cve = str(cve_id or '').strip().upper()
    normalized_loc = str(location_or_desc or '').strip().lower()[:120]
    raw = f"{asset_id}:{normalized_cve}:{normalized_loc}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_LEVEL_WORDS = {
    "nulo": "INFO", "nula": "INFO", "ninguno": "INFO", "none": "INFO",
    "bajo": "LOW", "baja": "LOW", "low": "LOW",
    "moderado": "MEDIUM", "moderada": "MEDIUM", "medio": "MEDIUM", "media": "MEDIUM", "medium": "MEDIUM",
    "alto": "HIGH", "alta": "HIGH", "high": "HIGH",
    "crítico": "CRITICAL", "critico": "CRITICAL", "crítica": "CRITICAL", "critica": "CRITICAL", "critical": "CRITICAL",
}
# Fallback ONLY for rows analyzed before the structured `severidad_real` field existed: the earlier
# prompts made the AI open with "Riesgo real <NIVEL> ..." (e.g. "Riesgo real BAJO-MODERADO",
# "Riesgo real de SEGURIDAD prácticamente nulo"). Captures every level word in the first 60 chars
# after "riesgo real" and keeps the HIGHEST (conservative: "BAJO-MODERADO" -> MEDIUM).
import re as _re
_RIESGO_REAL_RE = _re.compile(r"riesgo\s+real(?P<tail>[^.:\n]{0,60})", _re.IGNORECASE)
_LEVEL_TOKEN_RE = _re.compile(r"\b(" + "|".join(sorted(_LEVEL_WORDS, key=len, reverse=True)) + r")\b", _re.IGNORECASE)
_CONFIRMED_NO_RISK_PHRASES = (
    "sin riesgo real", "no representa un riesgo real", "falso positivo confirmado",
    "no requiere remediación", "patrón recomendado por angular",
    "no se generó un parche: este es exactamente el patrón recomendado",
)
# A verdict that depends on an assumption nobody verified is NOT downgraded (see docstring below).
_CONDITIONAL_MARKERS = (
    "condicionado a que", "siempre y cuando", "depende de que", "bajo el supuesto de que",
    "si en algún momento se agrega", "si esa condición se cumple", "dependiente de controles",
)


def _norm_ai_level(value: Optional[str]) -> Optional[str]:
    """Maps the AI's free-form level ("Nulo", "Bajo-Moderado", "Crítico") to a severity bucket,
    keeping the highest level mentioned. None if no recognizable level word."""
    found = [_LEVEL_WORDS[m.group(1).lower()] for m in _LEVEL_TOKEN_RE.finditer(str(value or ""))]
    return min(found, key=lambda x: _SEV_RANK[x]) if found else None


def assess_real_risk_verdict(
    business_impact: Optional[str],
    developer_steps: Optional[str],
    raw_severity: Optional[str] = None,
    ai_real_severity: Optional[str] = None,
    ai_depends_on_assumption: Optional[bool] = None,
) -> Dict[str, Optional[str]]:
    """
    Single shared source of truth for the AI's context-aware verdict of a finding's REAL
    exploitability, separate from the raw, context-blind severity a scanner assigned to the code
    PATTERN (a scanner has no idea whether this specific occurrence is reachable by an attacker).

    Source priority: (1) structured `ai_real_severity` / `ai_depends_on_assumption` the AI now
    returns as explicit JSON fields; (2) fallback for rows analyzed before those fields existed:
    the "Riesgo real <NIVEL>" phrase the older prompts made the AI write, plus a few fixed phrases.

    Returns {"real_severity": <bucket>|None, "risk_verdict": <str>|None}:
      * CONFIRMED_NO_RISK -> real_severity "INFO" (AI says risk is null / known-safe pattern)
      * DOWNGRADED        -> real_severity LOW/MEDIUM/HIGH, strictly LOWER than raw_severity
      * CONDITIONAL       -> real_severity None: the verdict depends on an unverified assumption,
                             so the raw severity is kept (only flagged for human review)
      * None              -> no override
    The AI can only LOWER severity here, never raise it above what the scanner reported.
    Every consumer must read COALESCE(real_severity, severity), never real_severity alone.
    """
    text = f"{business_impact or ''} {developer_steps or ''}".lower()
    conditional = bool(ai_depends_on_assumption) if ai_depends_on_assumption is not None \
        else any(m in text for m in _CONDITIONAL_MARKERS)

    level = _norm_ai_level(ai_real_severity) if ai_real_severity else None
    if level is None:  # fallback to the legacy phrase
        if any(p in text for p in _CONFIRMED_NO_RISK_PHRASES):
            level = "INFO"
        else:
            m = _RIESGO_REAL_RE.search(f"{business_impact or ''}")
            level = _norm_ai_level(m.group("tail")) if m else None

    if level is None:
        return {"real_severity": None, "risk_verdict": "CONDITIONAL" if conditional else None}
    if conditional:
        return {"real_severity": None, "risk_verdict": "CONDITIONAL"}
    raw = str(raw_severity or "").upper()
    raw = {"CRÍTICO": "CRITICAL", "ALTO": "HIGH", "MEDIO": "MEDIUM", "BAJO": "LOW"}.get(raw, raw)
    if level == "INFO":
        return {"real_severity": "INFO", "risk_verdict": "CONFIRMED_NO_RISK"}
    if raw in _SEV_RANK and _SEV_RANK[level] > _SEV_RANK[raw]:
        return {"real_severity": level, "risk_verdict": "DOWNGRADED"}
    return {"real_severity": None, "risk_verdict": None}


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


# Real gap fixed 2026-08-14, in response to a direct user challenge ("necesito separar
# vulnerabilidades reales de las informativas... pareciera que los más de 9000 detectados todos
# son de infraestructura"). Confirmed live: 92% of all rows (8,298/9,023) actually belong to
# GitLab-Repo (code) assets, not infrastructure -- the dashboard just never broke the total down
# by asset type or by whether a row is a real security finding vs. a code-quality/process-debt
# metric or an aggregate completion marker, so one undifferentiated number looked infrastructure-
# heavy by default. cve_id/scan_engine values confirmed live against the real DB, not guessed:
# SCAN-AUDIT/HEURISTIC-SECURITY-DEBT/CIS-BENCHMARK-AUDIT/SONARQUBE-QUALITY-GATE are aggregate
# "no findings" or audit-completion markers (Severity='Info' already), STD-ISO25010-LONG-METHOD
# and COGNITIVE-COMPLEXITY-EXCEEDED are ISO 25010 maintainability metrics (already documented in
# CLAUDE.md as deliberately unmapped in MITRE ATT&CK for the same reason -- not an attack
# technique), and cmmi-audit's whole engine (CMMI-CAR-SWALLOWED-EXCEPTION/CMMI-MSR-HARDCODED-
# SLEEP/CMMI-PQA-DEBT-TODO) measures process maturity/technical debt, not a security
# vulnerability. Centralized here (one classifier every writer funnels through via
# log_finding_deduplicated(), matching how mitre_attack.map_finding() is already centralized)
# rather than trusted to ~15 scattered call sites, so it can't silently drift out of sync the way
# per-engine dedup did before this module existed.
_INFORMATIONAL_CVE_EXACT = {
    "SCAN-AUDIT", "HEURISTIC-SECURITY-DEBT", "CIS-BENCHMARK-AUDIT", "SONARQUBE-QUALITY-GATE",
    "STD-ISO25010-LONG-METHOD", "COGNITIVE-COMPLEXITY-EXCEEDED",
    # authz-dast "auditor ran but had no multi-role credentials, so it was not exercised" marker
    # -- a state marker like CIS-BENCHMARK-AUDIT, not an individually actionable vulnerability.
    "AUTHZ-DAST-NO-CREDS",
    # completion markers of the 2026-09-23 audits (state, not an individually actionable finding)
    "OS-PATCH-AUDIT", "TLS-AUDIT", "GITLAB-CONFIG-AUDIT", "DNS-SECURITY-AUDIT",
    # conformance with the institutional validation catalogue (methodology 0B-4), not a vulnerability
    "VALIDATION-REIMPLEMENTED",
    # standards conformance / process (Estándar Maestro 5.4, 5.10, 5.11, 6): worth showing, not individually exploitable vulnerabilities
    "SWALLOWED-ERROR", "DESTRUCTIVE-ACTION-NO-CONFIRM", "NATIVE-BROWSER-DIALOG", "SQL-TABLE-WITHOUT-PRIMARY-KEY",
    "SMART-TESTS-FORM-INVALID-SUBMITTED", "SMART-TESTS-FORM-NO-FIELD-ERROR",
    "CICD-GATE-ALLOW-FAILURE", "TEST-SKIPPED-WITHOUT-REASON",
    # organisation database standard / Starter conventions (2026-10-27): conformance, not individually exploitable
    "SQL-PK-NOT-UUID", "SQL-TIMESTAMP-WITHOUT-TIMEZONE", "SQL-JSON-NOT-JSONB", "SQL-FLOAT-FOR-MONEY", "SQL-TABLE-WITHOUT-AUDIT-COLUMNS",
    "TRANSACTIONAL-ON-CONTROLLER", "FIELD-INJECTION-AUTOWIRED", "JPA-OBJECT-ARRAY-RESULT", "FRONTEND-HARDCODED-API-URL",
    "API-ENDPOINT-UNDOCUMENTED",
    # CORE/Starter business-rule catalogue (2026-10-28): data-model conformance (leading zeros), not exploitable
    "NUMERIC-CODE-STORED-AS-NUMBER",
    # compiled build output committed to git (ADR-0022): repository hygiene, not exploitable by itself
    "REPO-BUILD-OUTPUT-COMMITTED",
}
_INFORMATIONAL_SCAN_ENGINES = {"cmmi-audit"}

# Accessibility (WCAG 2.1) findings: a legal/contractual compliance requirement for the public-sector projects audited here, not a
# security vulnerability and not optional quality debt either. They keep their SLA, AI analysis and visibility, but are counted
# in their own COMPLIANCE category instead of the security-vulnerability headline (owner decision 2026-10-29).
FINDING_CATEGORIES = ("VULNERABILITY", "COMPLIANCE", "INFORMATIONAL")
_COMPLIANCE_CVE_PREFIXES = ("WCAG-", "ACCESSIBILITY-WCAG")
_COMPLIANCE_SCAN_ENGINES = {"accessibility-wcag", "wcag-render"}
# SQL twin of is_compliance_rule(), for backfills and filters that must match the classifier exactly.
COMPLIANCE_RULE_SQL = "(v.cve_id LIKE 'WCAG-%%' OR v.cve_id LIKE 'ACCESSIBILITY-WCAG%%' OR v.scan_engine IN ('accessibility-wcag', 'wcag-render'))"


def is_compliance_rule(cve_id: str, scan_engine: Optional[str] = None) -> bool:
    """True for accessibility (WCAG) findings, which belong to the COMPLIANCE category."""
    cve_u = str(cve_id or "").strip().upper()
    return cve_u.startswith(_COMPLIANCE_CVE_PREFIXES) or str(scan_engine or "").strip().lower() in _COMPLIANCE_SCAN_ENGINES


def classify_finding_category(cve_id: str, scan_engine: Optional[str], description: str = "") -> str:
    """Returns 'VULNERABILITY' (a real, individually actionable security finding), 'COMPLIANCE'
    (an accessibility/WCAG requirement: actionable and with SLA, but not a security vulnerability)
    or 'INFORMATIONAL' (an aggregate marker, code-quality metric, or process-debt item -- real and
    worth showing, but not a vulnerability). Only exact cve_id matches are used for INFORMATIONAL
    (never a prefix match), so a real per-check finding that merely shares an engine with a marker
    -- e.g. a real CIS-SSH-ROOT-LOGIN failure sharing scan_engine='cis-benchmark' with the
    CIS-BENCHMARK-AUDIT completion marker -- is never miscategorized alongside it."""
    cve_u = str(cve_id or "").strip().upper()
    if is_compliance_rule(cve_u, scan_engine):
        return "COMPLIANCE"
    if cve_u in _INFORMATIONAL_CVE_EXACT:
        return "INFORMATIONAL"
    if str(scan_engine or "").strip().lower() in _INFORMATIONAL_SCAN_ENGINES:
        return "INFORMATIONAL"
    # SonarQube issues are ingested as a single mixed batch spanning real Sonar "type"s
    # (VULNERABILITY/SECURITY_HOTSPOT are the only genuinely security-relevant ones; BUG is a
    # functional-reliability defect, CODE_SMELL is maintainability -- neither is a security
    # vulnerability) -- auditor_sonarqube.py's own _persist_issues() passes finding_category
    # explicitly using the real API value for a fresh write, so this text match only matters as
    # a backfill-time proxy for historical rows written before this column existed.
    if str(scan_engine or "").strip().lower() == "sonarqube" and (
        "**SonarQube CODE_SMELL**" in (description or "") or "**SonarQube BUG**" in (description or "")
    ):
        return "INFORMATIONAL"
    return "VULNERABILITY"


def find_active_suppression(cur, asset_id: Any, cve_id: str,
                            fingerprint_hash: Optional[str], url_path: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Item 3 (2026-08-27): learned false-positive / accepted-risk memory (CodeRabbit-style).

    Returns the matching public.finding_suppressions row (as a dict) if this finding is
    currently suppressed, else None. A suppression matches when EVERY one of its non-NULL
    predicates matches the finding, it is active, and it has not expired. The API guarantees at
    least one predicate is non-NULL, so an all-NULL row can never mute the whole platform.

    This is deliberately a plain read with no side effects -- log_finding_deduplicated() is the
    only caller and it updates the suppression's own hit counter itself, inside the same
    transaction as the vulnerability_log write.
    """
    try:
        cur.execute("""
            SELECT id, reason, scope, created_by
            FROM public.finding_suppressions
            WHERE active = TRUE
              AND (expires_at IS NULL OR expires_at > NOW())
              AND (asset_id IS NULL OR asset_id IS NOT DISTINCT FROM %s)
              AND (cve_id IS NULL OR cve_id = %s)
              AND (fingerprint_hash IS NULL OR fingerprint_hash = %s)
              AND (url_path_pattern IS NULL OR %s LIKE url_path_pattern)
            ORDER BY id DESC
            LIMIT 1
        """, (asset_id, cve_id, fingerprint_hash, url_path or ""))
    except Exception:
        # finding_suppressions is created by core.schema.ensure_core_schema() at startup; if a
        # deployment somehow hasn't run that yet, a missing table must NOT break finding
        # ingestion -- treat it as "nothing suppressed" and let the row through.
        import traceback
        print("⚠️ [Dedup] finding_suppressions lookup failed -- treating finding as not suppressed:")
        traceback.print_exc()
        return None
    row = cur.fetchone()
    if not row:
        return None
    return {"id": row[0], "reason": row[1], "scope": row[2], "created_by": row[3]}


def log_finding_deduplicated(cur, asset_id: str, cve_id: str, severity: str, description: str,
                              scan_engine: str, url_path: Optional[str] = None,
                              open_status: str = "OPEN",
                              reachability_status: Optional[str] = None,
                              preserve_status: bool = False,
                              finding_category: Optional[str] = None) -> "tuple[str, int]":
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

    finding_category: 'VULNERABILITY' (default, auto-classified), 'COMPLIANCE' or 'INFORMATIONAL' -- see
    classify_finding_category()'s own docstring. Pass explicitly only when the caller has real
    data the classifier can't see from cve_id/scan_engine/description alone (e.g. SonarQube's
    real per-issue API "type"); leave as None everywhere else so the shared classifier stays the
    single source of truth.

    Returns (action, row_id) where action is 'updated' | 'merged' | 'inserted'.
    """
    from core import threat_intel, mitre_attack

    if finding_category is None:
        finding_category = classify_finding_category(cve_id, scan_engine, description)

    # Normalized once, here, rather than trusting every one of the ~10 call sites across the
    # codebase to pass consistent casing. Confirmed live this was a real, not just cosmetic,
    # bug: 'Info' vs 'INFO' currently split 44 identical findings into two separate
    # /api/risk-distribution chart segments, AND several exact-match severity filters elsewhere
    # (main.py's HIGH-count health stat, PDF report KPI cards) silently undercounted anything
    # that wasn't exactly 'HIGH'/'CRITICAL'.
    severity = str(severity or '').strip().upper()

    fingerprint = calculate_fingerprint(asset_id, cve_id, url_path or description)

    # Item 3: if an analyst has recorded this finding as a false positive / accepted risk, do
    # not keep resurfacing it. An existing row is parked in SUPPRESSED (kept for the audit
    # trail, excluded from the AI-correlation queue and every "open findings" view); a
    # genuinely new one is not inserted at all. Either way the scanner's re-detection is
    # counted on the suppression itself so "this is still being detected" stays visible.
    suppression = find_active_suppression(cur, asset_id, cve_id, fingerprint, url_path or description)
    if suppression:
        cur.execute("""
            UPDATE public.finding_suppressions
            SET match_count = match_count + 1, last_matched_at = NOW()
            WHERE id = %s
        """, (suppression["id"],))
        cur.execute("""
            SELECT id FROM public.vulnerability_log
            WHERE asset_id IS NOT DISTINCT FROM %s AND fingerprint_hash = %s
        """, (asset_id, fingerprint))
        existing_row = cur.fetchone()
        if existing_row:
            cur.execute("""
                UPDATE public.vulnerability_log
                SET status = 'SUPPRESSED', detected_at = NOW()
                WHERE id = %s AND status <> 'SUPPRESSED'
            """, (existing_row[0],))
            return "suppressed", existing_row[0]
        return "suppressed", -1

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
                    standards = COALESCE(%s, standards),
                    finding_category = %s
                WHERE id = %s
            """, (severity, description, reachability_status, standards_value, finding_category, existing[0]))
        else:
            cur.execute("""
                UPDATE public.vulnerability_log
                SET severity = %s, description = %s, detected_at = NOW(), status = %s,
                    reachability_status = COALESCE(%s, reachability_status),
                    standards = COALESCE(%s, standards),
                    finding_category = %s
                WHERE id = %s
            """, (severity, description, open_status, reachability_status, standards_value, finding_category, existing[0]))
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
            (asset_id, cve_id, severity, description, status, scan_engine, detected_at, url_path, fingerprint_hash, reachability_status, standards, sla_due_date, finding_category)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, COALESCE(%s, 'REACHABLE'), %s, NOW() + %s, %s)
            ON CONFLICT (fingerprint_hash) WHERE fingerprint_hash IS NOT NULL DO UPDATE SET
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                detected_at = NOW(),
                status = CASE WHEN public.vulnerability_log.status = 'RESOLVED' THEN 'REOPENED' ELSE public.vulnerability_log.status END,
                reachability_status = COALESCE(EXCLUDED.reachability_status, public.vulnerability_log.reachability_status),
                standards = COALESCE(EXCLUDED.standards, public.vulnerability_log.standards),
                finding_category = EXCLUDED.finding_category
            RETURNING id, (xmax = 0) AS was_inserted
        """, (asset_id, cve_id, severity, description, open_status, scan_engine, url_path, fingerprint, reachability_status, standards_value, sla_delta, finding_category))
    else:
        cur.execute("""
            INSERT INTO public.vulnerability_log
            (asset_id, cve_id, severity, description, status, scan_engine, detected_at, url_path, fingerprint_hash, reachability_status, standards, sla_due_date, finding_category)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, COALESCE(%s, 'REACHABLE'), %s, NOW() + %s, %s)
            ON CONFLICT (fingerprint_hash) WHERE fingerprint_hash IS NOT NULL DO UPDATE SET
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                detected_at = NOW(),
                status = EXCLUDED.status,
                reachability_status = COALESCE(EXCLUDED.reachability_status, public.vulnerability_log.reachability_status),
                standards = COALESCE(EXCLUDED.standards, public.vulnerability_log.standards),
                finding_category = EXCLUDED.finding_category
            RETURNING id, (xmax = 0) AS was_inserted
        """, (asset_id, cve_id, severity, description, open_status, scan_engine, url_path, fingerprint, reachability_status, standards_value, sla_delta, finding_category))
    new_id, was_inserted = cur.fetchone()
    return ("inserted" if was_inserted else "updated"), new_id


def reconcile_resolved_findings(cur, asset_id: str, scan_engine: str, active_fingerprints: "set[str]",
                                url_origin: Optional[str] = None) -> int:
    """
    Marks RESOLVED any currently OPEN/NEW/CORRELATED/REOPENED finding for this
    (asset_id, scan_engine) whose fingerprint was NOT reproduced by the fresh scan that just
    ran. This closes a real, previously-missing capability: log_finding_deduplicated() only
    ever handles a finding being *redetected* (update in place) -- nothing ever marked a finding
    resolved when it simply stopped being detected. For line/text-anchored findings (SAST/SCA/
    standards, whose fingerprint bakes in the exact file:line), this matters a lot: editing code
    shifts line numbers constantly, so an old finding whose line moved (or whose underlying code
    was already fixed) never re-matches a fresh scan's fingerprint and was previously left open
    forever, phantom and unverifiable, no matter how long ago the real issue was actually fixed.

    Confirmed live, 2026-08-13: multiple SAST findings against Centinela's own actively-edited
    main.py/centinela.py pointed at line numbers that, when actually opened, contained completely
    unrelated code -- the flagged pattern had moved or been removed, but the finding stayed open
    indefinitely with no mechanism to ever close it.

    Caller runs a full fresh scan first, computes the fingerprint for every finding it produced
    into `active_fingerprints`, then calls this once per (asset_id, scan_engine) so only a real,
    complete re-scan can resolve anything -- a partial/failed scan naturally won't wipe out
    findings it simply didn't get around to checking, since it wouldn't call this at all in that
    case (call sites only invoke this after a scan completes without raising).

    `url_origin` (e.g. "http://192.0.2.16:8080") scopes the reconciliation to findings whose url_path is that
    origin or lives under it. Required by any engine that scans ONE asset in several independent calls (one
    per web port): without it, the call for port 8080 saw none of port 80's findings in its active set and
    marked them all RESOLVED, so a server's findings flapped open/resolved on every cycle (2026-09-23).
    """
    sql = """
        SELECT id, fingerprint_hash FROM public.vulnerability_log
        WHERE asset_id = %s AND scan_engine = %s
          AND status IN ('OPEN', 'NEW', 'CORRELATED', 'REOPENED')
          AND fingerprint_hash IS NOT NULL
    """
    params: list = [asset_id, scan_engine]
    if url_origin:
        sql += " AND (url_path = %s OR url_path LIKE %s OR url_path LIKE %s)"
        params += [url_origin, url_origin + "/%", url_origin + "?%"]
    cur.execute(sql, tuple(params))
    stale_ids = [row[0] for row in cur.fetchall() if row[1] not in active_fingerprints]
    if not stale_ids:
        return 0
    cur.execute("""
        UPDATE public.vulnerability_log SET status = 'RESOLVED'
        WHERE id = ANY(%s::uuid[])
    """, (stale_ids,))
    return len(stale_ids)
