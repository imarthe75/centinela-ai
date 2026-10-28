"""
Centinela -- idempotent schema for the tables this codebase owns end to end.

Historically every new column/table (finding_category, hostname, last_seen, fix_patch, ...) was
applied by hand straight to the live centinela_db with an ad-hoc scratch/ script and never
recorded anywhere in the repo. That reproduces exactly once and is impossible to stand up on a
fresh database. The tables Centinela creates itself (NOT the pre-existing infra_inventory /
vulnerability_log / remediation_history / runtime_alerts that predate this repo) are declared
here with CREATE TABLE / COLUMN / INDEX IF NOT EXISTS and applied on every service startup, so a
fresh deployment self-heals and the definition lives next to the code that depends on it.

Added 2026-08-27 for the CodeRabbit / "The Rock" robustness pass:
  * finding_suppressions -- learned false-positive / accepted-risk memory (item 3)
  * agent_actions        -- unified autonomous-action ledger (item 4)

**2026-09-30: every id / *_id column in this file (and in the pre-existing infra_inventory /
vulnerability_log / remediation_history / runtime_alerts tables) was converted from
INTEGER/SERIAL/BIGINT to UUID v7 (`uuidv7()`, native in PostgreSQL 18 -- no extension needed),
live against production, in a maintenance window. Real design error being corrected: integer PKs
leak row counts/creation order across tenants and don't compose with any future multi-writer or
offline-generated-id scenario; UUIDv7 keeps the same "sorts by creation time" property integers
had while removing that leak. `entity_id` (agent_actions) is genuinely polymorphic -- it holds
either another table's UUID (as text) or a real external identifier that was never a Centinela
row at all (a GitLab MR iid) -- so it is TEXT, not UUID. Fresh-DB CREATE TABLEs below reflect the
end state directly; the live migration itself (shadow-column backfill -> remap every dependent FK
by join -> swap) is not re-run by this file since it only ever applies to a database that still
has the old INTEGER columns, which no environment running this version of the code will have.
"""

CORE_SCHEMA_STATEMENTS = [
    # ------------------------------------------------------------------ 2026-09-30
    # Deliberate exception to this file's own "doesn't cover pre-existing tables" rule (see the
    # module docstring): vulnerability_log predates this repo, but ADD COLUMN IF NOT EXISTS is
    # just as safe to run against a pre-existing table as a fresh one, and centralizing this here
    # (instead of yet another untracked scratch/ one-off) is exactly the problem schema.py exists
    # to fix. Added after a direct user report that a scanner's raw, context-blind severity
    # (e.g. SonarQube marking ANY DomSanitizer bypass CRITICAL, regardless of whether the bypassed
    # value is attacker-reachable) was indistinguishable in reports/dashboards from a real,
    # unaddressed finding of that same severity, once Centinela's own AI correlation had already
    # determined the real-world risk differs. `real_severity`/`risk_verdict` hold that
    # AI-determined verdict separately from the scanner's raw `severity` (which is never
    # overwritten) -- see core/deduplication_engine.assess_real_risk_verdict(), the single shared
    # implementation. NULL in both columns means "not yet assessed" or "verdict matches the raw
    # severity", and every consumer must treat `COALESCE(real_severity, severity)` as the
    # effective severity, never read `real_severity` alone.
    "ALTER TABLE public.vulnerability_log ADD COLUMN IF NOT EXISTS real_severity TEXT",
    "ALTER TABLE public.vulnerability_log ADD COLUMN IF NOT EXISTS risk_verdict TEXT",

    # ------------------------------------------------------------------ item 3
    # A finding is suppressed when EVERY one of a row's non-NULL predicates matches it and the
    # row is active and unexpired. At least one predicate must be non-NULL (enforced by the API,
    # not the schema) so a suppression can never accidentally mute the whole platform.
    """
    CREATE TABLE IF NOT EXISTS public.finding_suppressions (
        id               UUID PRIMARY KEY DEFAULT uuidv7(),
        asset_id         UUID REFERENCES public.infra_inventory(id) ON DELETE CASCADE,
        cve_id           TEXT,
        url_path_pattern TEXT,
        fingerprint_hash TEXT,
        reason           TEXT NOT NULL,
        scope            TEXT NOT NULL DEFAULT 'FALSE_POSITIVE',
        created_by       TEXT NOT NULL DEFAULT 'analyst',
        active           BOOLEAN NOT NULL DEFAULT TRUE,
        match_count      INTEGER NOT NULL DEFAULT 0,
        last_matched_at  TIMESTAMP,
        created_at       TIMESTAMP NOT NULL DEFAULT NOW(),
        expires_at       TIMESTAMP
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_finding_suppressions_lookup ON public.finding_suppressions (active, asset_id, cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_finding_suppressions_fp ON public.finding_suppressions (fingerprint_hash) WHERE fingerprint_hash IS NOT NULL",

    # Human-review workflow for AI-PROPOSED suppressions (created_by='centinela-ai', active=FALSE):
    # review_status PENDING -> APPROVED (active=TRUE + retro-suppress) | REJECTED (findings revert to
    # the scanner's raw severity, risk_verdict='ANALYST_OVERRIDDEN'). NULL = a manual analyst
    # suppression that never went through review.
    "ALTER TABLE public.finding_suppressions ADD COLUMN IF NOT EXISTS review_status TEXT",
    "ALTER TABLE public.finding_suppressions ADD COLUMN IF NOT EXISTS reviewed_by TEXT",
    "ALTER TABLE public.finding_suppressions ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP",
    "ALTER TABLE public.finding_suppressions ADD COLUMN IF NOT EXISTS review_note TEXT",

    # ------------------------------------------------------------------ CMMI evidence (DECISIONS/0007, 2026-10-01)
    # One row per (scope, asset, CMMI area, evidence item of the the organization manual). level: L1 measured by Centinela, L2 verified
    # artifact, L3 attested by a named person. status: CUMPLE / NO_CUMPLE / NO_EVALUADO / NO_APLICA. Expired rows
    # (valid_until) stop counting; scope='ORG' rows have asset_id NULL.
    """
    CREATE TABLE IF NOT EXISTS public.cmmi_evidence (
        id            UUID PRIMARY KEY DEFAULT uuidv7(),
        scope         TEXT NOT NULL,
        asset_id      UUID REFERENCES public.infra_inventory(id) ON DELETE CASCADE,
        area          TEXT NOT NULL,
        item_key      TEXT NOT NULL,
        level         TEXT NOT NULL DEFAULT 'L1',
        status        TEXT NOT NULL,
        detail        JSONB,
        evidence_ref  TEXT,
        collected_at  TIMESTAMP NOT NULL DEFAULT NOW(),
        valid_until   TIMESTAMP,
        attested_by   TEXT
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_cmmi_evidence ON public.cmmi_evidence (scope, (COALESCE(asset_id, '00000000-0000-0000-0000-000000000000'::uuid)), area, item_key)",
    "CREATE INDEX IF NOT EXISTS idx_cmmi_evidence_asset ON public.cmmi_evidence (asset_id)",

    # ------------------------------------------------------------------ item 4
    """
    CREATE TABLE IF NOT EXISTS public.agent_actions (
        id           UUID PRIMARY KEY DEFAULT uuidv7(),
        action_type  TEXT NOT NULL,
        actor        TEXT NOT NULL DEFAULT 'centinela-ai',
        entity_type  TEXT,
        entity_id    TEXT,
        asset_id     UUID REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
        summary      TEXT NOT NULL,
        detail       JSONB,
        evidence     TEXT,
        outcome      TEXT NOT NULL DEFAULT 'success',
        created_at   TIMESTAMP NOT NULL DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_agent_actions_created ON public.agent_actions (created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_agent_actions_type ON public.agent_actions (action_type, created_at DESC)",

    # ------------------------------------------------------------------ item 2
    # Incident correlation: group related runtime/CTI/BloodHound/KEV signals that already exist
    # in runtime_alerts / vulnerability_log into one case with a timeline, an ATT&CK kill chain,
    # and an MTTD/MTTC clock. Fail-safe on no data -- the loop runs, finds nothing worth
    # grouping, and creates nothing. Full design in DECISIONS/0003.
    """
    CREATE TABLE IF NOT EXISTS public.incidents (
        id                      UUID PRIMARY KEY DEFAULT uuidv7(),
        asset_id                UUID REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
        title                   TEXT NOT NULL,
        category_code           TEXT,
        severity                TEXT NOT NULL DEFAULT 'MEDIUM',
        status                  TEXT NOT NULL DEFAULT 'OPEN',
        kill_chain              TEXT[],
        indicators              JSONB,
        narrative               TEXT,
        ai_summary              TEXT,
        analyst_notes           TEXT,
        recommended_containment TEXT,
        first_event_at          TIMESTAMP,
        last_event_at           TIMESTAMP,
        detected_at             TIMESTAMP NOT NULL DEFAULT NOW(),
        contained_at            TIMESTAMP,
        closed_at               TIMESTAMP,
        event_count             INTEGER NOT NULL DEFAULT 0,
        fingerprint             TEXT UNIQUE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS public.incident_events (
        incident_id  UUID NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
        source       TEXT NOT NULL,
        source_id    UUID NOT NULL,
        occurred_at  TIMESTAMP NOT NULL,
        tactic       TEXT,
        severity     TEXT,
        summary      TEXT,
        PRIMARY KEY (incident_id, source, source_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.incidents (status, detected_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_incident_events_src ON public.incident_events (source, source_id)",
    # ------------------------------------------------------------------ SOAR autoresponse (ADR-0004)
    # Policy layer over the existing remediation pipeline. Created by hand in production on
    # 2026-09-17 (never in code); now reproducible. dry_run defaults TRUE and active FALSE.
    """
    CREATE TABLE IF NOT EXISTS public.autoresponse_policy (
        id                    UUID PRIMARY KEY DEFAULT uuidv7(),
        action_kind           TEXT NOT NULL,
        max_severity_auto     TEXT,
        asset_scope           TEXT NOT NULL DEFAULT 'NON_CRITICAL',
        require_cti_confirmed BOOLEAN NOT NULL DEFAULT TRUE,
        daily_cap             INTEGER NOT NULL DEFAULT 3,
        dry_run               BOOLEAN NOT NULL DEFAULT TRUE,
        active                BOOLEAN NOT NULL DEFAULT FALSE,
        updated_by            TEXT,
        updated_at            TIMESTAMP DEFAULT NOW()
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_autoresponse_policy_kind ON public.autoresponse_policy (action_kind)",
    # Observation mode by default: the engine evaluates and records what it WOULD do. Flipping
    # dry_run to FALSE is a deliberate human decision (ADR-0004); host_isolate never auto-executes.
    """
    INSERT INTO public.autoresponse_policy (action_kind, max_severity_auto, asset_scope, require_cti_confirmed, daily_cap, dry_run, active, updated_by)
    VALUES ('proxy_ip_block', 'CRITICAL', 'NON_CRITICAL', TRUE, 3, TRUE, TRUE, 'schema-seed'),
           ('session_revoke', 'CRITICAL', 'NON_CRITICAL', FALSE, 5, TRUE, TRUE, 'schema-seed'),
           ('host_isolate',   'CRITICAL', 'NON_CRITICAL', TRUE, 0, TRUE, FALSE, 'schema-seed')
    ON CONFLICT (action_kind) DO NOTHING
    """,
    # Temporary reverse-proxy blocks added autonomously, so a reaper can lift exactly those.
    """
    CREATE TABLE IF NOT EXISTS public.soar_ip_blocks (
        id              UUID PRIMARY KEY DEFAULT uuidv7(),
        ip              TEXT NOT NULL,
        asset_id        UUID REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
        vuln_id         UUID,
        remediation_id  UUID,
        rule_name       TEXT,
        created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
        expires_at      TIMESTAMP NOT NULL,
        unblock_vuln_id UUID,
        unblock_remediation_id UUID,
        unblocked_at    TIMESTAMP
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_soar_ip_blocks_open ON public.soar_ip_blocks (expires_at) WHERE unblocked_at IS NULL",
    # One row per LLM call made by centinela.call_ai_cascade() (tokens are what the provider reported, NULL if it didn't).
    # Feeds the "Tokens IA" screen; pruned to 30 days by centinela._record_ai_usage().
    """
    CREATE TABLE IF NOT EXISTS public.ai_provider_usage (
        id                UUID PRIMARY KEY DEFAULT uuidv7(),
        ts                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        tier              TEXT NOT NULL,
        model             TEXT,
        ok                BOOLEAN NOT NULL,
        prompt_tokens     INTEGER,
        completion_tokens INTEGER,
        latency_ms        INTEGER,
        error_kind        TEXT,
        error_text        TEXT,
        cooldown_until    TIMESTAMPTZ
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ai_provider_usage_tier_ts ON public.ai_provider_usage (tier, ts DESC)",
]


import re as _re

_ADD_COLUMN_RE = _re.compile(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\S+)\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+(\S+)", _re.I)


def ensure_core_schema(cur) -> None:
    """Apply every CORE_SCHEMA_STATEMENT on an already-open cursor. All statements are
    IF NOT EXISTS, so this is a cheap no-op once the objects exist and safe to call on every
    startup."""
    for stmt in CORE_SCHEMA_STATEMENTS:
        # `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` takes an ACCESS EXCLUSIVE lock even when the column is already there, and
        # the correlation loop keeps transactions open on vulnerability_log for tens of seconds -> startup / test setup hit
        # LockNotAvailable. Check the catalog first and skip the ALTER when there is nothing to add.
        m = _ADD_COLUMN_RE.search(stmt)
        if m:
            table, column = m.group(1), m.group(2)
            cur.execute(
                "SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = %s AND column_name = %s",
                (table.split(".")[-1], column),
            )
            if cur.fetchone():
                continue
        cur.execute(stmt)
