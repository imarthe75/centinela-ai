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
"""

CORE_SCHEMA_STATEMENTS = [
    # ------------------------------------------------------------------ item 3
    # A finding is suppressed when EVERY one of a row's non-NULL predicates matches it and the
    # row is active and unexpired. At least one predicate must be non-NULL (enforced by the API,
    # not the schema) so a suppression can never accidentally mute the whole platform.
    """
    CREATE TABLE IF NOT EXISTS public.finding_suppressions (
        id               SERIAL PRIMARY KEY,
        asset_id         INTEGER REFERENCES public.infra_inventory(id) ON DELETE CASCADE,
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

    # ------------------------------------------------------------------ item 4
    """
    CREATE TABLE IF NOT EXISTS public.agent_actions (
        id           BIGSERIAL PRIMARY KEY,
        action_type  TEXT NOT NULL,
        actor        TEXT NOT NULL DEFAULT 'centinela-ai',
        entity_type  TEXT,
        entity_id    BIGINT,
        asset_id     INTEGER REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
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
        id                      BIGSERIAL PRIMARY KEY,
        asset_id                INTEGER REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
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
        incident_id  BIGINT NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
        source       TEXT NOT NULL,
        source_id    BIGINT NOT NULL,
        occurred_at  TIMESTAMP NOT NULL,
        tactic       TEXT,
        severity     TEXT,
        summary      TEXT,
        PRIMARY KEY (incident_id, source, source_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.incidents (status, detected_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_incident_events_src ON public.incident_events (source, source_id)",
]


def ensure_core_schema(cur) -> None:
    """Apply every CORE_SCHEMA_STATEMENT on an already-open cursor. All statements are
    IF NOT EXISTS, so this is a cheap no-op once the objects exist and safe to call on every
    startup."""
    for stmt in CORE_SCHEMA_STATEMENTS:
        cur.execute(stmt)
