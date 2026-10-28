"""triage: analyst classification catalog for a GitLab group (project + sub-projects).

The workbook "proyecto-a · Hallazgos de Centinela clasificados" separated each finding into Vulnerabilidad / Falso positivo / Calidad by ROOT CAUSE.
That judgement is an analyst's, not something a scanner can derive, so it is stored as data (who/when) instead of being guessed:

  * triage_groups      one row per GitLab group the report is built for (instance + path) with the plan parameters
  * triage_root_causes the catalog (V-01, FP-03, C-07 ...) with the analyst's rationale, strategy, owner and work-plan estimate
  * triage_rules       how a finding is matched to a root cause (rule / path / line). A finding no rule matches stays SIN CLASIFICAR.

Nothing here suppresses or changes a finding: it only classifies for reporting.
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.triage_groups (
            group_key text PRIMARY KEY,
            instance text NOT NULL,
            group_path text NOT NULL,
            title text NOT NULL,
            hours_per_day numeric NOT NULL DEFAULT 8,
            test_pct numeric NOT NULL DEFAULT 0.3,
            fp_check_hours numeric NOT NULL DEFAULT 0.5,
            areas jsonb NOT NULL DEFAULT '[]'::jsonb,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.triage_root_causes (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            group_key text NOT NULL REFERENCES public.triage_groups(group_key) ON DELETE CASCADE,
            code text NOT NULL,
            classification text NOT NULL,
            kind text,
            title text NOT NULL,
            severity text,
            certainty text,
            rationale text,
            how_to_confirm text,
            strategy text,
            owner text,
            outdated boolean NOT NULL DEFAULT false,
            dedup_scope text NOT NULL DEFAULT 'line',
            plan jsonb,
            classified_by text,
            classified_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT triage_rc_scope_chk CHECK (dedup_scope IN ('line', 'file')),
            CONSTRAINT triage_rc_class_chk CHECK (classification IN ('Vulnerabilidad', 'Falso positivo', 'Calidad')),
            CONSTRAINT triage_rc_unique UNIQUE (group_key, code)
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.triage_rules (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            group_key text NOT NULL REFERENCES public.triage_groups(group_key) ON DELETE CASCADE,
            rule_regex text NOT NULL,
            engine text,
            asset_regex text,
            path_regex text,
            line integer,
            root_cause_code text NOT NULL,
            priority integer NOT NULL DEFAULT 0,
            note text,
            created_by text,
            created_at timestamptz NOT NULL DEFAULT now(),
            FOREIGN KEY (group_key, root_cause_code) REFERENCES public.triage_root_causes (group_key, code) ON DELETE CASCADE
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_triage_rules_group ON public.triage_rules (group_key, priority DESC)")


def downgrade():
    op.execute("DROP TABLE IF EXISTS public.triage_rules")
    op.execute("DROP TABLE IF EXISTS public.triage_root_causes")
    op.execute("DROP TABLE IF EXISTS public.triage_groups")
