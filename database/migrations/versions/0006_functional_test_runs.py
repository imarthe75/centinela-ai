"""functional_test_runs / functional_test_cases: full runs sent by centinela-smart-tests (ADR-0015), for the "Pruebas funcionales" tab.

Until now Centinela only received the security-relevant FAILED cases (as findings). A run's real picture (passed / failed / blocked /
not executed, and why) lived only in the runner's own report. The runner now sends the whole run; findings keep their own endpoint.
"""
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.functional_test_runs (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            run_key text NOT NULL UNIQUE,
            project text NOT NULL,
            cycle text,
            package text,
            started text,
            finished text,
            asset_name text,
            asset_id uuid REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
            source text NOT NULL DEFAULT 'centinela-smart-tests',
            summary jsonb NOT NULL,
            meta jsonb NOT NULL DEFAULT '{}'::jsonb,
            received_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS idx_functional_test_runs_project ON public.functional_test_runs (project, received_at DESC);
        CREATE TABLE IF NOT EXISTS public.functional_test_cases (
            run_id uuid NOT NULL REFERENCES public.functional_test_runs(id) ON DELETE CASCADE,
            case_id text NOT NULL,
            status text NOT NULL CHECK (status IN ('PASSED', 'FAILED', 'BLOCKED', 'NOT_EXECUTED')),
            criterion text,
            detail text,
            reason text,
            substitution text,
            security_relevant boolean NOT NULL DEFAULT false,
            category text,
            evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
            ord integer NOT NULL DEFAULT 0,
            PRIMARY KEY (run_id, case_id)
        );
    """)


def downgrade():
    op.execute("DROP TABLE IF EXISTS public.functional_test_cases; DROP TABLE IF EXISTS public.functional_test_runs;")
