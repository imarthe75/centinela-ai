"""ci_test_reports: CI test reports of a project (JUnit + JaCoCo summaries) sent by centinela-smart-tests (its ADR-0002 §5).

Read-only data about the project's own pipeline, shown next to the functional runs: whether the unit/integration suite passed, its
coverage, and whether it contains the 401/403/409 API tests the development standards require (detected by test name).
Idempotent per (asset, project, commit, pipeline): re-sending the same pipeline replaces it.
"""
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.ci_test_reports (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            report_key text NOT NULL UNIQUE,
            asset_name text NOT NULL,
            asset_id uuid REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
            project text,
            ref text,
            commit_sha text,
            pipeline text,
            tests integer NOT NULL CHECK (tests >= 0),
            failures integer NOT NULL CHECK (failures >= 0),
            errors integer NOT NULL CHECK (errors >= 0),
            skipped integer NOT NULL CHECK (skipped >= 0),
            coverage_line_pct numeric(5,1),
            coverage_branch_pct numeric(5,1),
            has_401_tests boolean,
            has_403_tests boolean,
            has_409_tests boolean,
            summary jsonb NOT NULL,
            source text NOT NULL DEFAULT 'centinela-smart-tests',
            received_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS idx_ci_test_reports_asset ON public.ci_test_reports (asset_name, received_at DESC);
        COMMENT ON TABLE public.ci_test_reports IS 'Resumen de reportes de pruebas del CI de un proyecto (JUnit/JaCoCo) enviado por centinela-smart-tests; solo lectura.';
        COMMENT ON COLUMN public.ci_test_reports.has_403_tests IS 'Hay pruebas de 403 detectadas por NOMBRE (heurística: false = no encontradas por nombre).';
    """)


def downgrade():
    op.execute("DROP TABLE IF EXISTS public.ci_test_reports;")
