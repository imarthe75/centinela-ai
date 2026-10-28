"""scan_runs / scan_run_baseline: one row per scan of an asset, plus the findings that were open just before it started.

The comparison report ("última versión vs anterior") classifies each finding of the baseline by what the scan did to it
(solventado / persiste / suprimido / no re-verificado) and lists what appeared (nuevo / reaparecido). Without the baseline the
"before" state is lost: a scan updates and resolves rows in place.
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.scan_runs (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            asset_id uuid NOT NULL REFERENCES public.infra_inventory(id) ON DELETE CASCADE,
            started_at timestamptz NOT NULL DEFAULT now(),
            finished_at timestamptz,
            status text NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING', 'DONE', 'FAILED')),
            source text NOT NULL,
            commit_sha text,
            baseline_count integer NOT NULL DEFAULT 0,
            note text
        );
        CREATE INDEX IF NOT EXISTS idx_scan_runs_asset ON public.scan_runs (asset_id, started_at DESC);
        CREATE TABLE IF NOT EXISTS public.scan_run_baseline (
            run_id uuid NOT NULL REFERENCES public.scan_runs(id) ON DELETE CASCADE,
            finding_id uuid NOT NULL,
            cve_id text,
            severity text,
            finding_category text,
            status text,
            url_path text,
            scan_engine text,
            PRIMARY KEY (run_id, finding_id)
        );
    """)


def downgrade():
    op.execute("DROP TABLE IF EXISTS public.scan_run_baseline; DROP TABLE IF EXISTS public.scan_runs;")
