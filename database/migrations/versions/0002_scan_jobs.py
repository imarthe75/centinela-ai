"""scan_jobs: persistent job queue for long-running scans (ADR-0008 #4).

A scan that was running when a service restarted used to be lost (the work lived in a thread). Jobs now live in Postgres with a lease: a worker
that dies stops renewing its lease, and the job goes back to QUEUED for another worker.
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.scan_jobs (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            kind text NOT NULL,
            target text NOT NULL,
            payload jsonb NOT NULL DEFAULT '{}'::jsonb,
            status text NOT NULL DEFAULT 'QUEUED',
            attempts integer NOT NULL DEFAULT 0,
            max_attempts integer NOT NULL DEFAULT 3,
            worker text,
            lease_until timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            started_at timestamptz,
            finished_at timestamptz,
            last_error text,
            CONSTRAINT scan_jobs_status_chk CHECK (status IN ('QUEUED', 'RUNNING', 'DONE', 'FAILED'))
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_claim ON public.scan_jobs (status, created_at)")
    # at most ONE active (queued or running) job per (kind, target): enqueue is idempotent and atomic
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_jobs_active ON public.scan_jobs (kind, target) WHERE status IN ('QUEUED', 'RUNNING')")


def downgrade():
    op.execute("DROP TABLE IF EXISTS public.scan_jobs")
