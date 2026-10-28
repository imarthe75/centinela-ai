"""Baseline: the production schema as of 2026-10-05 (ADR-0008 #5).

On an EMPTY database (a fresh install or the disposable test DB) this creates the whole schema from database/baseline_schema.sql.
On the existing production database it is never executed: the database is marked at this revision with `alembic stamp 0001`.
Every later schema change goes in a new revision (`alembic revision -m "..."`), not in ad-hoc scripts.
"""
from pathlib import Path

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    sql = (Path(__file__).resolve().parents[3] / "database" / "baseline_schema.sql").read_text()
    # pg_dump emits psql meta-commands and a search_path reset that a plain DBAPI execute cannot run; strip them.
    cleaned = "\n".join(l for l in sql.splitlines() if not l.startswith("\\") and "set_config('search_path'" not in l)
    # raw DBAPI cursor: no parameter processing, so '%' inside the SQL (LIKE patterns, formats) is left alone
    cur = op.get_bind().connection.cursor()
    cur.execute(cleaned)


def downgrade():
    raise RuntimeError("The baseline cannot be downgraded: it is the starting point of the schema history.")
