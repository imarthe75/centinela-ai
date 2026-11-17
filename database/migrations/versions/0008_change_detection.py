"""Change detection for GitLab assets: only re-analyze code (or rules) that changed since the last analysis.

* scan_runs.engine_version: fingerprint of the detector code a scan ran with (core/change_detection.engine_version). With the commit
  already stored in scan_runs.commit_sha, "what was analyzed" is (commit, engine_version).
* gitlab_branch_heads: the latest commit of every branch that has a GitLab asset (plus each project's fleet branch), refreshed in the
  background and on demand. Comparing it with the last analyzed commit tells which assets changed, without asking GitLab per page view.
"""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE public.scan_runs ADD COLUMN IF NOT EXISTS engine_version text;
        COMMENT ON COLUMN public.scan_runs.engine_version IS
            'Huella del código de los detectores con que corrió el escaneo (core/change_detection.engine_version). NULL = escaneo anterior al registro.';

        CREATE TABLE IF NOT EXISTS public.gitlab_branch_heads (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            instance text NOT NULL,
            project_path text NOT NULL,
            branch text NOT NULL,
            asset_name text NOT NULL,
            commit_sha text,
            committed_at timestamptz,
            is_fleet_branch boolean NOT NULL DEFAULT false,
            missing boolean NOT NULL DEFAULT false,
            checked_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_gitlab_branch_heads UNIQUE (instance, project_path, branch)
        );
        CREATE INDEX IF NOT EXISTS idx_gitlab_branch_heads_asset ON public.gitlab_branch_heads (asset_name);
        COMMENT ON TABLE public.gitlab_branch_heads IS
            'Último commit conocido de cada rama de GitLab con activo en Centinela (y la rama que audita el escaneo diario). Se compara con scan_runs.commit_sha para saber qué cambió.';
        COMMENT ON COLUMN public.gitlab_branch_heads.asset_name IS 'Nombre del activo GitLab[N]/<ruta>@<rama> (core/gitlab_instances.asset_name).';
        COMMENT ON COLUMN public.gitlab_branch_heads.commit_sha IS 'Último commit de la rama en GitLab al momento de checked_at; NULL si la rama ya no existe.';
        COMMENT ON COLUMN public.gitlab_branch_heads.is_fleet_branch IS 'Es la rama que el escaneo diario elige para el proyecto (develop/desarrollo/dev o la rama por defecto).';
        COMMENT ON COLUMN public.gitlab_branch_heads.missing IS 'La rama tiene activo en Centinela pero ya no existe en GitLab.';
        COMMENT ON COLUMN public.gitlab_branch_heads.checked_at IS 'Cuándo se consultó GitLab por última vez para esta rama.';
    """)


def downgrade():
    op.execute("DROP TABLE IF EXISTS public.gitlab_branch_heads; ALTER TABLE public.scan_runs DROP COLUMN IF EXISTS engine_version;")
