"""Per-project / per-group data access (ADR-0019, phase 1).

access_scopes grants a user or an Authentik group access to the assets whose name equals an asset prefix or sits below it
('GitLab2/grupo-a/proyecto-a' covers 'GitLab2/grupo-a/proyecto-a/...' and 'GitLab2/grupo-a/proyecto-a@branch'). Admins and the service token are never restricted.
"""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.access_scopes (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            subject_type text NOT NULL CHECK (subject_type IN ('user', 'group')),
            subject text NOT NULL,
            asset_prefix text NOT NULL CHECK (length(asset_prefix) > 0),
            note text,
            created_by text,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (subject_type, subject, asset_prefix)
        );
        COMMENT ON TABLE public.access_scopes IS
            'Alcance de datos por usuario o grupo de Authentik: qué activos (por prefijo de nombre) puede ver. Sin filas para un usuario rige ACCESS_SCOPE_DEFAULT. ADR-0019.';
        COMMENT ON COLUMN public.access_scopes.subject_type IS 'user = preferred_username o correo; group = nombre del grupo de Authentik.';
        COMMENT ON COLUMN public.access_scopes.asset_prefix IS 'Nombre de activo o prefijo (GitLab2/grupo-a/proyecto-a cubre sus subproyectos y ramas).';
        CREATE INDEX IF NOT EXISTS idx_access_scopes_subject ON public.access_scopes (subject_type, lower(subject));
    """)


def downgrade():
    op.execute("DROP TABLE IF EXISTS public.access_scopes")
