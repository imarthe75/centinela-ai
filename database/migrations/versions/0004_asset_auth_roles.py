"""asset_auth_roles / asset_auth_sources: the application profiles (roles) discovered in a repository, and which repositories feed an application asset.

Roles are NAMES only (no credentials: those live in Vault, `<namespace>/authz/<asset>`). They feed the dropdown of the "credenciales de prueba" panel
so that one set of test credentials can be stored per profile of an application.
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS public.asset_auth_roles (
            id uuid PRIMARY KEY DEFAULT uuidv7(),
            asset_id uuid NOT NULL REFERENCES public.infra_inventory(id) ON DELETE CASCADE,
            role_name text NOT NULL,
            source text NOT NULL,
            source_file text,
            discovered_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (asset_id, role_name, source)
        );
        CREATE INDEX IF NOT EXISTS idx_asset_auth_roles_asset ON public.asset_auth_roles (asset_id);
        CREATE TABLE IF NOT EXISTS public.asset_auth_sources (
            asset_id uuid NOT NULL REFERENCES public.infra_inventory(id) ON DELETE CASCADE,
            source_asset_id uuid NOT NULL REFERENCES public.infra_inventory(id) ON DELETE CASCADE,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (asset_id, source_asset_id)
        );
    """)


def downgrade():
    op.execute("DROP TABLE IF EXISTS public.asset_auth_sources; DROP TABLE IF EXISTS public.asset_auth_roles;")
