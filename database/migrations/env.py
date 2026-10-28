"""Alembic environment (ADR-0008 #5). Raw-SQL migrations (the app uses psycopg2, not an ORM), connection taken from the app's own config."""
from urllib.parse import quote_plus

from alembic import context
from sqlalchemy import create_engine, pool

from core.db_manager import DB_CONFIG

config = context.config
target_metadata = None


def _url():
    c = DB_CONFIG
    return f"postgresql+psycopg2://{quote_plus(str(c['user']))}:{quote_plus(str(c['password']))}@{c['host']}/{c['database']}"


def run_migrations_offline():
    context.configure(url=_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
