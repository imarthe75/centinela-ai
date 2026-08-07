"""
Centinela Database & Vault Connection Manager
Manages PostgreSQL connection pooling, Vault secret resolution, and database transaction contexts.
"""
import os
try:
    import psycopg2
    from psycopg2 import pool
except ImportError:
    psycopg2 = None
    pool = None
from contextlib import contextmanager
try:
    import hvac
except ImportError:
    hvac = None


def get_vault_secrets():
    """Fetch secrets from Vault if configured"""
    vault_addr = os.getenv("VAULT_ADDR")
    vault_token = os.getenv("VAULT_TOKEN")
    
    if not vault_addr or not vault_token:
        return {}
        
    try:
        client = hvac.Client(url=vault_addr, token=vault_token)
        read_response = client.secrets.kv.v2.read_secret_version(path='casmarts/security')
        secrets = read_response['data']['data']
        return secrets
    except Exception as e:
        print(f"⚠️ [DB-Manager] Could not fetch secrets from Vault: {e}")
        return {}

# Load Secrets once
VAULT_SECRETS = get_vault_secrets()

def get_secret(key, default=None):
    env_val = os.getenv(key)
    if env_val:
        return env_val
    return VAULT_SECRETS.get(key, default)

# DB Config
DB_CONFIG = {
    "host": get_secret("DB_HOST", "10.4.3.23"),
    "database": get_secret("DB_NAME", "centinela_db"),
    "user": get_secret("DB_USER", "centinela_user"),
    "password": get_secret("DB_PASSWORD", "centinela_sec_db_2026")
}

# Connection Pool Initialization
try:
    if psycopg2:
        print(f"🔌 [DB-Manager] Initializing Connection Pool for {DB_CONFIG['host']}...")
        db_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=20,
            **DB_CONFIG
        )
        print("✅ [DB-Manager] Connection Pool initialized successfully.")
    else:
        db_pool = None
except Exception as e:
    print(f"❌ [DB-Manager] Error initializing Connection Pool: {e}")
    db_pool = None

@contextmanager
def get_db_connection():
    """Context manager to get a connection from the pool and return it."""
    if not psycopg2:
        yield None
        return
        
    if not db_pool:
        # Fallback to direct connection if pool failed to initialize
        conn = psycopg2.connect(**DB_CONFIG)
        try:
            yield conn
        finally:
            conn.close()
        return

    conn = db_pool.getconn()
    try:
        yield conn
    finally:
        # putconn() used to run unconditionally, which recycles a dead connection right back
        # into the pool if the server side closed it (idle timeout, network blip, Postgres
        # restart) -- psycopg2 marks conn.closed non-zero in that case, but nothing here ever
        # checked it. The next getconn() call would then hand that same poisoned connection to
        # a *different* caller, who'd immediately hit "connection already closed" on their first
        # query. This is what caused Sentinel's intermittent main-loop crashes: not a bug in
        # Sentinel itself, but a pool that kept re-issuing a connection it should have discarded.
        # close=True tells the pool to actually drop this slot and open a fresh connection next
        # time instead of recycling it.
        db_pool.putconn(conn, close=bool(conn.closed))

@contextmanager
def get_db_cursor(cursor_factory=None):
    """Context manager to get a cursor from a pooled connection."""
    with get_db_connection() as conn:
        if conn is None:
            yield None
            return
        cur = conn.cursor(cursor_factory=cursor_factory)
        try:
            yield cur
            conn.commit()
        except Exception as e:
            # rollback() itself raises InterfaceError on an already-dead connection (e.g. the
            # server closed it mid-transaction) -- guard it so that secondary failure doesn't
            # mask the real exception `e` that callers need to see.
            try:
                conn.rollback()
            except Exception:
                pass
            raise e
        finally:
            try:
                cur.close()
            except Exception:
                pass
