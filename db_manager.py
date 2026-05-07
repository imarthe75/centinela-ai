import os
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager
import hvac

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
    "host": get_secret("DB_HOST", "casmarts-core-db-primary"),
    "database": get_secret("DB_NAME", "casmarts_security"),
    "user": get_secret("DB_USER", "admin"),
    "password": get_secret("DB_PASSWORD", "casmarts_secure_db_pwd_2026")
}

# Connection Pool Initialization
try:
    print(f"🔌 [DB-Manager] Initializing Connection Pool for {DB_CONFIG['host']}...")
    db_pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=2,
        maxconn=20,
        **DB_CONFIG
    )
    print("✅ [DB-Manager] Connection Pool initialized successfully.")
except Exception as e:
    print(f"❌ [DB-Manager] Error initializing Connection Pool: {e}")
    db_pool = None

@contextmanager
def get_db_connection():
    """Context manager to get a connection from the pool and return it."""
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
        db_pool.putconn(conn)

@contextmanager
def get_db_cursor(cursor_factory=None):
    """Context manager to get a cursor from a pooled connection."""
    with get_db_connection() as conn:
        cur = conn.cursor(cursor_factory=cursor_factory)
        try:
            yield cur
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cur.close()
