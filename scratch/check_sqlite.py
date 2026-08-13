import re
import sqlite3

db_path = "/home/ia/ecosistema-casmarts/centinela-ai/sentinela.db"
# SQL identifiers (table/column names) can't be bound via `?` placeholders -- SQLite has no
# parameter syntax for them, so f-string interpolation is unavoidable here. Validating against
# a strict identifier allowlist before interpolating is the standard mitigation for this
# specific, unavoidable case.
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"SQLite Tables: {tables}")

    for table in tables:
        if not _SAFE_IDENTIFIER_RE.match(table):
            print(f"  Skipping table with unexpected name: {table!r}")
            continue
        count_query = f"SELECT COUNT(*) FROM {table};"
        cursor.execute(count_query)
        count = cursor.fetchone()[0]
        print(f"  Table {table}: {count} rows")

        # print columns
        pragma_query = f"PRAGMA table_info({table});"
        cursor.execute(pragma_query)
        cols = [c[1] for c in cursor.fetchall()]
        print(f"    Columns: {cols}")
        
except Exception as e:
    print(f"Error: {e}")
