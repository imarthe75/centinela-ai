import sqlite3

db_path = "/home/ia/ecosistema-casmarts/centinela-ai/sentinela.db"
try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"SQLite Tables: {tables}")
    
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table};")
        count = cursor.fetchone()[0]
        print(f"  Table {table}: {count} rows")
        
        # print columns
        cursor.execute(f"PRAGMA table_info({table});")
        cols = [c[1] for c in cursor.fetchall()]
        print(f"    Columns: {cols}")
        
except Exception as e:
    print(f"Error: {e}")
