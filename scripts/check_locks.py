import sys
sys.path.insert(0, '/app')
from core import db_manager
from psycopg2.extras import RealDictCursor

with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
    cur.execute('''
        SELECT l.pid, a.usename, a.client_addr, a.state, now() - a.query_start as dur, l.mode, a.query
        FROM pg_locks l
        JOIN pg_stat_activity a ON l.pid = a.pid
        WHERE l.relation = 'public.vulnerability_log'::regclass
          AND l.mode LIKE '%Exclusive%'
          AND l.pid <> pg_backend_pid();
    ''')
    rows = cur.fetchall()
    print("Exclusive locks on vulnerability_log:", len(rows))
    for r in rows:
        print(f"PID {r['pid']} | Mode {r['mode']} | Client {r['client_addr']} | Dur {r['dur']} | Query: {r['query'][:120]}")
        print(f"Terminating PID {r['pid']}...")
        cur.execute("SELECT pg_terminate_backend(%s);", (r['pid'],))
        print("Terminated.")
