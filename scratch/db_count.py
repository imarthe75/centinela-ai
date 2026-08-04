import sys
import os
sys.path.insert(0, '/app')
from core import db_manager

with db_manager.get_db_connection() as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM vulnerability_log;")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE executive_summary LIKE '%None%';")
        none_exec = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE business_impact LIKE '%No impact%';")
        no_impact = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM vulnerability_log WHERE developer_steps LIKE '%No steps%';")
        no_steps = cur.fetchone()[0]
        print(f"Total: {total}, none_exec: {none_exec}, no_impact: {no_impact}, no_steps: {no_steps}")
        
        # Let's print the unique statuses
        cur.execute("SELECT status, COUNT(*) FROM vulnerability_log GROUP BY status;")
        print("Statuses:", cur.fetchall())
