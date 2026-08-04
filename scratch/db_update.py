import sys
import os
sys.path.insert(0, '/app')
from core import db_manager

sql_delete = """
DELETE FROM public.remediation_history 
WHERE vuln_id IN (
    SELECT id FROM public.vulnerability_log 
    WHERE executive_summary LIKE '%None%' 
       OR business_impact LIKE '%No impact%' 
       OR developer_steps LIKE '%No steps%'
);
"""

sql_update = """
UPDATE public.vulnerability_log 
SET status = 'PENDING', 
    executive_summary = NULL, 
    business_impact = NULL, 
    developer_steps = NULL 
WHERE executive_summary LIKE '%None%' 
   OR business_impact LIKE '%No impact%' 
   OR developer_steps LIKE '%No steps%';
"""

with db_manager.get_db_connection() as conn:
    with conn.cursor() as cur:
        cur.execute(sql_delete)
        deleted = cur.rowcount
        cur.execute(sql_update)
        updated = cur.rowcount
        print(f"Deleted: {deleted}, Updated: {updated}")
