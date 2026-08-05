import sys
sys.path.insert(0, '/opt/centinela-ai')
from core import db_manager
from psycopg2.extras import RealDictCursor

with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
    cur.execute("SELECT id, asset_name, ip_address, asset_type FROM public.infra_inventory;")
    assets = cur.fetchall()
    print("=== ASSETS EN INVENTARIO ===")
    for a in assets:
        print(a)

    cur.execute("""
        SELECT v.id, v.asset_id, i.asset_name, v.cve_id, v.severity, v.status, r.id as remediation_id, r.script_path
        FROM public.vulnerability_log v
        LEFT JOIN public.infra_inventory i ON v.asset_id = i.id
        LEFT JOIN public.remediation_history r ON v.id = r.vuln_id;
    """)
    vulns = cur.fetchall()
    print("\n=== VULNERABILIDADES Y REMEDIACIONES ===")
    for v in vulns:
        print(v)
