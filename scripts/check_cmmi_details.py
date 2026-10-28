import sys
sys.path.insert(0, '/app')
from core import db_manager
from psycopg2.extras import RealDictCursor

with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
    cur.execute('''
        SELECT id, asset_id, cve_id, url_path, fix_patch, executive_summary, developer_steps
        FROM public.vulnerability_log
        WHERE cve_id = 'CMMI-GIT-HISTORY-CHECK'
        ORDER BY asset_id;
    ''')
    rows = cur.fetchall()
    print(f"Total CMMI-GIT-HISTORY-CHECK rows across all assets: {len(rows)}")
    proyecto-g_rows = [r for r in rows if 55059 <= (r['asset_id'] or 0) <= 55066]
    non_proyecto-g_rows = [r for r in rows if not (55059 <= (r['asset_id'] or 0) <= 55066)]
    print(f"proyecto-g rows: {len(proyecto-g_rows)}")
    for r in proyecto-g_rows:
        print(f"  Asset {r['asset_id']} | ID {r['id']}")
        print(f"  Patch:\n{r['fix_patch']}")
    print(f"Non-proyecto-g rows: {len(non_proyecto-g_rows)}")
    if non_proyecto-g_rows:
        print("Sample Non-proyecto-g row patch:")
        print(non_proyecto-g_rows[0]['fix_patch'])
