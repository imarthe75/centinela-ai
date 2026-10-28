import sys
sys.path.insert(0, '/app')
from core import db_manager
from psycopg2.extras import RealDictCursor

with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
    cur.execute('''
        SELECT 
            count(CASE WHEN fix_patch LIKE '%%Patrón detectado%%' THEN 1 END) as patron,
            count(CASE WHEN fix_patch LIKE '%%Corrección explícita%%' THEN 1 END) as correccion,
            count(CASE WHEN fix_patch LIKE '%%Configuración de seguridad endurecida%%' THEN 1 END) as endurecida,
            count(CASE WHEN fix_patch LIKE '--- a/CMMI%%' THEN 1 END) as fake_cmmi,
            count(CASE WHEN fix_patch LIKE '--- a/HEURISTIC%%' THEN 1 END) as fake_heuristic,
            count(CASE WHEN fix_patch LIKE '--- a/SONARQUBE%%' THEN 1 END) as fake_sonarqube
        FROM public.vulnerability_log;
    ''')
    res = cur.fetchone()
    print("====================================================")
    print("📊 RESULTADO FINAL DE AUDITORÍA GLOBAL DE BASE DE DATOS:")
    for k, v in res.items():
        print(f"   {k}: {v}")
    print("====================================================")
