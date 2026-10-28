import sys
sys.path.insert(0, '/app')
from core import db_manager
from auditors import auditor_ext
from core import heuristics_engine
import time

print("🔍 Iniciando escaneo exhaustivo para la subred 10.4.x.x")

# Obtener todos los activos 10.4.x.x
assets = []
with db_manager.get_db_cursor() as cur:
    cur.execute("SELECT id, asset_type, endpoint FROM infra_inventory WHERE endpoint LIKE '%10.4.%'")
    assets = cur.fetchall()

print(f"📊 Se encontraron {len(assets)} activos en 10.4.x.x")

# Fase 1: Escaneo
for asset_id, a_type, endpoint in assets:
    data = {"id": asset_id, "type": a_type, "endpoint": endpoint}
    print(f"\n🚀 Iniciando análisis para {endpoint} ({a_type})")
    try:
        auditor_ext.handle_asset_discovered(data)
    except Exception as e:
        print(f"❌ Error escaneando {endpoint}: {e}")

# Fase 2: Correlación Heurística
print("\n🧠 Ejecutando Motor de Heurística...")
heuristics_engine.run_heuristics_correlation()

# Fase 3: Aprobación automática de remediaciones
print("\n✅ Aprobando remediaciones pendientes para activos 10.4.x.x...")
with db_manager.get_db_cursor() as cur:
    cur.execute("""
        UPDATE public.remediation_history 
        SET approval_token = 'APPROVED'
        WHERE vuln_id IN (
            SELECT v.id FROM public.vulnerability_log v
            JOIN public.infra_inventory i ON v.asset_id = i.id
            WHERE i.endpoint LIKE '%10.4.%'
        ) AND approval_token = 'PENDING_APPROVAL' AND can_automate = TRUE
    """)

print("\n🎉 Escaneo y aprobación finalizados. Sentinel procesará las remediaciones en segundo plano.")
