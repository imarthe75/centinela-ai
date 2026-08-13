import os
import requests
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor

# Connect to db -- credentials from environment, never hardcoded (see CASMARTS_CORE_DB_* in .env)
conn = psycopg2.connect(
    host=os.environ["CASMARTS_CORE_DB_HOST"],
    database=os.environ["CASMARTS_CORE_DB_NAME"],
    user=os.environ["CASMARTS_CORE_DB_USER"],
    password=os.environ["CASMARTS_CORE_DB_PASSWORD"]
)

def json_serializable(data):
    if isinstance(data, dict):
        return {k: json_serializable(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [json_serializable(v) for v in data]
    elif hasattr(data, "strftime"):
        return data.strftime("%Y-%m-%d %H:%M")
    return data

def render_pdf_with_weasyprint(html_content: str) -> bytes:
    from weasyprint import HTML
    from io import BytesIO
    try:
        pdf_file = BytesIO()
        HTML(string=html_content).write_pdf(pdf_file)
        return pdf_file.getvalue()
    except Exception as e:
        raise Exception(f"WeasyPrint PDF generation failed: {str(e)}")

try:
    asset_name = "gateway"
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Info del activo
        cur.execute("SELECT id, asset_name, asset_type, endpoint, status, criticality, last_audit FROM public.infra_inventory WHERE asset_name = %s", (asset_name,))
        asset = cur.fetchone()
        if not asset:
            print("Asset not found in DB")
            exit(1)
        
        # Vulnerabilidades del activo
        cur.execute("SELECT severity, title, description, solution, detected_at FROM public.vulnerability_log WHERE asset_name = %s ORDER BY detected_at DESC", (asset_name,))
        vulns = cur.fetchall()

    report_data = {
        "generationDate": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "asset": asset,
        "vulns": vulns,
        "totalVulns": len(vulns),
        "criticalVulns": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
        "highVulns": sum(1 for v in vulns if v["severity"] == "HIGH")
    }
    
    html_content = f"""
    <html>
    <head>
        <title>Reporte de Activo: {asset_name}</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1E293B; }}
            h1 {{ color: #0f172a; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }}
            .meta-table, .vuln-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            .meta-table th, .meta-table td, .vuln-table th, .vuln-table td {{ border: 1px solid #e2e8f0; padding: 12px; text-align: left; }}
            .meta-table th {{ background-color: #f1f5f9; width: 30%; }}
            .vuln-table th {{ background-color: #f8fafc; }}
            .badge {{ padding: 4px 8px; border-radius: 6px; font-weight: bold; font-size: 12px; }}
            .badge-critical {{ background: #fee2e2; color: #991b1b; }}
            .badge-high {{ background: #ffedd5; color: #9a3412; }}
        </style>
    </head>
    <body>
        <h1>Reporte de Seguridad de Activo: {asset_name}</h1>
        <p><strong>Fecha de Generación:</strong> {report_data['generationDate']}</p>
        
        <h2>Detalles del Activo</h2>
        <table class="meta-table">
            <tr><th>Tipo de Activo</th><td>{asset['asset_type']}</td></tr>
            <tr><th>Endpoint</th><td>{asset['endpoint']}</td></tr>
            <tr><th>Wazuh Status</th><td>{asset['status']}</td></tr>
            <tr><th>Criticidad de Riesgo</th><td>{asset['criticality']}</td></tr>
            <tr><th>Último Audit / Escaneo</th><td>{asset['last_audit']}</td></tr>
        </table>

        <h2>Resumen de Vulnerabilidades ({report_data['totalVulns']})</h2>
        <p>Críticas: <strong>{report_data['criticalVulns']}</strong> | Altas: <strong>{report_data['highVulns']}</strong></p>

        <h2>Historial de Vulnerabilidades</h2>
        <table class="vuln-table">
            <tr><th>Severidad</th><th>Título</th><th>Descripción</th><th>Solución Sugerida</th></tr>
            {"".join([f"<tr><td><span class='badge badge-{v['severity'].lower()}'>{v['severity']}</span></td><td>{v['title']}</td><td>{v['description']}</td><td>{v['solution']}</td></tr>" for v in vulns])}
        </table>
    </body>
    </html>
    """

    pdf_bytes = render_pdf_with_weasyprint(html_content)
    print("Render success! Size:", len(pdf_bytes))

except Exception as e:
    import traceback
    traceback.print_exc()

finally:
    conn.close()
