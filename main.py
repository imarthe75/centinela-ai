from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import psycopg2
from datetime import datetime
from psycopg2.extras import RealDictCursor
import pandas as pd
import db_manager
from pydantic import BaseModel
from typing import Optional
import requests
import re

def is_private_ip(ip):
    # Regex simple para detectar rangos RFC 1918 (10.x, 172.16-31.x, 192.168.x) y localhost
    private_patterns = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^localhost'
    ]
    return any(re.match(pattern, ip) for pattern in private_patterns)

def get_geoip_location(ip):
    """Obtiene lat/lon para IPs públicas usando ip-api.com"""
    if is_private_ip(ip):
        return None, None
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,lat,lon", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return data.get("lat"), data.get("lon")
    except Exception as e:
        print(f"GeoIP Error for {ip}: {e}")
    return None, None
class AssetModel(BaseModel):
    asset_name: str
    asset_type: str
    endpoint: str
    criticality: Optional[str] = "MEDIUM"
    location_lat: Optional[float] = None
    location_lon: Optional[float] = None

app = FastAPI(title="Centinela-AI Security API")

@app.post("/api/inventory")
async def add_inventory_item(item: AssetModel):
    try:
        with db_manager.get_db_cursor() as cur:
            # Evitar duplicidad de endpoints (Ej. misma IP 199 con diferente asset_name)
            cur.execute("SELECT id FROM public.infra_inventory WHERE endpoint = %s", (item.endpoint,))
            existing_ep = cur.fetchone()
            
            # Autogeolocalización si faltan coordenadas y es IP pública
            if item.location_lat is None or item.location_lon is None:
                lat, lon = get_geoip_location(item.endpoint)
                if lat and lon:
                    item.location_lat = lat
                    item.location_lon = lon

            if existing_ep:
                cur.execute("""
                    UPDATE public.infra_inventory SET
                        asset_name = %s,
                        asset_type = %s,
                        criticality = %s,
                        location_lat = %s,
                        location_lon = %s
                    WHERE endpoint = %s
                """, (item.asset_name, item.asset_type, item.criticality, item.location_lat, item.location_lon, item.endpoint))
            else:
                cur.execute("""
                    INSERT INTO public.infra_inventory (asset_name, asset_type, endpoint, criticality, location_lat, location_lon)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (asset_name) DO UPDATE SET
                        asset_type = EXCLUDED.asset_type,
                        endpoint = EXCLUDED.endpoint,
                        criticality = EXCLUDED.criticality,
                        location_lat = EXCLUDED.location_lat,
                        location_lon = EXCLUDED.location_lon
                """, (item.asset_name, item.asset_type, item.endpoint, item.criticality, item.location_lat, item.location_lon))
        return {"status": "success", "message": f"Asset {item.asset_name} registered."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# CORS para el nuevo frontend React
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DB_CONFIG moved to db_manager.py

@app.get("/api/stats")
async def get_stats():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            # Hallazgos totales
            cur.execute("SELECT COUNT(*) as total FROM public.vulnerability_log")
            total = cur.fetchone()["total"]
            
            # Cola de IA
            cur.execute("""
                SELECT COUNT(*) as count 
                FROM public.vulnerability_log v 
                LEFT JOIN public.remediation_history r ON v.id = r.vuln_id 
                WHERE r.id IS NULL
            """)
            pending_ia = cur.fetchone()["count"]
            
            # Críticos y Altos
            cur.execute("SELECT COUNT(*) as count FROM public.vulnerability_log WHERE severity = 'CRITICAL'")
            critical = cur.fetchone()["count"]
            
            cur.execute("SELECT COUNT(*) as count FROM public.vulnerability_log WHERE severity = 'HIGH'")
            high = cur.fetchone()["count"]
            
            # Pendientes de aprobación
            cur.execute("SELECT COUNT(*) as count FROM public.remediation_history WHERE approval_token = 'PENDING_APPROVAL'")
            pending_approval = cur.fetchone()["count"]
            
            return {
                "total": total,
                "pending_ia": pending_ia,
                "critical": critical,
                "high": high,
                "pending_approval": pending_approval
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats/extended")
async def get_extended_stats():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            # Runtime Alerts
            cur.execute("SELECT COUNT(*) as count FROM public.runtime_alerts")
            alerts_count = cur.fetchone()["count"]
            
            # Endpoints
            cur.execute("SELECT COUNT(*) as count FROM public.infra_inventory")
            endpoints_count = cur.fetchone()["count"]
            
            # Simulated Wazuh/User metrics (can be expanded later)
            users_count = 129 # Example from Seceon image
            private_hosts = endpoints_count
            public_hosts = 0 # Placeholder
            
            return {
                "alerts": alerts_count,
                "endpoints": endpoints_count,
                "users": users_count,
                "private_hosts": private_hosts,
                "public_hosts": public_hosts
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/map")
async def get_map_data():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT asset_name, asset_type, criticality, location_lat, location_lon, country_code 
                FROM public.infra_inventory 
                WHERE location_lat IS NOT NULL
            """)
            results = cur.fetchall()
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts/runtime")
async def get_runtime_alerts():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT r.id, r.priority, r.rule_name, r.alert_text, r.detected_at, i.asset_name
                FROM public.runtime_alerts r
                LEFT JOIN public.infra_inventory i ON r.asset_id = i.id
                ORDER BY r.detected_at DESC
                LIMIT 50
            """)
            results = cur.fetchall()
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/risk-distribution")
async def get_risk_distribution():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT severity, COUNT(*) as value FROM public.vulnerability_log GROUP BY severity")
            results = cur.fetchall()
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/inventory")
async def get_inventory():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    i.asset_name, 
                    i.asset_type, 
                    i.endpoint, 
                    COALESCE(COUNT(DISTINCT v.id), 0) as vulnerability_count,
                    COALESCE(COUNT(DISTINCT r.id), 0) as runtime_alerts_count
                FROM public.infra_inventory i
                LEFT JOIN public.vulnerability_log v ON i.id = v.asset_id
                LEFT JOIN public.runtime_alerts r ON i.id = r.asset_id
                GROUP BY i.asset_name, i.asset_type, i.endpoint
            """)
            results = cur.fetchall()
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/remediation")
async def get_remediation_history(asset: Optional[str] = None):
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            query = """
                SELECT DISTINCT ON (v.id) 
                       v.id, r.script_path, r.executed_bool, r.approval_token, r.executed_at, r.can_automate, r.log_output,
                       v.cve_id, v.severity, i.asset_name,
                       v.executive_summary, v.business_impact, v.developer_steps, v.status
                FROM public.vulnerability_log v
                LEFT JOIN public.remediation_history r ON v.id = r.vuln_id
                JOIN public.infra_inventory i ON v.asset_id = i.id
            """
            params = []
            if asset:
                query += " WHERE i.asset_name ILIKE %s"
                params.append(f"%{asset}%")
            
            # El ORDER BY para DISTINCT ON debe empezar con la columna de distinción
            query += " ORDER BY v.id DESC, r.executed_at DESC NULLS LAST LIMIT 5000"
            
            cur.execute(query, params)
            results = cur.fetchall()
            return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/remediation/script/{vuln_id}")
async def get_remediation_script(vuln_id: int):
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT script_path FROM public.remediation_history WHERE vuln_id = %s", (vuln_id,))
            res = cur.fetchone()
        
        if not res:
            raise HTTPException(status_code=404, detail="Script path not found")
            
        script_path = res["script_path"]
        if os.path.exists(script_path):
            with open(script_path, "r") as f:
                content = f.read()
            return {"content": content, "filename": os.path.basename(script_path)}
        else:
            raise HTTPException(status_code=404, detail=f"Script file not found on disk: {script_path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/remediation/approve/{vuln_id}")
async def approve_remediation(vuln_id: int):
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("UPDATE public.remediation_history SET approval_token = 'APPROVED' WHERE vuln_id = %s", (vuln_id,))
            return {"status": "success", "message": "Remediation approved and queued for execution."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/investigate/runtime")
async def investigate_alert(data: dict):
    alert_id = data.get("alert_id")
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM public.runtime_alerts WHERE id = %s", (alert_id,))
            alert = cur.fetchone()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        prompt = f"""
        Analiza esta alerta de seguridad en tiempo real y proporciona un reporte ultra-conciso para un CISO:
        
        ALERTA: {alert['rule_name']}
        PRIORIDAD: {alert['priority']}
        DETALLE: {alert['alert_text']}
        TIMESTAMP: {alert['detected_at']}
        
        Proporciona el resultado en JSON con:
        - "contexto": ¿Qué significa esto técnicamente?
        - "riesgo": Nivel de peligro real para el negocio.
        - "accion_inmediata": [Lista de 3 pasos críticos a seguir]
        - "remediation_script": "Comando bash exacto o script para mitigar esta amenaza de inmediato. Usa '\\n' para saltos de línea."
        
        NOTA OBLIGATORIA: Si el activo no es un contenedor (ej. servidor o máquina virtual), DEBES incluir explícitamente en el último paso de 'accion_inmediata' la siguiente instrucción de instalación del agente Wazuh: "Para habilitar remediación automática, ejecute: curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x_amd64.deb && sudo dpkg -i wazuh-agent*.deb"
        """
        
        # Primary: Gemini
        try:
            from google import genai
            from google.genai import types
            
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                raise Exception("Missing GOOGLE_API_KEY")
                
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model="gemini-1.5-flash-latest",
                contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json")
            )
            return json.loads(response.text)
        except Exception as gem_e:
            print(f"Gemini failed, trying Groq fallback: {gem_e}")
            
            # Fallback: Groq
            groq_key = os.getenv("GROQ_API_KEY")
            if groq_key:
                from groq import Groq
                client = Groq(api_key=groq_key)
                chat_completion = client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model="llama-3.3-70b-versatile",
                    response_format={"type": "json_object"}
                )
                return json.loads(chat_completion.choices[0].message.content)
            else:
                raise gem_e

    except Exception as e:
        print(f"Critical error in investigation: {e}")
        return {
            "contexto": f"Error crítico de comunicación con el motor de IA: {str(e)}",
            "riesgo": "CRÍTICO (SIN ANALIZAR)",
            "accion_inmediata": ["Revisar logs en /app/logs/security.log", "Ejecutar triaje manual", "Reiniciar agentes de IA"]
        }

@app.get("/api/health")
async def get_system_health():
    # Mocking for now but checking DB connectivity
    try:
        with db_manager.get_db_connection() as conn:
            pass
        return {
            "status": "Healthy",
            "services": [
                {"name": "Nginx Gateway", "status": "Online", "latency": "12ms"},
                {"name": "Centinela Backend", "status": "Online", "latency": "5ms"},
                {"name": "Database Maestro", "status": "Online", "latency": "2ms"},
                {"name": "AI Engine (Gemini)", "status": "Online", "latency": "450ms"},
                {"name": "Scanning Engine (Nuclei)", "status": "Active", "latency": "N/A"}
            ],
            "last_check": datetime.now().isoformat()
        }
    except Exception as e:
        return {"status": "Degraded", "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
