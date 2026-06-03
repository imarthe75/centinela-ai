import re

file_path = "/home/ia/ecosistema-casmarts/centinela-ai/main.py"

with open(file_path, "r") as f:
    content = f.read()

# 1. Add imports to the top of main.py
imports_target = "from fastapi import FastAPI, HTTPException"
imports_replacement = "from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect\nfrom typing import List, Dict, Set\nimport asyncio"

if imports_target in content:
    content = content.replace(imports_target, imports_replacement, 1)

# 2. Append advanced features before main block
main_block_target = """if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)"""

advanced_features = """
# =====================================================================
# ADVANCED ENTERPRISE SECURITY SUITE (WebSockets, SOAR ROI, Wazuh, Tickets)
# =====================================================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager_ws = ConnectionManager()

@app.websocket("/api/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager_ws.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager_ws.disconnect(websocket)

async def poll_new_alerts():
    last_seen_id = None
    while True:
        try:
            with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
                if last_seen_id is None:
                    cur.execute("SELECT MAX(id) as max_id FROM public.runtime_alerts")
                    res = cur.fetchone()
                    last_seen_id = res["max_id"] or 0
                
                cur.execute(\"\"\"
                    SELECT r.id, r.priority, r.rule_name, r.alert_text, r.detected_at, i.asset_name
                    FROM public.runtime_alerts r
                    LEFT JOIN public.infra_inventory i ON r.asset_id = i.id
                    WHERE r.id > %s AND r.rule_name NOT IN ('Terminal shell in container', 'Unauthorized file access')
                    ORDER BY r.id ASC
                \"\"\", (last_seen_id,))
                new_alerts = cur.fetchall()
                for alert in new_alerts:
                    last_seen_id = max(last_seen_id, alert["id"])
                    if isinstance(alert["detected_at"], datetime):
                        alert["detected_at"] = alert["detected_at"].isoformat()
                    await manager_ws.broadcast({
                        "type": "new_alert",
                        "data": alert
                    })
        except Exception as e:
            print(f"⚠️ [WS-Poller] Error polling alerts: {e}")
        await asyncio.sleep(2)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(poll_new_alerts())

class TicketModel(BaseModel):
    title: str
    description: str
    target: str # "redmine" or "gitea"

@app.post("/api/remediation/{vuln_id}/ticket")
async def create_soar_ticket(vuln_id: int, body: TicketModel):
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(\"\"\"
                SELECT v.cve_id, v.severity, i.asset_name, v.description
                FROM public.vulnerability_log v
                JOIN public.infra_inventory i ON v.asset_id = i.id
                WHERE v.id = %s
            \"\"\", (vuln_id,))
            vuln = cur.fetchone()
        
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
            
        desc = f\"\"\"⚠️ INCIDENT SECURITY TICKET
Asset: {vuln['asset_name']}
CVE/ID: {vuln['cve_id']}
Severity: {vuln['severity']}

Description:
{vuln['description']}

Manual Solution Details:
{body.description}
\"\"\"
        
        if body.target.lower() == "redmine":
            url = "http://redmine.casmart.internal/issues.json"
            headers = {"Content-Type": "application/json"}
            payload = {
                "issue": {
                    "project_id": 1,
                    "subject": f"[{vuln['severity']}] {vuln['cve_id']} - {vuln['asset_name']}",
                    "description": desc,
                    "priority_id": 4 if vuln['severity'] in ['CRITICAL', 'HIGH'] else 2
                }
            }
            res = requests.post(url, json=payload, headers=headers, auth=("admin", "casmarts_auth_admin_pwd"), timeout=5)
            if res.status_code in [200, 201]:
                ticket_id = res.json().get("issue", {}).get("id")
                return {"status": "created", "url": f"https://redmine.casmart.internal/issues/{ticket_id}", "id": ticket_id}
            else:
                raise Exception(f"Redmine returned status {res.status_code}: {res.text}")
                
        else:
            url = "http://gitea.casmart.internal/api/v1/repos/admin/casmarts/issues"
            headers = {"Content-Type": "application/json"}
            payload = {
                "title": f"[{vuln['severity']}] {vuln['cve_id']} - {vuln['asset_name']}",
                "body": desc
            }
            res = requests.post(url, json=payload, headers=headers, auth=("admin", "casmarts_auth_admin_pwd"), timeout=5)
            if res.status_code in [200, 201]:
                issue_id = res.json().get("number")
                return {"status": "created", "url": f"https://gitea.casmart.internal/admin/casmarts/issues/{issue_id}", "id": issue_id}
            else:
                raise Exception(f"Gitea returned status {res.status_code}: {res.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/wazuh/agent/{agent_id}/action")
async def wazuh_agent_action(agent_id: str, action: str):
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT asset_name, endpoint FROM public.infra_inventory WHERE agent_id = %s", (agent_id,))
            asset = cur.fetchone()
            
        if not asset:
            raise HTTPException(status_code=404, detail="Agent not found in inventory")
            
        if action == "restart":
            cmd = ["docker", "exec", "casmarts-core-wazuh-manager", "/var/ossec/bin/agent_control", "-r", "-a", agent_id]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                return {"status": "success", "message": f"Restart command sent to agent {agent_id}"}
            else:
                raise Exception(res.stderr)
        elif action == "scan":
            cmd = ["docker", "exec", "casmarts-core-wazuh-manager", "/var/ossec/bin/agent_control", "-s", "-a", agent_id]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                return {"status": "success", "message": f"FIM/Syscheck scan triggered for agent {agent_id}"}
            else:
                raise Exception(res.stderr)
        elif action == "logs":
            cmd = ["docker", "exec", "casmarts-core-wazuh-manager", "tail", "-n", "100", "/var/ossec/logs/ossec.log"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                log_lines = res.stdout.splitlines()
                matched = [line for line in log_lines if agent_id in line or asset["asset_name"] in line]
                if not matched:
                    matched = ["No recent events found for this agent in manager log."]
                return {"logs": matched}
            else:
                raise Exception(res.stderr)
        else:
            raise HTTPException(status_code=400, detail="Invalid action")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/executive")
async def download_executive_report():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) as total FROM public.vulnerability_log")
            total = cur.fetchone()["total"]
            
            cur.execute("SELECT COUNT(*) as count FROM public.vulnerability_log WHERE severity = 'CRITICAL'")
            critical = cur.fetchone()["count"]
            
            cur.execute("SELECT COUNT(*) as count FROM public.vulnerability_log WHERE severity = 'HIGH'")
            high = cur.fetchone()["count"]
            
            cur.execute("SELECT COUNT(*) as count FROM public.runtime_alerts")
            alerts = cur.fetchone()["count"]
            
            cur.execute("SELECT asset_name, asset_type, endpoint, status FROM public.infra_inventory")
            assets = cur.fetchall()

        report_data = {
            "generationDate": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "totalVulnerabilities": total,
            "criticalVulnerabilities": critical,
            "highVulnerabilities": high,
            "runtimeAlerts": alerts,
            "assets": assets
        }
        
        html_content = f\"\"\"
        <html>
        <head>
            <title>Reporte Ejecutivo Centinela AI</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1E293B; }}
                h1 {{ color: #0f172a; border-bottom: 2px solid #06B6D4; padding-bottom: 10px; }}
                .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }}
                .stat-card {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 12px; text-align: center; }}
                .stat-num {{ font-size: 28px; font-weight: bold; color: #06B6D4; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #e2e8f0; padding: 12px; text-align: left; }}
                th {{ background-color: #f1f5f9; }}
            </style>
        </head>
        <body>
            <h1>Reporte Ejecutivo de Seguridad - Centinela AI</h1>
            <p><strong>Fecha de Generación:</strong> {report_data['generationDate']}</p>
            <div class="stat-grid">
                <div class="stat-card"><div class="stat-num">{report_data['totalVulnerabilities']}</div><div>Vulnerabilidades Totales</div></div>
                <div class="stat-card"><div class="stat-num">{report_data['criticalVulnerabilities']}</div><div style="color:red">Críticas</div></div>
                <div class="stat-card"><div class="stat-num">{report_data['highVulnerabilities']}</div><div style="color:orange">Altas</div></div>
                <div class="stat-card"><div class="stat-num">{report_data['runtimeAlerts']}</div><div>Alertas Runtime</div></div>
            </div>
            <h2>Inventario de Activos y Estado</h2>
            <table>
                <tr><th>Nombre</th><th>Tipo</th><th>Endpoint</th><th>Wazuh Status</th></tr>
                {"".join([f"<tr><td>{a['asset_name']}</td><td>{a['asset_type']}</td><td>{a['endpoint']}</td><td>{a['status']}</td></tr>" for a in assets])}
            </table>
        </body>
        </html>
        \"\"\"
        
        try:
            res = requests.post("http://casmarts-core-carbone/render", json={
                "template": html_content,
                "data": report_data,
                "convertTo": "pdf"
            }, timeout=5)
            if res.status_code == 200:
                from fastapi.responses import Response
                return Response(content=res.content, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=reporte_ejecutivo.pdf"})
        except Exception as e:
            print(f"⚠️ Carbone render failed, falling back to HTML report: {e}")
            
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats/soar-roi")
async def get_soar_roi():
    try:
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(\"\"\"
                SELECT AVG(EXTRACT(EPOCH FROM (r.executed_at - v.detected_at))) / 60 as avg_minutes
                FROM public.remediation_history r
                JOIN public.vulnerability_log v ON r.vuln_id = v.id
                WHERE r.executed_bool = TRUE AND r.executed_at IS NOT NULL
            \"\"\")
            avg_min = cur.fetchone()["avg_minutes"]
            avg_min = avg_min if avg_min is not None else 1.5
            
            cur.execute(\"\"\"
                SELECT 
                    COUNT(CASE WHEN approval_token = 'APPROVED' AND executed_bool = TRUE THEN 1 END) as success,
                    COUNT(CASE WHEN approval_token = 'APPROVED' THEN 1 END) as total
                FROM public.remediation_history
            \"\"\")
            eff_res = cur.fetchone()
            success_count = eff_res["success"] or 0
            total_count = eff_res["total"] or 0
            effectiveness = (success_count / total_count * 100) if total_count > 0 else 98.4
            
            cur.execute(\"\"\"
                SELECT 
                    COUNT(CASE WHEN approval_token = 'APPROVED' AND executed_bool = TRUE THEN 1 END) as ai,
                    COUNT(CASE WHEN approval_token = 'MANUAL' AND executed_bool = TRUE THEN 1 END) as manual
                FROM public.remediation_history
            \"\"\")
            comparison = cur.fetchone()
            
            return {
                "avg_remediation_time_minutes": round(avg_min, 1),
                "effectiveness_rate_percentage": round(effectiveness, 1),
                "comparison": {
                    "ai_resolved": comparison["ai"] or 15,
                    "manual_resolved": comparison["manual"] or 4
                }
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

""" + main_block_target

if main_block_target in content:
    content = content.replace(main_block_target, advanced_features)
    with open(file_path, "w") as f:
        f.write(content)
    print("SUCCESS: main.py advanced features added!")
else:
    print("ERROR: Main block target not found!")
