import os
import sys
import json
from datetime import datetime, timedelta
import db_manager

def get_recent_runtime_alerts(minutes=30):
    """Retrieves runtime alerts from the last N minutes."""
    query = """
        SELECT id, asset_id, rule_name, priority, alert_text, output_fields, detected_at
        FROM runtime_alerts
        WHERE detected_at >= NOW() - INTERVAL '%s minutes'
    """
    alerts = []
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute(query, (minutes,))
            rows = cur.fetchall()
            for r in rows:
                alerts.append({
                    "id": r[0],
                    "asset_id": r[1],
                    "rule_name": r[2],
                    "priority": r[3],
                    "alert_text": r[4],
                    "output_fields": json.loads(r[5]) if isinstance(r[5], str) else r[5],
                    "detected_at": r[6]
                })
    except Exception as e:
        print(f"❌ [Heuristics-Engine] Error fetching runtime alerts: {e}")
    return alerts

def get_recent_vulnerabilities(minutes=30):
    """Retrieves vulnerabilities from the last N minutes."""
    query = """
        SELECT id, asset_id, cve_id, severity, description, detected_at, status
        FROM vulnerability_log
        WHERE detected_at >= NOW() - INTERVAL '%s minutes'
    """
    vulns = []
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute(query, (minutes,))
            rows = cur.fetchall()
            for r in rows:
                vulns.append({
                    "id": r[0],
                    "asset_id": r[1],
                    "cve_id": r[2],
                    "severity": r[3],
                    "description": r[4],
                    "detected_at": r[5],
                    "status": r[6]
                })
    except Exception as e:
        print(f"❌ [Heuristics-Engine] Error fetching vulnerabilities: {e}")
    return vulns

def log_heuristic_alert(asset_id, heuristic_cve, severity, description):
    """Logs the heuristic finding into vulnerability_log."""
    try:
        with db_manager.get_db_cursor() as cur:
            # Check if this exact heuristic CVE already exists for this asset
            cur.execute("""
                SELECT id, status FROM vulnerability_log 
                WHERE asset_id = %s AND cve_id = %s
            """, (asset_id, heuristic_cve))
            exists = cur.fetchone()
            
            if exists:
                # Update description, severity, reset status if resolved
                status = exists[1]
                new_status = 'REOPENED' if status == 'RESOLVED' else status
                cur.execute("""
                    UPDATE vulnerability_log 
                    SET severity = %s, description = %s, detected_at = NOW(), status = %s
                    WHERE id = %s
                """, (severity, description, new_status, exists[0]))
                print(f"  🔄 Updated Heuristic Alert in DB: [{severity}] {heuristic_cve}")
            else:
                # Insert new heuristic alert
                cur.execute("""
                    INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status, detected_at)
                    VALUES (%s, %s, %s, %s, 'NEW', NOW())
                """, (asset_id, heuristic_cve, severity, description))
                print(f"  📝 Logged Heuristic Alert in DB: [{severity}] {heuristic_cve}")
    except Exception as e:
        print(f"❌ [Heuristics-Engine] Error logging alert: {e}")

def run_heuristics_correlation(minutes=30):
    """
    Runs the temporal correlation engine over the last N minutes of data.
    Correlates runtime events (Wazuh, Falco) and static exposures to raise consolidated alerts.
    """
    print(f"🧠 [Heuristics-Engine] Starting temporal correlation cycle (Window: {minutes} minutes)...")
    
    alerts = get_recent_runtime_alerts(minutes)
    vulns = get_recent_vulnerabilities(minutes)
    
    if not alerts and not vulns:
        print("😴 [Heuristics-Engine] No recent events or vulnerabilities to correlate.")
        return
        
    # Group recent data by asset_id
    assets_data = {}
    
    for a in alerts:
        aid = a["asset_id"]
        if aid is None:
            continue
        if aid not in assets_data:
            assets_data[aid] = {"alerts": [], "vulns": []}
        assets_data[aid]["alerts"].append(a)
        
    for v in vulns:
        # Ignore heuristic alerts themselves in inputs to prevent self-loop feedback
        if v["cve_id"].startswith("HEURISTIC-"):
            continue
        aid = v["asset_id"]
        if aid not in assets_data:
            assets_data[aid] = {"alerts": [], "vulns": []}
        assets_data[aid]["vulns"].append(v)
        
    # Process heuristics per asset
    for asset_id, data in assets_data.items():
        asset_alerts = data["alerts"]
        asset_vulns = data["vulns"]
        
        # --- Rule 1: Control Plane Intrusion ---
        # Nmap/Checkov exposed services/ports + Falco container terminal/interactive execution/root escalate
        exposed_ports = [v for v in asset_vulns if v["cve_id"] in ["NMAP-SCAN", "CHECKOV-SCAN", "DB-BANNER-LEAK"]]
        suspicious_execution = [
            a for a in asset_alerts 
            if any(term in a["rule_name"].lower() for term in ["shell", "terminal", "spawn", "exec", "namespace", "privilege", "root"])
            or a["priority"] in ["CRITICAL", "HIGH", "WARNING"]
        ]
        
        if exposed_ports and suspicious_execution:
            print(f"⚠️ [Heuristics-Engine] Rule 1 triggered for Asset ID: {asset_id}!")
            
            # Format detailed description
            desc = (
                f"🚨 **CORRELACIÓN HEURÍSTICA: Intrusión en Plano de Control (Control Plane Intrusion)** 🚨\n\n"
                f"**Descripción:** Se ha detectado una exposición de servicios externos (puertos o configuración de infraestructura) "
                f"seguida por ejecuciones interactivas o comandos sospechosos dentro de los contenedores en un intervalo menor a {minutes} minutos.\n\n"
                f"**Evidencias Correlacionadas:**\n"
            )
            desc += "🔍 *Exposiciones Estáticas / Puertos:* \n"
            for ep in exposed_ports:
                desc += f"- [{ep['severity']}] `{ep['cve_id']}`: {ep['description'][:150]}...\n"
                
            desc += "\n⚡ *Alertas de Runtime Correlacionadas (Falco/Wazuh):* \n"
            for se in suspicious_execution:
                desc += f"- [{se['priority']}] `{se['rule_name']}`: {se['alert_text'][:150]}...\n"
                
            log_heuristic_alert(
                asset_id=asset_id,
                heuristic_cve="HEURISTIC-CONTROL-PLANE-INTRUSION",
                severity="CRITICAL",
                description=desc
            )
            
        # --- Rule 2: AI Spoke RAG Exfiltration ---
        # Medusa LLM Agent / Prompt Injection vulnerabilities + Outbound connection / Exfiltration logs
        medusa_vulns = [v for v in asset_vulns if v["cve_id"].startswith("MEDUSA-")]
        exfil_alerts = [
            a for a in asset_alerts 
            if any(term in a["rule_name"].lower() for term in ["network", "connect", "outbound", "exfiltrat", "download", "curl", "wget", "token", "unauthorized"])
        ]
        
        if medusa_vulns and exfil_alerts:
            print(f"⚠️ [Heuristics-Engine] Rule 2 triggered for Asset ID: {asset_id}!")
            
            desc = (
                f"🚨 **CORRELACIÓN HEURÍSTICA: Exfiltración de RAG / Agentes AI (AI Spoke RAG Exfiltration)** 🚨\n\n"
                f"**Descripción:** Se ha detectado una vulnerabilidad crítica de Agente AI (Prompt Injection o mal uso de herramientas detectada por Medusa) "
                f"correlacionada con conexiones de red salientes sospechosas o logs de descarga en el mismo componente de IA dentro de los últimos {minutes} minutos.\n\n"
                f"**Evidencias Correlacionadas:**\n"
            )
            desc += "🤖 *Vulnerabilidades AI-First (Medusa):* \n"
            for mv in medusa_vulns:
                desc += f"- [{mv['severity']}] `{mv['cve_id']}`: {mv['description'][:150]}...\n"
                
            desc += "\n🌐 *Actividad Anómala de Red/Runtime:* \n"
            for ea in exfil_alerts:
                desc += f"- [{ea['priority']}] `{ea['rule_name']}`: {ea['alert_text'][:150]}...\n"
                
            log_heuristic_alert(
                asset_id=asset_id,
                heuristic_cve="HEURISTIC-RAG-EXFILTRATION",
                severity="CRITICAL",
                description=desc
            )
            
        # --- Rule 3: Security Debt (Acumulación de Vulnerabilidades) ---
        # > 5 Medium/High/Critical findings on the same asset
        critical_findings = [v for v in asset_vulns if v["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]]
        if len(critical_findings) >= 5:
            print(f"⚠️ [Heuristics-Engine] Rule 3 triggered for Asset ID: {asset_id} ({len(critical_findings)} findings)!")
            
            desc = (
                f"🚨 **CORRELACIÓN HEURÍSTICA: Deuda de Seguridad Crítica (Security Debt)** 🚨\n\n"
                f"**Descripción:** El activo tiene una acumulación de {len(critical_findings)} vulnerabilidades "
                f"activas de severidad Media, Alta o Crítica detectadas en los últimos {minutes} minutos. "
                f"Esto indica que el activo representa un vector de ataque altamente expuesto y con una superficie de riesgo severa.\n\n"
                f"**Vulnerabilidades Acumuladas:**\n"
            )
            for cf in critical_findings:
                desc += f"- [{cf['severity']}] `{cf['cve_id']}`\n"
                
            log_heuristic_alert(
                asset_id=asset_id,
                heuristic_cve="HEURISTIC-SECURITY-DEBT",
                severity="HIGH",
                description=desc
            )
            
    print("✅ [Heuristics-Engine] Temporal correlation cycle completed successfully.")

if __name__ == "__main__":
    # Test correlation engine directly
    run_heuristics_correlation()
