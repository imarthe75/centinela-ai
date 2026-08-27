"""
Centinela Temporal Heuristics Correlation Engine
Correlates static findings, SAST/SCA vulnerabilities, and runtime alerts (Wazuh/Falco) to detect compound attack vectors.
"""
import os
import sys
import json
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
from core import db_manager

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
        from core import deduplication_engine
        with db_manager.get_db_cursor() as cur:
            # description varies between calls (e.g. HEURISTIC-SECURITY-DEBT lists whichever
            # underlying CVEs happened to be accumulated this time), so heuristic_cve itself is
            # passed as url_path to keep the fingerprint stable across re-runs instead of
            # falling back to the varying description. preserve_status=True keeps the original
            # RESOLVED->REOPENED nuance (and leaves any other status untouched).
            action, _ = deduplication_engine.log_finding_deduplicated(
                cur, asset_id, heuristic_cve, severity, description, "heuristics-engine",
                url_path=heuristic_cve, open_status="NEW", preserve_status=True
            )
            if action == "updated":
                print(f"  🔄 Updated Heuristic Alert in DB: [{severity}] {heuristic_cve}")
            elif action == "merged":
                print(f"  🔗 Merged Heuristic Alert into existing cross-tool ticket: [{severity}] {heuristic_cve}")
            elif action == "suppressed":
                print(f"  🔇 Suppressed Heuristic Alert (analyst-recorded): [{severity}] {heuristic_cve}")
            else:
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
                f"**Resumen Ejecutivo:** Se ha detectado un posible acceso no autorizado a los sistemas internos. Alguien podría estar ejecutando comandos directamente dentro de nuestra infraestructura.\n\n"
                f"**Detalles Técnicos:** Se ha detectado una exposición de servicios externos (puertos o configuración de infraestructura) "
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
                f"**Resumen Ejecutivo:** Una aplicación de Inteligencia Artificial muestra indicios de estar siendo manipulada, con un posible riesgo de robo o fuga de información hacia el exterior.\n\n"
                f"**Detalles Técnicos:** Se ha detectado una vulnerabilidad crítica de Agente AI (Prompt Injection o mal uso de herramientas detectada por Medusa) "
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
                f"**Resumen Ejecutivo:** Este sistema presenta múltiples fallos de seguridad graves sin resolver. Está muy expuesto a ataques y requiere de atención o mantenimiento de forma urgente para reducir el riesgo.\n\n"
                f"**Detalles Técnicos:** El activo tiene una acumulación de {len(critical_findings)} vulnerabilidades "
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
            
        # --- Rule 4: DAST Auth Bypass Chain ---
        # ZAP found auth/session flaw + runtime privilege escalation alert
        zap_auth_vulns = [v for v in asset_vulns if v["cve_id"].startswith("ZAP-") and
                          any(term in v["description"].lower() for term in ["auth", "session", "cookie", "csrf", "bypass", "token"])]
        priv_alerts = [a for a in asset_alerts if
                       any(term in a["rule_name"].lower() for term in ["privilege", "root", "sudo", "escalat", "admin"])]

        if zap_auth_vulns and priv_alerts:
            print(f"⚠️ [Heuristics-Engine] Rule 4 triggered for Asset ID: {asset_id} (DAST Auth Bypass)!")
            desc = (
                f"🚨 **CORRELACIÓN HEURÍSTICA: Cadena de Bypass de Autenticación (DAST → Runtime)** 🚨\n\n"
                f"**Resumen Ejecutivo:** Existe un fallo crítico de seguridad que le permite a un atacante saltarse la pantalla de inicio de sesión y obtener permisos de administrador dentro de la aplicación.\n\n"
                f"**Detalles Técnicos:** ZAP DAST detectó vulnerabilidades de autenticación/sesión en la aplicación web "
                f"Y se observó escalada de privilegios en el mismo activo dentro de {minutes} minutos. "
                f"Esto puede indicar explotación activa de las debilidades DAST encontradas.\n\n"
                f"**Vulnerabilidades DAST (ZAP):**\n"
            )
            for zv in zap_auth_vulns[:5]:
                desc += f"- [{zv['severity']}] `{zv['cve_id']}`: {zv['description'][:120]}...\n"
            desc += "\n**Alertas de Runtime (Privilege Escalation):**\n"
            for pa in priv_alerts[:5]:
                desc += f"- [{pa['priority']}] `{pa['rule_name']}`: {pa['alert_text'][:120]}...\n"

            log_heuristic_alert(
                asset_id=asset_id,
                heuristic_cve="HEURISTIC-DAST-AUTH-BYPASS-CHAIN",
                severity="CRITICAL",
                description=desc
            )

        # --- Rule 5: Secrets Exposure + Network Activity ---
        # Secrets found in code + outbound network connections = active exfil risk
        secrets_vulns = [v for v in asset_vulns if v["cve_id"].startswith("SECRETS-")]
        net_alerts = [a for a in asset_alerts if
                      any(term in a["rule_name"].lower() for term in ["network", "connect", "outbound", "download", "curl", "wget"])]

        if secrets_vulns and net_alerts:
            print(f"⚠️ [Heuristics-Engine] Rule 5 triggered for Asset ID: {asset_id} (Secrets Exfil)!")
            desc = (
                f"🚨 **CORRELACIÓN HEURÍSTICA: Exfiltración de Secretos (Secrets + Network Activity)** 🚨\n\n"
                f"**Resumen Ejecutivo:** Se han detectado contraseñas o claves de acceso expuestas, en conjunto con actividad de red inusual que sugiere que un tercero podría estar robando esa información.\n\n"
                f"**Detalles Técnicos:** Se detectaron credenciales o secretos hardcodeados en el repositorio "
                f"Y actividad de red saliente sospechosa en el mismo activo dentro de {minutes} minutos. "
                f"Existe riesgo de que los secretos comprometidos sean usados activamente para exfiltración.\n\n"
                f"**Secretos Detectados:**\n"
            )
            for sv in secrets_vulns[:5]:
                desc += f"- [{sv['severity']}] `{sv['cve_id']}`: {sv['description'][:120]}...\n"
            desc += "\n**Actividad de Red Sospechosa:**\n"
            for na in net_alerts[:5]:
                desc += f"- [{na['priority']}] `{na['rule_name']}`: {na['alert_text'][:120]}...\n"

            log_heuristic_alert(
                asset_id=asset_id,
                heuristic_cve="HEURISTIC-SECRETS-EXFIL-RISK",
                severity="CRITICAL",
                description=desc
            )

        # --- Rule 6: Multi-Scanner Convergence ---
        # Same asset flagged by 3+ different scan engines = verified high risk
        scan_engines_hit = set()
        for v in asset_vulns:
            if v.get("severity") in ["HIGH", "CRITICAL"]:
                engine = "nuclei"  # default for legacy findings without scan_engine
                desc_lower = v.get("description", "").lower()
                if v["cve_id"].startswith("ZAP-"):
                    engine = "zap"
                elif v["cve_id"].startswith("MEDUSA-"):
                    engine = "medusa"
                elif v["cve_id"].startswith("SECRETS-"):
                    engine = "secrets"
                elif v["cve_id"].startswith("OSINT-"):
                    engine = "spiderfoot"
                elif v["cve_id"].startswith("CHECKOV-"):
                    engine = "checkov"
                scan_engines_hit.add(engine)

        if len(scan_engines_hit) >= 3:
            print(f"⚠️ [Heuristics-Engine] Rule 6 triggered for Asset ID: {asset_id} (Multi-Scanner)!")
            desc = (
                f"🚨 **CORRELACIÓN HEURÍSTICA: Convergencia Multi-Scanner (Activo de Alto Riesgo Verificado)** 🚨\n\n"
                f"**Resumen Ejecutivo:** Múltiples herramientas de seguridad coinciden simultáneamente en que este activo es altamente vulnerable. No es una falsa alarma, el riesgo es real, verificado y requiere acción inmediata.\n\n"
                f"**Detalles Técnicos:** El activo ha sido marcado como vulnerable por **{len(scan_engines_hit)} motores de escaneo diferentes** "
                f"dentro de los últimos {minutes} minutos. Esta convergencia multi-scanner confirma que el activo tiene "
                f"una superficie de ataque real y verificada, no falsos positivos.\n\n"
                f"**Motores que detectaron vulnerabilidades HIGH/CRITICAL:**\n"
            )
            for engine in scan_engines_hit:
                engine_vulns = [v for v in asset_vulns
                                if v.get("severity") in ["HIGH", "CRITICAL"]
                                and (v["cve_id"].startswith(engine.upper()[:3]) or engine == "nuclei")]
                desc += f"- 🔍 **{engine.upper()}**: {len(engine_vulns)} hallazgos críticos/altos\n"

            log_heuristic_alert(
                asset_id=asset_id,
                heuristic_cve="HEURISTIC-MULTI-SCANNER-CONVERGENCE",
                severity="CRITICAL",
                description=desc
            )

    print("✅ [Heuristics-Engine] Temporal correlation cycle completed successfully.")


class HeuristicsEngine:
    """Motor Heurístico Determinista basado en reglas y expresiones lógicas (Resident Agent OS)."""
    def __init__(self, rules_file: Optional[str] = None):
        self.rules = [
            {
                "id": "H001",
                "condition": {"op": "and", "args": [{"var": "has_external_api", "op": "eq", "val": True}, {"var": "has_local_alternative", "op": "eq", "val": True}]},
                "action": "use_local",
                "priority": 1
            },
            {
                "id": "H002",
                "condition": {"op": "and", "args": [{"var": "valkey_available", "op": "eq", "val": True}]},
                "action": "check_semantic_cache",
                "priority": 2
            },
            {
                "id": "H003",
                "condition": {"var": "retry_count", "op": "gte", "val": 3},
                "action": "halt_and_reflect",
                "priority": 3
            }
        ]

    def _eval_cond(self, cond: Dict[str, Any], context: Dict[str, Any]) -> bool:
        if "op" in cond and cond["op"] in ["and", "or"]:
            op = cond["op"]
            args = cond.get("args", [])
            if op == "and":
                return all(self._eval_cond(a, context) for a in args)
            else:
                return any(self._eval_cond(a, context) for a in args)
        
        var_val = context.get(cond.get("var"))
        op = cond.get("op")
        target_val = cond.get("val")

        if op == "eq":
            return var_val == target_val
        elif op == "gte":
            return var_val is not None and var_val >= target_val
        elif op == "lte":
            return var_val is not None and var_val <= target_val
        return False

    def evaluate(self, context: Dict[str, Any]) -> List[str]:
        triggered_actions = []
        # Sort by priority
        sorted_rules = sorted(self.rules, key=lambda r: r.get("priority", 99))
        for rule in sorted_rules:
            if self._eval_cond(rule["condition"], context):
                triggered_actions.append(rule["action"])
        return triggered_actions


if __name__ == "__main__":
    run_heuristics_correlation()
