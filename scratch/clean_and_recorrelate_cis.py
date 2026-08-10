"""
Clean up generic placeholder remediation_log entries and re-correlate active vulnerabilities.
"""
import sys
sys.path.insert(0, "/app")

from core import db_manager
import centinela

def main():
    with db_manager.get_db_cursor() as cur:
        # 1. Delete generic placeholder rows from remediation_log
        cur.execute("""
            DELETE FROM remediation_log 
            WHERE riesgo_detectado LIKE '%sin regla de remediación específica%' 
               OR script_remediacion LIKE '%Agente Wazuh activo%';
        """)
        deleted_count = cur.rowcount
        print(f"🗑️ Deleted {deleted_count} generic placeholder remediation log entries.")

        # 2. Fetch all OPEN vulnerabilities that do not have a remediation entry in remediation_log
        cur.execute("""
            SELECT v.id, v.asset_id, v.cve_id, v.severity, v.description, v.tool_source, 
                   v.url_path, v.open_status, a.asset_name, a.asset_type, a.endpoint
            FROM vulnerabilities v
            JOIN assets a ON v.asset_id = a.id
            WHERE v.open_status = 'OPEN'
            AND NOT EXISTS (
                SELECT 1 FROM remediation_log r WHERE r.vulnerability_id = v.id
            )
            ORDER BY v.id DESC;
        """)
        missing_vulns = cur.fetchall()
        print(f"🔍 Found {len(missing_vulns)} active vulnerabilities needing valid remediation generation.")

        recreated = 0
        for row in missing_vulns:
            vuln = {
                "id": row[0],
                "asset_id": row[1],
                "cve_id": row[2],
                "severity": row[3],
                "description": row[4] or "",
                "tool_source": row[5] or "",
                "url_path": row[6] or "",
                "open_status": row[7] or "OPEN",
                "asset_name": row[8] or "",
                "asset_type": row[9] or "",
                "endpoint": row[10] or "0.0.0.0"
            }
            
            # Generate clean heuristic analysis and script
            riesgo, impacto, accion = centinela.generate_heuristic_analysis(vuln)
            script = centinela.generate_heuristic_script(vuln)
            can_auto = centinela.heuristic_can_automate(vuln)

            cur.execute("""
                INSERT INTO remediation_log (
                    vulnerability_id, asset_name, cve_id, riesgo_detectado, 
                    impacto_negocio, accion_remediacion, script_remediacion, 
                    can_automate, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'PENDING_APPROVAL');
            """, (
                vuln["id"], vuln["asset_name"], vuln["cve_id"], riesgo, 
                impacto, accion, script, can_auto
            ))
            recreated += 1

        print(f"✅ Successfully created {recreated} clean, specific remediation entries!")

if __name__ == "__main__":
    main()
