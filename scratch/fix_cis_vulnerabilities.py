"""
Update all generic CIS findings in vulnerability_log and remediation_history with real scripts and detailed technical analysis.
"""
import sys
import os
sys.path.insert(0, "/app")

from core import db_manager
import centinela

def main():
    with db_manager.get_db_cursor() as cur:
        # Fetch all rows with generic summary or CIS findings
        cur.execute("""
            SELECT v.id, v.cve_id, v.severity, v.executive_summary, v.business_impact, v.developer_steps,
                   i.asset_name, i.asset_type, i.endpoint, r.script_path
            FROM public.vulnerability_log v
            JOIN public.infra_inventory i ON v.asset_id = i.id
            LEFT JOIN public.remediation_history r ON v.id = r.vuln_id
            WHERE v.executive_summary LIKE '%sin regla de remediación específica%'
               OR v.cve_id LIKE 'CIS%'
               OR r.script_path IS NULL;
        """)
        rows = cur.fetchall()
        print(f"🔍 Found {len(rows)} vulnerability records to update with clean CIS/heuristic remediations.")

        updated_count = 0
        for r in rows:
            vuln_id = r[0]
            cve_id = r[1]
            severity = r[2]
            asset_name = r[6]
            asset_type = r[7]
            endpoint = r[8]
            existing_script_path = r[9]

            vuln = {
                "id": vuln_id,
                "cve_id": cve_id,
                "severity": severity,
                "asset_name": asset_name,
                "asset_type": asset_type,
                "endpoint": endpoint,
                "url_path": cve_id
            }

            riesgo, impacto, accion = centinela.generate_heuristic_analysis(vuln)
            script_code = centinela.generate_heuristic_script(vuln)
            can_automate = centinela.heuristic_can_automate(vuln)

            # Update vulnerability_log text fields
            cur.execute("""
                UPDATE public.vulnerability_log
                SET executive_summary = %s,
                    business_impact = %s,
                    developer_steps = %s
                WHERE id = %s;
            """, (riesgo, impacto, accion, vuln_id))

            # Determine script_path
            script_path = existing_script_path or f"/app/data/remediation/{cve_id}_{vuln_id}.sh"
            
            # Write physical script file
            try:
                os.makedirs(os.path.dirname(script_path), exist_ok=True)
                with open(script_path, "w") as f:
                    f.write(str(script_code))
                os.chmod(script_path, 0o755)
            except Exception as fe:
                print(f"⚠️ Could not write script file {script_path}: {fe}")

            # Check if exists in remediation_history
            cur.execute("SELECT id FROM public.remediation_history WHERE vuln_id = %s LIMIT 1;", (vuln_id,))
            rh_row = cur.fetchone()
            if rh_row:
                cur.execute("""
                    UPDATE public.remediation_history
                    SET script_path = %s, can_automate = %s
                    WHERE vuln_id = %s;
                """, (script_path, str(can_automate), vuln_id))
            else:
                cur.execute("""
                    INSERT INTO public.remediation_history (vuln_id, script_path, can_automate, executed_bool)
                    VALUES (%s, %s, %s, FALSE);
                """, (vuln_id, script_path, str(can_automate)))

            updated_count += 1

        print(f"✅ Successfully updated {updated_count} vulnerability records and script files!")

if __name__ == "__main__":
    main()
