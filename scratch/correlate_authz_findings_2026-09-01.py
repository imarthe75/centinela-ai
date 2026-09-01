"""
One-time backfill: correlate all currently-open AUTHZ-INCONSISTENT-FAMILY and
AUTHZ-CLIENT-SIDE-ONLY findings (the exact vulnerability class the SIDECO retest
reported -- privilege escalation via a missing server-side role check / client-side-only
enforcement) through the real AI cascade, instead of waiting for them to reach the front of
the ~46k-row main correlation queue.

Mirrors centinela.py's main_loop() persistence exactly (status -> CORRELATED,
executive_summary/business_impact/developer_steps/fix_patch, script written to
/app/data/remediation/), so results are indistinguishable from the periodic loop's own output
and immediately visible in the SOAR queue.
"""
import sys, os, time
sys.path.insert(0, "/app")
from core import db_manager, agent_ledger
import centinela

CVE_IDS = ("AUTHZ-INCONSISTENT-FAMILY", "AUTHZ-CLIENT-SIDE-ONLY")


def fetch_batch():
    with db_manager.get_db_cursor() as cur:
        cur.execute("""
            SELECT v.id, v.cve_id, v.severity, v.description, v.url_path, v.asset_id,
                   i.asset_name, i.asset_type, i.endpoint
            FROM vulnerability_log v
            JOIN infra_inventory i ON v.asset_id = i.id
            WHERE v.cve_id = ANY(%s) AND v.status NOT IN ('RESOLVED', 'SUPPRESSED', 'CORRELATED')
            ORDER BY v.id
        """, (list(CVE_IDS),))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def main():
    rows = fetch_batch()
    print(f"{len(rows)} hallazgo(s) AUTHZ-INCONSISTENT-FAMILY / AUTHZ-CLIENT-SIDE-ONLY por correlacionar")
    ok = fail = 0
    for i, vuln in enumerate(rows, 1):
        print(f"\n[{i}/{len(rows)}] #{vuln['id']} {vuln['cve_id']} {vuln['asset_name']} :: {vuln['url_path']}")
        try:
            analysis = centinela.correlate_vulnerability(vuln)
        except Exception as e:
            import traceback; traceback.print_exc()
            fail += 1
            continue
        if analysis == "RATE_LIMIT":
            print("  ⏳ rate limit -- esperando 30s")
            time.sleep(30)
            continue
        if not analysis:
            print("  ⚠️ sin análisis (todos los proveedores fallaron)")
            fail += 1
            continue

        script_path = f"/app/data/remediation/{vuln['cve_id']}_{vuln['id']}.sh"
        os.makedirs(os.path.dirname(script_path), exist_ok=True)
        fix_patch = analysis.get('fix_patch', '') or ''
        if fix_patch.strip():
            remediation_content = (
                f"# Parche generado por IA para {vuln['cve_id']} -- aplicado automáticamente\n"
                f"# vía Merge Request por Sentinel (remediation/gitlab_autofix.py), no ejecutado como script.\n\n"
                f"{fix_patch}")
        else:
            remediation_content = analysis.get('remediation_script', '# No script provided')
        with open(script_path, "w") as f:
            f.write(str(remediation_content))

        with db_manager.get_db_cursor() as write_cur:
            write_cur.execute("""
                UPDATE vulnerability_log
                SET status = 'CORRELATED', executive_summary = %s, business_impact = %s,
                    developer_steps = %s, fix_patch = %s
                WHERE id = %s
            """, (analysis.get('executive_summary', 'No summary available'),
                  analysis.get('business_impact', 'No impact analysis available'),
                  analysis.get('developer_steps', 'No steps provided'),
                  fix_patch if fix_patch.strip() else None, vuln['id']))
            write_cur.execute("SELECT id, approval_token FROM remediation_history WHERE vuln_id=%s LIMIT 1", (vuln['id'],))
            existing = write_cur.fetchone()
            if existing:
                new_token = existing[1] if existing[1] not in ('PENDING_APPROVAL', None) else 'PENDING_APPROVAL'
                write_cur.execute("""UPDATE remediation_history
                    SET script_path=%s, approval_token=%s, can_automate=%s WHERE id=%s""",
                    (script_path, new_token, analysis.get('can_automate', True), existing[0]))
            else:
                write_cur.execute("""INSERT INTO remediation_history
                    (vuln_id, script_path, approval_token, can_automate) VALUES (%s, %s, %s, %s)""",
                    (vuln['id'], script_path, "PENDING_APPROVAL", analysis.get('can_automate', True)))
        agent_ledger.record_action(
            agent_ledger.ACTION_AI_CORRELATION,
            f"Correlación IA completada para {vuln['cve_id']} en {vuln['asset_name']}",
            entity_type="vulnerability", entity_id=vuln['id'], asset_id=vuln.get('asset_id'),
            detail={"can_automate": analysis.get('can_automate'), "has_patch": bool(fix_patch.strip()),
                    "asset_type": vuln.get('asset_type')},
            outcome="success",
        )
        ok += 1
        print(f"  ✅ CORRELATED  can_automate={analysis.get('can_automate')}  fix_patch={'sí' if fix_patch.strip() else 'no'}")
        time.sleep(3)  # same inter-request pacing as main_loop, avoid tripping provider rate limits

    print(f"\n\n==== {ok} correlacionados, {fail} fallidos, {len(rows)} total ====")


if __name__ == "__main__":
    main()
    os._exit(0)
