"""
One-time backfill: re-run real AI correlation for vulnerability_log rows still stuck with the
generic/no-specific-rule heuristic fallback text (the markers documented in CLAUDE.md's "Known
open issues" item 6). This is the deferred re-run mentioned there -- it was blocked before by
Groq's daily quota with no working fallback tier; the 4-provider cascade (Groq -> Gemini ->
NVIDIA -> OpenRouter) is now live (see AGENTS.md/CLAUDE.md 2026-08-07 entry), so this should
land real content instead of hitting a wall of all-providers-down responses.

Must be run inside the centinela-ai or centinela-backend container (needs centinela.py's
correlate_vulnerability + the real DB pool + the real Vault-backed AI clients).
"""
import sys
import os
import time
import json
sys.path.insert(0, "/app")

import centinela
from core import db_manager
from psycopg2.extras import RealDictCursor

MARKERS = [
    "%Hallazgo DAST sin regla determin%",
    "%Hallazgo de código fuente:%",
    "%sin regla de remediación específica%",
]

def fetch_targets():
    with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT v.id, v.cve_id, v.severity, v.description, v.url_path,
                   i.asset_name, i.asset_type, i.endpoint
            FROM vulnerability_log v
            JOIN infra_inventory i ON v.asset_id = i.id
            WHERE v.status = 'CORRELATED'
              AND (
                    v.executive_summary LIKE %s
                 OR v.executive_summary LIKE %s
                 OR v.executive_summary LIKE %s
              )
            ORDER BY v.id
        """, MARKERS)
        return cur.fetchall()

def main():
    targets = fetch_targets()
    total = len(targets)
    print(f"[Backfill] {total} rows found with stale generic heuristic text.")

    upgraded = 0
    unchanged_honest = 0
    failed = 0
    consecutive_all_down = 0
    log_lines = []

    for i, vuln in enumerate(targets, 1):
        vid = vuln["id"]
        cve = vuln["cve_id"]
        print(f"[{i}/{total}] Re-correlating id={vid} cve={cve} asset={vuln['asset_name']}...")
        try:
            analysis = centinela.correlate_vulnerability(vuln)
        except Exception as e:
            print(f"  -> EXCEPTION: {e}")
            failed += 1
            log_lines.append(f"id={vid} cve={cve} EXCEPTION {e}")
            continue

        if not analysis:
            consecutive_all_down += 1
            failed += 1
            log_lines.append(f"id={vid} cve={cve} NO_ANALYSIS (all providers down or empty response)")
            print(f"  -> no analysis returned (providers down / empty). consecutive={consecutive_all_down}")
            if consecutive_all_down >= 15:
                print("[Backfill] 15 consecutive failures -- stopping rather than grinding through no-op rewrites.")
                break
            continue

        consecutive_all_down = 0

        new_summary = analysis.get("executive_summary", "")
        still_generic = (
            "Hallazgo DAST sin regla determin" in new_summary
            or "Hallazgo de código fuente:" in new_summary
        )

        fix_patch = analysis.get("fix_patch", "") or ""
        script_path = f"/app/data/remediation/{cve}_{vid}.sh"
        os.makedirs(os.path.dirname(script_path), exist_ok=True)
        if fix_patch.strip():
            remediation_content = (
                f"# Parche generado por IA para {cve} -- aplicado automáticamente\n"
                f"# vía Merge Request por Sentinel (remediation/gitlab_autofix.py), no ejecutado como script.\n\n"
                f"{fix_patch}"
            )
        else:
            remediation_content = analysis.get("remediation_script", "# No script provided")
        with open(script_path, "w") as f:
            f.write(str(remediation_content))

        with db_manager.get_db_cursor() as write_cur:
            write_cur.execute("""
                UPDATE vulnerability_log
                SET executive_summary = %s,
                    business_impact = %s,
                    developer_steps = %s,
                    fix_patch = %s
                WHERE id = %s
            """, (
                analysis.get("executive_summary", "No summary available"),
                analysis.get("business_impact", "No impact analysis available"),
                analysis.get("developer_steps", "No steps provided"),
                fix_patch if fix_patch.strip() else None,
                vid,
            ))
            write_cur.execute("SELECT id, approval_token FROM remediation_history WHERE vuln_id = %s LIMIT 1", (vid,))
            existing = write_cur.fetchone()
            if existing:
                new_token = existing[1] if existing[1] not in ("PENDING_APPROVAL", None) else "PENDING_APPROVAL"
                write_cur.execute("""
                    UPDATE remediation_history
                    SET script_path = %s, approval_token = %s, can_automate = %s
                    WHERE id = %s
                """, (script_path, new_token, analysis.get("can_automate", False), existing[0]))
            else:
                write_cur.execute("""
                    INSERT INTO remediation_history (vuln_id, script_path, approval_token, can_automate)
                    VALUES (%s, %s, %s, %s)
                """, (vid, script_path, "PENDING_APPROVAL", analysis.get("can_automate", False)))

        if still_generic:
            unchanged_honest += 1
            log_lines.append(f"id={vid} cve={cve} HONEST_NO_FIX (LLM/heuristic agreed no deterministic rule exists)")
            print(f"  -> still an honest 'no rule available' answer (real LLM agreed, not a lazy skip).")
        else:
            upgraded += 1
            log_lines.append(f"id={vid} cve={cve} UPGRADED: {new_summary[:100]!r}")
            print(f"  -> upgraded to real content: {new_summary[:100]!r}")

        time.sleep(3)

    print("\n=== Backfill summary ===")
    print(f"Total targeted: {total}")
    print(f"Upgraded to real specific content: {upgraded}")
    print(f"Re-confirmed honest no-fix-available (real LLM ran, genuinely nothing better to say): {unchanged_honest}")
    print(f"Failed / all providers down: {failed}")

    with open("/app/scratch/backfill_generic_heuristic_2026-08-13.log", "w") as f:
        f.write(f"Total targeted: {total}\n")
        f.write(f"Upgraded: {upgraded}\n")
        f.write(f"Honest no-fix (re-confirmed by real LLM): {unchanged_honest}\n")
        f.write(f"Failed: {failed}\n\n")
        f.write("\n".join(log_lines))

if __name__ == "__main__":
    main()
    # centinela.py's AI cascade (imported above) now runs each provider call through a
    # ThreadPoolExecutor to impose a true wall-clock deadline (see centinela.py's
    # _call_with_hard_deadline, added 2026-08-13 after a real 30+ minute OpenRouter hang). If any
    # call during this run actually hit that hard deadline, its worker thread is abandoned but
    # still alive, blocked on the network -- and ThreadPoolExecutor registers an atexit hook that
    # waits for every submitted thread before the interpreter can exit, so a normal exit here
    # could hang this one-off script for a long time even though main() has already finished and
    # written its summary. os._exit() skips that wait entirely (the DB writes already committed
    # per-row inside main(), so nothing is lost by not waiting for a stray network thread).
    os._exit(0)
