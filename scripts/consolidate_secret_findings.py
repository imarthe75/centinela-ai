#!/usr/bin/env python3
"""One-off consolidation of git-history secret findings loaded BEFORE aggregation existed (2026-10-12: 11,270 rows, 10,056 from two SQL dumps).

Groups `secrets` rows by (asset, detector, file) -> keeps the earliest row, states the detection count in its description, deletes the rest (and their remediation rows).
Never touches a group that holds a human decision (an approved/rejected remediation) or a RESOLVED/SUPPRESSED row.
usage (inside centinela-backend):  python scripts/consolidate_secret_findings.py [--apply]     (default: dry run)
"""
import sys

sys.path.insert(0, "/app")
from core import db_manager  # noqa: E402

SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
APPLY = "--apply" in sys.argv

with db_manager.get_db_cursor() as cur:
    cur.execute("""SELECT v.id::text, v.asset_id::text, v.cve_id, v.url_path, v.severity, v.status, v.detected_at,
                          EXISTS(SELECT 1 FROM remediation_history r WHERE r.vuln_id = v.id AND r.approval_token IS NOT NULL AND r.approval_token <> 'PENDING_APPROVAL')
                   FROM vulnerability_log v WHERE v.scan_engine = 'secrets'""")
    rows = cur.fetchall()
    groups = {}
    for vid, aid, cve, up, sev, st, ts, decided in rows:
        file_ = (up or "").rsplit(":", 1)[0]
        groups.setdefault((aid, cve, file_), []).append((ts, vid, sev, st, decided))
    plan, skipped_human = [], 0
    for key, items in groups.items():
        if len(items) < 2:
            continue
        if any(i[4] or i[3] in ("RESOLVED", "SUPPRESSED") for i in items):
            skipped_human += 1
            continue
        items.sort(key=lambda i: (i[0], i[1]))
        plan.append((key, items[0][1], [i[1] for i in items[1:]], max((i[2] for i in items), key=lambda s: SEV.get(s, 0)), len(items)))
    to_delete = sum(len(p[2]) for p in plan)
    print(f"filas secrets: {len(rows)} | grupos a consolidar: {len(plan)} | filas a eliminar: {to_delete} | grupos omitidos (decisión humana/resueltos): {skipped_human}")
    print(f"quedarían: {len(rows) - to_delete}")
    if not APPLY:
        print("(ensayo: no se modificó nada; usar --apply)")
        sys.exit(0)
    for (aid, cve, file_), keep, drop, sev, n in plan:
        note = f"\n\n**Detecciones agrupadas:** {n} en este archivo (se muestra la primera; el historial de git contiene todas)."
        if file_.lower().endswith((".sql", ".dump", ".bak", ".csv")) and n >= 20:
            note += " Parece un **volcado de base de datos versionado**: el volcado completo en el repositorio es en sí un riesgo de exposición de datos (quitarlo del historial y rotar las credenciales y tokens que contenía)."
        cur.execute("UPDATE vulnerability_log SET severity = %s, description = description || %s WHERE id = %s", (sev, note, keep))
        cur.execute("DELETE FROM remediation_history WHERE vuln_id = ANY(%s::uuid[])", (drop,))
        cur.execute("DELETE FROM vulnerability_log WHERE id = ANY(%s::uuid[])", (drop,))
    cur.execute("SELECT count(*), count(*) FILTER (WHERE status IN ('NEW','OPEN','PENDING')) FROM vulnerability_log WHERE scan_engine = 'secrets'")
    print("después:", cur.fetchone())
