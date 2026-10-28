"""Full functional-test runs sent by centinela-smart-tests (ADR-0015): validation, storage and queries for the "Pruebas funcionales" tab.

Every case goes through centinela_core.results.CaseResult, the same model the runner uses: PASSED/FAILED need evidence and
BLOCKED/NOT_EXECUTED need a reason, so an invalid run is rejected whole instead of being shown half-true. The summary is recomputed here
with centinela_core.results.summarize (executed share over the plan, pass rate over what executed); the sender's own summary is ignored.
Re-sending the same run replaces it (idempotent by run_key).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from centinela_core.results import CaseResult, ResultError, summarize

MAX_CASES = 2000
MAX_EVIDENCE = 20
_TXT = 4000


class RunError(ValueError):
    pass


def _cut(s: Any, n: int = _TXT) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def run_key(run: Dict[str, Any], asset_name: str) -> str:
    explicit = str(run.get("run_id") or "").strip()
    if explicit:
        return explicit[:120]
    basis = json.dumps([run.get(k) for k in ("project", "cycle", "package", "started", "finished")] + [asset_name], ensure_ascii=False)
    return "auto-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def validate_run(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], List[CaseResult], int]:
    if not isinstance(payload, dict):
        raise RunError("el cuerpo debe ser un objeto JSON")
    run = payload.get("run")
    if not isinstance(run, dict) or not str(run.get("project") or "").strip():
        raise RunError("falta run.project")
    items = payload.get("results")
    if not isinstance(items, list) or not items:
        raise RunError("results debe ser una lista no vacía con todos los casos de la corrida")
    if len(items) > MAX_CASES:
        raise RunError(f"máximo {MAX_CASES} casos por corrida")
    results, errors, seen = [], [], set()
    for raw in items:
        cid = str((raw or {}).get("case_id", "?")) if isinstance(raw, dict) else "?"
        try:
            r = CaseResult.from_dict(raw)
        except (ResultError, TypeError, ValueError) as e:
            errors.append(f"{cid}: {e}")
            continue
        if r.case_id in seen:
            errors.append(f"{r.case_id}: caso repetido en la corrida")
            continue
        seen.add(r.case_id)
        results.append(r)
    if errors:
        raise RunError(f"{len(errors)} caso(s) inválido(s); la corrida no se registra: " + "; ".join(errors[:20]))
    # planned_total = package cases + generic checks (centinela-smart-tests ADR-0002); older senders only send planned_in_package
    planned = run.get("planned_total", run.get("planned_in_package", run.get("planned")))
    try:
        planned = int(planned) if planned is not None else len(results)
    except (TypeError, ValueError):
        raise RunError("run.planned_in_package debe ser un entero")
    if planned < len(results):
        raise RunError(f"run.planned_in_package ({planned}) es menor que los casos enviados ({len(results)})")
    return run, results, planned


def store_run(cur, payload: Dict[str, Any]) -> Dict[str, Any]:
    run, results, planned = validate_run(payload)
    asset_name = str(payload.get("asset_name") or run.get("asset") or "").strip()[:300] or None
    asset_id = None
    if asset_name:
        cur.execute("SELECT id FROM public.infra_inventory WHERE asset_name = %s", (asset_name,))
        row = cur.fetchone()
        asset_id = (row[0] if not isinstance(row, dict) else row["id"]) if row else None
    summary = summarize(results, total_planned=planned)
    key = run_key(run, asset_name or "")
    meta = {k: v for k, v in run.items() if k not in ("project", "cycle", "package", "started", "finished")}
    meta_json = json.dumps(meta, ensure_ascii=False, default=str)
    if len(meta_json) > 20000:
        meta_json = json.dumps({"truncated": True}, ensure_ascii=False)
    cur.execute("""
        INSERT INTO public.functional_test_runs (run_key, project, cycle, package, started, finished, asset_name, asset_id, source, summary, meta)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
        ON CONFLICT (run_key) DO UPDATE SET project = EXCLUDED.project, cycle = EXCLUDED.cycle, package = EXCLUDED.package,
            started = EXCLUDED.started, finished = EXCLUDED.finished, asset_name = EXCLUDED.asset_name, asset_id = EXCLUDED.asset_id,
            source = EXCLUDED.source, summary = EXCLUDED.summary, meta = EXCLUDED.meta, updated_at = now()
        RETURNING id, (xmax = 0) AS inserted
    """, (key, _cut(run["project"], 120), _cut(run.get("cycle"), 200), _cut(run.get("package"), 300), _cut(run.get("started"), 40),
          _cut(run.get("finished"), 40), asset_name, asset_id, _cut(payload.get("source") or "centinela-smart-tests", 80),
          json.dumps(summary), meta_json))
    row = cur.fetchone()
    run_id, inserted = (row[0], row[1]) if not isinstance(row, dict) else (row["id"], row["inserted"])
    cur.execute("DELETE FROM public.functional_test_cases WHERE run_id = %s", (run_id,))
    for i, r in enumerate(results):
        ev = [{"kind": _cut(e.kind, 40), "value": _cut(e.value, 600), "note": _cut(e.note, 600)} for e in r.evidence[:MAX_EVIDENCE]]
        cur.execute("""
            INSERT INTO public.functional_test_cases (run_id, case_id, status, criterion, detail, reason, substitution, security_relevant,
                                                      category, evidence, ord)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        """, (run_id, _cut(r.case_id, 120), r.status.value, _cut(r.criterion, 500), _cut(r.detail), _cut(r.reason), _cut(r.substitution, 1000),
              bool(r.security_relevant), _cut((r.meta or {}).get("category"), 60) or None, json.dumps(ev, ensure_ascii=False), i))
    return {"run_id": str(run_id), "run_key": key, "created": bool(inserted), "cases": len(results), "summary": summary,
            "asset_linked": asset_id is not None}


def list_runs(cur, project: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    sql = """SELECT r.id::text, r.project, r.cycle, r.package, r.started, r.finished, r.asset_name, r.asset_id::text AS asset_id,
                    r.summary, r.received_at, r.updated_at
             FROM public.functional_test_runs r"""
    params: list = []
    if project:
        sql += " WHERE r.project = %s"
        params.append(project)
    sql += " ORDER BY r.received_at DESC LIMIT %s"
    params.append(max(1, min(int(limit), 500)))
    cur.execute(sql, tuple(params))
    cols = [d[0] for d in cur.description]
    return [_jsonable(dict(zip(cols, r))) for r in cur.fetchall()]


def get_run(cur, run_id: str) -> Optional[Dict[str, Any]]:
    cur.execute("""SELECT id::text, run_key, project, cycle, package, started, finished, asset_name, asset_id::text AS asset_id, source,
                          summary, meta, received_at, updated_at
                   FROM public.functional_test_runs WHERE id = %s""", (run_id,))
    row = cur.fetchone()
    if not row:
        return None
    run = _jsonable(dict(zip([d[0] for d in cur.description], row)))
    cur.execute("""SELECT case_id, status, criterion, detail, reason, substitution, security_relevant, category, evidence
                   FROM public.functional_test_cases WHERE run_id = %s ORDER BY ord""", (run_id,))
    cols = [d[0] for d in cur.description]
    cases = [dict(zip(cols, r)) for r in cur.fetchall()]
    # Security-relevant failures also exist as findings (POST /api/ingest/smart-tests): link them so the tab shows their current status.
    sec = [c["case_id"] for c in cases if c["security_relevant"]]
    if sec and run.get("asset_id"):
        locs = [f"smart-tests:{str(run['project'])[:60]}:{c}" for c in sec]
        cur.execute("""SELECT url_path, id::text, status, COALESCE(real_severity, severity) FROM public.vulnerability_log
                       WHERE asset_id = %s AND scan_engine = 'smart-tests' AND url_path = ANY(%s)""", (run["asset_id"], locs))
        found = {r[0]: {"id": r[1], "status": r[2], "severity": r[3]} for r in cur.fetchall()}
        for c in cases:
            if c["security_relevant"]:
                c["finding"] = found.get(f"smart-tests:{str(run['project'])[:60]}:{c['case_id']}")
    run["cases"] = cases
    return run


def _jsonable(d: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in list(d.items()):
        if hasattr(v, "isoformat"):
            d[k] = v.isoformat()
    return d
