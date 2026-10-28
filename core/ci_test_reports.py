"""CI test report summaries sent by centinela-smart-tests (its ci_report.summarize_dir): validation, storage and queries.

The summary is accepted only with sane, non-negative integer totals (failures + errors + skipped <= tests) and percentages in 0..100;
anything else is rejected whole. Re-sending the same pipeline (asset, project, commit, pipeline) replaces it. Nothing here runs tests.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional


class CIReportError(ValueError):
    pass


def _int(summary: Dict[str, Any], key: str) -> int:
    v = summary.get(key)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise CIReportError(f"summary.{key} debe ser un entero >= 0")
    return v


def _pct(summary: Dict[str, Any], key: str) -> Optional[float]:
    v = summary.get(key)
    if v is None:
        return None
    if not isinstance(v, (int, float)) or isinstance(v, bool) or not 0 <= v <= 100:
        raise CIReportError(f"summary.{key} debe estar entre 0 y 100")
    return round(float(v), 1)


def _flag(summary: Dict[str, Any], key: str) -> Optional[bool]:
    v = summary.get(key)
    if v is not None and not isinstance(v, bool):
        raise CIReportError(f"summary.{key} debe ser booleano o nulo")
    return v


def validate(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise CIReportError("el cuerpo debe ser un objeto JSON")
    asset = str(payload.get("asset_name") or "").strip()
    if not asset:
        raise CIReportError("falta asset_name")
    s = payload.get("summary")
    if not isinstance(s, dict):
        raise CIReportError("falta summary")
    row = {k: _int(s, k) for k in ("tests", "failures", "errors", "skipped")}
    if row["failures"] + row["errors"] + row["skipped"] > row["tests"]:
        raise CIReportError("fallos + errores + omitidas supera el total de pruebas")
    row.update({k: _pct(s, k) for k in ("coverage_line_pct", "coverage_branch_pct")})
    row.update({k: _flag(s, k) for k in ("has_401_tests", "has_403_tests", "has_409_tests")})
    run = payload.get("run") or {}
    row.update({"asset_name": asset[:300], "project": str(run.get("project") or "")[:200], "ref": str(run.get("ref") or "")[:200],
                "commit_sha": str(run.get("commit") or "")[:80], "pipeline": str(run.get("pipeline") or "")[:300]})
    clean = {k: s.get(k) for k in ("tests", "failures", "errors", "skipped", "suites", "duration_s", "coverage_line_pct", "coverage_branch_pct",
                                   "has_401_tests", "has_403_tests", "has_409_tests", "detection_note", "files", "rejected")}
    clean["failed_tests"] = [{"test": str(f.get("test", ""))[:200], "kind": str(f.get("kind", ""))[:20]}
                             for f in (s.get("failed_tests") or [])[:100] if isinstance(f, dict)]
    row["summary"] = clean
    basis = json.dumps([row["asset_name"], row["project"], row["commit_sha"], row["pipeline"]], ensure_ascii=False)
    row["report_key"] = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:40]
    return row


def store(cur, payload: Dict[str, Any]) -> Dict[str, Any]:
    row = validate(payload)
    cur.execute("SELECT id FROM public.infra_inventory WHERE asset_name = %s", (row["asset_name"],))
    hit = cur.fetchone()
    if not hit:
        raise LookupError(f"el activo «{row['asset_name']}» no existe en el inventario")
    asset_id = hit[0] if not isinstance(hit, dict) else hit["id"]
    cur.execute("""
        INSERT INTO public.ci_test_reports (report_key, asset_name, asset_id, project, ref, commit_sha, pipeline, tests, failures, errors,
                                            skipped, coverage_line_pct, coverage_branch_pct, has_401_tests, has_403_tests, has_409_tests, summary)
        VALUES (%(report_key)s, %(asset_name)s, %(asset_id)s, %(project)s, %(ref)s, %(commit_sha)s, %(pipeline)s, %(tests)s, %(failures)s,
                %(errors)s, %(skipped)s, %(coverage_line_pct)s, %(coverage_branch_pct)s, %(has_401_tests)s, %(has_403_tests)s,
                %(has_409_tests)s, %(summary)s::jsonb)
        ON CONFLICT (report_key) DO UPDATE SET tests = EXCLUDED.tests, failures = EXCLUDED.failures, errors = EXCLUDED.errors,
            skipped = EXCLUDED.skipped, coverage_line_pct = EXCLUDED.coverage_line_pct, coverage_branch_pct = EXCLUDED.coverage_branch_pct,
            has_401_tests = EXCLUDED.has_401_tests, has_403_tests = EXCLUDED.has_403_tests, has_409_tests = EXCLUDED.has_409_tests,
            summary = EXCLUDED.summary, ref = EXCLUDED.ref, received_at = now()
        RETURNING id, (xmax = 0) AS created""", {**row, "asset_id": asset_id, "summary": json.dumps(row["summary"], ensure_ascii=False)})
    rid, created = cur.fetchone()
    return {"report_id": str(rid), "created": bool(created), "asset_id": str(asset_id)}


def list_reports(cur, asset: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    cur.execute("""
        SELECT id, asset_name, project, ref, commit_sha, pipeline, tests, failures, errors, skipped, coverage_line_pct, coverage_branch_pct,
               has_401_tests, has_403_tests, has_409_tests, summary, received_at
        FROM public.ci_test_reports WHERE (%s::text IS NULL OR asset_name = %s) ORDER BY received_at DESC LIMIT %s""", (asset, asset, limit))
    cols = [d[0] for d in cur.description]
    out = []
    for r in cur.fetchall():
        d = dict(zip(cols, r))
        d["id"] = str(d["id"])
        d["received_at"] = d["received_at"].isoformat() if d["received_at"] else None
        for k in ("coverage_line_pct", "coverage_branch_pct"):
            d[k] = float(d[k]) if d[k] is not None else None
        out.append(d)
    return out
