"""Group triage report (ADR-0010): a GitLab group -> project + all its sub-projects, classified by the analyst's root causes.

  GET    /api/triage/groups                         catalogs that exist
  GET    /api/triage/summary?instance=&group=       the Resumen as JSON (+ coverage of sub-projects, + findings no rule classifies)
  GET    /api/triage/unclassified?instance=&group=  the SIN CLASIFICAR findings
  GET    /api/triage/report.xlsx?instance=&group=   the workbook
  GET    /api/triage/matrix?instance=&group=        records for the consolidation skill's tracking matrix
  POST   /api/triage/root-causes                    create / update a root cause (analyst judgement, stored with who/when)
  POST   /api/triage/rules   DELETE /api/triage/rules/{id}   how findings map to a root cause
"""
import logging
import re
from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from psycopg2.extras import Json
from pydantic import BaseModel

from core import db_manager, triage
from core.gitlab_instances import get_instance
from core.triage_matrix import matrix_records
from core.triage_workbook import build_workbook

logger = logging.getLogger(__name__)
router = APIRouter()


def _instance(key: Optional[str]):
    try:
        return get_instance(key)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


def _data(instance: Optional[str], group: str, check_gitlab: bool = True) -> Dict[str, Any]:
    inst = _instance(instance)
    try:
        with db_manager.get_db_cursor() as cur:
            return triage.build_report_data(cur, inst, group, check_gitlab=check_gitlab)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error("triage report failed for %s/%s", instance, group, exc_info=True)
        raise HTTPException(status_code=500, detail=f"No se pudo construir el reporte: {e}")


def _actor(request: Request, fallback: Optional[str]) -> str:
    user = getattr(request.state, "user", None) or {}
    return str(user.get("preferred_username") or user.get("email") or user.get("sub") or fallback or "analyst")


@router.get("/api/triage/groups")
def list_groups():
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT g.group_key, g.instance, g.group_path, g.title,
                              (SELECT count(*) FROM triage_root_causes c WHERE c.group_key=g.group_key),
                              (SELECT count(*) FROM triage_rules r WHERE r.group_key=g.group_key)
                       FROM triage_groups g ORDER BY g.group_key""")
        return {"groups": [dict(zip(("group_key", "instance", "group_path", "title", "root_causes", "rules"), r)) for r in cur.fetchall()]}


@router.get("/api/triage/summary")
def triage_summary(group: str, instance: Optional[str] = None):
    d = _data(instance, group)
    fs = d["findings"]
    by_cls = Counter(f["classification"] for f in fs)
    uniq = Counter(f["classification"] for f in fs if not f["duplicate_of"])
    plan_total = sum(p["total"] for p in d["plan"])
    return {
        "group": {"instance": d["group"]["instance"], "path": d["group"]["group_path"], "title": d["group"]["title"]},
        "generated_at": d["generated_at"].isoformat(),
        "total": len(fs),
        "by_classification": {k: {"reported": by_cls.get(k, 0), "unique": uniq.get(k, 0)}
                              for k in ("Vulnerabilidad", "Falso positivo", "Calidad", "Sin clasificar")},
        "by_repo": {repo: dict(Counter(f["classification"] for f in fs if f["repo"] == repo)) for repo in sorted({f["repo"] for f in fs})},
        "unclassified": by_cls.get("Sin clasificar", 0),
        "informational_not_in_report": d["informational"],
        "coverage": d["coverage"],
        "coverage_error": d["coverage_error"],
        "not_scanned": [c["path"] for c in d["coverage"] if not c["status"].startswith("Escaneado")],
        "plan": {"hours": plan_total, "days": plan_total / d["group"]["hours_per_day"] if d["group"]["hours_per_day"] else None,
                 "note": "Horas = supuestos del analista; solo la parte SonarQube es estimación de la herramienta."},
    }


@router.get("/api/triage/unclassified")
def triage_unclassified(group: str, instance: Optional[str] = None, limit: int = 500):
    d = _data(instance, group, check_gitlab=False)
    rows = [{"repo": f["repo"], "engine": f["engine"], "rule": f["rule"], "severity": f["severity_eff"], "location": f["url_path"], "title": f["title"]}
            for f in d["findings"] if f["cause"] == triage.UNCLASSIFIED]
    return {"count": len(rows), "findings": rows[:max(1, min(limit, 5000))]}


@router.get("/api/triage/report.xlsx")
def triage_report(group: str, instance: Optional[str] = None):
    d = _data(instance, group)
    try:
        blob = build_workbook(d)
    except Exception as e:
        logger.error("triage workbook generation failed for %s/%s", instance, group, exc_info=True)
        raise HTTPException(status_code=500, detail=f"No se pudo generar el libro: {e}")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", d["group"]["group_path"]).strip("_")
    return Response(content=blob, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{safe}_hallazgos_clasificados.xlsx"'})


@router.get("/api/triage/matrix")
def triage_matrix(group: str, instance: Optional[str] = None):
    """The group's findings as records of the consolidation skill's tracking matrix (one per rule x repository), so the matrix is built from
    Centinela directly instead of from parsed PDFs. Classification and root cause are the analyst's; unclassified findings are carried as such."""
    d = _data(instance, group)
    d["source_label"] = "Centinela (API)"
    recs = matrix_records(d)
    return {"group": d["group"]["group_path"], "generated_at": d["generated_at"].isoformat(), "count": len(recs),
            "occurrences": len(d["findings"]), "unclassified": sum(1 for f in d["findings"] if f["cause"] == triage.UNCLASSIFIED),
            "registros": recs}


class RootCauseModel(BaseModel):
    instance: Optional[str] = None
    group: str
    code: str
    classification: str
    title: str
    kind: Optional[str] = None
    severity: Optional[str] = None
    certainty: Optional[str] = None
    rationale: Optional[str] = None
    how_to_confirm: Optional[str] = None
    strategy: Optional[str] = None
    owner: Optional[str] = None
    outdated: bool = False
    dedup_scope: str = "line"
    plan: Optional[Dict[str, Any]] = None


@router.post("/api/triage/root-causes")
def upsert_root_cause(body: RootCauseModel, request: Request):
    prefix = {"Vulnerabilidad": "V-", "Falso positivo": "FP-", "Calidad": "C-"}.get(body.classification)
    if prefix is None:
        raise HTTPException(status_code=400, detail="classification debe ser Vulnerabilidad, Falso positivo o Calidad")
    if not body.code.startswith(prefix):
        raise HTTPException(status_code=400, detail=f"El código de una causa '{body.classification}' debe empezar con {prefix} (de ahí sale la clasificación en el libro)")
    if body.dedup_scope not in ("line", "file"):
        raise HTTPException(status_code=400, detail="dedup_scope debe ser line o file")
    key = triage.group_key_for(_instance(body.instance).key, body.group)
    actor = _actor(request, None)
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT 1 FROM triage_groups WHERE group_key=%s", (key,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail=f"No hay catálogo de triage para '{body.group}'")
        cur.execute("""INSERT INTO triage_root_causes (group_key, code, classification, kind, title, severity, certainty, rationale, how_to_confirm,
                           strategy, owner, outdated, dedup_scope, plan, classified_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (group_key, code) DO UPDATE SET classification=EXCLUDED.classification, kind=EXCLUDED.kind, title=EXCLUDED.title,
                           severity=EXCLUDED.severity, certainty=EXCLUDED.certainty, rationale=EXCLUDED.rationale,
                           how_to_confirm=EXCLUDED.how_to_confirm, strategy=EXCLUDED.strategy, owner=EXCLUDED.owner, outdated=EXCLUDED.outdated,
                           dedup_scope=EXCLUDED.dedup_scope, plan=EXCLUDED.plan, classified_by=EXCLUDED.classified_by, classified_at=now()""",
                    (key, body.code, body.classification, body.kind, body.title, body.severity, body.certainty, body.rationale, body.how_to_confirm,
                     body.strategy, body.owner, body.outdated, body.dedup_scope, Json(body.plan) if body.plan else None, actor))
    return {"status": "saved", "code": body.code, "classified_by": actor}


class RuleModel(BaseModel):
    instance: Optional[str] = None
    group: str
    rule_regex: str
    root_cause_code: str
    engine: Optional[str] = None
    asset_regex: Optional[str] = None
    path_regex: Optional[str] = None
    line: Optional[int] = None
    note: Optional[str] = None


@router.post("/api/triage/rules")
def create_rule(body: RuleModel, request: Request):
    for name in ("rule_regex", "asset_regex", "path_regex"):
        val = getattr(body, name)
        if val:
            try:
                re.compile(val)
            except re.error as e:
                raise HTTPException(status_code=400, detail=f"{name} no es una expresión regular válida: {e}")
    key = triage.group_key_for(_instance(body.instance).key, body.group)
    # more specific criteria win over generic ones
    priority = (20 if body.line is not None else 10) if (body.path_regex or body.asset_regex or body.line is not None) else 0
    actor = _actor(request, None)
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT 1 FROM triage_root_causes WHERE group_key=%s AND code=%s", (key, body.root_cause_code))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail=f"La causa raíz '{body.root_cause_code}' no existe en este grupo")
        cur.execute("""INSERT INTO triage_rules (group_key, rule_regex, engine, asset_regex, path_regex, line, root_cause_code, priority, note, created_by)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id::text""",
                    (key, body.rule_regex, body.engine, body.asset_regex, body.path_regex, body.line, body.root_cause_code, priority, body.note, actor))
        return {"status": "created", "id": cur.fetchone()[0], "priority": priority, "created_by": actor}


@router.delete("/api/triage/rules/{rule_id}")
def delete_rule(rule_id: str):
    with db_manager.get_db_cursor() as cur:
        cur.execute("DELETE FROM triage_rules WHERE id=%s::uuid RETURNING id::text", (rule_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Regla no encontrada")
    return {"status": "deleted", "id": rule_id}
