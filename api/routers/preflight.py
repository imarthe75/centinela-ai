"""Read-only evidence endpoints (ADR-0012 D10). Nothing here changes a finding, an asset or any XDR behaviour.

  GET /api/preflight?asset=<name>&paths=a/B.java,c/D.ts[&include_informational=true]
        Open findings Centinela already holds for those files, BEFORE someone edits them (an agent or a developer).
        "No findings" never means "clean": the answer carries when the asset was last audited and which engines ever wrote a row for it.
  GET /api/checklist-evidence/{asset}
        Measured facts for the security / accessibility / code-quality / credentials points of the stage-closing checklist
        (ART-MC-02, points of 0A-4 read from skills/generador-entregables-ca/references/0A-4_puntos.json). It signs nothing:
        the person who closes the stage still validates; the manual's second pair of eyes is not replaced.
Contract of /api/preflight (so any other tool can implement it): {"asset", "paths", "findings":[{"path","line","rule","severity","status",
"risk_verdict","engine","category"}], "paths_without_findings":[...], "last_audit", "engines_seen":[...], "note"}.
"""
import json
import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from auditors.starter_lineage import split_location
from core import db_manager

logger = logging.getLogger(__name__)
router = APIRouter()

OPEN_STATUSES_EXCLUDED = ("RESOLVED", "SUPPRESSED")
MAX_PATHS = 200
_WCAG_RULE_SQL = "(v.cve_id LIKE 'WCAG-%%' OR v.cve_id LIKE 'ACCESSIBILITY-WCAG%%')"


# Official stage-closing checklist points (0A-4), shipped with the deliverables skill: the skill is the single source of their text.
CHECKLIST_POINTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                     "skills", "generador-entregables-ca", "references", "0A-4_puntos.json")
# Which 0A-4 point each evidence block informs. Centinela measures part of the point; the person who closes the stage answers it.
POINTS_INFORMED = {"security": ["3.10"], "code_quality": ["3.10"], "accessibility": ["3.7"], "secrets": ["5.8"]}


def checklist_points(ids: List[str], path: str = CHECKLIST_POINTS_FILE) -> List[Dict[str, Any]]:
    """Text of the given 0A-4 points; ids only (with `text: None`) if the skill file is missing or unreadable."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        by_id = {p["id"]: p for st in data.get("etapas", {}).values() for p in st.get("puntos", [])}
    except (OSError, ValueError, KeyError):
        logger.error("No se pudieron leer los puntos de 0A-4 desde %s", path, exc_info=True)
        by_id = {}
    return [{"id": i, "text": (by_id.get(i) or {}).get("punto"), "responde": (by_id.get(i) or {}).get("responde"),
             "critico": (by_id.get(i) or {}).get("critico")} for i in ids]


def _asset_row(cur, asset: str):
    """Exact asset, or the project name with its `@branch` assets tolerated (assets are `<project>@<branch>` since 2026-10-12)."""
    cur.execute("""SELECT id, asset_name, last_audit FROM infra_inventory
                   WHERE asset_name = %s OR starts_with(asset_name, %s) ORDER BY (asset_name = %s) DESC, asset_name LIMIT 1""",
                (asset, asset + "@", asset))
    return cur.fetchone()


def preflight_query(cur, asset: str, paths: List[str], include_informational: bool = False) -> Dict[str, Any]:
    clean: List[str] = []
    for p in paths:
        rel = split_location(p.strip())
        if rel and rel not in clean:
            clean.append(rel)
    row = _asset_row(cur, asset)
    if not row:
        return {"asset": asset, "known_asset": False, "paths": clean, "findings": [], "paths_without_findings": clean, "last_audit": None,
                "engines_seen": [], "note": "Centinela no conoce este activo: no hay información, lo cual NO significa que el código esté limpio."}
    asset_id, asset_name, last_audit = row
    cur.execute("SELECT DISTINCT scan_engine FROM vulnerability_log WHERE asset_id=%s AND scan_engine IS NOT NULL ORDER BY 1", (asset_id,))
    engines = [r[0] for r in cur.fetchall()]
    findings: List[Dict[str, Any]] = []
    if clean:
        cur.execute("""SELECT v.url_path, v.cve_id, COALESCE(v.real_severity, v.severity), v.status, v.risk_verdict, v.scan_engine, v.finding_category
                       FROM vulnerability_log v
                       WHERE v.asset_id = %s AND v.status NOT IN %s AND (%s OR v.finding_category IN ('VULNERABILITY', 'COMPLIANCE'))
                         AND v.url_path IS NOT NULL
                       ORDER BY v.url_path""", (asset_id, OPEN_STATUSES_EXCLUDED, include_informational))
        wanted = set(clean)
        for up, rule, sev, status, verdict, engine, cat in cur.fetchall():
            rel = split_location(up)
            if rel in wanted:
                line = int(up.rpartition(":")[2]) if up.rpartition(":")[2].isdigit() else None
                findings.append({"path": rel, "line": line, "rule": rule, "severity": sev, "status": status, "risk_verdict": verdict,
                                 "engine": engine, "category": cat})
    with_findings = {f["path"] for f in findings}
    return {"asset": asset_name, "known_asset": True, "paths": clean, "findings": findings,
            "paths_without_findings": [p for p in clean if p not in with_findings], "last_audit": str(last_audit) if last_audit else None,
            "engines_seen": engines,
            "note": "Sin hallazgos en un archivo no prueba que esté limpio: solo que ningún motor (ver engines_seen) lo marcó en el último escaneo."}


def checklist_evidence(cur, asset: str) -> Optional[Dict[str, Any]]:
    row = _asset_row(cur, asset)
    if not row:
        return None
    asset_id, asset_name, last_audit = row
    base = "FROM vulnerability_log v WHERE v.asset_id=%s AND v.status NOT IN %s"
    args = (asset_id, OPEN_STATUSES_EXCLUDED)
    cur.execute("SELECT COALESCE(v.real_severity, v.severity), count(*) " + base + " AND v.finding_category='VULNERABILITY' AND NOT "
                + _WCAG_RULE_SQL + " GROUP BY 1", args)
    sec = {k: n for k, n in cur.fetchall()}
    cur.execute("SELECT COALESCE(v.real_severity, v.severity), count(*) " + base + " AND " + _WCAG_RULE_SQL + " GROUP BY 1", args)
    acc = {k: n for k, n in cur.fetchall()}
    cur.execute("SELECT count(*) " + base + " AND v.finding_category='INFORMATIONAL' AND NOT " + _WCAG_RULE_SQL, args)
    quality_info = cur.fetchone()[0]
    cur.execute("SELECT scan_engine, max(detected_at) FROM vulnerability_log WHERE asset_id=%s AND scan_engine IS NOT NULL GROUP BY 1 ORDER BY 1", (asset_id,))
    engines = {e: str(t) for e, t in cur.fetchall()}
    cur.execute("SELECT description, status FROM vulnerability_log WHERE asset_id=%s AND cve_id='SONARQUBE-QUALITY-GATE' ORDER BY detected_at DESC LIMIT 1",
                (asset_id,))
    qg = cur.fetchone()
    cur.execute("SELECT count(*) " + base + " AND (v.scan_engine = 'secrets' OR v.cve_id ILIKE '%%SECRET%%')", args)
    secrets_open = cur.fetchone()[0]

    def block(counts, extra=None):
        d = {"open_by_effective_severity": counts, "open_total": sum(counts.values())}
        d.update(extra or {})
        return d
    sec_block = block(sec, {"source": "vulnerability_log (finding_category=VULNERABILITY, sin reglas WCAG), severidad efectiva",
                            "blocking_note": "críticos/altos abiertos: " + str(sec.get("CRITICAL", 0) + sec.get("HIGH", 0)),
                            "informs_points": POINTS_INFORMED["security"]})
    return {
        "asset": asset_name, "last_audit": str(last_audit) if last_audit else None, "engines_last_detection": engines,
        "security": sec_block,
        "accessibility": block(acc, {"source": "reglas WCAG-* / ACCESSIBILITY-WCAG* del código; NO incluye revisión manual ni lector de pantalla",
                                     "informs_points": POINTS_INFORMED["accessibility"],
                                     "partial_note": "el punto 3.7 pide recorrer cada pantalla solo con teclado y compararla con el diseño: "
                                                     "Centinela solo aporta los hallazgos estáticos"}),
        "code_quality": {"informational_open": quality_info, "sonarqube_quality_gate": (qg[0][:200] if qg else None),
                         "source": "hallazgos INFORMATIONAL + marca SONARQUBE-QUALITY-GATE si existe",
                         "informs_points": POINTS_INFORMED["code_quality"]},
        "secrets": {"open_total": secrets_open, "informs_points": POINTS_INFORMED["secrets"],
                    "source": "motor de secretos (código e historial) + reglas *SECRET*; el punto 5.8 pide que el paquete de handover "
                              "no incluya credenciales: un secreto abierto en el repositorio lo incumple"},
        "checklist_points": checklist_points(sorted({i for v in POINTS_INFORMED.values() for i in v})),
        "not_evaluated_by_centinela": ["revisión de código por un segundo técnico (ART-F3-03)", "validación humana del código de IA (ART-F3-04)",
                                       "pruebas funcionales y de aceptación", "accesibilidad que exige navegador o juicio humano"],
        "signs_nothing": "Evidencia medida; quien cierra la etapa la valida y la verifica la Gerencia de Calidad.",
    }


@router.get("/api/preflight")
def preflight(asset: str = Query(..., min_length=1), paths: str = Query("", description="comma-separated repo-relative paths"),
              include_informational: bool = False):
    items = [p for p in paths.split(",") if p.strip()]
    if len(items) > MAX_PATHS:
        raise HTTPException(status_code=400, detail=f"máximo {MAX_PATHS} rutas por consulta")
    with db_manager.get_db_cursor() as cur:
        return preflight_query(cur, asset, items, include_informational)


@router.get("/api/checklist-evidence/{asset:path}")
def api_checklist_evidence(asset: str):
    with db_manager.get_db_cursor() as cur:
        out = checklist_evidence(cur, asset)
    if out is None:
        raise HTTPException(status_code=404, detail="activo desconocido")
    return out
