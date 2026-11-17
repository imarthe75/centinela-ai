# -*- coding: utf-8 -*-
"""
Centinela-AI — evidencia CMMI V3.0 (DECISIONS/0007, FASE A: solo lo medible HOY, sin decisiones externas).

La metodología interna (Anexo 10) define para cada una de las 19 áreas su «Evidencia de cumplimiento». Este módulo:
  1. declara esas 19 áreas con los ítems de evidencia que el manual exige (CMMI_AREA_ITEMS), incluidos los que Centinela
     TODAVÍA no puede medir (fuente = artefacto ART-*, atestación o política pendiente) -> se muestran como NO_EVALUADO,
     nunca se omiten ni se rellenan;
  2. implementa los colectores L1 (medidos por Centinela desde GitLab, el repositorio clonado y su propia BD);
  3. guarda cada hallazgo de evidencia en `cmmi_evidence` y arma el reporte de las 19 áreas.

Estados de un ítem:  CUMPLE | NO_CUMPLE | NO_EVALUADO | NO_APLICA.
Regla anti-inflación (ADR-0007 §2): la AUSENCIA de evidencia solo es NO_CUMPLE cuando la comprobación es definitiva
(p. ej. un MR fusionado sin ninguna revisión, el último pipeline en rojo, ninguna etiqueta de versión). Cuando la evidencia
del estándar vive en otro lugar (documentación de diseño, ADR, contrato OpenAPI, pruebas de integración) y solo buscamos
INDICIOS en el repositorio, encontrarlos da CUMPLE y no encontrarlos da NO_EVALUADO, jamás NO_CUMPLE.
Este reporte NO altera el porcentaje de las 5 áreas históricas: se muestra aparte (cobertura de evidencia vs. cumplimiento).
No es una evaluación CMMI formal (el propio manual lo advierte).
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

try:
    from core import db_manager
except ImportError:  # pragma: no cover
    db_manager = None

logger = logging.getLogger(__name__)

CUMPLE, NO_CUMPLE, NO_EVALUADO, NO_APLICA = "CUMPLE", "NO_CUMPLE", "NO_EVALUADO", "NO_APLICA"
SCANS_BASE = os.getenv("GITLAB_SCANS_DIR", "/tmp/centinela_gitlab_scans")
REPO_ROOT = os.getenv("CENTINELA_REPO_ROOT", "/app")

# Cada ítem: (clave, descripción según el manual, fuente, alcance, ausencia, colector)
#   fuente: gitlab | repo | org-git | org-db | artefacto | atestacion | politica
#   ausencia: qué significa NO encontrar evidencia -> NO_CUMPLE (comprobación definitiva) o NO_EVALUADO (solo indicios)
#   colector: nombre de la función en COLLECTORS, o None si hoy NO se puede medir (decisión/artefacto/política pendiente)
CMMI_AREA_ITEMS: Dict[str, Dict[str, Any]] = {
    "RDM": {"name": "Requisitos", "items": [
        ("rdm.traceability_matrix_validated", "Matriz de trazabilidad validada (ART-F1-04)", "artefacto", "ASSET", NO_EVALUADO, None),
        ("rdm.acceptance_criteria", "Requerimientos con criterio de aceptación (ART-F1-03)", "artefacto", "ASSET", NO_EVALUADO, None)]},
    "PQA": {"name": "Aseguramiento de calidad", "items": [
        ("pqa.ai_validation_trace", "Rastro de validación humana sobre cada salida de IA (flujo propio de Centinela)", "org-db", "ORG", NO_CUMPLE, "pqa_ai_validation_trace"),
        ("pqa.art_f3_04", "Validación humana sobre código IA del proyecto (ART-F3-04)", "artefacto", "ASSET", NO_EVALUADO, None)]},
    "PR": {"name": "Revisión por pares", "items": [
        ("pr.merged_mr_reviewed", "Revisiones registradas con identidad del revisor (MR fusionados con revisión de alguien distinto del autor)", "gitlab", "ASSET", NO_CUMPLE, "pr_merged_mr_reviewed")]},
    "VV": {"name": "Verificación y validación", "items": [
        ("vv.tests_green", "Pruebas en verde (existen pruebas y el último pipeline de la rama por defecto pasó)", "gitlab", "ASSET", NO_CUMPLE, "vv_tests_green"),
        ("vv.uat_signed", "Acta de aceptación de UAT firmada (ART-F4-0x)", "artefacto", "ASSET", NO_EVALUADO, None)]},
    "TS": {"name": "Solución técnica", "items": [
        ("ts.design_docs", "Documento de arquitectura/diseño (indicio: carpeta docs con documentos)", "repo", "ASSET", NO_EVALUADO, "ts_design_docs"),
        ("ts.data_design_versioned", "Diseño de datos versionado (Liquibase/Flyway/Alembic)", "repo", "ASSET", NO_EVALUADO, "ts_data_design_versioned"),
        ("ts.art_f2", "Arquitectura, diseño y especificación de campos y validaciones (ART-F2-01/02/04/08)", "artefacto", "ASSET", NO_EVALUADO, None)]},
    "PI": {"name": "Integración de producto", "items": [
        ("pi.api_contract", "Contratos de API (especificación OpenAPI o springdoc)", "repo", "ASSET", NO_EVALUADO, "pi_api_contract"),
        ("pi.integration_tests", "Pruebas de integración", "repo", "ASSET", NO_EVALUADO, "pi_integration_tests"),
        ("pi.prod_interface_verification", "Verificación de interfaces en producción", "atestacion", "ASSET", NO_EVALUADO, None)]},
    "EST": {"name": "Estimación", "items": [
        ("est.estimate_vs_actual", "Estimación con supuestos y registro estimado-vs-real (ART-F1-06, ART-F5-08)", "artefacto", "ASSET", NO_EVALUADO, None)]},
    "PLAN": {"name": "Planeación", "items": [
        ("plan.project_plan_baseline", "Plan de proyecto con línea base y tailoring registrado (ART-F1-07/08/09, 0A-2b)", "artefacto", "ASSET", NO_EVALUADO, None)]},
    "MC": {"name": "Monitoreo y control", "items": [
        ("mc.biweekly_report_cadence", "Seguimiento quincenal dentro del plan + bitácora (ART-MC-01)", "artefacto", "ASSET", NO_EVALUADO, None)]},
    "RSK": {"name": "Riesgo y oportunidad", "items": [
        ("rsk.risk_section_updated", "Sección de riesgos del Plan actualizada por período (ART-F1-07)", "artefacto", "ASSET", NO_EVALUADO, None)]},
    "OT": {"name": "Capacitación organizacional", "items": [
        ("ot.training_register", "Registro de capacitación del equipo en los activos del estándar", "atestacion", "ORG", NO_EVALUADO, None)]},
    "CM": {"name": "Gestión de configuración", "items": [
        ("cm.git_history", "Historial de versiones en Git (más de un commit real)", "repo", "ASSET", NO_CUMPLE, "cm_git_history"),
        ("cm.release_tags", "Versiones/releases etiquetadas", "gitlab", "ASSET", NO_CUMPLE, "cm_release_tags"),
        ("cm.protected_default_branch", "Rama por defecto protegida", "gitlab", "ASSET", NO_CUMPLE, "cm_protected_default_branch"),
        ("cm.schema_versioned", "Versionado del esquema de datos", "repo", "ASSET", NO_CUMPLE, "cm_schema_versioned"),
        ("cm.two_repositories", "Historial y release en DOS repositorios (proveedor y cliente)", "politica", "ASSET", NO_EVALUADO, None)]},
    "DAR": {"name": "Análisis de decisiones", "items": [
        ("dar.exceptions_register", "Registro de excepciones estructuradas (0B-3 / ART-F2-04)", "artefacto", "ASSET", NO_EVALUADO, None),
        ("dar.adr_records", "Decisiones registradas (indicio: ADR en docs/adr o DECISIONS)", "repo", "ASSET", NO_EVALUADO, "dar_adr_records")]},
    "CAR": {"name": "Análisis causal", "items": [
        ("car.root_cause_analysis", "Análisis causal sobre defectos reales (madura con volumen; política de activación pendiente)", "politica", "ORG", NO_EVALUADO, None)]},
    "GOV": {"name": "Gobernanza", "items": [
        ("gov.catalog_versioned", "Catálogo publicado y versionado", "org-git", "ORG", NO_CUMPLE, "gov_catalog_versioned"),
        ("gov.committee_minutes", "Actas del comité y certificación de fidelidad", "atestacion", "ORG", NO_EVALUADO, None)]},
    "II": {"name": "Infraestructura de implementación", "items": [
        ("ii.asset_repo_versioned", "Repositorio de activos versionado y accesible", "org-git", "ORG", NO_CUMPLE, "ii_asset_repo_versioned"),
        ("ii.adoption", "Repositorio de activos adoptado (proyectos que usan las plantillas)", "artefacto", "ORG", NO_EVALUADO, None)]},
    "MPM": {"name": "Desempeño y medición", "items": [
        ("mpm.estimate_vs_actual_accumulated", "Datos estimado-vs-real acumulados (política de activación pendiente)", "politica", "ORG", NO_EVALUADO, None)]},
    "PAD": {"name": "Desarrollo de activos", "items": [
        ("pad.manifests_valid", "Plantillas/manifiestos válidos (cargan y declaran código, nombre y área CMMI)", "org-git", "ORG", NO_CUMPLE, "pad_manifests_valid"),
        ("pad.templates_versioned", "Plantillas, checklists y prompts versionados en git", "org-git", "ORG", NO_CUMPLE, "pad_templates_versioned")]},
    "PCM": {"name": "Gestión de procesos", "items": [
        ("pcm.process_assets_history", "Versionado de activos y cambios de proceso (historial git de skills/)", "org-git", "ORG", NO_CUMPLE, "pcm_process_assets_history"),
        ("pcm.lessons_learned", "Lecciones aprendidas consolidadas (ART-F5-08)", "artefacto", "ORG", NO_EVALUADO, None)]},
}


# ------------------------------------------------------------------------------------------------ helpers
def _result(status: str, detail: Dict[str, Any], ref: str = "") -> Dict[str, Any]:
    return {"status": status, "detail": detail, "ref": ref}


def _absence(item_key: str) -> str:
    for area in CMMI_AREA_ITEMS.values():
        for it in area["items"]:
            if it[0] == item_key:
                return it[4]
    return NO_EVALUADO


class GitLabAPI:
    """Minimal read-only GitLab REST client bound to ONE instance (never mixes instances' credentials)."""

    def __init__(self, base_url: str, token: str, timeout: float = 20.0):
        self.base = base_url.rstrip("/") + "/api/v4"
        self.headers = {"PRIVATE-TOKEN": token} if token else {}
        self.timeout = timeout

    def get(self, path: str, **params) -> Tuple[int, Any, Dict[str, str]]:
        try:
            r = requests.get(self.base + path, headers=self.headers, params=params, timeout=self.timeout)
            body = r.json() if r.status_code == 200 and r.content else None
            return r.status_code, body, dict(r.headers)
        except Exception as exc:
            logger.warning("GitLab API call %s failed: %s: %s", path, type(exc).__name__, exc)
            return 0, None, {}


def _walk_files(root: str, max_files: int = 20000):
    skip = (".git", "node_modules", "target", "dist", "build", "__pycache__", ".venv")
    n = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in skip]
        for f in fn:
            n += 1
            if n > max_files:
                return
            yield dp, f


def _git(args: List[str], cwd: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", cwd] + args, capture_output=True, text=True, timeout=30)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception as exc:
        logger.warning("git %s failed in %s: %s: %s", args[:1], cwd, type(exc).__name__, exc)
        return None


def _uses_database(root: str) -> bool:
    pat = re.compile(r"@Entity\b|sqlalchemy|psycopg2|typeorm|prisma|mongoose|spring\.datasource|jdbc:", re.IGNORECASE)
    for dp, f in _walk_files(root, 4000):
        if f.endswith((".java", ".py", ".ts", ".properties", ".yml", ".yaml", ".xml", ".json")):
            try:
                with open(os.path.join(dp, f), "r", encoding="utf-8", errors="ignore") as fh:
                    if pat.search(fh.read(60000)):
                        return True
            except OSError:
                continue
    return False


# ------------------------------------------------------------------------------------------------ colectores por activo (GitLab)
def pr_merged_mr_reviewed(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """PR — MR fusionados (últimos 180 días, hasta 20) con al menos una revisión de alguien distinto del autor."""
    api: GitLabAPI = ctx["api"]
    since = (datetime.now(timezone.utc) - timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sc, mrs, _ = api.get(f"/projects/{ctx['project_id']}/merge_requests", state="merged", order_by="updated_at", sort="desc",
                         per_page=20, updated_after=since)
    if sc != 200 or mrs is None:
        return _result(NO_EVALUADO, {"reason": f"la API de GitLab no devolvió los MR (HTTP {sc})"})
    if not mrs:
        return _result(NO_EVALUADO, {"reason": "sin MR fusionados en los últimos 180 días: no hay revisiones que medir", "merged_mrs": 0})
    reviewed = []
    for mr in mrs:
        author = (mr.get("author") or {}).get("id")
        ok = bool(mr.get("reviewers"))
        if not ok:
            sc2, notes, _ = api.get(f"/projects/{ctx['project_id']}/merge_requests/{mr['iid']}/notes", per_page=100)
            ok = any((not n.get("system")) and (n.get("author") or {}).get("id") != author for n in (notes or []))
        if not ok:
            sc3, ap, _ = api.get(f"/projects/{ctx['project_id']}/merge_requests/{mr['iid']}/approvals")
            ok = bool(sc3 == 200 and ap and ap.get("approved_by"))
        reviewed.append(ok)
    n, r = len(mrs), sum(reviewed)
    detail = {"merged_mrs_sampled": n, "with_recorded_review": r, "ratio": round(r / n, 2),
              "rule": "CUMPLE solo si el 100 % de los MR muestreados tiene revisión de una persona distinta del autor (criterio de Centinela; el manual no fija umbral)"}
    return _result(CUMPLE if r == n else NO_CUMPLE, detail)


def vv_tests_green(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """VV — existen pruebas en el repositorio y el último pipeline de la rama por defecto terminó en verde."""
    api: GitLabAPI = ctx["api"]
    root = ctx.get("clone_dir")
    if not root or not os.path.isdir(root):
        return _result(NO_EVALUADO, {"reason": "sin clon local del repositorio para buscar pruebas"})
    test_files = 0
    for dp, f in _walk_files(root):
        rel = os.path.join(dp, f).replace("\\", "/")
        if re.search(r"(/src/test/|/tests?/|/__tests__/|\.spec\.(ts|js)$|\.test\.(ts|js|tsx)$|Test\.java$|Tests\.java$|test_.*\.py$)", rel):
            test_files += 1
    sc, pls, _ = api.get(f"/projects/{ctx['project_id']}/pipelines", ref=ctx.get("default_branch") or "", per_page=20, order_by="id", sort="desc")
    if sc != 200 or pls is None:
        return _result(NO_EVALUADO, {"reason": f"la API de GitLab no devolvió los pipelines (HTTP {sc})", "test_files": test_files})
    latest = pls[0]["status"] if pls else None
    ok_count = sum(1 for p in pls if p.get("status") == "success")
    detail = {"test_files": test_files, "pipelines_sampled": len(pls), "pipelines_success": ok_count, "latest_status": latest,
              "rule": "CUMPLE si hay archivos de prueba y el último pipeline de la rama por defecto es `success`"}
    if test_files and latest == "success":
        return _result(CUMPLE, detail)
    if not test_files:
        detail["why"] = "no se encontraron archivos de prueba en el repositorio"
    elif latest is None:
        detail["why"] = "hay pruebas pero ningún pipeline que demuestre su ejecución"
    else:
        detail["why"] = f"el último pipeline de la rama por defecto terminó en `{latest}`"
    return _result(NO_CUMPLE, detail)


def cm_release_tags(ctx: Dict[str, Any]) -> Dict[str, Any]:
    api: GitLabAPI = ctx["api"]
    sc, tags, headers = api.get(f"/projects/{ctx['project_id']}/repository/tags", per_page=1)
    sc2, rels, headers2 = api.get(f"/projects/{ctx['project_id']}/releases", per_page=1)
    if sc != 200 and sc2 != 200:
        return _result(NO_EVALUADO, {"reason": f"la API no devolvió etiquetas ni releases (HTTP {sc}/{sc2})"})
    n_tags = int(headers.get("X-Total", len(tags or []))) if sc == 200 else None
    n_rel = int(headers2.get("X-Total", len(rels or []))) if sc2 == 200 else None
    detail = {"tags": n_tags, "releases": n_rel}
    return _result(CUMPLE if (n_tags or n_rel) else NO_CUMPLE, detail)


def cm_protected_default_branch(ctx: Dict[str, Any]) -> Dict[str, Any]:
    api: GitLabAPI = ctx["api"]
    default = ctx.get("default_branch")
    sc, prot, _ = api.get(f"/projects/{ctx['project_id']}/protected_branches", per_page=100)
    if sc != 200 or prot is None:
        return _result(NO_EVALUADO, {"reason": f"el token no puede leer las ramas protegidas (HTTP {sc})"})
    names = [p.get("name") for p in prot]
    protected = any(n == default or (n and "*" in n and re.fullmatch(n.replace("*", ".*"), default or "")) for n in names)
    return _result(CUMPLE if protected else NO_CUMPLE, {"default_branch": default, "protected_branches": names})


# ------------------------------------------------------------------------------------------------ colectores por activo (repositorio clonado)
def _repo_ctx_check(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    root = ctx.get("clone_dir")
    if not root or not os.path.isdir(root):
        return _result(NO_EVALUADO, {"reason": "sin clon local del repositorio"})
    return None


def cm_git_history(ctx: Dict[str, Any]) -> Dict[str, Any]:
    # Preferred source: GitLab's own project statistics (the scanner's clones are shallow, so `git rev-list` there only
    # sees 1 commit and proves nothing -- measured 2026-10-01: that made this item NO_EVALUADO for all 26 priority repos).
    # NOTE: `statistics.commit_count` counts the DEFAULT BRANCH only. Verified live 2026-10-01: six proyecto-g repos report 1 there yet
    # have 3-6 commits across their branches, so concluding "no history" from it would be a false negative. The commit list over
    # ALL branches (capped at 100) is the deciding evidence; the default-branch figure is only reported.
    api = ctx.get("api")
    if api is not None and ctx.get("project_id") is not None:
        sc, commits, _ = api.get(f"/projects/{ctx['project_id']}/repository/commits", per_page=100, all="true")
        sc_st, proj, _ = api.get(f"/projects/{ctx['project_id']}", statistics="true")
        default_branch_count = ((proj or {}).get("statistics") or {}).get("commit_count") if sc_st == 200 else None
        if sc == 200 and isinstance(commits, list):
            n_all = len(commits)
            detail = {"commits_all_branches": n_all if n_all < 100 else "100+", "commits_default_branch": default_branch_count,
                      "source": "listado de commits de todas las ramas en GitLab"}
            return _result(CUMPLE if n_all > 1 else NO_CUMPLE, detail)
        if isinstance(default_branch_count, int) and default_branch_count > 1:
            return _result(CUMPLE, {"commits_default_branch": default_branch_count, "source": "estadísticas del proyecto (solo rama por defecto)"})
    guard = _repo_ctx_check(ctx)
    if guard:
        return guard
    out = _git(["rev-list", "--count", "HEAD"], ctx["clone_dir"])
    if out is None or not out.isdigit():
        return _result(NO_CUMPLE, {"reason": "no es un repositorio git verificable (carpeta sin historial)"})
    n = int(out)
    shallow = _git(["rev-parse", "--is-shallow-repository"], ctx["clone_dir"]) == "true"
    detail = {"commits_visible": n, "shallow_clone": shallow,
              "note": "clon superficial: el conteo es un mínimo, no el historial completo" if shallow else ""}
    # a shallow clone with exactly 1 visible commit proves nothing about history: cannot conclude NO_CUMPLE from it
    if n > 1:
        return _result(CUMPLE, detail)
    return _result(NO_EVALUADO if shallow else NO_CUMPLE, detail)


def cm_schema_versioned(ctx: Dict[str, Any]) -> Dict[str, Any]:
    guard = _repo_ctx_check(ctx)
    if guard:
        return guard
    root = ctx["clone_dir"]
    found = []
    for dp, f in _walk_files(root):
        rel = os.path.relpath(os.path.join(dp, f), root).replace("\\", "/")
        if re.search(r"(db/changelog|db/migration|/migrations?/|alembic/versions|changelog.*\.(xml|ya?ml|sql)$)", "/" + rel):
            found.append(rel)
            if len(found) >= 3:
                break
    if found:
        return _result(CUMPLE, {"examples": found})
    if not _uses_database(root):
        return _result(NO_APLICA, {"reason": "el repositorio no muestra uso de base de datos"})
    return _result(NO_CUMPLE, {"reason": "usa base de datos pero no hay changelog/migraciones versionadas"})


def ts_design_docs(ctx: Dict[str, Any]) -> Dict[str, Any]:
    guard = _repo_ctx_check(ctx)
    if guard:
        return guard
    root = ctx["clone_dir"]
    docs = []
    for dp, f in _walk_files(root):
        rel = os.path.relpath(os.path.join(dp, f), root).replace("\\", "/")
        if re.match(r"^(docs?|documentaci[oó]n)/", rel, re.IGNORECASE) and f.lower().endswith((".md", ".pdf", ".docx", ".drawio", ".puml", ".png")):
            docs.append(rel)
    if docs:
        return _result(CUMPLE, {"documents": len(docs), "examples": docs[:3], "level_note": "indicio en repositorio; no sustituye al ART-F2-01"})
    return _result(NO_EVALUADO, {"reason": "no hay carpeta docs/ con documentos en el repositorio (la documentación puede vivir en otro lugar)"})


def ts_data_design_versioned(ctx: Dict[str, Any]) -> Dict[str, Any]:
    res = cm_schema_versioned(ctx)
    if res["status"] == NO_CUMPLE:
        res = _result(NO_EVALUADO, res["detail"])   # for TS this is only an indicator: absence is not a verdict
    return res


def dar_adr_records(ctx: Dict[str, Any]) -> Dict[str, Any]:
    guard = _repo_ctx_check(ctx)
    if guard:
        return guard
    root = ctx["clone_dir"]
    adrs = []
    for dp, f in _walk_files(root):
        rel = os.path.relpath(os.path.join(dp, f), root).replace("\\", "/")
        if f.lower().endswith(".md") and re.search(r"(^|/)(adr|adrs|decisions|decisiones)/", rel, re.IGNORECASE):
            adrs.append(rel)
    if adrs:
        return _result(CUMPLE, {"records": len(adrs), "examples": adrs[:3], "level_note": "indicio; no sustituye al registro de excepciones 0B-3"})
    return _result(NO_EVALUADO, {"reason": "sin carpeta adr/decisions con registros en el repositorio"})


def pi_api_contract(ctx: Dict[str, Any]) -> Dict[str, Any]:
    guard = _repo_ctx_check(ctx)
    if guard:
        return guard
    root = ctx["clone_dir"]
    for dp, f in _walk_files(root):
        low = f.lower()
        if re.match(r"^(openapi|swagger)[\w.-]*\.(ya?ml|json)$", low):
            return _result(CUMPLE, {"contract_file": os.path.relpath(os.path.join(dp, f), root)})
        if low in ("pom.xml", "build.gradle", "build.gradle.kts", "package.json", "requirements.txt"):
            try:
                txt = open(os.path.join(dp, f), encoding="utf-8", errors="ignore").read(200000)
            except OSError:
                continue
            if re.search(r"springdoc|springfox|swagger|openapi|@nestjs/swagger|fastapi", txt, re.IGNORECASE):
                return _result(CUMPLE, {"declared_in": os.path.relpath(os.path.join(dp, f), root), "kind": "dependencia que genera el contrato OpenAPI"})
    return _result(NO_EVALUADO, {"reason": "no se encontró especificación OpenAPI ni librería que la genere"})


def pi_integration_tests(ctx: Dict[str, Any]) -> Dict[str, Any]:
    guard = _repo_ctx_check(ctx)
    if guard:
        return guard
    root = ctx["clone_dir"]
    hits = []
    for dp, f in _walk_files(root):
        rel = os.path.relpath(os.path.join(dp, f), root).replace("\\", "/")
        if re.search(r"(IT\.java$|IntegrationTests?\.java$|\.e2e-spec\.ts$|/integration/|/e2e/|cypress|playwright)", rel, re.IGNORECASE):
            hits.append(rel)
        elif f.endswith((".java", ".py", ".ts")) and "/test" in rel.lower():
            try:
                if re.search(r"@SpringBootTest|testcontainers|supertest|TestClient\(", open(os.path.join(dp, f), encoding="utf-8", errors="ignore").read(40000)):
                    hits.append(rel)
            except OSError:
                pass
        if len(hits) >= 5:
            break
    if hits:
        return _result(CUMPLE, {"examples": hits[:3]})
    return _result(NO_EVALUADO, {"reason": "no se encontraron pruebas de integración en el repositorio"})


# ------------------------------------------------------------------------------------------------ colectores organizacionales
def _org_git(path: str) -> Optional[Dict[str, Any]]:
    full = os.path.join(REPO_ROOT, path)
    if not os.path.exists(full):
        return None
    count = _git(["log", "--oneline", "--", path], REPO_ROOT)
    last = _git(["log", "-1", "--format=%cI", "--", path], REPO_ROOT)
    n = len(count.splitlines()) if count else 0
    return {"path": path, "commits": n, "last_change": last}


# The deliverables generator (methodology skill) is the single source of the artifact catalogue, manifests and schemas since 2026-10-28.
_DELIVERABLES_SKILL = "skills/generador-entregables-ca"


def gov_catalog_versioned(ctx: Dict[str, Any]) -> Dict[str, Any]:
    info = _org_git(_DELIVERABLES_SKILL + "/references/catalogo.md")
    if not info:
        return _result(NO_EVALUADO, {"reason": "no se encontró el catálogo de artefactos en este repositorio"})
    return _result(CUMPLE if info["commits"] > 0 else NO_CUMPLE, info)


def ii_asset_repo_versioned(ctx: Dict[str, Any]) -> Dict[str, Any]:
    info = _org_git("skills")
    if not info:
        return _result(NO_EVALUADO, {"reason": "no se encontró el directorio de activos `skills/`"})
    return _result(CUMPLE if info["commits"] > 0 else NO_CUMPLE, info)


def pcm_process_assets_history(ctx: Dict[str, Any]) -> Dict[str, Any]:
    info = _org_git("skills")
    if not info:
        return _result(NO_EVALUADO, {"reason": "no se encontró `skills/`"})
    return _result(CUMPLE if info["commits"] > 1 else NO_CUMPLE, info)


def pad_templates_versioned(ctx: Dict[str, Any]) -> Dict[str, Any]:
    info = _org_git(_DELIVERABLES_SKILL + "/references/manifiestos")
    schemas = _org_git(_DELIVERABLES_SKILL + "/schemas")
    if not info:
        return _result(NO_EVALUADO, {"reason": "no se encontró el directorio de manifiestos"})
    ok = info["commits"] > 0 and (schemas is None or schemas["commits"] > 0)
    return _result(CUMPLE if ok else NO_CUMPLE, {"manifests": info, "schemas": schemas})


def pad_manifests_valid(ctx: Dict[str, Any]) -> Dict[str, Any]:
    import glob
    try:
        import yaml
    except ImportError:
        return _result(NO_EVALUADO, {"reason": "PyYAML no está instalado"})
    files = sorted(glob.glob(os.path.join(REPO_ROOT, _DELIVERABLES_SKILL, "references/manifiestos/*.manifest.yaml")))
    if not files:
        return _result(NO_EVALUADO, {"reason": "no hay manifiestos en el repositorio"})
    bad = []
    for f in files:
        try:
            d = yaml.safe_load(open(f, encoding="utf-8")) or {}
            pl = d.get("plantilla") or {}
            if not (pl.get("codigo") and pl.get("nombre")) or "ancla_pa_cmmi" not in pl:
                bad.append(os.path.basename(f))
        except Exception as exc:
            bad.append(f"{os.path.basename(f)} ({type(exc).__name__})")
    return _result(CUMPLE if not bad else NO_CUMPLE, {"manifests": len(files), "invalid": bad})


def ii_starter_base_governed(ctx: Dict[str, Any]) -> Dict[str, Any]:  # kept out of CMMI_AREA_ITEMS until the starters mapping is confirmed
    return _result(NO_EVALUADO, {"reason": "mapeo de la base de arranque pendiente"})


def pqa_ai_validation_trace(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """PQA (flujo propio): toda propuesta de la IA de Centinela debe terminar en una decisión humana con nombre."""
    if db_manager is None:
        return _result(NO_EVALUADO, {"reason": "sin acceso a la BD"})
    with db_manager.get_db_cursor() as cur:
        cur.execute("""
            SELECT count(*) FILTER (WHERE review_status = 'PENDING'),
                   count(*) FILTER (WHERE review_status IN ('APPROVED', 'REJECTED') AND reviewed_by IS NOT NULL),
                   count(*) FILTER (WHERE review_status = 'PENDING' AND created_at < now() - interval '14 days'),
                   count(*)
            FROM finding_suppressions WHERE created_by = 'centinela-ai'
        """)
        pending, reviewed, stale, total = cur.fetchone()
    detail = {"ai_suppression_proposals": total, "reviewed_with_reviewer": reviewed, "pending": pending, "pending_over_14_days": stale,
              "scope": "solo la IA de Centinela; la IA que usa cada equipo en su código se evidencia con ART-F3-04",
              "rule": "CUMPLE si ninguna propuesta de la IA lleva más de 14 días sin decisión humana"}
    if total == 0:
        return _result(NO_EVALUADO, {**detail, "reason": "la IA aún no ha generado propuestas que revisar"})
    return _result(CUMPLE if stale == 0 else NO_CUMPLE, detail)


COLLECTORS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    f.__name__: f for f in (
        pr_merged_mr_reviewed, vv_tests_green, cm_release_tags, cm_protected_default_branch, cm_git_history, cm_schema_versioned,
        ts_design_docs, ts_data_design_versioned, dar_adr_records, pi_api_contract, pi_integration_tests,
        gov_catalog_versioned, ii_asset_repo_versioned, pcm_process_assets_history, pad_templates_versioned, pad_manifests_valid,
        pqa_ai_validation_trace)
}


# ------------------------------------------------------------------------------------------------ persistencia y reporte
_UPSERT = """
INSERT INTO public.cmmi_evidence (scope, asset_id, area, item_key, level, status, detail, evidence_ref, collected_at, valid_until, attested_by)
VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, NOW(), %s, %s)
ON CONFLICT (scope, (COALESCE(asset_id, '00000000-0000-0000-0000-000000000000'::uuid)), area, item_key)
DO UPDATE SET level = EXCLUDED.level, status = EXCLUDED.status, detail = EXCLUDED.detail, evidence_ref = EXCLUDED.evidence_ref,
              collected_at = NOW(), valid_until = EXCLUDED.valid_until, attested_by = EXCLUDED.attested_by
"""


def save_evidence(cur, scope: str, asset_id: Optional[str], area: str, item_key: str, result: Dict[str, Any],
                  level: str = "L1", valid_days: int = 30, attested_by: Optional[str] = None) -> None:
    cur.execute(_UPSERT, (scope, asset_id, area, item_key, level, result["status"], json.dumps(result["detail"], ensure_ascii=False),
                          result.get("ref", ""), datetime.now() + timedelta(days=valid_days), attested_by))


def _collect(scope: str, ctx: Dict[str, Any], asset_id: Optional[str], cur) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for area, spec in CMMI_AREA_ITEMS.items():
        for key, _desc, _src, item_scope, absence, collector in spec["items"]:
            if item_scope != scope or collector is None:
                continue
            try:
                res = COLLECTORS[collector](ctx)
            except Exception as exc:
                import traceback
                traceback.print_exc()
                res = _result(NO_EVALUADO, {"reason": f"el colector falló: {type(exc).__name__}: {exc}"})
            save_evidence(cur, scope, asset_id, area, key, res)
            out[key] = res["status"]
    return out


def collect_asset_evidence(asset_id: str, asset_name: str, instance, project: Dict[str, Any], branch: str = None) -> Dict[str, str]:
    """Collects every per-asset L1 item for ONE GitLab project and stores it. `instance` is a core.gitlab_instances.GitLabInstance."""
    api = GitLabAPI(instance.url, instance.token)
    clone_dir = os.path.join(SCANS_BASE, instance.clone_folder(project["path_with_namespace"], branch))
    ctx = {"api": api, "project_id": project["id"], "default_branch": project.get("default_branch"),
           "clone_dir": clone_dir if os.path.isdir(clone_dir) else None, "asset_name": asset_name}
    with db_manager.get_db_cursor() as cur:
        return _collect("ASSET", ctx, asset_id, cur)


def collect_org_evidence() -> Dict[str, str]:
    with db_manager.get_db_cursor() as cur:
        return _collect("ORG", {}, None, cur)


def build_area_report(asset_id: Optional[str]) -> Dict[str, Any]:
    """The 19 areas, always all of them, each item with its real status. Cumplimiento y cobertura se informan por separado."""
    rows: Dict[Tuple[str, str], Dict[str, Any]] = {}
    with db_manager.get_db_cursor() as cur:
        cur.execute("""SELECT scope, area, item_key, level, status, detail, evidence_ref, collected_at, valid_until, attested_by
                       FROM cmmi_evidence WHERE scope = 'ORG' OR asset_id IS NOT DISTINCT FROM %s""", (asset_id,))
        for scope, area, key, level, status, detail, ref, collected, valid_until, attested in cur.fetchall():
            rows[(area, key)] = {"level": level, "status": status, "detail": detail, "ref": ref, "collected_at": collected,
                                 "valid_until": valid_until, "attested_by": attested}
    now = datetime.now()
    areas = []
    for area, spec in CMMI_AREA_ITEMS.items():
        items = []
        for key, desc, src, item_scope, absence, collector in spec["items"]:
            row = rows.get((area, key))
            if row and row["valid_until"] and row["valid_until"] < now:
                row = None  # expired evidence stops counting (ADR-0007 §2f)
            if row:
                st, level = row["status"], row["level"]
            else:
                st = NO_EVALUADO
                level = "L0"
            items.append({"key": key, "description": desc, "source": src, "scope": item_scope, "status": st, "level": level,
                          "measurable_today": collector is not None, "detail": (row or {}).get("detail", {}) if row else
                          {"reason": "sin colector o evidencia aún no disponible: " + ("requiere " + src)}})
        evaluated = [i for i in items if i["status"] in (CUMPLE, NO_CUMPLE)]
        applicable = [i for i in items if i["status"] != NO_APLICA]
        met = [i for i in evaluated if i["status"] == CUMPLE]
        if not evaluated:
            state = "NO_EVALUADA"
        elif len(evaluated) < len(applicable):
            state = "PARCIAL_CUMPLE" if len(met) == len(evaluated) else "PARCIAL_NO_CUMPLE"
        else:
            state = "CUMPLE" if len(met) == len(evaluated) else "NO_CUMPLE"
        areas.append({"area": area, "name": spec["name"], "state": state, "items": items,
                      "items_total": len(applicable), "items_evaluated": len(evaluated), "items_met": len(met)})
    with_evidence = [a for a in areas if a["items_evaluated"] > 0]
    return {
        "areas": areas,
        "summary": {
            "areas_total": len(areas),
            "areas_with_any_evidence": len(with_evidence),
            "areas_fully_evaluated": sum(1 for a in areas if a["state"] in ("CUMPLE", "NO_CUMPLE")),
            "areas_met": sum(1 for a in areas if a["state"] == "CUMPLE"),
            "items_total": sum(a["items_total"] for a in areas),
            "items_evaluated": sum(a["items_evaluated"] for a in areas),
            "items_met": sum(a["items_met"] for a in areas),
        },
        "reliability_note": ("Indicador interno de preparación según la columna «Evidencia de cumplimiento» del manual de metodología; NO es una evaluación "
                             "CMMI formal (el propio manual indica que para ello se requiere el modelo completo de ISACA). Las áreas sin evidencia "
                             "se muestran como NO_EVALUADA; la cobertura de evidencia y el cumplimiento se informan por separado."),
    }
