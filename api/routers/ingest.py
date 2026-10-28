"""POST /api/ingest/smart-tests — security-relevant failures sent by centinela-smart-tests (ADR-0015).

Fail-closed (rule 7): without SMART_TESTS_INGEST_TOKEN configured -> 503; wrong or missing bearer -> 401 (constant-time comparison).
The path is exempt from the Authentik middleware (core/auth.py) because it has its own service token.
"""
import hmac
import logging
import os

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from core import agent_ledger, db_manager, smart_tests_ingest

logger = logging.getLogger(__name__)
router = APIRouter()


def _check_token(request: Request) -> None:
    secret = os.getenv("SMART_TESTS_INGEST_TOKEN", "")
    if not secret:
        raise HTTPException(status_code=503, detail="ingesta deshabilitada: SMART_TESTS_INGEST_TOKEN no está configurado")
    auth = request.headers.get("authorization", "")
    supplied = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not supplied or not hmac.compare_digest(supplied.encode("utf-8"), secret.encode("utf-8")):
        raise HTTPException(status_code=401, detail="token de ingesta inválido")


def _persist(payload):
    with db_manager.get_db_cursor() as cur:
        return smart_tests_ingest.ingest(cur, payload)


@router.post("/api/ingest/smart-tests")
async def ingest_smart_tests(request: Request):
    # Order matters (rule 7): the token is checked BEFORE the body is read or parsed, so an unauthenticated call always gets 401/503,
    # never a 422 that reveals the schema. FastAPI parses a declared Body before running route dependencies, hence the manual read.
    _check_token(request)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="el cuerpo no es JSON válido")
    try:
        smart_tests_ingest.validate(payload)
    except smart_tests_ingest.IngestError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:
        out = await run_in_threadpool(_persist, payload)       # blocking DB write off the event loop (ADR-0008)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        logger.error("ingesta de centinela-smart-tests fallida", exc_info=True)
        raise HTTPException(status_code=500, detail="error al registrar los resultados")
    if not out["accepted"]:
        raise HTTPException(status_code=422, detail={"message": "ningún resultado aceptado", "rejected": out["rejected"]})
    await run_in_threadpool(
        agent_ledger.record_action, agent_ledger.ACTION_SMART_TESTS_INGEST,
        f"{out['accepted']} fallo(s) de pruebas funcionales con impacto de seguridad registrados para {payload['asset_name']}",
        actor="centinela-smart-tests", entity_type="asset", entity_id=out["asset_id"], asset_id=out["asset_id"],
        detail={"run": payload.get("run"), "findings": out["findings"], "rejected": out["rejected"]})
    return out


def _store_run(payload):
    from core import functional_tests
    with db_manager.get_db_cursor() as cur:
        return functional_tests.store_run(cur, payload)


@router.post("/api/ingest/smart-tests/run")
async def ingest_smart_tests_run(request: Request):
    """Whole run (every case, any status) for the "Pruebas funcionales" tab. Same token and fail-closed order as /api/ingest/smart-tests;
    security findings keep their own endpoint. Re-sending a run replaces it."""
    from core import functional_tests
    _check_token(request)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="el cuerpo no es JSON válido")
    try:
        functional_tests.validate_run(payload)
    except functional_tests.RunError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:
        out = await run_in_threadpool(_store_run, payload)
    except functional_tests.RunError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception:
        logger.error("registro de corrida de centinela-smart-tests fallido", exc_info=True)
        raise HTTPException(status_code=500, detail="error al registrar la corrida")
    s = out["summary"]
    await run_in_threadpool(
        agent_ledger.record_action, agent_ledger.ACTION_SMART_TESTS_INGEST,
        f"Corrida de pruebas funcionales «{payload['run'].get('project')}» registrada: {s['counts']} de {s['planned']} planeados",
        actor="centinela-smart-tests", entity_type="functional_test_run", entity_id=out["run_id"],
        detail={"run_key": out["run_key"], "created": out["created"], "summary": s})
    return out


def _store_ci(payload):
    from core import ci_test_reports
    with db_manager.get_db_cursor() as cur:
        return ci_test_reports.store(cur, payload)


@router.post("/api/ingest/smart-tests/ci")
async def ingest_smart_tests_ci(request: Request):
    """CI test report summary (JUnit/JaCoCo) of a project, read by centinela-smart-tests. Same token and fail-closed order as the other
    smart-tests endpoints. Re-sending the same pipeline replaces it."""
    from core import ci_test_reports
    _check_token(request)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="el cuerpo no es JSON válido")
    try:
        ci_test_reports.validate(payload)
    except ci_test_reports.CIReportError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:
        out = await run_in_threadpool(_store_ci, payload)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        logger.error("registro de reporte de CI fallido", exc_info=True)
        raise HTTPException(status_code=500, detail="error al registrar el reporte de CI")
    s = payload["summary"]
    await run_in_threadpool(
        agent_ledger.record_action, agent_ledger.ACTION_SMART_TESTS_INGEST,
        f"Reporte de CI de «{payload['asset_name']}» registrado: {s.get('tests')} pruebas, {s.get('failures')} fallidas",
        actor="centinela-smart-tests", entity_type="ci_test_report", entity_id=out["report_id"], asset_id=out["asset_id"],
        detail={"run": payload.get("run"), "created": out["created"]})
    return out
