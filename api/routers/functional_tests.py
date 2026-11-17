"""Read side of the "Pruebas funcionales" tab: runs sent by centinela-smart-tests (core/functional_tests.py)."""
import os

from core import access_scope
from fastapi import APIRouter, HTTPException

from core import db_manager, functional_tests

router = APIRouter()


@router.get("/api/functional-tests/status")
def functional_tests_status():
    """Whether ingestion is enabled (the token exists; its value is never returned) and how many runs have arrived."""
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT count(*), max(received_at) FROM public.functional_test_runs")
        n, last = cur.fetchone()
    return {"ingest_enabled": bool(os.getenv("SMART_TESTS_INGEST_TOKEN")), "runs": n,
            "last_received_at": last.isoformat() if last else None,
            "endpoints": {"run": "/api/ingest/smart-tests/run", "security_failures": "/api/ingest/smart-tests",
                          "ci": "/api/ingest/smart-tests/ci"}}


@router.get("/api/functional-tests/runs")
def list_functional_test_runs(project: str = None, limit: int = 200):
    with db_manager.get_db_cursor() as cur:
        return [r for r in functional_tests.list_runs(cur, project, limit) if access_scope.allows(r.get("asset_name"))]   # ADR-0019


@router.get("/api/functional-tests/runs/{run_id}")
def get_functional_test_run(run_id: str):
    import uuid
    try:
        uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Corrida no encontrada")
    with db_manager.get_db_cursor() as cur:
        run = functional_tests.get_run(cur, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Corrida no encontrada")
    return run


@router.get("/api/functional-tests/ci-reports")
def list_ci_test_reports(asset: str = None, limit: int = 100):
    """CI test report summaries (JUnit/JaCoCo) sent by centinela-smart-tests, newest first."""
    from core import ci_test_reports
    with db_manager.get_db_cursor() as cur:
        return [r for r in ci_test_reports.list_reports(cur, asset, limit) if access_scope.allows(r.get("asset_name"))]   # ADR-0019
