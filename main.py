from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request, BackgroundTasks, UploadFile, File, Form
import shutil
from core import agent_ledger
from core import access_scope
from typing import List, Dict, Set, Optional, Union, Any
import asyncio
import logging
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import psycopg2
from datetime import datetime
from psycopg2.extras import RealDictCursor
import pandas as pd
from core import db_manager, itdr_engine, clickhouse_manager, ebpf_telemetry, attack_graph, ueba_engine, soar_engine, deduplication_engine
from pydantic import BaseModel
from typing import Optional
import requests
import re
import html
import hvac
import threading
import subprocess
import tempfile
import stat
import time


import socket
import threading as _threading

from api.common import (
    poll_asset_status,
    poll_new_alerts,
)


app = FastAPI(title="Centinela-AI Security API")




# CORS para el nuevo frontend React
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API authentication (ADR-0008 #8): mode via API_AUTH_MODE (off | log | enforce; default log). See core/auth.py.
from core.auth import ApiAuthMiddleware, status as _auth_status
app.add_middleware(ApiAuthMiddleware)


@app.get("/api/auth/status")
def api_auth_status():
    """Auth mode and what log-mode WOULD have rejected -- the evidence needed to decide when to enforce."""
    return _auth_status()



@app.on_event("startup")
async def startup_event():
    # Sync handlers run in anyio's thread pool (default 40 threads) but the DB pool has 20
    # connections: cap the threads well below that (and bound peak memory) so a burst can't exhaust the pool (PoolError).
    import anyio.to_thread
    anyio.to_thread.current_default_thread_limiter().total_tokens = 8
    asyncio.create_task(poll_new_alerts())
    asyncio.create_task(poll_asset_status())

    # Self-heal the tables this codebase owns (finding_suppressions, agent_actions). All
    # statements are CREATE ... IF NOT EXISTS -- see core/schema.py.
    try:
        from core.schema import ensure_core_schema
        with db_manager.get_db_cursor() as _schema_cur:
            ensure_core_schema(_schema_cur)
    except Exception as e:
        print(f"⚠️ [Centinela-Backend] ensure_core_schema failed (continuing): {e}")

    # Same reap as centinela-ai's startup -- this service can also independently launch a ZAP
    # scan (see /api/audit endpoints below), so an ungraceful restart here can orphan a sibling
    # container the same way. Age-gated (see reap_orphaned_zap_containers()'s docstring), so it
    # can't race-kill a scan the *other* service genuinely has in flight right now.
    try:
        from auditors.auditor_zap import reap_orphaned_zap_containers
        reap_orphaned_zap_containers()
    except Exception as e:
        print(f"⚠️ [Centinela-Backend] ZAP container reap at startup failed: {e}")

# --- API routers (ADR-0008 #3) ---
from api.routers.compliance import router as _router_compliance
from api.routers.findings import router as _router_findings
from api.routers.gitlab import router as _router_gitlab
from api.routers.inventory import router as _router_inventory
from api.routers.platform import router as _router_platform
from api.routers.preflight import router as _router_preflight
from api.routers.reports import router as _router_reports
from api.routers.response import router as _router_response
from api.routers.triage import router as _router_triage
from api.routers.test_credentials import router as _router_test_credentials
from api.routers.ingest import router as _router_ingest
from api.routers.functional_tests import router as _router_functional_tests
from api.routers.access import router as _router_access
app.include_router(_router_compliance, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_findings, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_gitlab, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_inventory, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_platform, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_preflight, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_reports, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_response, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_triage, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_test_credentials, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_ingest, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_functional_tests, dependencies=[Depends(access_scope.enforce_request_scope)])
app.include_router(_router_access, dependencies=[Depends(access_scope.enforce_request_scope)])

# Backwards-compatible re-exports: tests and a few auditors import helpers from `main` (e.g. `from main import extract_clean_code`).
import api.common as _api_common
import importlib as _il
for _m in ['compliance', 'findings', 'gitlab', 'inventory', 'platform', 'reports', 'response']:
    for _k, _v in vars(_il.import_module("api.routers." + _m)).items():
        if not _k.startswith("__") and _k not in globals():
            globals()[_k] = _v
for _k, _v in vars(_api_common).items():
    if not _k.startswith("__") and _k not in globals():
        globals()[_k] = _v



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
