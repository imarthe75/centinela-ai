"""Schemathesis safe-mode auditor. The end-to-end test runs the REAL schemathesis container against a throwaway API served from the
test process (reachable on aura-network by this container's IP) and persists into the disposable test DB."""
import json
import shutil
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from auditors import auditor_api_fuzz as fz
from core import db_manager

OPENAPI = {"openapi": "3.0.2", "info": {"title": "t", "version": "1"}, "paths": {
    "/ok": {"get": {"responses": {"200": {"description": "ok"}}}},
    "/item": {"get": {"parameters": [{"name": "q", "in": "query", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}}}}}


class _Api(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/openapi.json":
            code, body = 200, json.dumps(OPENAPI).encode()
        elif u.path == "/item":
            q = parse_qs(u.query).get("q", [""])[0]
            code, body = (500, b"boom") if len(q) >= 1 else (200, b"{}")
        else:
            code, body = 200, b"{}"
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass


def test_refuses_own_stack_and_bad_schemes():
    assert fz.refuse_reason("http://centinela-backend:8000/openapi.json")
    assert fz.refuse_reason("http://127.0.0.1:8302/openapi.json")
    assert fz.refuse_reason("file:///etc/passwd")
    assert fz.refuse_reason("http://192.0.2.16:8088/openapi.json") is None
    with pytest.raises(ValueError):
        fz.run_schemathesis("http://centinela-backend:8000/openapi.json", "http://centinela-backend:8000")


def test_no_targets_configured_is_a_noop(monkeypatch):
    monkeypatch.delenv("SCHEMATHESIS_TARGETS", raising=False)
    assert fz.load_targets() == []
    monkeypatch.setenv("SCHEMATHESIS_TARGETS", "not json")
    assert fz.load_targets() == []


def test_report_parsing_and_trust():
    rep = {"complete": True, "stop_reason": "completed", "errors": [], "failures": [
        {"type": "ServerError", "count": 2, "operations": ["GET /item"]}, {"type": "Other", "operations": ["GET /x"]}]}
    f = fz.report_to_findings(rep, "http://api/")
    assert [(x["cve_id"], x["url_path"]) for x in f] == [("WSTG-ERRH-01-API-SERVER-ERROR", "http://api/item")]
    assert fz.report_is_trustworthy(rep)
    assert not fz.report_is_trustworthy({**rep, "errors": [{"x": 1}]})
    assert not fz.report_is_trustworthy({**rep, "complete": False})


def _docker_ready():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", fz.IMAGE], capture_output=True).returncode == 0


@pytest.mark.skipif(not _docker_ready(), reason="docker / schemathesis image unavailable")
def test_real_container_finds_5xx_and_persists_idempotently():
    srv = HTTPServer(("0.0.0.0", 0), _Api)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://{socket.gethostbyname(socket.gethostname())}:{srv.server_port}"
    try:
        with db_manager.get_db_cursor() as cur:
            cur.execute("SELECT id FROM infra_inventory WHERE asset_name = 'servidor-de-pruebas'")
            aid = cur.fetchone()[0]
        target = {"endpoint": base, "schema_url": base + "/openapi.json"}
        n1 = fz.scan_target(aid, target)
        n2 = fz.scan_target(aid, target)
    finally:
        srv.shutdown()
    assert n1 == n2 == 1
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT count(*), min(url_path) FROM vulnerability_log WHERE asset_id = %s AND scan_engine = 'api-fuzz' AND status <> 'RESOLVED' AND url_path LIKE %s", (aid, base + "%"))
        count, path = cur.fetchone()
        cur.execute("DELETE FROM vulnerability_log WHERE asset_id = %s AND scan_engine = 'api-fuzz'", (aid,))     # leave the test DB as found
    assert count == 1 and path == base + "/item"
