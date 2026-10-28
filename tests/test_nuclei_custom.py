"""Real nuclei binary against a local HTTP server: templates must fire on exposure and stay silent on a clean target."""
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from auditors import nuclei_custom

pytestmark = pytest.mark.skipif(not shutil.which("nuclei"), reason="nuclei not installed")


def _serve(routes):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = routes.get(self.path)
            self.send_response(200 if body is not None else 404)
            self.end_headers()
            self.wfile.write((body or "not found").encode())
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_templates_fire_on_exposed_endpoints():
    srv = _serve({"/api/v1/_openapi": '{"openapi":"3.0","paths":{}}', "/metrics": "# HELP up x\n# TYPE up gauge\nup 1\n"})
    try:
        ids = {h["template_id"] for h in nuclei_custom.run_custom_templates(f"http://127.0.0.1:{srv.server_port}")}
    finally:
        srv.shutdown()
    assert ids == {"centinela-superset-api-docs-exposed", "centinela-prometheus-metrics-exposed"}


def test_templates_silent_on_clean_target():
    srv = _serve({"/": "hello"})
    try:
        assert nuclei_custom.run_custom_templates(f"http://127.0.0.1:{srv.server_port}") == []
    finally:
        srv.shutdown()


def test_missing_template_dir_raises(monkeypatch):
    monkeypatch.setattr(nuclei_custom, "TEMPLATE_DIR", "/nonexistent")
    with pytest.raises(FileNotFoundError):
        nuclei_custom.run_custom_templates("http://127.0.0.1:1")
