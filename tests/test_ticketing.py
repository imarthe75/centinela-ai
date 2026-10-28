"""core/ticketing.py and the ticket endpoint: no credentials in code, configured only by environment, header auth, honest status codes."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from core import ticketing as t

VULN = {"severity": "CRITICAL", "cve_id": "SQL-INJECTION", "asset_name": "GitLab/x/y"}
REDMINE = {"REDMINE_URL": "https://redmine.example.test/", "REDMINE_API_KEY": "key-123", "REDMINE_PROJECT_ID": "7"}
GITEA = {"GITEA_URL": "https://gitea.example.test", "GITEA_TOKEN": "tok-456", "GITEA_REPO": "seg/incidentes"}


class TestConfig(unittest.TestCase):
    def test_missing_variables_are_named(self):
        with self.assertRaises(t.TicketingNotConfigured) as cm:
            t.load_config("redmine", {"REDMINE_URL": "https://r.test"})
        self.assertEqual(cm.exception.missing, ["REDMINE_API_KEY", "REDMINE_PROJECT_ID"])
        with self.assertRaises(t.TicketingNotConfigured):
            t.load_config("gitea", {})

    def test_bad_target_and_bad_url(self):
        with self.assertRaises(ValueError):
            t.load_config("jira", {})
        with self.assertRaises(t.TicketingError):
            t.load_config("redmine", {**REDMINE, "REDMINE_URL": "ftp://r.test"})
        with self.assertRaises(t.TicketingError):
            t.build_request("gitea", t.load_config("gitea", {**GITEA, "GITEA_REPO": "solo-un-nombre"}), VULN, "d")


class TestRequests(unittest.TestCase):
    def test_redmine_uses_the_api_key_header_not_basic_auth(self):
        url, headers, payload = t.build_request("redmine", t.load_config("redmine", REDMINE), VULN, "desc")
        self.assertEqual(url, "https://redmine.example.test/issues.json")
        self.assertEqual(headers["X-Redmine-API-Key"], "key-123")
        self.assertEqual(payload["issue"]["project_id"], "7")
        self.assertEqual(payload["issue"]["priority_id"], 4)
        self.assertNotIn("auth", headers)

    def test_gitea_uses_a_token_header(self):
        url, headers, payload = t.build_request("gitea", t.load_config("gitea", GITEA), VULN, "desc")
        self.assertEqual(url, "https://gitea.example.test/api/v1/repos/seg/incidentes/issues")
        self.assertEqual(headers["Authorization"], "token tok-456")
        self.assertEqual(payload["title"], "[CRITICAL] SQL-INJECTION - GitLab/x/y")


class TestSend(unittest.TestCase):
    """Against a LOCAL server that imitates the trackers' answers (isolated test of our client)."""

    def run_server(self, status, body):
        seen = []

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append((self.path, self.headers.get("X-Redmine-API-Key") or self.headers.get("Authorization"),
                             json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                self.send_response(status)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        return f"http://127.0.0.1:{srv.server_port}", seen

    def test_redmine_and_gitea_roundtrip(self):
        base, seen = self.run_server(201, {"issue": {"id": 42}})
        r = t.send_ticket("redmine", VULN, "d", {**REDMINE, "REDMINE_URL": base})
        self.assertEqual((r["status"], r["id"], r["url"]), ("created", 42, f"{base}/issues/42"))
        self.assertEqual(seen[0][:2], ("/issues.json", "key-123"))
        base, seen = self.run_server(201, {"number": 9})
        r = t.send_ticket("gitea", VULN, "d", {**GITEA, "GITEA_URL": base})
        self.assertEqual((r["id"], r["url"]), (9, f"{base}/seg/incidentes/issues/9"))
        self.assertEqual(seen[0][:2], ("/api/v1/repos/seg/incidentes/issues", "token tok-456"))

    def test_tracker_error_is_reported_not_swallowed(self):
        base, _ = self.run_server(403, {"message": "forbidden"})
        with self.assertRaises(t.TicketingError):
            t.send_ticket("gitea", VULN, "d", {**GITEA, "GITEA_URL": base})


class TestNoLiteralsInCode(unittest.TestCase):
    def test_source_has_no_hardcoded_admin_credentials(self):
        root = Path(__file__).resolve().parents[1]
        for rel in ("api/routers/findings.py", "core/ticketing.py"):
            text = (root / rel).read_text(encoding="utf-8")
            self.assertNotIn('auth=("admin"', text, rel)
            self.assertNotIn("_pwd", text, rel)


class TestEndpoint(unittest.TestCase):
    def test_unconfigured_integration_answers_503_and_unknown_target_400(self):
        import main
        c = TestClient(main.app)
        fake = {"cve_id": "X", "severity": "HIGH", "asset_name": "a", "description": "d"}
        cur = mock.MagicMock()
        cur.__enter__.return_value.fetchone.return_value = fake
        with mock.patch("api.routers.findings.db_manager.get_db_cursor", return_value=cur), mock.patch.dict("os.environ", {}, clear=False):
            for k in list(REDMINE) + list(GITEA):
                __import__("os").environ.pop(k, None)
            r = c.post("/api/remediation/00000000-0000-0000-0000-000000000001/ticket", json={"title": "t", "description": "d", "target": "gitea"})
            self.assertEqual(r.status_code, 503)
            self.assertIn("GITEA_URL", r.json()["detail"])
            r = c.post("/api/remediation/00000000-0000-0000-0000-000000000001/ticket", json={"title": "t", "description": "d", "target": "jira"})
            self.assertEqual(r.status_code, 400)
        cur.__enter__.return_value.fetchone.return_value = None
        with mock.patch("api.routers.findings.db_manager.get_db_cursor", return_value=cur):
            r = c.post("/api/remediation/00000000-0000-0000-0000-000000000002/ticket", json={"title": "t", "description": "d", "target": "gitea"})
            self.assertEqual(r.status_code, 404)                       # used to surface as 500


if __name__ == "__main__":
    unittest.main()
