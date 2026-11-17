"""Signed, hash-pinned Wazuh agent one-liner (/api/inventory/{asset}/agent-install-command and the public /api/agent/install-script).
Runs inside a transaction that is rolled back (rule 8)."""
import contextlib
import hashlib
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from core import db_manager


class TestAgentInstallCommand(unittest.TestCase):
    def setUp(self):
        self._stack = contextlib.ExitStack()
        self.conn = self._stack.enter_context(db_manager.get_db_connection())

        @contextlib.contextmanager
        def shared_cursor(cursor_factory=None):
            cur = self.conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cur
            finally:
                cur.close()
        self._stack.enter_context(mock.patch.object(db_manager, "get_db_cursor", shared_cursor))
        self._stack.enter_context(mock.patch.dict("os.environ", {"API_SERVICE_TOKEN": "t" * 40, "API_AUTH_MODE": "enforce"}))
        cur = self.conn.cursor()
        cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES ('test-agent-linux', 'SERVER', '192.0.2.25')")
        cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES ('test-agent-win', 'SERVER_WINDOWS', '192.0.2.24')")
        from main import app
        self.c = TestClient(app)
        self.auth = {"Authorization": "Bearer " + "t" * 40}

    def tearDown(self):
        self.conn.rollback()
        self._stack.close()

    def test_command_downloads_exactly_the_hashed_script(self):
        r = self.c.get("/api/inventory/test-agent-linux/agent-install-command", headers=self.auth)
        self.assertEqual(r.status_code, 200, r.text)
        out = r.json()
        self.assertIn("sha256sum -c -", out["command"])
        self.assertIn(out["sha256"], out["command"])
        u = urlparse(out["url"])
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        s = self.c.get(u.path, params=q)                 # no session: the signature is the authorization
        self.assertEqual(s.status_code, 200, s.text)
        self.assertEqual(hashlib.sha256(s.content).hexdigest(), out["sha256"])
        self.assertTrue(s.text.startswith("#!/usr/bin/env bash"))

    def test_bad_signature_expired_link_and_non_linux(self):
        exp = int(time.time()) + 3600
        self.assertEqual(self.c.get("/api/agent/install-script", params={"asset": "test-agent-linux", "exp": exp, "sig": "0" * 64}).status_code, 403)
        from api.routers import inventory
        old = int(time.time()) - 10
        sig = inventory._agent_install_sig("test-agent-linux", old)
        self.assertEqual(self.c.get("/api/agent/install-script", params={"asset": "test-agent-linux", "exp": old, "sig": sig}).status_code, 410)
        self.assertEqual(self.c.get("/api/inventory/test-agent-win/agent-install-command", headers=self.auth).status_code, 422)

    def test_unsafe_asset_name_gets_no_one_liner(self):
        from api.routers import inventory
        self.assertIsNone(inventory._linux_installer_bytes('x"; rm -rf /; "', int(time.time()) + 100))

    def test_fails_closed_without_signing_key(self):
        with mock.patch.dict("os.environ", {"API_SERVICE_TOKEN": ""}):
            r = self.c.get("/api/agent/install-script", params={"asset": "test-agent-linux", "exp": int(time.time()) + 60, "sig": "x"})
            self.assertEqual(r.status_code, 503)


if __name__ == "__main__":
    unittest.main()
