"""DB hardening auditor. The PostgreSQL probe is exercised against a local fake server that speaks the real wire protocol (SSLRequest answer +
first authentication message), and persistence runs inside a transaction that is rolled back (rule 8)."""
import contextlib
import socket
import struct
import threading
import unittest
from unittest import mock

from auditors import auditor_db_hardening as dbh
from core.db_manager import get_db_connection


class FakePostgres:
    """Answers 'N' to SSLRequest and then the given AuthenticationRequest code (0 trust, 3 password, 5 md5, 10 SASL)."""

    def __init__(self, auth_code: int):
        self.auth_code = auth_code
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.received_password = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    length, code = struct.unpack("!II", conn.recv(8))
                    if code == dbh.PG_SSL_REQUEST:
                        conn.sendall(b"N")
                        length, code = struct.unpack("!II", conn.recv(8))
                    conn.recv(length - 8)
                    body = struct.pack("!I", self.auth_code) + (b"salt" if self.auth_code == 5 else b"")
                    conn.sendall(b"R" + struct.pack("!I", len(body) + 4) + body)
                    conn.settimeout(0.5)
                    try:
                        if conn.recv(1) == b"p":      # PasswordMessage: the probe must never send one
                            self.received_password = True
                    except OSError:
                        pass
                except (OSError, struct.error):
                    pass

    def close(self):
        self.sock.close()


class TestParseEndpoint(unittest.TestCase):
    def test_explicit_port_and_scheme(self):
        self.assertEqual(dbh.parse_endpoint("postgresql://192.0.2.15:5433/db"), ("192.0.2.15", 5433, "postgres"))
        self.assertEqual(dbh.parse_endpoint("192.0.2.3"), ("192.0.2.3", 5432, "postgres"))
        self.assertEqual(dbh.parse_endpoint("mongodb://192.0.2.4"), ("192.0.2.4", 27017, "mongo"))


class TestPostgresProbe(unittest.TestCase):
    def test_reads_auth_method_without_sending_a_password(self):
        for code, method in ((10, "scram"), (5, "md5"), (0, "trust"), (3, "password")):
            srv = FakePostgres(code)
            try:
                res = dbh.probe_postgres("127.0.0.1", srv.port)
                self.assertTrue(res["reachable"])
                self.assertFalse(res["tls_active"])
                self.assertEqual(res["auth_method"], method)
                self.assertFalse(srv.received_password)
            finally:
                srv.close()

    def test_unreachable_host(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertFalse(dbh.probe_postgres("127.0.0.1", port)["reachable"])


class TestPersistence(unittest.TestCase):
    """Runs the real auditor body on a real connection, then rolls back: no rows are left in production tables."""

    def setUp(self):
        self._stack = contextlib.ExitStack()
        self.conn = self._stack.enter_context(get_db_connection())
        self._stack.enter_context(mock.patch.object(dbh.subprocess, "run", return_value=mock.Mock(stdout="")))   # no nuclei in tests
        self.cur = self.conn.cursor()
        self.no_commit = mock.Mock(commit=lambda: None)

    def tearDown(self):
        self.conn.rollback()
        self._stack.close()

    def rules(self, location):
        self.cur.execute("SELECT cve_id, status FROM vulnerability_log WHERE scan_engine='db-hardening' AND asset_id IS NULL AND url_path=%s",
                         (location,))
        return dict(self.cur.fetchall())

    def test_unreachable_database_logs_nothing(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        dbh._audit_database_security_inner(self.cur, self.no_commit, None, f"postgresql://127.0.0.1:{port}", "SQL")
        self.assertEqual(self.rules(f"127.0.0.1:{port}"), {})

    def test_trust_without_tls(self):
        srv = FakePostgres(0)
        try:
            dbh._audit_database_security_inner(self.cur, self.no_commit, None, f"postgresql://127.0.0.1:{srv.port}", "SQL")
        finally:
            srv.close()
        got = self.rules(f"127.0.0.1:{srv.port}")
        self.assertIn("DB-NO-TLS-ENCRYPTION", got)
        self.assertIn("DB-AUTH-TRUST", got)
        self.assertNotIn("DB-AUTH-MD5", got)

    def test_scram_closes_a_previous_md5_finding(self):
        srv = FakePostgres(5)
        loc = f"127.0.0.1:{srv.port}"
        try:
            dbh._audit_database_security_inner(self.cur, self.no_commit, None, f"postgresql://{loc}", "SQL")
            self.assertIn(self.rules(loc).get("DB-AUTH-MD5"), ("NEW", "OPEN"))
        finally:
            srv.close()
        srv2 = FakePostgres(10)
        try:
            dbh._audit_database_security_inner(self.cur, self.no_commit, None, f"postgresql://127.0.0.1:{srv2.port}", "SQL")
            dbh._resolve(self.cur, None, "DB-AUTH-MD5", loc, "test")
        finally:
            srv2.close()
        self.assertEqual(self.rules(loc).get("DB-AUTH-MD5"), "RESOLVED")


if __name__ == "__main__":
    unittest.main()
