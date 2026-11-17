"""Per-project data access (ADR-0019 phase 1): scope matching, the request gate and the scope-aware list endpoints.
DB tests run inside a transaction that is rolled back (rule 8)."""
import contextlib
import unittest
from unittest import mock

from core import access_scope as sc
from core import auth, db_manager

SCOPE = ["GitLab2/grupo-a/proyecto-a"]


class TestMatching(unittest.TestCase):
    def test_prefix_covers_subprojects_and_branches_only(self):
        for name in ("GitLab2/grupo-a/proyecto-a", "GitLab2/grupo-a/proyecto-a/backend/x@develop", "GitLab2/grupo-a/proyecto-a@main"):
            self.assertTrue(sc.allows(name, SCOPE), name)
        for name in ("GitLab2/grupo-a/proyecto-asigo/x", "GitLab2/grupo-a/proyecto-l/x", "GitLab/grupo-a/proyecto-a/x", "", None):
            self.assertFalse(sc.allows(name, SCOPE), name)
        self.assertTrue(sc.allows("anything", sc.UNRESTRICTED))
        self.assertFalse(sc.allows("GitLab2/grupo-a/proyecto-a", []))

    def test_sql_filter_escapes_like_wildcards(self):
        clause, params = sc.sql_filter("i.asset_name", ["GitLab/a_b%c"])
        self.assertIn("LIKE ANY", clause)
        self.assertEqual(params[0], ["GitLab/a_b%c"])
        self.assertEqual(params[1], ["GitLab/a\\_b\\%c/%", "GitLab/a\\_b\\%c@%"])
        self.assertEqual(sc.sql_filter("x", sc.UNRESTRICTED), ("", []))
        self.assertEqual(sc.sql_filter("x", []), (" AND FALSE", []))

    def test_request_gate(self):
        ok = sc.check_request
        self.assertIsNone(ok("/api/inventory/GitLab2/grupo-a/proyecto-a/x@d/details", {"asset_name": "GitLab2/grupo-a/proyecto-a/x@d"}, {}, SCOPE))
        self.assertIsNotNone(ok("/api/inventory/GitLab/proyecto-g/x/details", {"asset_name": "GitLab/proyecto-g/x"}, {}, SCOPE))
        self.assertIsNotNone(ok("/api/reports/group/general", {}, {"prefix": "GitLab2/adem"}, SCOPE))       # wider than the grant
        self.assertIsNone(ok("/api/reports/group/general", {}, {"prefix": "GitLab2/grupo-a/proyecto-a/backend"}, SCOPE))
        self.assertIsNotNone(ok("/api/stats/tops", {}, {}, SCOPE))                                           # fleet aggregate
        self.assertIsNotNone(ok("/api/incidents", {}, {}, SCOPE))                                            # not scope-aware: closed
        self.assertIsNotNone(ok("/api/inventory", {}, {}, SCOPE, method="POST"))                             # administrative
        self.assertIsNone(ok("/api/inventory", {}, {}, SCOPE))                                               # list: filtered
        self.assertIsNotNone(ok("/api/quality-gates/check", {}, {}, SCOPE))                                  # needs an asset
        self.assertIsNone(ok("/api/anything", {}, {}, sc.UNRESTRICTED))


class TestApiWithRestrictedUser(unittest.TestCase):
    """A real user token (userinfo mocked) restricted to one prefix, against the real router stack and a real (rolled back) DB."""

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
        self._stack.enter_context(mock.patch.dict("os.environ", {"API_AUTH_MODE": "enforce", "ACCESS_SCOPE_DEFAULT": "all"}))
        claims = {"sub": "u-scope", "preferred_username": "scope_tester", "groups": ["Centinela Analyst"]}
        self._stack.enter_context(mock.patch.object(auth, "verify_token", lambda t: claims))
        sc.invalidate()
        cur = self.conn.cursor()
        for name in ("GitLab2/grupo-a/proyecto-a/back@d", "GitLab/proyecto-g/other@d"):
            cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES (%s, 'GitLab-Repo', 't') RETURNING id", (name,))
            aid = cur.fetchone()[0]
            cur.execute("""INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status, finding_category)
                           VALUES (%s, 'R-SCOPE', 'CRITICAL', 'd', 'OPEN', 'VULNERABILITY')""", (aid,))
        cur.execute("INSERT INTO access_scopes (subject_type, subject, asset_prefix) VALUES ('user', 'scope_tester', 'GitLab2/grupo-a/proyecto-a')")
        from fastapi.testclient import TestClient
        from main import app
        self.c = TestClient(app)
        self.h = {"Authorization": "Bearer " + "u" * 40}

    def tearDown(self):
        sc.invalidate()
        self.conn.rollback()
        self._stack.close()

    def test_lists_only_show_the_granted_project(self):
        names = {a["asset_name"] for a in self.c.get("/api/inventory", headers=self.h).json()}
        self.assertIn("GitLab2/grupo-a/proyecto-a/back@d", names)
        self.assertNotIn("GitLab/proyecto-g/other@d", names)
        rem = self.c.get("/api/remediation", params={"status_scope": "all"}, headers=self.h).json()
        assets = {r["asset_name"] for r in (rem if isinstance(rem, list) else rem.get("items", []))}
        self.assertNotIn("GitLab/proyecto-g/other@d", assets)
        me = self.c.get("/api/access-scopes/me", headers=self.h).json()
        self.assertEqual((me["unrestricted"], me["prefixes"]), (False, ["GitLab2/grupo-a/proyecto-a"]))

    def test_other_projects_and_fleet_views_are_closed(self):
        self.assertEqual(self.c.get("/api/reports/asset/GitLab/proyecto-g/other@d", params={"format": "html"}, headers=self.h).status_code, 403)
        self.assertEqual(self.c.get("/api/reports/asset/GitLab2/grupo-a/proyecto-a/back@d", params={"format": "html"}, headers=self.h).status_code, 200)
        self.assertEqual(self.c.get("/api/stats/tops", headers=self.h).status_code, 403)
        self.assertEqual(self.c.get("/api/access-scopes", headers=self.h).status_code, 403)          # not an admin
        self.assertEqual(self.c.get("/api/stats", headers=self.h).status_code, 200)

    def test_stats_count_only_the_granted_project(self):
        mine = self.c.get("/api/stats", headers=self.h).json()
        self.assertEqual(mine["total"], 1)


class TestAdminEndpoints(unittest.TestCase):
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
        self._stack.enter_context(mock.patch.dict("os.environ", {"API_AUTH_MODE": "enforce", "API_SERVICE_TOKEN": "s" * 40}))
        from core import agent_ledger
        self._stack.enter_context(mock.patch.object(agent_ledger, "record_action", lambda *a, **k: None))
        from fastapi.testclient import TestClient
        from main import app
        self.c = TestClient(app)
        self.h = {"Authorization": "Bearer " + "s" * 40}

    def tearDown(self):
        sc.invalidate()
        self.conn.rollback()
        self._stack.close()

    def test_grant_list_and_revoke(self):
        r = self.c.post("/api/access-scopes", json={"subject_type": "group", "subject": "Equipo proyecto-a", "asset_prefix": "GitLab2/grupo-a/proyecto-a/"},
                        headers=self.h)
        self.assertEqual(r.status_code, 200, r.text)
        sid = r.json()["id"]
        self.assertEqual(r.json()["asset_prefix"], "GitLab2/grupo-a/proyecto-a")
        self.assertEqual(self.c.post("/api/access-scopes", json={"subject_type": "group", "subject": "Equipo proyecto-a",
                                                                  "asset_prefix": "GitLab2/grupo-a/proyecto-a"}, headers=self.h).status_code, 409)
        self.assertIn(sid, [s["id"] for s in self.c.get("/api/access-scopes", headers=self.h).json()["scopes"]])
        self.assertEqual(self.c.delete(f"/api/access-scopes/{sid}", headers=self.h).status_code, 200)
        self.assertEqual(self.c.post("/api/access-scopes", json={"subject_type": "x", "subject": "a", "asset_prefix": "b"},
                                     headers=self.h).status_code, 422)


if __name__ == "__main__":
    unittest.main()
