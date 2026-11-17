"""Issue for a code finding in its own GitLab project (POST /api/remediation/{id}/ticket target=gitlab).
The GitLab call is replaced by a recorder (an issue on a real client project is an outward action); DB work is rolled back (rule 8)."""
import contextlib
import unittest
from unittest import mock

from core import db_manager, gitlab_instances, ticketing

INST = gitlab_instances.GitLabInstance("primary", "http://gitlab.test", "tok-xyz", "GitLab/", "")


class _Res:
    status_code = 201

    def json(self):
        return {"iid": 7, "web_url": "http://gitlab.test/grp/app/-/issues/7"}


class TestBuild(unittest.TestCase):
    def test_issue_goes_to_the_assets_project_and_redacts_secrets(self):
        with mock.patch.object(gitlab_instances, "parse_asset_name", return_value=(INST, "grp/app", "develop")):
            inst, path, payload = ticketing.build_gitlab_issue(
                {"asset_name": "GitLab/grp/app@develop", "cve_id": "CONFIG-SECRET-LITERAL", "severity": "HIGH", "url_path": "a.properties:3"},
                "password=SuperSecreto123 en a.properties")
        self.assertEqual((inst.key, path), ("primary", "grp/app"))
        self.assertIn("a.properties:3", payload["title"])
        self.assertIn("Rama analizada: `develop`", payload["description"])
        self.assertNotIn("SuperSecreto123", payload["description"])

    def test_non_gitlab_asset_is_rejected(self):
        with mock.patch.object(gitlab_instances, "parse_asset_name", return_value=(None, "srv", None)):
            with self.assertRaises(ticketing.TicketingError):
                ticketing.build_gitlab_issue({"asset_name": "srv", "cve_id": "X", "severity": "LOW"}, "d")


class TestEndpoint(unittest.TestCase):
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
        self._stack.enter_context(mock.patch.object(gitlab_instances, "parse_asset_name", return_value=(INST, "grp/app", None)))
        self.posts = []
        self._stack.enter_context(mock.patch.object(ticketing.requests, "post", lambda url, **kw: (self.posts.append((url, kw)) or _Res())))
        cur = self.conn.cursor()
        cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES ('GitLab/grp/app', 'GitLab-Repo', 't') RETURNING id")
        aid = cur.fetchone()[0]
        cur.execute("""INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status, finding_category)
                       VALUES (%s, 'R-ISSUE', 'HIGH', 'desc', 'OPEN', 'VULNERABILITY') RETURNING id""", (aid,))
        self.vid = str(cur.fetchone()[0])
        from fastapi.testclient import TestClient
        from main import app
        self.c = TestClient(app)

    def tearDown(self):
        self.conn.rollback()
        self._stack.close()

    def test_creates_once_then_returns_the_existing_issue(self):
        r = self.c.post(f"/api/remediation/{self.vid}/ticket", json={"target": "gitlab"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["url"], "http://gitlab.test/grp/app/-/issues/7")
        url, kw = self.posts[0]
        self.assertEqual(url, "http://gitlab.test/api/v4/projects/grp%2Fapp/issues")
        self.assertEqual(kw["headers"]["PRIVATE-TOKEN"], "tok-xyz")
        r2 = self.c.post(f"/api/remediation/{self.vid}/ticket", json={"target": "gitlab"})
        self.assertEqual((r2.json()["status"], len(self.posts)), ("exists", 1))


if __name__ == "__main__":
    unittest.main()
