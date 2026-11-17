"""GET /api/gitlab/branch-diff: a branch compared with the project's main branch by (rule, file), so a moved line is not 'new'.
Runs inside a transaction that is rolled back (rule 8)."""
import contextlib
import unittest
from unittest import mock

from core import db_manager, gitlab_instances

INST = gitlab_instances.GitLabInstance("primary", "http://gitlab.test", "t", "GitLab/", "")


class TestBranchDiff(unittest.TestCase):
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
        self._stack.enter_context(mock.patch.object(gitlab_instances, "parse_asset_name",
                                                    side_effect=lambda n: (INST, n.split("/", 1)[1].split("@")[0], n.split("@")[1])))
        cur = self.conn.cursor()
        ids = {}
        for name in ("GitLab/g/app@main", "GitLab/g/app@feature"):
            cur.execute("INSERT INTO infra_inventory (asset_name, asset_type, endpoint) VALUES (%s, 'GitLab-Repo', 't') RETURNING id", (name,))
            ids[name] = cur.fetchone()[0]
        cur.execute("""INSERT INTO gitlab_branch_heads (instance, project_path, branch, asset_name, is_fleet_branch, checked_at)
                       VALUES ('primary', 'g/app', 'main', 'GitLab/g/app@main', true, now())""")
        ins = """INSERT INTO vulnerability_log (asset_id, cve_id, severity, description, status, finding_category, url_path)
                 VALUES (%s, %s, 'HIGH', 'd', 'OPEN', 'VULNERABILITY', %s)"""
        cur.execute(ins, (ids["GitLab/g/app@main"], "R-A", "src/x.ts:10"))
        cur.execute(ins, (ids["GitLab/g/app@main"], "R-GONE", "src/y.ts:1"))
        cur.execute(ins, (ids["GitLab/g/app@feature"], "R-A", "src/x.ts:14"))     # same finding, line moved
        cur.execute(ins, (ids["GitLab/g/app@feature"], "R-NEW", "src/z.ts:3"))
        from fastapi.testclient import TestClient
        from main import app
        self.c = TestClient(app)

    def tearDown(self):
        self.conn.rollback()
        self._stack.close()

    def test_diff_by_rule_and_file(self):
        r = self.c.get("/api/gitlab/branch-diff", params={"asset": "GitLab/g/app@feature"})
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()
        self.assertEqual(d["base"], "GitLab/g/app@main")
        self.assertEqual([x["cve_id"] for x in d["only_in_branch"]], ["R-NEW"])
        self.assertEqual([x["cve_id"] for x in d["only_in_base"]], ["R-GONE"])
        self.assertEqual(d["common"], 1)
        self.assertTrue(self.c.get("/api/gitlab/branch-diff", params={"asset": "GitLab/g/app@main"}).json()["is_base"])


if __name__ == "__main__":
    unittest.main()
