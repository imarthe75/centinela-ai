"""GET /api/remediation/script/{vuln_id}: a missing record or a missing file is a 404 (it used to surface as a 500 because the
generic `except Exception` also caught the HTTPException), and a NULL script_path is a 404, not a TypeError."""
import contextlib
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from core import db_manager


def _cursor_returning(row):
    @contextlib.contextmanager
    def fake_cursor(cursor_factory=None):
        cur = mock.MagicMock()
        cur.fetchone.return_value = row
        yield cur
    return fake_cursor


class TestRemediationScriptEndpoint(unittest.TestCase):
    def setUp(self):
        from main import app
        self.client = TestClient(app)

    def get(self, row):
        with mock.patch.object(db_manager, "get_db_cursor", _cursor_returning(row)):
            return self.client.get("/api/remediation/script/00000000-0000-0000-0000-000000000001")

    def test_no_record_is_404(self):
        self.assertEqual(self.get(None).status_code, 404)

    def test_file_missing_on_disk_is_404(self):
        r = self.get({"script_path": "/app/data/remediation/does-not-exist-xyz.sh"})
        self.assertEqual(r.status_code, 404)
        self.assertIn("not found on disk", r.json()["detail"])

    def test_null_script_path_is_404(self):
        self.assertEqual(self.get({"script_path": None}).status_code, 404)

    def test_existing_file_is_returned(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write("echo ok\n")
        try:
            r = self.get({"script_path": f.name})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["content"], "echo ok\n")
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
