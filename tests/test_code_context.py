"""
Item 5 (2026-08-27): blast-radius / enclosing-scope context for repo remediation prompts.

Pure unit tests -- build a throwaway git repo in tmp_path, then check gather_repo_context()
finds the enclosing function, picks the right symbol, and `git grep`s its other call sites.
No DB, no network.
"""
import os
import subprocess
import unittest
import tempfile
import shutil

from core.code_context import gather_repo_context, _parse_url_path, _extract_enclosing


def _git(repo, *args):
    subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True)


class TestParseUrlPath(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(_parse_url_path("a/b/c.py:42"), ("a/b/c.py", 42))

    def test_invalid(self):
        self.assertIsNone(_parse_url_path("a/b/c.py"))
        self.assertIsNone(_parse_url_path("a/b/c.py:notanumber"))
        self.assertIsNone(_parse_url_path(""))


class TestExtractEnclosing(unittest.TestCase):
    def test_finds_enclosing_def(self):
        lines = [
            "import os",
            "",
            "def helper(x):",
            "    y = x + 1",
            "    return dangerous(y)",
            "",
            "def other():",
            "    pass",
        ]
        snippet, symbol = _extract_enclosing(lines, 5)  # the `return dangerous(y)` line
        self.assertEqual(symbol, "helper")
        self.assertIn("def helper(x):", snippet)
        self.assertIn(">>     5 |", snippet)
        self.assertNotIn("def other()", snippet)


class TestGatherRepoContext(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix="cc-test-")
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@t.t")
        _git(self.repo, "config", "user.name", "t")
        os.makedirs(os.path.join(self.repo, "src"))
        with open(os.path.join(self.repo, "src", "vuln.py"), "w") as fh:
            fh.write(
                "def build_query(user_input):\n"
                "    sql = \"SELECT * FROM t WHERE x = '\" + user_input + \"'\"\n"
                "    return sql\n"
            )
        with open(os.path.join(self.repo, "src", "caller_a.py"), "w") as fh:
            fh.write("from vuln import build_query\n\nq = build_query(request.args['x'])\n")
        with open(os.path.join(self.repo, "src", "caller_b.py"), "w") as fh:
            fh.write("import vuln\n\nprint(vuln.build_query('literal'))\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "init")

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_context_and_blast_radius(self):
        ctx = gather_repo_context("irrelevant", "src/vuln.py:2", repo_root=self.repo)
        self.assertEqual(ctx["rel_path"], "src/vuln.py")
        self.assertEqual(ctx["line"], 2)
        self.assertEqual(ctx["symbol"], "build_query")
        self.assertIn("def build_query", ctx["enclosing_snippet"])
        # both callers found, the definition line itself excluded
        self.assertGreaterEqual(ctx["caller_count"], 2)
        joined = "\n".join(ctx["callers"])
        self.assertIn("src/caller_a.py", joined)
        self.assertIn("src/caller_b.py", joined)
        self.assertIn("BLAST RADIUS", ctx["prompt_block"])

    def test_missing_repo_returns_empty(self):
        ctx = gather_repo_context("x", "src/vuln.py:2", repo_root="/nonexistent/path/xyz")
        self.assertEqual(ctx["prompt_block"], "")
        self.assertEqual(ctx["caller_count"], 0)

    def test_bad_url_path_returns_empty(self):
        ctx = gather_repo_context("x", "src/vuln.py", repo_root=self.repo)
        self.assertEqual(ctx["prompt_block"], "")

    def test_line_out_of_range_returns_empty(self):
        ctx = gather_repo_context("x", "src/vuln.py:9999", repo_root=self.repo)
        self.assertEqual(ctx["prompt_block"], "")


if __name__ == "__main__":
    unittest.main()
