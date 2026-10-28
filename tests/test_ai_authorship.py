"""ADR-0012 D6 on a REAL temporary git repository (no mocks)."""
import os
import subprocess
import tempfile
import unittest

from auditors import ai_authorship as aa


def git(repo, *args, env=None):
    e = dict(os.environ, GIT_AUTHOR_NAME="Dev", GIT_AUTHOR_EMAIL="d@x", GIT_COMMITTER_NAME="Dev", GIT_COMMITTER_EMAIL="d@x")
    subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, env=e)


class TestAuthorship(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.repo = os.path.join(self.t.name, "r")
        os.makedirs(self.repo)
        git(self.repo, "init", "-q")
        with open(os.path.join(self.repo, "Human.java"), "w") as f:
            f.write("".join(f"line{i}\n" for i in range(10)))
        git(self.repo, "add", "."); git(self.repo, "commit", "-q", "-m", "human work")
        with open(os.path.join(self.repo, "Ai.java"), "w") as f:
            f.write("".join(f"ai{i}\n" for i in range(20)))
        git(self.repo, "add", "."); git(self.repo, "commit", "-q", "-m", "feat: x\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>")
        with open(os.path.join(self.repo, "node_modules_skip.txt"), "w") as f:
            f.write("not code\n")
        os.makedirs(os.path.join(self.repo, "node_modules"))
        with open(os.path.join(self.repo, "node_modules", "dep.js"), "w") as f:
            f.write("vendored\n")
        git(self.repo, "add", "."); git(self.repo, "commit", "-q", "-m", "more")

    def test_lines_and_findings_are_attributed_by_trailer(self):
        findings = [{"url_path": "Human.java:3"}, {"url_path": "Ai.java:5"}, {"url_path": "Ai.java:6"}, {"url_path": "Nope.java:1"}, {"url_path": None}]
        r = aa.measure(self.repo, findings)
        self.assertTrue(r["evaluable"])
        self.assertEqual((r["ai_lines"], r["other_lines"]), (20, 10))       # vendored node_modules and non-code file excluded
        self.assertEqual((r["findings_ai"], r["findings_other"], r["findings_unattributed"], r["findings_without_file_line"]), (2, 1, 1, 1))
        self.assertEqual(r["density_per_kloc_ai"], 100.0)
        self.assertEqual(r["density_per_kloc_other"], 100.0)
        self.assertTrue(r["small_sample"])
        self.assertTrue(r["caveats"])

    def test_uncommitted_lines_are_unattributed_not_human(self):
        with open(os.path.join(self.repo, "Human.java"), "a") as f:
            f.write("uncommitted line\n")
        r = aa.measure(self.repo, [{"url_path": "Human.java:11"}])
        self.assertEqual(r["findings_unattributed"], 1)
        self.assertEqual(r["other_lines"], 10)             # the uncommitted line is not counted as human

    def test_shallow_clone_is_not_evaluable_not_human(self):
        shallow = os.path.join(self.t.name, "s")
        subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + self.repo, shallow], check=True, capture_output=True)
        r = aa.measure(shallow, [{"url_path": "Ai.java:5"}])
        self.assertFalse(r["evaluable"])
        self.assertIn("superficial", r["reason"])

    def test_custom_patterns_via_env(self):
        old = os.environ.get("AI_AUTHOR_PATTERNS")
        os.environ["AI_AUTHOR_PATTERNS"] = "mybot"
        try:
            self.assertFalse(aa.ai_trailer_regex().search("Co-Authored-By: Claude <x@y>"))
            self.assertTrue(aa.ai_trailer_regex().search("Co-Authored-By: MyBot <x@y>"))
        finally:
            os.environ.pop("AI_AUTHOR_PATTERNS") if old is None else os.environ.__setitem__("AI_AUTHOR_PATTERNS", old)


if __name__ == "__main__":
    unittest.main()
