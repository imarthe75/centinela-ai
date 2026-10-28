"""scripts/hooks/post_edit_check.py: exit codes as Claude Code reads them (2 = blocking)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "post_edit_check.py"


def run(stdin_obj=None, raw=None):
    data = raw if raw is not None else json.dumps(stdin_obj)
    return subprocess.run([sys.executable, str(HOOK)], input=data, capture_output=True, text=True)


class TestHook(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = Path(t.name)

    def f(self, name, text):
        p = self.d / name
        p.write_text(text, encoding="utf-8")
        return {"tool_input": {"file_path": str(p)}}

    def test_good_files_pass(self):
        for name, text in (("a.py", "x = 1\n"), ("a.json", '{"a": 1}'), ("a.yml", "a: [1, 2]\n"), ("a.md", "# anything ((")):
            self.assertEqual(run(self.f(name, text)).returncode, 0, name)

    def test_broken_files_block_with_a_message(self):
        for name, text in (("b.py", "def f(:\n"), ("b.json", "{bad"), ("b.yaml", "a: [1, 2\n")):
            r = run(self.f(name, text))
            self.assertEqual(r.returncode, 2, name)
            self.assertTrue(r.stderr.strip(), name)

    def test_does_not_execute_the_module(self):
        marker = self.d / "ran"
        r = run(self.f("c.py", f"open({str(marker)!r}, 'w').write('x')\n"))
        self.assertEqual(r.returncode, 0)
        self.assertFalse(marker.exists())

    def test_not_applicable_inputs_are_ignored(self):
        self.assertEqual(run(raw="not json").returncode, 0)
        self.assertEqual(run({"tool_input": {}}).returncode, 0)
        self.assertEqual(run({"tool_input": {"file_path": str(self.d / "missing.py")}}).returncode, 0)

    def test_settings_json_points_at_the_hook(self):
        s = json.loads((HOOK.parents[2] / ".claude" / "settings.json").read_text())
        cmd = s["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        self.assertIn("scripts/hooks/post_edit_check.py", cmd)
        self.assertTrue(HOOK.exists())


if __name__ == "__main__":
    unittest.main()
