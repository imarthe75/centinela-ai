"""ADR-0022 §8: structural confirmation of the noisiest regex families with ast-grep (skipped where the binary is absent)."""
import os
import tempfile
import unittest

from auditors import astgrep_confirm as a
from auditors.auditor_master_vulnerabilities import scan_sast_code


def _write(d, name, text):
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


def _lines(findings, rule):
    return sorted(f["line"] for f in findings if f["cve_id"] == rule)


@unittest.skipUnless(a.available(), "ast-grep binary not installed in this image")
class TestStructuralConfirmation(unittest.TestCase):
    def test_python_families(self):
        src = ('x = eval(user_input)\ny = eval("1+2")\nz = eval(f"{a}+1")\n'
               'subprocess.run(cmd, shell=True)\nsubprocess.run("ls -la", shell=True)\n'
               'open(base + name)\nopen("/etc/hosts")\n'
               'cur.execute("SELECT * FROM t WHERE id=" + uid + "")\n')
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "m.py", src)
            out = scan_sast_code(p, src)
        self.assertEqual(_lines(out, "CODE-INJECTION-EVAL"), [1, 3])
        self.assertEqual(_lines(out, "CMD-INJECTION-SHELL-TRUE"), [4])
        self.assertTrue(all(a.CONFIRMED_NOTE in f["description"] for f in out if f["cve_id"] in a.FAMILIES))

    def test_javascript_window_open_and_literals_are_not_findings(self):
        src = ('const a = eval(code);\nconst b = eval("2+2");\nconst c = eval(`2+2`);\n'
               'window.open(url + "?q=" + x);\nfs.readFileSync(dir + name);\n'
               'db.query("SELECT * FROM t WHERE id=" + id);\ndb.query("SELECT 1");\n')
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "m.js", src)
            matches = a.structural_matches(p, "javascript")
        got = sorted((fam, first) for fam, first, _last in matches)
        self.assertEqual(got, [("CODE-INJECTION-EVAL", 1), ("PATH-TRAVERSAL-RISK", 5), ("SQL-INJECTION-CONCAT", 6)])

    def test_java_eval_needs_a_script_engine_import(self):
        body = ('class T { void m(ScriptEngine engine, String s, Condition c) throws Exception {\n'
                '  engine.eval(s);\n  c.eval(ctx);\n  engine.eval("1+1");\n}}\n')
        finding = lambda line: {"cve_id": "CODE-INJECTION-EVAL", "line": line, "description": "x"}
        with tempfile.TemporaryDirectory() as d:
            with_engine = _write(d, "A.java", "import javax.script.ScriptEngine;\n" + body)
            kept, dropped = a.confirm(with_engine, [finding(3), finding(5)])
            self.assertEqual(([f["line"] for f in kept], dropped), ([3], 1))
            without = _write(d, "B.java", body)
            kept, dropped = a.confirm(without, [finding(2), finding(3)])
            self.assertEqual((kept, dropped), ([], 2))

    def test_java_sql_concatenation(self):
        src = ('class T { void m(Statement st, String id) throws Exception {\n'
               '  st.executeQuery("SELECT * FROM t WHERE id=" + id);\n  st.executeQuery("SELECT 1");\n'
               '  log("Error in HttpClient execute(" + e.getMessage() + ")");\n}}\n')
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "S.java", src)
            got = sorted(first for fam, first, _l in a.structural_matches(p, "java") if fam == "SQL-INJECTION-CONCAT")
        self.assertEqual(got, [2])


class TestFailClosed(unittest.TestCase):
    def test_unsupported_language_or_missing_binary_keeps_everything(self):
        f = [{"cve_id": "CODE-INJECTION-EVAL", "line": 1, "description": "x"}]
        self.assertEqual(a.confirm("/tmp/page.html", f), (f, 0))
        orig = a.available
        a.available = lambda: False
        try:
            self.assertEqual(a.confirm("/tmp/m.py", f), (f, 0))
        finally:
            a.available = orig

    def test_ast_grep_error_keeps_everything(self):
        f = [{"cve_id": "PATH-TRAVERSAL-RISK", "line": 1, "description": "x"}]
        orig = a.structural_matches

        def boom(*_a, **_k):
            raise RuntimeError("parse failure")
        a.structural_matches = boom
        try:
            self.assertEqual(a.confirm("/tmp/m.py", f), (f, 0))
        finally:
            a.structural_matches = orig

    def test_relative_or_missing_path_never_drops_a_real_finding(self):
        """Regression: mr_review passes a RELATIVE path; ast-grep found no file, returned [] and a real eval() was dropped."""
        src = "def h(user):\n    return eval(user)\n"
        f = [{"cve_id": "CODE-INJECTION-EVAL", "line": 2, "description": "x"}]
        self.assertEqual(a.confirm("src/does-not-exist.py", f), (f, 0))
        if a.available():
            kept, dropped = a.confirm("src/does-not-exist.py", f, content=src)
            self.assertEqual((len(kept), dropped), (1, 0))
            kept, dropped = a.confirm("src/does-not-exist.py", f, content="def h():\n    return eval('1+1')\n")
            self.assertEqual((kept, dropped), ([], 1))

    def test_other_rules_are_never_touched(self):
        f = [{"cve_id": "HARDCODED-SECRET", "line": 1, "description": "x"}]
        self.assertEqual(a.confirm("/tmp/m.py", f), (f, 0))


if __name__ == "__main__":
    unittest.main()
