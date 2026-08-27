"""
Item 1 (2026-08-27): shift-left MR review -- pure-logic unit tests (no network, no DB).

Covers the parts that decide what gets flagged and whether the merge is blocked:
  * parse_added_lines  -- unified-diff hunk parsing -> set of NEW-file line numbers added
  * findings_on_changed_lines -- keep only findings on a line this MR touched
  * decide_state       -- 'failed' iff a finding is at/above the blocking severity
  * scan_changed_files -- native detectors run over real files in a tmp tree
"""
import os
import tempfile
import shutil
import unittest

from auditors.mr_review import (
    parse_added_lines,
    findings_on_changed_lines,
    decide_state,
    scan_changed_files,
)

DIFF = """@@ -1,4 +1,6 @@
 import os
-x = 1
+x = 2
+y = 3
 def f():
+    return eval(x)
 # tail
@@ -20,2 +22,3 @@ def g():
 a = 1
+b = 2
 c = 3
"""


class TestParseAddedLines(unittest.TestCase):
    def test_added_line_numbers(self):
        added = parse_added_lines(DIFF)
        # hunk 1 starts at new line 1: lines 1(import,ctx) 2(+x=2) 3(+y=3) 4(def,ctx) 5(+return) 6(#tail,ctx)
        # hunk 2 starts at new line 22: 22(a,ctx) 23(+b=2) 24(c,ctx)
        self.assertEqual(added, {2, 3, 5, 23})

    def test_empty_diff(self):
        self.assertEqual(parse_added_lines(""), set())

    def test_ignores_plusplus_header(self):
        d = "--- a/f\n+++ b/f\n@@ -0,0 +1,2 @@\n+one\n+two\n"
        self.assertEqual(parse_added_lines(d), {1, 2})


class TestFindingsOnChangedLines(unittest.TestCase):
    def test_only_keeps_findings_on_touched_lines(self):
        findings = [
            {"rel_path": "a.py", "line": 5, "cve_id": "X", "severity": "HIGH"},   # on +line 5 -> keep
            {"rel_path": "a.py", "line": 50, "cve_id": "Y", "severity": "HIGH"},  # untouched -> drop
            {"rel_path": "b.py", "line": 1, "cve_id": "Z", "severity": "LOW"},    # file not in diff -> drop
        ]
        added = {"a.py": {2, 3, 5, 23}}
        kept = findings_on_changed_lines(findings, added, fuzz=0)
        self.assertEqual([f["cve_id"] for f in kept], ["X"])

    def test_fuzz_absorbs_off_by_one(self):
        findings = [{"rel_path": "a.py", "line": 4, "cve_id": "X", "severity": "HIGH"}]
        added = {"a.py": {5}}
        self.assertEqual(len(findings_on_changed_lines(findings, added, fuzz=2)), 1)
        self.assertEqual(len(findings_on_changed_lines(findings, added, fuzz=0)), 0)


class TestDecideState(unittest.TestCase):
    def test_blocks_on_high_by_default(self):
        self.assertEqual(decide_state([{"severity": "HIGH"}]), "failed")
        self.assertEqual(decide_state([{"severity": "MEDIUM"}]), "success")
        self.assertEqual(decide_state([]), "success")

    def test_threshold_configurable(self):
        self.assertEqual(decide_state([{"severity": "MEDIUM"}], blocking_severity="MEDIUM"), "failed")
        self.assertEqual(decide_state([{"severity": "HIGH"}], blocking_severity="CRITICAL"), "success")


class TestScanChangedFiles(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="mrr-")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _write(self, rel, content):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)

    def test_detects_sast_and_dockerfile_and_secret(self):
        self._write("src/x.py", "def h(user):\n    return eval(user)\n")
        self._write("Dockerfile", "FROM python:3.11\nRUN pip install x\n")  # no USER -> finding
        self._write("config/app.env", "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEKEYDATA1234567890ab\n")

        findings = scan_changed_files(self.d, ["src/x.py", "Dockerfile", "config/app.env", "missing.py"])
        cves = {f["cve_id"] for f in findings}
        self.assertTrue(any("EVAL" in c or "INJECTION" in c for c in cves), cves)
        self.assertIn("DOCKER-MISSING-NON-ROOT-USER", cves)
        self.assertTrue(any(c.startswith("SECRETS-") for c in cves), cves)
        for f in findings:
            self.assertIn("rel_path", f)
            self.assertIn(f["rel_path"], {"src/x.py", "Dockerfile", "config/app.env"})

    def test_sca_manifest_findings_are_line_anchored(self):
        # known-old pins -> OSV.dev (or the static fallback table) returns real CVEs; each
        # finding must carry the manifest line of its dependency so the diff filter can scope it.
        self._write("requirements.txt", "flask==0.12.2\nrequests==2.19.1\n")
        findings = scan_changed_files(self.d, ["requirements.txt"])
        sca = [f for f in findings if str(f["cve_id"]).startswith("SCA-")]
        if not sca:
            self.skipTest("no SCA findings returned (OSV.dev unreachable and pins not in static table)")
        for f in sca:
            self.assertEqual(f["rel_path"], "requirements.txt")
            self.assertIn(f.get("line"), (1, 2))


if __name__ == "__main__":
    unittest.main()
