"""Semgrep runner helpers: timeout kills the whole process group; per-file errors become skipped files."""
import os
import subprocess
import time

import pytest

from auditors import auditor_semgrep


def test_skipped_files_from_errors_relativizes_and_ignores_pathless():
    errs = [{"type": "Timeout", "level": "warn", "path": "/r/src/A.java"},
            {"type": "Timeout", "level": "warn", "path": "src/B.java"},
            {"type": "Rule error", "level": "error"}]
    assert auditor_semgrep.skipped_files_from_errors(errs, "/r") == {"src/A.java", "src/B.java"}


def test_detect_language_rulesets_includes_security_audit(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    rs = auditor_semgrep.detect_language_rulesets(str(tmp_path))
    assert "p/security-audit" in rs and "p/python" in rs


def test_run_semgrep_timeout_kills_grandchildren(tmp_path):
    pidfile = tmp_path / "child.pid"
    # parent shell starts a long-lived grandchild (like pysemgrep -> semgrep-core), then waits
    cmd = ["sh", "-c", f"sleep 60 & echo $! > {pidfile}; wait"]
    with pytest.raises(subprocess.TimeoutExpired):
        auditor_semgrep.run_semgrep(cmd, 1)
    child = int(pidfile.read_text().strip())
    deadline = time.time() + 5
    alive = True
    while time.time() < deadline:
        try:
            os.kill(child, 0)
            with open(f"/proc/{child}/stat") as f:
                if f.read().split()[2] == "Z":
                    alive = False
                    break
        except (ProcessLookupError, FileNotFoundError):
            alive = False
            break
        time.sleep(0.1)
    assert not alive, "grandchild survived the timeout"


def test_run_semgrep_returns_output():
    r = auditor_semgrep.run_semgrep(["sh", "-c", "echo ok; exit 1"], 10)
    assert r.returncode == 1 and r.stdout.strip() == "ok"
