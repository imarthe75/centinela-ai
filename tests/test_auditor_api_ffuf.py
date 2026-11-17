"""ffuf auditor: result parsing, audit-log retention and run completeness (auditors/auditor_api.py)."""
import os
import time

from auditors import auditor_api as a


def test_parse_results_sets_location_and_severity():
    data = {"results": [{"input": {"FUZZ": ".env"}, "status": 200, "length": 10},
                        {"input": {"FUZZ": "admin/login"}, "status": 302, "length": 0, "redirectlocation": "/login"}]}
    out = a.parse_ffuf_results(data, "aid")
    assert [(f["cve_id"], f["url_path"], f["severity"]) for f in out] == [
        ("FFUF-DISCOVER-.ENV", "/.env", "HIGH"), ("FFUF-DISCOVER-ADMIN-LOGIN", "/admin/login", "INFO")]
    assert "Redirects to /login" in out[1]["description"]


def test_prune_audit_logs_removes_only_old_files(tmp_path):
    old, new = tmp_path / "old.jsonl", tmp_path / "new.jsonl"
    old.write_text("x"); new.write_text("y")
    past = time.time() - 40 * 86400
    os.utime(old, (past, past))
    assert a.prune_audit_logs(str(tmp_path), days=30) == 1
    assert not old.exists() and new.exists()


def test_failed_run_is_incomplete_and_never_reconciles(monkeypatch, tmp_path):
    monkeypatch.setattr(a, "AUDIT_LOG_DIR", str(tmp_path))
    monkeypatch.setattr(a, "ensure_wordlists", lambda: None)

    class R:
        returncode = 1
        stderr = "connection refused"
    monkeypatch.setattr(a.subprocess, "run", lambda *x, **k: R())
    res = a.run_ffuf("http://h.test", "aid")
    assert res.complete is False and list(res) == []


def test_command_includes_audit_log(monkeypatch, tmp_path):
    monkeypatch.setattr(a, "AUDIT_LOG_DIR", str(tmp_path))
    monkeypatch.setattr(a, "ensure_wordlists", lambda: None)
    seen = {}

    class R:
        returncode = 1
        stderr = ""
    def fake(cmd, **k):
        seen["cmd"] = cmd
        return R()
    monkeypatch.setattr(a.subprocess, "run", fake)
    a.run_ffuf("http://h.test", "aid")
    cmd = seen["cmd"]
    assert cmd[cmd.index("-audit-log") + 1].startswith(str(tmp_path))
    # auto-calibration: an SPA answering 200 + index.html for any path must not produce one finding per word
    assert "-ac" in cmd
