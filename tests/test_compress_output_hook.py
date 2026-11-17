"""scripts/hooks/compress_output.py: dev-session hook that shrinks long Bash output without losing errors or the original."""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "scripts" / "hooks" / "compress_output.py"
spec = importlib.util.spec_from_file_location("compress_output", HOOK)
co = importlib.util.module_from_spec(spec)
spec.loader.exec_module(co)


def bash(stdout, stderr=""):
    return {"tool_name": "Bash", "tool_input": {"command": "x"},
            "tool_response": {"stdout": stdout, "stderr": stderr, "interrupted": False, "isImage": False}}


def test_short_output_and_other_tools_untouched():
    assert co.process_payload(bash("3 passed")) is None
    big = "\n".join(f"line {i}" for i in range(3000))
    for tool in ("Read", "Edit", "Write", "Grep", "mcp__x__y"):
        assert co.process_payload({"tool_name": tool, "tool_response": {"stdout": big}}) is None


def test_long_output_keeps_errors_summary_and_recoverable_original(tmp_path, monkeypatch):
    monkeypatch.setenv("CENTINELA_COMPRESS_SPILL_DIR", str(tmp_path / "spill"))
    log = "\n".join("FAILED tests/test_a.py::test_x - AssertionError" if i == 1500 else
                    "===== 1 failed, 812 passed in 9.1s =====" if i == 2999 else f"collecting module_{i} ... ok"
                    for i in range(3000))
    out = co.process_payload(bash(log))
    assert set(out) == {"stdout", "stderr", "interrupted", "isImage"}
    assert len(out["stdout"]) < len(log) / 5
    assert "AssertionError" in out["stdout"] and "1 failed, 812 passed" in out["stdout"]
    path = out["stdout"].split("salida completa en ")[1].split("]")[0]
    assert Path(path).read_text() == log and (os.stat(path).st_mode & 0o777) == 0o600


def test_nothing_is_cut_if_the_original_cannot_be_saved(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("CENTINELA_COMPRESS_SPILL_DIR", str(blocker))
    log = "\n".join(f"distinct line {i}" for i in range(3000))
    assert co.shrink(log) == log


def test_kill_switch_and_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("CENTINELA_COMPRESS_OUTPUT", "0")
    assert co.process_payload(bash("\n".join(f"l{i}" for i in range(5000)))) is None
    env = {**os.environ, "CENTINELA_COMPRESS_OUTPUT": "1", "CENTINELA_COMPRESS_SPILL_DIR": str(tmp_path / "s")}
    payload = bash("\n".join(f"Downloading artifact {i}" for i in range(3000)))
    res = json.loads(subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload), capture_output=True, text=True,
                                    env=env, check=True).stdout)
    assert res["hookSpecificOutput"]["updatedToolOutput"]["stdout"].count("\n") < 200
    bad = subprocess.run([sys.executable, str(HOOK)], input="not json", capture_output=True, text=True, env=env)
    assert bad.returncode == 0 and bad.stdout == "" and "Traceback" in bad.stderr


def test_lossless_cleanup():
    assert co.clean("\x1b[31mred\x1b[0m\nsame\nsame\nsame\nsame\nsame\nend") == "red\nsame\n[línea anterior repetida 4 veces más]\nend"
