"""trufflehog output parsing + a real run of the binary (no mocks) against a throwaway git repo."""
import json
import os
import shutil
import subprocess
import tempfile

import pytest

from auditors import auditor_secrets as sec

REAL_SHAPE = json.dumps({
    "SourceMetadata": {"Data": {"Git": {"commit": "3e23e487b4d86b7a42a978dc13660570364b6507", "file": "leaked.key", "line": 1}}},
    "DetectorName": "PrivateKey", "Verified": False, "Raw": "-----BEGIN RSA PRIVATE KEY-----\nSECRETBODY", "Redacted": "-----BEGIN RSA PRIVATE KEY-----\nMIIE",
    "SecretParts": {"token": "SECRETBODY"},
})


def test_parser_reads_real_v3_shape_and_never_keeps_raw_secret():
    out = sec.parse_trufflehog_output('{"level":"info-0","msg":"running source"}\n' + REAL_SHAPE + "\n")
    assert len(out) == 1
    f = out[0]
    assert (f["file"], f["line"], f["type"], f["commit"]) == ("leaked.key", 1, "PrivateKey", "3e23e487")
    assert f["verified"] is None and f["severity"] == "HIGH"
    assert "SECRETBODY" not in json.dumps(f)


def test_verified_secret_is_critical_only_when_live_verification_ran():
    rec = json.loads(REAL_SHAPE); rec["Verified"] = True
    assert sec.parse_trufflehog_output(json.dumps(rec), verify_live=True)[0]["severity"] == "CRITICAL"
    assert sec.parse_trufflehog_output(json.dumps(rec), verify_live=False)[0]["verified"] is None


def test_unverified_with_live_check_is_marked_not_confirmed():
    assert sec.parse_trufflehog_output(REAL_SHAPE, verify_live=True)[0]["verified"] is False


@pytest.mark.skipif(not shutil.which("trufflehog") or not shutil.which("ssh-keygen"), reason="trufflehog/ssh-keygen not installed")
def test_real_binary_finds_leaked_key_in_history(monkeypatch):
    monkeypatch.delenv("SECRETS_VERIFY_LIVE", raising=False)      # offline: nothing may leave the host
    with tempfile.TemporaryDirectory() as d:
        run = lambda *a: subprocess.run(a, cwd=d, check=True, capture_output=True)
        run("git", "init", "-q"); run("git", "config", "user.email", "t@t"); run("git", "config", "user.name", "t")
        run("ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-m", "PEM", "-f", os.path.join(d, "leaked.key"))
        os.remove(os.path.join(d, "leaked.key.pub"))
        run("git", "add", "."); run("git", "commit", "-qm", "k")
        found = sec.SecretsScanner.scan_git_history(d, 50)
    assert [f["file"] for f in found] == ["leaked.key"]
    assert found[0]["type"] == "PrivateKey" and found[0]["verified"] is None


def test_verification_error_is_kept_and_raised_to_high():
    rec = json.loads(REAL_SHAPE)
    rec.update({"Verified": False, "VerificationError": "dial tcp: i/o timeout", "DetectorName": "AWS"})
    f = sec.parse_trufflehog_output(json.dumps(rec), verify_live=True)[0]
    assert f["verification"] == "error" and f["severity"] == "HIGH"
    assert "podría seguir activa" in f["description"]


def test_verification_status_values():
    assert sec.verification_status({"Verified": True}, verify_live=False) == "not_run"
    assert sec.verification_status({"Verified": True}, verify_live=True) == "verified"
    assert sec.verification_status({"Verified": False}, verify_live=True) == "unconfirmed"
    assert sec.verification_status({"VerificationError": "x"}, verify_live=True) == "error"


def test_live_verification_requests_unknown_results():
    assert "unknown" in sec.TRUFFLEHOG_RESULTS_VERIFY
