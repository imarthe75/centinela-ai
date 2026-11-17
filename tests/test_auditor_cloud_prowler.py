"""Prowler 5 OCSF parsing (auditors/auditor_cloud.py). Record shape copied from a real `prowler iac` run (5.47.0, 2026-11-06)."""
import json
import os

from auditors import auditor_cloud as a

FAIL = {"status_code": "FAIL", "status": "New", "severity": "High",
        "metadata": {"event_code": "AWS-0107", "product": {"name": "Prowler", "version": "5.47.0"}},
        "finding_info": {"title": "Security groups should not allow unrestricted ingress to SSH or RDP from any IP address.",
                         "desc": "d", "uid": "prowler-iac-AWS-0107"},
        "resources": [{"region": "branch", "uid": "main.tf", "name": "main.tf"}],
        "status_detail": "Security group rule allows unrestricted ingress from any IP address.",
        "remediation": {"desc": "Set a more restrictive CIDR range"}}
PASS = dict(FAIL, status_code="PASS")


def test_only_fail_records_become_findings():
    out = a.parse_ocsf([FAIL, PASS, dict(FAIL, status_code="MANUAL")])
    assert len(out) == 1
    f = out[0]
    assert f["cve_id"] == "PROWLER-AWS-0107" and f["severity"] == "HIGH" and f["url_path"] == "main.tf"
    assert "address.." not in f["description"] and "Recomendación: Set a more restrictive" in f["description"]


def test_informational_severity_and_missing_resource():
    out = a.parse_ocsf([dict(FAIL, severity="Informational", resources=[])])
    assert out[0]["severity"] == "INFO" and out[0]["url_path"] == "N/A"


def test_read_output_none_without_file_and_list_with_file(tmp_path):
    assert a.read_output(str(tmp_path)) is None
    (tmp_path / "centinela.ocsf.json").write_text(json.dumps([FAIL]))
    assert a.read_output(str(tmp_path)) == [FAIL]


def test_build_command_uses_prowler5_flags_and_secret_validation_opt_in(tmp_path):
    cmd = a.build_command("aws", str(tmp_path))
    assert "-M" not in cmd and cmd[cmd.index("--output-formats") + 1] == "json-ocsf"
    assert "--scan-secrets-validate" not in cmd
    assert "--scan-secrets-validate" in a.build_command("aws", str(tmp_path), verify_secrets=True)


def test_run_prowler_failure_returns_none(monkeypatch):
    class R:
        returncode = 1
        stderr = "boom"
        stdout = ""
    monkeypatch.setattr(a.subprocess, "run", lambda *x, **k: R())
    assert a.run_prowler("asset", "aws") is None
