"""trivy config auditor: pure parsing, failure semantics and (real tool) behaviour on a Dockerfile."""
import os
import shutil
import tempfile
import pytest

from auditors import auditor_trivy_config as T

DOC = {"Results": [{"Target": "deployment.yaml", "Class": "config", "Type": "kubernetes", "Misconfigurations": [
    {"ID": "KSV-0014", "Title": "Root file system is not read-only", "Description": "d", "Message": "m", "Resolution": "set readOnlyRootFilesystem",
     "Severity": "HIGH", "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv014", "CauseMetadata": {"StartLine": 26}},
    {"ID": "KSV-0030", "Title": "Runtime/Default Seccomp profile not set", "Severity": "UNKNOWN", "CauseMetadata": {}}]}]}


def test_parse_maps_id_severity_file_and_line():
    out = T.parse_trivy_config(DOC)
    assert [(f["cve_id"], f["severity"], f["file"], f["line"]) for f in out] == [("TRIVY-KSV-0014", "HIGH", "deployment.yaml", 26), ("TRIVY-KSV-0030", "LOW", "deployment.yaml", 1)]
    assert "readOnlyRootFilesystem" in out[0]["description"] and "ksv014" in out[0]["description"]


def test_parse_of_an_empty_or_clean_document_is_empty():
    assert T.parse_trivy_config({}) == [] and T.parse_trivy_config({"Results": [{"Target": "x", "Misconfigurations": None}]}) == []


def test_a_tool_failure_is_none_not_an_empty_clean_result(monkeypatch):
    class R:
        returncode = 1
        stdout = ""
        stderr = "boom"
    monkeypatch.setattr(T.subprocess, "run", lambda *a, **k: R())
    assert T.scan_directory("/nonexistent") is None
    assert T.run_trivy_config_audit("/nonexistent", asset_id="x") == []


@pytest.mark.skipif(shutil.which("trivy") is None, reason="trivy is not installed in this environment")
def test_real_trivy_flags_a_dockerfile_without_user():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "Dockerfile"), "w").write("FROM alpine:3.19\nRUN echo hi\nCMD [\"sh\"]\n")
        out = T.scan_directory(d)
    assert out is not None and "TRIVY-DS-0002" in {f["cve_id"] for f in out}
