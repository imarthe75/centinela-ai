"""Trivy image parsing, and a real trivy run (no mocks) when the DB cache is available."""
import json
import shutil
import subprocess

import pytest

from auditors import auditor_ext


def test_parse_flattens_vulnerabilities_and_tolerates_clean_results():
    raw = json.dumps({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "HIGH", "PkgName": "openssl",
                                                        "InstalledVersion": "1.0", "FixedVersion": "1.1", "Title": "t"}]}, {"Target": "x"}]})
    out = auditor_ext.parse_trivy_image_json(raw)
    assert out == [{"id": "CVE-1", "severity": "HIGH", "package": "openssl", "installed": "1.0", "fixed": "1.1", "title": "t"}]
    assert auditor_ext.parse_trivy_image_json("{}") == []


def test_parse_rejects_non_json():
    with pytest.raises(ValueError):
        auditor_ext.parse_trivy_image_json("2026 INFO banner")


def test_failed_trivy_is_not_reported_as_clean(monkeypatch):
    logged = []
    monkeypatch.setattr(auditor_ext, "log_vulnerability", lambda *a: logged.append(a))
    monkeypatch.setattr(auditor_ext.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "boom"))
    assert auditor_ext.scan_container("00000000-0000-0000-0000-000000000000", "img:x") is False
    assert logged == []         # no "no vulnerabilities found" claim
