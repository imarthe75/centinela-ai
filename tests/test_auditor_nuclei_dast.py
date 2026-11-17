"""Nuclei DAST from OpenAPI (auditors/auditor_nuclei_dast.py): gating, GET-only spec, result parsing."""
import json

import pytest

from auditors import auditor_nuclei_dast as n

SPEC3 = {"openapi": "3.0.0", "servers": [{"url": "http://other"}],
         "paths": {"/a": {"get": {}, "post": {}, "parameters": [{"name": "x", "in": "query"}]},
                   "/w": {"post": {}, "delete": {}}}}


def test_get_only_spec_drops_non_get_and_points_at_target():
    out = n.get_only_spec(SPEC3, "http://api.test:8080/v1/")
    assert list(out["paths"]) == ["/a"]
    assert set(out["paths"]["/a"]) == {"get", "parameters"}
    assert out["servers"] == [{"url": "http://api.test:8080/v1"}]
    assert "post" in SPEC3["paths"]["/a"]   # original untouched


def test_get_only_spec_swagger2():
    out = n.get_only_spec({"swagger": "2.0", "paths": {"/a": {"get": {}, "put": {}}}}, "https://h:9443/base")
    assert out["host"] == "h:9443" and out["schemes"] == ["https"] and out["basePath"] == "/base"
    assert list(out["paths"]["/a"]) == ["get"]


def test_parse_results_dedupes_and_maps_severity():
    rec = {"template-id": "sqli-error-based", "info": {"name": "Error based SQL Injection", "severity": "critical"},
           "matched-at": "http://h/item?id=1'", "fuzzing_parameter": "id", "fuzzing_method": "GET"}
    out = n.parse_results("\n".join([json.dumps(rec), json.dumps(rec), "[INF] noise"]))
    assert out == [{"cve_id": "NUCLEI-DAST-sqli-error-based", "severity": "CRITICAL", "url_path": "/item?id",
                    "description": "[nuclei DAST] Error based SQL Injection: GET /item, parámetro «id»"}]


def test_command_is_low_impact():
    cmd = n.build_command("/s.json", "/o.jsonl")
    for flag in ("-dast", "-ni", "-duc"):
        assert flag in cmd
    assert cmd[cmd.index("-c") + 1] == "1" and cmd[cmd.index("-fa") + 1] == "low"


def test_refuses_own_stack_before_any_request(monkeypatch):
    monkeypatch.setattr(n.requests, "get", lambda *a, **k: pytest.fail("must not fetch"))
    with pytest.raises(ValueError):
        n.scan("http://centinela-backend:8000/openapi.json", "http://centinela-backend:8000")


def test_run_for_asset_is_noop_without_opt_in(monkeypatch):
    monkeypatch.delenv("NUCLEI_DAST_TARGETS", raising=False)
    monkeypatch.setattr(n, "scan", lambda *a, **k: pytest.fail("must not scan"))
    assert n.run_for_asset("asset", "http://api.test") is None
