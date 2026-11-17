"""
Nuclei DAST driven by an API's OpenAPI/Swagger spec: sends nuclei's fuzzing templates (SQLi, XSS, SSTI, LFI, CRLF, open redirect,
command injection...) to the parameters of each operation the spec declares.

This is active testing with attack payloads, so it is gated exactly like Schemathesis (auditor_api_fuzz.py):
  * opt-in per target -- nothing runs unless NUCLEI_DAST_TARGETS lists the API (JSON list of
    {"endpoint": "<base url of the registered asset>", "schema_url": "<openapi/swagger url>"});
  * GET operations only: the spec is downloaded and every non-GET operation removed before nuclei sees it, so no payload is ever
    sent in a body that could write data;
  * low aggression, one connection, 2 requests/s, no interactsh (no out-of-band callbacks to the internet), hard wall-clock timeout
    that kills the whole process group;
  * refuses Centinela's own stack and non-http(s) schemes (same rule as auditor_api_fuzz.refuse_reason);
  * only a run that exited cleanly reconciles (RESOLVES) findings it no longer reproduces.
"""
import json
import logging
import os
import shutil
import signal
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

import requests

from auditors.auditor_api_fuzz import refuse_reason
from core import db_manager, deduplication_engine as de

logger = logging.getLogger(__name__)

ENGINE = "nuclei-dast"
NUCLEI_BIN = os.getenv("NUCLEI_BIN", "nuclei")
TEMPLATES = os.getenv("NUCLEI_DAST_TEMPLATES", os.path.expanduser("~/nuclei-templates/dast/vulnerabilities"))
TIMEOUT_S = int(os.getenv("NUCLEI_DAST_TIMEOUT_S", "1800"))
RATE_LIMIT = os.getenv("NUCLEI_DAST_RATE_LIMIT", "2")
_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def load_targets() -> List[Dict[str, str]]:
    raw = os.getenv("NUCLEI_DAST_TARGETS", "").strip()
    if not raw:
        return []
    try:
        targets = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("NUCLEI_DAST_TARGETS is not valid JSON", exc_info=True)
        return []
    return [t for t in targets if isinstance(t, dict) and t.get("endpoint") and t.get("schema_url")]


def get_only_spec(spec: Dict[str, Any], base_url: str) -> Dict[str, Any]:
    """Copy of the spec with only GET operations, pointed at base_url (OpenAPI 3 `servers`, Swagger 2 host/basePath/schemes)."""
    out = json.loads(json.dumps(spec))
    paths = {}
    for path, item in (out.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        kept = {k: v for k, v in item.items() if k.lower() not in _HTTP_METHODS or k.lower() == "get"}
        if "get" in {k.lower() for k in kept}:
            paths[path] = kept
    out["paths"] = paths
    if "swagger" in out:
        from urllib.parse import urlparse
        u = urlparse(base_url)
        out["host"] = u.netloc
        out["schemes"] = [u.scheme]
        out["basePath"] = u.path or "/"
    else:
        out["servers"] = [{"url": base_url.rstrip("/")}]
    return out


def build_command(spec_path: str, output_path: str) -> List[str]:
    return [NUCLEI_BIN, "-im", "openapi", "-l", spec_path, "-dast", "-t", TEMPLATES, "-fa", "low",
            "-c", "1", "-rl", RATE_LIMIT, "-timeout", "10", "-retries", "0", "-ni", "-duc", "-silent",
            "-jsonl", "-o", output_path, "-sfv"]


def parse_results(jsonl: str) -> List[Dict[str, str]]:
    """nuclei -jsonl -> [{cve_id, severity, url_path, description}], one per (template, path, parameter)."""
    out, seen = [], set()
    for line in (jsonl or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = r.get("template-id") or "unknown"
        info = r.get("info") or {}
        matched = r.get("matched-at") or r.get("url") or ""
        param = r.get("fuzzing_parameter") or ""
        from urllib.parse import urlparse
        path = urlparse(matched).path or matched
        loc = f"{path}?{param}" if param else path
        key = (tid, loc)
        if key in seen:
            continue
        seen.add(key)
        name = info.get("name") or tid
        desc = f"[nuclei DAST] {name}: {r.get('fuzzing_method') or 'GET'} {path}" + (f", parámetro «{param}»" if param else "")
        if info.get("description"):
            desc += f". {str(info['description']).strip()[:600]}"
        out.append({"cve_id": f"NUCLEI-DAST-{tid}"[:100], "severity": _SEVERITY.get(str(info.get("severity", "")).lower(), "MEDIUM"),
                    "url_path": loc[:500], "description": desc[:2000]})
    return out


def _run(cmd: List[str], timeout_s: int) -> int:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        _, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        raise
    if proc.returncode != 0:
        logger.error("nuclei exited %s: %s", proc.returncode, (err or "")[-800:])
    return proc.returncode


def scan(schema_url: str, base_url: str, timeout_s: int = TIMEOUT_S) -> Dict[str, Any]:
    """Runs the DAST pass. Returns {"findings": [...], "complete": bool, "operations": n}. Raises ValueError on a refused target."""
    for u in (schema_url, base_url):
        why = refuse_reason(u)
        if why:
            raise ValueError(f"refusing {u}: {why}")
    resp = requests.get(schema_url, timeout=20)
    resp.raise_for_status()
    spec = get_only_spec(resp.json(), base_url)
    ops = sum(1 for item in spec["paths"].values() for k in item if k.lower() == "get")
    if ops == 0:
        return {"findings": [], "complete": True, "operations": 0}
    work = tempfile.mkdtemp(prefix="nuclei-dast-")
    try:
        spec_path, out_path = os.path.join(work, "spec.json"), os.path.join(work, "out.jsonl")
        with open(spec_path, "w") as f:
            json.dump(spec, f)
        try:
            rc = _run(build_command(spec_path, out_path), timeout_s)
        except subprocess.TimeoutExpired:
            logger.error("nuclei DAST timed out after %ss on %s", timeout_s, base_url)
            rc = None
        text = open(out_path).read() if os.path.exists(out_path) else ""
        return {"findings": parse_results(text), "complete": rc == 0, "operations": ops}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def persist(asset_id: str, base_url: str, result: Dict[str, Any]) -> Dict[str, int]:
    seen = set()
    with db_manager.get_db_cursor() as cur:
        for f in result["findings"]:
            de.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], ENGINE,
                                        url_path=f["url_path"], open_status="NEW", preserve_status=True)
            seen.add(de.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
        resolved = de.reconcile_resolved_findings(cur, asset_id, ENGINE, seen) if result["complete"] else 0
    return {"persisted": len(result["findings"]), "resolved": resolved}


def run_for_asset(asset_id: str, endpoint: str) -> Optional[Dict[str, int]]:
    """No-op unless `endpoint` is an opted-in NUCLEI_DAST_TARGETS entry."""
    target = next((t for t in load_targets() if t["endpoint"].rstrip("/") == (endpoint or "").rstrip("/")), None)
    if not target:
        return None
    try:
        result = scan(target["schema_url"], target["endpoint"])
    except Exception:
        logger.error("nuclei DAST failed for %s", endpoint, exc_info=True)
        return None
    stats = persist(asset_id, target["endpoint"], result)
    print(f"🧪 [Nuclei-DAST] {endpoint}: {result['operations']} GET operation(s), {stats['persisted']} finding(s)"
          + ("" if result["complete"] else " (incomplete run: nothing reconciled)"))
    return stats
