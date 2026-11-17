"""Schemathesis (property-based API testing) in SAFE mode: finds operations that answer 5xx to schema-valid but unusual input
(WSTG-ERRH-01 / OWASP API8). Runs the official image as a sibling container, like ZAP and the a11y worker.

Safety by construction -- an earlier un-gated GET fuzz against Centinela's own API took the backend down (many GET routes run heavy audits):
  * opt-in per target: nothing runs unless SCHEMATHESIS_TARGETS lists the API (JSON list of
    {"endpoint": "<base url of the registered asset>", "schema_url": "...", "exclude_path_regex": "optional"});
  * GET/HEAD only, one worker, rate-limited, few examples, deterministic generation (same inputs every run: a finding must not flap
    open/resolved just because a random sample missed it -- the price is that exploration does not grow over time), hard wall-clock timeout with the container force-removed;
  * refuses Centinela's own stack (backend/ai/sentinel hostnames, ports 8000/8302) and non-http(s) schemes;
  * a run that did not complete, or hit network errors, persists what it found but reconciles (RESOLVES) nothing."""
import json
import logging
import os
import subprocess
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core import db_manager, deduplication_engine as de

logger = logging.getLogger(__name__)
IMAGE = os.getenv("SCHEMATHESIS_IMAGE", "schemathesis/schemathesis:stable")
NETWORK = "aura-network"
ENGINE = "api-fuzz"
RULE_ID = "WSTG-ERRH-01-API-SERVER-ERROR"
_OWN_HOSTS = {"centinela-backend", "centinela-ai", "centinela-sentinel", "centinela-frontend"}
_OWN_PORTS = {8000, 8302}


def load_targets() -> List[Dict]:
    raw = os.getenv("SCHEMATHESIS_TARGETS", "").strip()
    if not raw:
        return []
    try:
        targets = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("SCHEMATHESIS_TARGETS is not valid JSON", exc_info=True)
        return []
    return [t for t in targets if isinstance(t, dict) and t.get("endpoint") and t.get("schema_url")]


def refuse_reason(url: str) -> Optional[str]:
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return "only http(s) URLs are allowed"
    if u.hostname in _OWN_HOSTS or (u.port in _OWN_PORTS and u.hostname in ("127.0.0.1", "localhost", "192.0.2.17")):
        return "target is Centinela's own stack (fuzzing it already caused an outage)"
    return None


def run_schemathesis(schema_url: str, base_url: str, exclude_path_regex: str = "", timeout: int = 300, network: str = NETWORK) -> Dict:
    """Run the container and return the parsed JSON run report. Raises on docker failure/timeout/missing report."""
    for u in (schema_url, base_url):
        why = refuse_reason(u)
        if why:
            raise ValueError(f"refusing {u}: {why}")
    name = f"schemathesis-{int(time.time())}"
    cmd = ["docker", "run", "--name", name, "--network", network, "--memory", "512m", "--cpus", "1", IMAGE, "run", schema_url,
           "--url", base_url, "--include-method", "GET", "--include-method", "HEAD", "--checks", "not_a_server_error",
           "--phases", "examples,fuzzing", "--max-examples", "5", "--workers", "1", "--rate-limit", "2/s", "--request-timeout", "10",
           "--max-failures", "50", "--generation-deterministic", "--report-json-path", "/tmp/run.json"]
    if exclude_path_regex:
        cmd += ["--exclude-path-regex", exclude_path_regex]
    try:
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")     # exit 1 = failures found: expected
        except subprocess.TimeoutExpired:
            logger.error("schemathesis timed out after %ss on %s", timeout, schema_url, exc_info=True)
            raise
        cp = subprocess.run(["docker", "cp", f"{name}:/tmp/run.json", "-"], capture_output=True)
        if cp.returncode != 0:
            raise RuntimeError(f"schemathesis produced no report: {cp.stderr.decode(errors='replace')[-300:]}")
        import io, tarfile
        with tarfile.open(fileobj=io.BytesIO(cp.stdout)) as tf:
            return json.load(tf.extractfile("run.json"))
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def report_to_findings(report: Dict, base_url: str) -> List[Dict]:
    out = []
    for fail in report.get("failures", []):
        if fail.get("type") != "ServerError":
            continue                                    # other check types are not enabled; never invent a finding
        for op in fail.get("operations", []):
            method, _, path = op.partition(" ")
            out.append({"cve_id": RULE_ID, "severity": "MEDIUM", "url_path": f"{base_url.rstrip('/')}{path}",
                        "description": (f"**{method} {path}** respondió HTTP 5xx a entradas válidas según su propio esquema OpenAPI "
                                        f"(Schemathesis, {fail.get('count', 1)} caso(s)). Un error de servidor ante entrada inesperada indica "
                                        f"validación o manejo de errores incompleto y puede filtrar detalles internos. "
                                        f"Solo se probaron métodos de lectura (GET/HEAD), sin credenciales.")})
    return out


def report_is_trustworthy(report: Dict) -> bool:
    return bool(report.get("complete")) and not report.get("errors") and report.get("stop_reason") == "completed"


def scan_target(asset_id, target: Dict) -> Optional[int]:
    base = target["endpoint"]
    try:
        report = run_schemathesis(target["schema_url"], base, target.get("exclude_path_regex", ""))
    except Exception:
        logger.error("api fuzz failed for %s", base, exc_info=True)
        return None
    findings = report_to_findings(report, base)
    seen = set()
    with db_manager.get_db_cursor() as cur:
        for f in findings:
            de.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], ENGINE,
                                        url_path=f["url_path"], open_status="NEW", preserve_status=True)
            seen.add(de.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
        if report_is_trustworthy(report):
            de.reconcile_resolved_findings(cur, asset_id, ENGINE, seen, url_origin=base.rstrip("/"))
        else:
            logger.warning("api fuzz of %s incomplete (%s, %d errors): nothing reconciled", base, report.get("stop_reason"), len(report.get("errors", [])))
    print(f"🧪 [API-Fuzz] {base}: {len(findings)} operation(s) answering 5xx")
    return len(findings)


def run_for_asset(asset_id, endpoint: str) -> None:
    """Hook for the per-asset dispatcher: runs only when this asset's endpoint is an explicitly configured target."""
    for t in load_targets():
        if t["endpoint"].rstrip("/") == str(endpoint).rstrip("/"):
            scan_target(asset_id, t)
