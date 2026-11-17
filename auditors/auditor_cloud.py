"""
auditor_cloud.py — Prowler (CSPM) for assets of type Cloud-Serverless.

Prowler 5 writes its results as OCSF Detection Findings (`--output-formats json-ocsf`, a JSON array in
`<dir>/<name>.ocsf.json`). Until 2026-11-06 this module called `prowler <provider> -M json`: that format does not exist in
Prowler 5 (argparse error on every run) and the parser read Prowler 3 keys (CheckID/Status/ResourceID), so the engine had never
produced a single row. Today no Cloud-Serverless asset is registered, so this runs nowhere until one is.

Each FAIL becomes one finding per (check, resource); a complete run closes the findings it no longer reproduces. A failed run
(no OCSF file) persists nothing and never reconciles.

Secret validation (`--scan-secrets-validate`) uses each discovered secret against its provider and the call shows in the audited
account's logs: it is off unless SECRETS_VERIFY_LIVE=1, the same opt-in as TruffleHog's live verification.
"""
import glob
import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from core import db_manager, deduplication_engine

logger = logging.getLogger(__name__)

PROWLER_BIN = os.getenv("PROWLER_BIN", "prowler")
CREDENTIALS_PATH = os.getenv("PROWLER_GCP_CREDENTIALS", "/app/keys/gcp-credentials.json")
PROWLER_TIMEOUT_S = int(os.getenv("PROWLER_TIMEOUT_S", "3600"))
ENGINE = "prowler"

_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
             "INFORMATIONAL": "INFO", "INFO": "INFO"}


def _map_severity(prowler_sev: str) -> str:
    return _SEVERITY.get((prowler_sev or "").upper(), "INFO")


def build_command(provider: str, output_dir: str, verify_secrets: bool = False,
                  credentials_path: Optional[str] = None) -> List[str]:
    cmd = [PROWLER_BIN, provider, "--output-formats", "json-ocsf", "--output-directory", output_dir,
           "--output-filename", "centinela", "--no-banner"]
    if provider == "gcp" and credentials_path and os.path.exists(credentials_path):
        cmd += ["--credentials-file", credentials_path]
    if verify_secrets:
        cmd.append("--scan-secrets-validate")
    return cmd


def parse_ocsf(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """FAIL detection findings -> [{cve_id, severity, url_path, description}]. PASS/MANUAL are not findings."""
    out = []
    for r in records or []:
        if (r.get("status_code") or "").upper() != "FAIL":
            continue
        check = (r.get("metadata") or {}).get("event_code") or "PROWLER-CHECK"
        info = r.get("finding_info") or {}
        resources = r.get("resources") or [{}]
        res = resources[0] or {}
        resource = res.get("uid") or res.get("name") or "N/A"
        region = res.get("region") or res.get("namespace") or ""
        remediation = (r.get("remediation") or {}).get("desc") or ""
        detail = r.get("status_detail") or info.get("desc") or ""
        title = (info.get("title") or check).rstrip(". ")
        desc = f"[{check}] {title}. Recurso: {resource}" + (f" ({region})" if region else "") + f". {detail}"
        if remediation:
            desc += f" Recomendación: {remediation}"
        out.append({"cve_id": f"PROWLER-{check}"[:100], "severity": _map_severity(r.get("severity")),
                    "url_path": f"{resource}"[:500], "description": desc[:2000]})
    return out


def read_output(output_dir: str) -> Optional[List[Dict[str, Any]]]:
    """Records from the OCSF file, or None when prowler wrote none (a failed run, never read as 'no findings')."""
    files = glob.glob(os.path.join(output_dir, "*.ocsf.json"))
    if not files:
        return None
    with open(max(files, key=os.path.getmtime)) as f:
        content = f.read().strip()
    if not content:
        return []
    data = json.loads(content)
    return data if isinstance(data, list) else [data]


def run_prowler(asset_id: str, provider: str = "gcp") -> Optional[List[Dict[str, Any]]]:
    """Runs prowler; returns parsed findings, or None when the run failed."""
    verify = os.getenv("SECRETS_VERIFY_LIVE", "0") == "1"
    output_dir = tempfile.mkdtemp(prefix="prowler-")
    cmd = build_command(provider, output_dir, verify, CREDENTIALS_PATH)
    print(f"☁️ [Prowler] {provider}: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=PROWLER_TIMEOUT_S)
        # exit 3 = checks failed (findings present); anything else non-zero is a real error
        if result.returncode not in (0, 3):
            logger.error("prowler exited %s: %s", result.returncode, (result.stderr or result.stdout or "")[-800:])
            return None
        records = read_output(output_dir)
        if records is None:
            logger.error("prowler wrote no OCSF output (exit %s): %s", result.returncode, (result.stderr or "")[-800:])
            return None
        return parse_ocsf(records)
    except subprocess.TimeoutExpired:
        logger.error("prowler timed out after %ss", PROWLER_TIMEOUT_S, exc_info=True)
        return None
    except Exception:
        logger.error("prowler run failed", exc_info=True)
        return None
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


def persist_findings(asset_id: str, findings: List[Dict[str, Any]]) -> Dict[str, int]:
    seen = set()
    with db_manager.get_db_cursor() as cur:
        for f in findings:
            deduplication_engine.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], ENGINE,
                                                          url_path=f["url_path"], open_status="NEW", preserve_status=True)
            seen.add(deduplication_engine.calculate_fingerprint(asset_id, f["cve_id"], f["url_path"]))
        resolved = deduplication_engine.reconcile_resolved_findings(cur, asset_id, ENGINE, seen)
    print(f"💾 [Prowler] {len(findings)} findings persisted, {resolved} no longer reproduced -> RESOLVED")
    return {"persisted": len(findings), "resolved": resolved}


def run(asset_id: str, asset_name: str, provider: str = "gcp"):
    """Entry point called by auditor_ext for Cloud-Serverless assets."""
    findings = run_prowler(asset_id, provider)
    if findings is None:
        print(f"⚠️ [Prowler] {asset_name}: scan failed, nothing persisted or reconciled")
        return
    persist_findings(asset_id, findings)
