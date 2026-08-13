"""
auditor_semgrep.py — Centinela-AI v3
Motor de análisis estático de código fuente (SAST) usando Semgrep.
Escanea repositorios Git montados o rutas locales y reporta hallazgos
en vulnerability_log con scan_engine='semgrep'.
"""

import subprocess
import json
import os
import traceback
from core import db_manager, deduplication_engine

SEMGREP_BIN = os.getenv("SEMGREP_BIN", "semgrep")
REPOS_BASE  = os.getenv("REPOS_BASE", "/app/repos")   # directorio donde se montan repos
RULESETS    = os.getenv("SEMGREP_RULESETS", "p/owasp-top-ten p/secrets p/python p/javascript")


def _severity_from_semgrep(impact: str) -> str:
    mapping = {
        "ERROR":   "HIGH",
        "WARNING": "MEDIUM",
        "INFO":    "LOW",
    }
    return mapping.get((impact or "").upper(), "LOW")


def scan_path(path: str, asset_id: int, asset_name: str) -> list[dict]:
    """Run semgrep on `path` and return list of normalized findings."""
    rulesets = RULESETS.split()
    cmd = [SEMGREP_BIN, "--json", "--quiet"] + [f"--config={r}" for r in rulesets] + [path]
    print(f"🔍 [Semgrep] Scanning {path} with rulesets: {rulesets}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode not in (0, 1):
            print(f"⚠️ [Semgrep] Non-zero exit {result.returncode}: {result.stderr[:200]}")
            return []
        data = json.loads(result.stdout or "{}")
    except subprocess.TimeoutExpired:
        print(f"⏰ [Semgrep] Timeout scanning {path}")
        return []
    except json.JSONDecodeError as e:
        print(f"⚠️ [Semgrep] JSON parse error: {e}")
        return []

    findings = []
    for r in data.get("results", []):
        check_id  = r.get("check_id", "semgrep-finding")
        severity  = _severity_from_semgrep(r.get("extra", {}).get("severity"))
        file_path = r.get("path", "unknown")
        start_line = r.get("start", {}).get("line", 0)
        message   = r.get("extra", {}).get("message", "Sin descripción")
        findings.append({
            "asset_id":    asset_id,
            "asset_name":  asset_name,
            "cve_id":      check_id,
            "severity":    severity,
            "description": f"[{file_path}:{start_line}] {message}",
            "url_path":    f"{file_path}:{start_line}",
            "scan_engine": "semgrep",
        })
    print(f"✅ [Semgrep] {len(findings)} findings for {asset_name} at {path}")
    return findings


def persist_findings(findings: list[dict]):
    """
    Persists semgrep findings via the shared cross-tool dedup engine. Previously this ran its
    own ad-hoc `SELECT ... WHERE asset_id=%s AND cve_id=%s AND scan_engine='semgrep'` check and,
    on a match, did nothing at all -- not even refreshing detected_at/severity -- meaning
    re-detected findings never got their SLA due date, fingerprint_hash, or MITRE ATT&CK
    mapping computed, because none of that lives in this ad-hoc INSERT; every other auditor in
    this codebase already funnels through log_finding_deduplicated() for exactly that reason.
    preserve_status=True: semgrep re-scans the same GitLab repos repeatedly via the idle loop,
    same reasoning as ZAP's documented preserve_status bug -- without it, every re-detection
    would reset an already-triaged finding back to OPEN.
    """
    if not findings:
        return
    persisted = 0
    with db_manager.get_db_cursor() as cur:
        for f in findings:
            deduplication_engine.log_finding_deduplicated(
                cur, f["asset_id"], f["cve_id"], f["severity"], f["description"],
                "semgrep", url_path=f["url_path"], open_status="OPEN", preserve_status=True
            )
            persisted += 1
    print(f"💾 [Semgrep] Persisted {persisted} findings to vulnerability_log")


def run(asset_id: int, asset_name: str, repo_path: str = None):
    """Entry point called by auditor_ext."""
    path = repo_path or os.path.join(REPOS_BASE, asset_name.replace(" ", "_"))
    if not os.path.isdir(path):
        print(f"⚠️ [Semgrep] Path not found: {path} — skipping {asset_name}")
        return
    findings = scan_path(path, asset_id, asset_name)
    persist_findings(findings)
