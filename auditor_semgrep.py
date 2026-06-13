"""
auditor_semgrep.py — Centinela-AI v3
Motor de análisis estático de código fuente (SAST) usando Semgrep.
Escanea repositorios Git montados o rutas locales y reporta hallazgos
en vulnerability_log con scan_engine='semgrep'.
"""

import subprocess
import json
import os
import db_manager
from datetime import datetime
from psycopg2.extras import RealDictCursor

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
            "scan_engine": "semgrep",
        })
    print(f"✅ [Semgrep] {len(findings)} findings for {asset_name} at {path}")
    return findings


def persist_findings(findings: list[dict]):
    """Insert semgrep findings into vulnerability_log (skip duplicates)."""
    if not findings:
        return
    with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
        for f in findings:
            # Avoid duplicate: same asset + same rule + same description
            cur.execute("""
                SELECT id FROM public.vulnerability_log
                WHERE asset_id = %s AND cve_id = %s AND scan_engine = 'semgrep'
                LIMIT 1
            """, (f["asset_id"], f["cve_id"]))
            if cur.fetchone():
                continue
            cur.execute("""
                INSERT INTO public.vulnerability_log
                    (asset_id, cve_id, severity, description, status, scan_engine, detected_at)
                VALUES (%s, %s, %s, %s, 'PENDING', 'semgrep', %s)
            """, (
                f["asset_id"], f["cve_id"], f["severity"],
                f["description"], datetime.utcnow()
            ))
    print(f"💾 [Semgrep] Persisted {len(findings)} findings to vulnerability_log")


def run(asset_id: int, asset_name: str, repo_path: str = None):
    """Entry point called by auditor_ext."""
    path = repo_path or os.path.join(REPOS_BASE, asset_name.replace(" ", "_"))
    if not os.path.isdir(path):
        print(f"⚠️ [Semgrep] Path not found: {path} — skipping {asset_name}")
        return
    findings = scan_path(path, asset_id, asset_name)
    persist_findings(findings)
