"""
auditor_sbom.py — Centinela-AI v3
Motor de generación de SBOM (Syft) y escaneo de vulnerabilidades en dependencias (Grype).
Procesa imágenes Docker o directorios de proyecto y reporta CVEs de dependencias
en vulnerability_log con scan_engine='grype'.
"""

import subprocess
import json
import os
import tempfile
import db_manager
from datetime import datetime
from psycopg2.extras import RealDictCursor

SYFT_BIN  = os.getenv("SYFT_BIN",  "syft")
GRYPE_BIN = os.getenv("GRYPE_BIN", "grype")


def _map_severity(grype_sev: str) -> str:
    mapping = {
        "Critical":   "CRITICAL",
        "High":       "HIGH",
        "Medium":     "MEDIUM",
        "Low":        "LOW",
        "Negligible": "LOW",
        "Unknown":    "INFO",
    }
    return mapping.get(grype_sev, "INFO")


def generate_sbom(target: str) -> dict | None:
    """Run syft on `target` (docker image or directory) and return SBOM dict."""
    print(f"📦 [Syft] Generating SBOM for {target}")
    try:
        result = subprocess.run(
            [SYFT_BIN, target, "-o", "json", "--quiet"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            print(f"⚠️ [Syft] Error: {result.stderr[:300]}")
            return None
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"⏰ [Syft] Timeout for {target}")
        return None
    except json.JSONDecodeError as e:
        print(f"⚠️ [Syft] JSON error: {e}")
        return None


def scan_sbom(sbom_data: dict) -> list[dict]:
    """Pipe SBOM JSON into grype and return vulnerability list."""
    print(f"🔬 [Grype] Scanning SBOM for vulnerabilities...")
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(sbom_data, f)
            sbom_path = f.name
        result = subprocess.run(
            [GRYPE_BIN, f"sbom:{sbom_path}", "-o", "json", "--quiet"],
            capture_output=True, text=True, timeout=300
        )
        os.unlink(sbom_path)
        if result.returncode != 0:
            print(f"⚠️ [Grype] Error: {result.stderr[:300]}")
            return []
        data = json.loads(result.stdout)
        return data.get("matches", [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"⚠️ [Grype] Failed: {e}")
        return []


def normalize_findings(matches: list[dict], asset_id: int, target: str) -> list[dict]:
    findings = []
    for m in matches:
        vuln    = m.get("vulnerability", {})
        cve_id  = vuln.get("id", "UNKNOWN-CVE")
        severity = _map_severity(vuln.get("severity", "Unknown"))
        artifact = m.get("artifact", {})
        pkg_name = artifact.get("name", "unknown")
        pkg_ver  = artifact.get("version", "?")
        fix_vers = vuln.get("fix", {}).get("versions", [])
        fix_str  = f"Fix available: {', '.join(fix_vers)}" if fix_vers else "No fix available yet."
        description = (
            f"Package {pkg_name}@{pkg_ver} in {target} is affected by {cve_id}. "
            f"{vuln.get('description', '')[:400]} {fix_str}"
        )
        findings.append({
            "asset_id":    asset_id,
            "cve_id":      cve_id,
            "severity":    severity,
            "description": description,
            "scan_engine": "grype",
        })
    return findings


def persist_findings(findings: list[dict]):
    if not findings:
        return
    inserted = 0
    with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
        for f in findings:
            cur.execute("""
                SELECT id FROM public.vulnerability_log
                WHERE asset_id = %s AND cve_id = %s AND scan_engine = 'grype'
                LIMIT 1
            """, (f["asset_id"], f["cve_id"]))
            if cur.fetchone():
                continue
            cur.execute("""
                INSERT INTO public.vulnerability_log
                    (asset_id, cve_id, severity, description, status, scan_engine, detected_at)
                VALUES (%s, %s, %s, %s, 'PENDING', 'grype', %s)
            """, (
                f["asset_id"], f["cve_id"], f["severity"],
                f["description"], datetime.utcnow()
            ))
            inserted += 1
    print(f"💾 [Grype] Persisted {inserted} new findings to vulnerability_log")


def run(asset_id: int, asset_name: str, target: str = None):
    """
    Entry point called by auditor_ext.
    `target` can be a Docker image name (e.g. 'nginx:latest') or a directory path.
    Defaults to using asset_name as the image target.
    """
    scan_target = target or asset_name
    sbom = generate_sbom(scan_target)
    if not sbom:
        return
    matches = scan_sbom(sbom)
    print(f"✅ [Grype] {len(matches)} CVEs found for {asset_name}")
    findings = normalize_findings(matches, asset_id, scan_target)
    persist_findings(findings)
