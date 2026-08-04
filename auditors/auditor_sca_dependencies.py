"""
Centinela Native Software Composition Analysis (SCA) & Dependency Auditor
Parses package manifests (requirements.txt, package.json) to detect vulnerable dependencies and security risks.
"""
import os
import json
import re
from typing import List, Dict, Any
from core import db_manager

# Known vulnerable package versions dictionary
KNOWN_VULNERABLE_PACKAGES = {
    "requests": [("<2.31.0", "CVE-2023-32681", "HIGH", "Unintended leak of Proxy-Authorization header")],
    "urllib3": [("<1.26.17", "CVE-2023-45803", "MEDIUM", "Request body not stripped on HTTP redirect")],
    "jinja2": [("<3.1.3", "CVE-2024-22195", "MEDIUM", "Cross-site scripting (XSS) vulnerability in xmlattr filter")],
    "pyyaml": [("<5.4", "CVE-2020-14343", "CRITICAL", "Arbitrary Code Execution via FullLoader")],
    "cryptography": [("<41.0.6", "CVE-2023-49083", "HIGH", "NULL pointer dereference in PKCS12 parsing")],
    "express": [("<4.19.2", "CVE-2024-29041", "HIGH", "Open redirect vulnerability in express.static")],
    "axios": [("<1.7.4", "CVE-2024-39338", "HIGH", "Server-Side Request Forgery via relative URL manipulation")]
}


def audit_requirements_txt(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Python requirements.txt file."""
    findings = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("#"):
            continue

        match = re.match(r'^([a-zA-Z0-9_-]+)\s*(==|<=|>=|<|>)?\s*([0-9a-zA-Z.]+)?', clean_line)
        if match:
            pkg_name = match.group(1).lower()
            version = match.group(3) or ""

            if pkg_name in KNOWN_VULNERABLE_PACKAGES:
                for target_ver, cve, severity, desc in KNOWN_VULNERABLE_PACKAGES[pkg_name]:
                    findings.append({
                        "cve_id": f"SCA-{cve}",
                        "severity": severity,
                        "file": file_path,
                        "line": idx,
                        "package": pkg_name,
                        "installed_version": version,
                        "description": f"Vulnerable dependency '{pkg_name}' ({version}). {desc} ({cve})."
                    })

    return findings


def audit_package_json(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits Node.js package.json file."""
    findings = []
    try:
        data = json.loads(content)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

        for pkg_name, version in deps.items():
            clean_pkg = pkg_name.lower()
            if clean_pkg in KNOWN_VULNERABLE_PACKAGES:
                for target_ver, cve, severity, desc in KNOWN_VULNERABLE_PACKAGES[clean_pkg]:
                    findings.append({
                        "cve_id": f"SCA-{cve}",
                        "severity": severity,
                        "file": file_path,
                        "package": clean_pkg,
                        "installed_version": version,
                        "description": f"Vulnerable npm dependency '{clean_pkg}' ({version}). {desc} ({cve})."
                    })
    except Exception as e:
        print(f"⚠️ [SCA-Auditor] Error parsing {file_path}: {e}")

    return findings


def run_sca_audit(target_dir: str = "/opt/centinela-ai", asset_id: int = None) -> List[Dict[str, Any]]:
    """Scans target directory for package manifests and audits open-source dependencies."""
    all_findings = []

    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if file == "requirements.txt":
                    all_findings.extend(audit_requirements_txt(full_path, content))
                elif file == "package.json":
                    all_findings.extend(audit_package_json(full_path, content))
            except Exception as e:
                print(f"⚠️ [SCA-Auditor] Could not read {full_path}: {e}")

    # Persist findings to database
    try:
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                cur.execute("""
                    INSERT INTO public.vulnerability_log
                    (asset_id, cve_id, severity, description, status, scan_engine, detected_at)
                    VALUES (%s, %s, %s, %s, 'OPEN', 'sca-native', NOW())
                    ON CONFLICT DO NOTHING
                """, (asset_id, item["cve_id"], item["severity"], item["description"]))
    except Exception as db_err:
        print(f"⚠️ [SCA-Auditor] Could not log findings to DB: {db_err}")

    return all_findings
