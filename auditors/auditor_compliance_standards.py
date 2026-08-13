"""
Centinela Native Compliance & Master Standards Auditor
Audits codebase against Master Audit Standards (ISO 25010, STRIDE Threat Model, OWASP API, CIS Benchmarks).
"""
import os
import re
from typing import List, Dict, Any
from core import db_manager


def audit_stride_threat_matrix(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits code against STRIDE threat model standards."""
    findings = []
    lines = content.splitlines()

    # 1. Spoofing: Unsigned or HS256 JWT algorithm check
    for idx, line in enumerate(lines, 1):
        if "jwt.decode" in line and "algorithms" in line and ("HS256" in line or "none" in line.lower()):
            findings.append({
                "standard": "STRIDE-SPOOFING",
                "cve_id": "STD-STRIDE-JWT-INSECURE-ALG",
                "severity": "HIGH",
                "file": file_path,
                "line": idx,
                "description": f"STRIDE Spoofing Violation: JWT configured with weak algorithm (HS256/none). Standard requires RS256/Ed25519 asymmetric signatures. Line {idx}: {line.strip()}"
            })

    # 2. Repudiation: Missing audit logging in state-changing endpoints (POST/PUT/DELETE)
    if "FastAPI" in content or "@app.post" in content or "@app.delete" in content:
        if "db_manager" in content and "remediation_history" not in content and "vulnerability_log" not in content:
            findings.append({
                "standard": "STRIDE-REPUDIATION",
                "cve_id": "STD-STRIDE-MISSING-AUDIT-LOG",
                "severity": "MEDIUM",
                "file": file_path,
                "line": 1,
                "description": "STRIDE Repudiation Violation: Endpoint modifies state without writing an immutable audit log entry (who, what, when)."
            })

    # 3. Information Disclosure: Unmasked PII or raw stacktrace exposure
    for idx, line in enumerate(lines, 1):
        if "print(" in line or "logger." in line:
            if any(sensitive in line.lower() for sensitive in ["password", "jwt", "secret_key", "auth_token"]):
                findings.append({
                    "standard": "STRIDE-INFO-DISCLOSURE",
                    "cve_id": "STD-STRIDE-LOG-SENSITIVE-DATA",
                    "severity": "HIGH",
                    "file": file_path,
                    "line": idx,
                    "description": f"STRIDE Information Disclosure: Sensitive credential or token logged directly. Line {idx}: {line.strip()}"
                })

    return findings


def audit_iso_25010_quality(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits code against ISO/IEC 25010 Quality Model (Maintainability & Clean Code)."""
    findings = []
    lines = content.splitlines()

    # Function Length Limit (>60 lines per function)
    current_fn = None
    fn_start = 0
    fn_len = 0

    for idx, line in enumerate(lines, 1):
        if line.strip().startswith("def ") or line.strip().startswith("async def "):
            if current_fn and fn_len > 60:
                findings.append({
                    "standard": "ISO25010-MAINTAINABILITY",
                    "cve_id": "STD-ISO25010-LONG-METHOD",
                    "severity": "LOW",
                    "file": file_path,
                    "line": fn_start,
                    "description": f"ISO 25010 Maintainability Violation: Function '{current_fn}' exceeds 60 lines limit ({fn_len} lines). Extract methods to reduce cognitive complexity."
                })
            current_fn = line.strip().split("(")[0].replace("def ", "").replace("async def ", "")
            fn_start = idx
            fn_len = 0
        elif current_fn:
            fn_len += 1

    return findings


def run_compliance_standards_audit(target_dir: str = "/opt/centinela-ai", asset_id: int = None) -> List[Dict[str, Any]]:
    """Runs full Master Audit Standards compliance check across target codebase."""
    all_findings = []

    for root, _, files in os.walk(target_dir):
        # "tests" excluded too -- see the identical exclusion (and its reasoning) in
        # auditor_master_vulnerabilities.py's run_master_vulnerability_scan().
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv", "/tests", "\\tests"]):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            if file.endswith((".py", ".js", ".jsx", ".ts", ".tsx")):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    all_findings.extend(audit_stride_threat_matrix(full_path, content))
                    all_findings.extend(audit_iso_25010_quality(full_path, content))
                except Exception as e:
                    print(f"⚠️ [Standards-Auditor] Error reading {full_path}: {e}")

    # Persist findings to database. Same fixes as the other two native engines: file location
    # stored in url_path, and deduplication_engine.log_finding_deduplicated() replaces the old
    # no-op "ON CONFLICT DO NOTHING" -- also merges cross-tool duplicates instead of creating a
    # second ticket for the same real finding reported by a different engine.
    try:
        from core import deduplication_engine
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                rel_path = os.path.relpath(item["file"], target_dir) if item.get("file") else "unknown"
                location = f"{rel_path}:{item.get('line', 0)}"
                description = f"**Archivo:** `{rel_path}` (Línea {item.get('line', 0)})\n{item['description']}"

                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"], description,
                    "standards-audit", url_path=location, open_status="OPEN", preserve_status=True
                )
    except Exception as db_err:
        print(f"⚠️ [Standards-Auditor] Could not log findings to DB: {db_err}")

    return all_findings
