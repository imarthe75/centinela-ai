"""
Centinela Native Compliance & Master Standards Auditor
Audits codebase against Master Audit Standards (ISO 25010, STRIDE Threat Model, OWASP API, CIS Benchmarks).
"""
import os
import re
from typing import List, Dict, Any
from core import db_manager


# Real bug fixed 2026-08-13, same self-referential class already fixed in
# auditor_master_vulnerabilities.py's CODE-INJECTION-EVAL check: naive substring matching on
# "jwt.decode"/"password"/etc. flags this scanner's OWN detector logic (which necessarily
# contains those words to define what it looks for) and any log message merely *mentioning* a
# word like "password" as descriptive English text (e.g. "Attempting Password authentication...")
# without ever interpolating a real secret value. Confirmed live: 100% of this codebase's own
# STD-STRIDE-JWT-INSECURE-ALG (1/1) and STD-STRIDE-LOG-SENSITIVE-DATA (8/8) findings were exactly
# this, not real issues.
_JWT_WEAK_ALG_RE = re.compile(r'jwt\.decode\s*\([^)]*algorithms\s*=\s*\[[^\]]*(HS256|none)', re.IGNORECASE)
# Only flags a log statement that actually *interpolates* a sensitive-looking variable
# ({password}, {token}, f"{obj.secret_key}", %s formatting of one, etc.) -- not the word
# appearing anywhere in the message text.
_SENSITIVE_INTERPOLATION_RE = re.compile(
    r'(print|logger\.\w+)\s*\(.*[{%](\s*\w*\.)?(password|jwt|secret_key|auth_token)\w*[}%s]', re.IGNORECASE
)


def audit_stride_threat_matrix(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits code against STRIDE threat model standards."""
    findings = []
    lines = content.splitlines()

    # 1. Spoofing: Unsigned or HS256 JWT algorithm check -- requires an actual jwt.decode(...)
    # call with an algorithms=[...] argument naming a weak algorithm, not just those words
    # appearing anywhere on the line (which self-matched this very detector's own source).
    for idx, line in enumerate(lines, 1):
        if _JWT_WEAK_ALG_RE.search(line) and not line.lstrip().startswith("#"):
            findings.append({
                "standard": "STRIDE-SPOOFING",
                "cve_id": "STD-STRIDE-JWT-INSECURE-ALG",
                "severity": "HIGH",
                "file": file_path,
                "line": idx,
                "description": f"STRIDE Spoofing Violation: JWT configured with weak algorithm (HS256/none). Standard requires RS256/Ed25519 asymmetric signatures. Line {idx}: {line.strip()}"
            })

    # 2. Repudiation: Missing audit logging in state-changing endpoints (POST/PUT/DELETE).
    # Real FastAPI route decorators only, not any file that merely mentions the word "FastAPI"
    # or contains the substring "@app.post" inside an unrelated regex/string (e.g. a route-
    # discovery detector's own pattern definition).
    has_state_changing_route = bool(re.search(r'@app\.(post|put|delete|patch)\s*\(', content))
    if has_state_changing_route and "db_manager" in content and "remediation_history" not in content and "vulnerability_log" not in content:
        findings.append({
            "standard": "STRIDE-REPUDIATION",
            "cve_id": "STD-STRIDE-MISSING-AUDIT-LOG",
            "severity": "MEDIUM",
            "file": file_path,
            "line": 1,
            "description": "STRIDE Repudiation Violation: Endpoint modifies state without writing an immutable audit log entry (who, what, when)."
        })

    # 3. Information Disclosure: only flags when a sensitive-looking VARIABLE is actually
    # interpolated into the log call -- not when the word merely appears as descriptive text
    # (e.g. "Attempting Password authentication..." logs no real secret value at all).
    for idx, line in enumerate(lines, 1):
        if _SENSITIVE_INTERPOLATION_RE.search(line):
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


def run_compliance_standards_audit(target_dir: str = "/app", asset_id: int = None) -> List[Dict[str, Any]]:
    """Runs full Master Audit Standards compliance check across target codebase."""
    all_findings = []

    for root, _, files in os.walk(target_dir):
        # "tests" excluded too -- see the identical exclusion (and its reasoning) in
        # auditor_master_vulnerabilities.py's run_master_vulnerability_scan().
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv", "/tests", "\\tests", "data/remediation", "data/sonar_scans"]):
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
        active_fingerprints = set()
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                rel_path = os.path.relpath(item["file"], target_dir) if item.get("file") else "unknown"
                location = f"{rel_path}:{item.get('line', 0)}"
                description = f"**Archivo:** `{rel_path}` (Línea {item.get('line', 0)})\n{item['description']}"

                active_fingerprints.add(deduplication_engine.calculate_fingerprint(asset_id, item["cve_id"], location))
                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"], description,
                    "standards-audit", url_path=location, open_status="OPEN", preserve_status=True
                )

            if asset_id is not None:
                resolved_count = deduplication_engine.reconcile_resolved_findings(cur, asset_id, "standards-audit", active_fingerprints)
                if resolved_count:
                    print(f"✅ [Standards-Auditor] Reconciled {resolved_count} stale standards-audit finding(s) as RESOLVED for asset {asset_id}.")
    except Exception as db_err:
        print(f"⚠️ [Standards-Auditor] Could not log findings to DB: {db_err}")

    return all_findings
