"""
Centinela Native CMMI V3.0 (Level 5 - Optimizing) Quality & Process Auditor
Audits codebase, pipelines, and asset metadata against CMMI V3.0 Practice Areas.
Level 5 Areas: CAR (Causal Analysis & Resolution), MSR (Measurement & Performance), PQA (Process Quality Assurance).
"""
import os
import re
from typing import List, Dict, Any
from core import db_manager
from core.deduplication_engine import log_finding_deduplicated

def audit_cmmi_v3_level5(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits code, manifests, and documentation for CMMI V3.0 Level 5 compliance."""
    findings = []
    lines = content.splitlines()
    filename = os.path.basename(file_path)

    # 1. CMMI PQA / CAR: Swallowed exceptions check.
    # Real bug fixed here: `re.search(r'except.*:\s*pass', content, re.DOTALL)` matched across
    # the ENTIRE file rather than within a single except block -- with DOTALL, the greedy `.*`
    # backtracks until it finds the LAST ": pass" anywhere later in the file, so any file
    # containing the word "except" followed, anywhere further down (even hundreds of lines and
    # several unrelated functions later), by any unrelated ": pass" (e.g. `if x: pass`) got
    # flagged as a HIGH-severity swallowed-exception violation with zero real exception handling
    # involved. Confirmed live: core/db_manager.py and 12 other files were flagged this way.
    # Fixed to match only an except line immediately followed by `pass` as the block's own body
    # (only whitespace/comments between them), attributed to the real offending line instead of
    # a hardcoded line 1.
    for idx, line in enumerate(lines):
        if not re.match(r'^\s*except\b.*:\s*(#.*)?$', line):
            continue
        for next_line in lines[idx + 1: idx + 4]:
            stripped = next_line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if stripped == 'pass':
                findings.append({
                    "cve_id": "CMMI-CAR-SWALLOWED-EXCEPTION",
                    "severity": "HIGH",
                    "file": file_path,
                    "line": idx + 1,
                    "description": f"CMMI V3.0 Level 5 CAR Violation: Swallowed exception block (except: pass). Defect prevention requires root-cause logging and handling. Line {idx + 1}: {line.strip()}"
                })
            break

    # 2. CMMI MSR (Measurement & Performance): Hardcoded timeout or debt tags
    msr_patterns = [
        (r'time\.sleep\s*\(\s*\d+\s*\)', "CMMI-MSR-HARDCODED-SLEEP", "MEDIUM", "CMMI V3.0 Level 5 MSR Violation: Hardcoded blocking sleep delay reduces process predictability."),
        (r'#\s*TODO', "CMMI-PQA-DEBT-TODO", "LOW", "CMMI V3.0 Level 5 PQA Violation: Unresolved TODO technical debt tag found in production code.")
    ]

    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in msr_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    return findings

def run_cmmi_audit(target_dir: str = "/app", asset_id: int = None) -> List[Dict[str, Any]]:
    """Scans target directory for CMMI V3.0 Level 5 process and quality violations."""
    all_findings = []
    for root, _, files in os.walk(target_dir):
        # "tests" excluded too -- see the identical exclusion (and its reasoning) in
        # auditor_master_vulnerabilities.py's run_master_vulnerability_scan().
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv", "/tests", "\\tests", "data/remediation", "data/sonar_scans"]):
            continue
        for file in files:
            if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php")):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    all_findings.extend(audit_cmmi_v3_level5(full_path, content))
                except Exception:
                    continue

    # Log to DB -- previously a raw INSERT with no asset_id/url_path and an "ON CONFLICT DO
    # NOTHING" with no matching unique constraint (same silent no-op class as gotcha #3 in
    # CLAUDE.md), so every finding was permanently unattributed to any asset AND re-inserted as
    # a fresh duplicate on every re-scan. log_finding_deduplicated() fixes both: real dedup via
    # fingerprint_hash, and asset_id/url_path so the CMMI per-asset compliance report
    # (compliance_mapper.get_cmmi_v3_asset_audit_report(), which joins on asset_id OR
    # url_path ILIKE asset_name) can actually see this engine's own findings instead of being
    # silently blind to them.
    try:
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                rel_path = os.path.relpath(item["file"], target_dir)
                log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"],
                    f"{rel_path}:{item['line']} - {item['description']}",
                    "cmmi-audit", url_path=f"{rel_path}:{item['line']}", preserve_status=True
                )
    except Exception as e:
        print(f"⚠️ [CMMI-Auditor] Error logging to DB: {e}")

    return all_findings

def run(asset_id: int = None, endpoint: str = "") -> List[Dict[str, Any]]:
    """Wrapper for auditor_ext compatibility."""
    print(f"📐 [CMMI-Auditor] Running CMMI V3.0 Level 5 Process & Quality Audit on: {endpoint or 'Target Workspace'}")
    return run_cmmi_audit(asset_id=asset_id)
