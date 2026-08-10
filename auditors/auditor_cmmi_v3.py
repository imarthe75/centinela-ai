"""
Centinela Native CMMI V3.0 (Level 5 - Optimizing) Quality & Process Auditor
Audits codebase, pipelines, and asset metadata against CMMI V3.0 Practice Areas.
Level 5 Areas: CAR (Causal Analysis & Resolution), MSR (Measurement & Performance), PQA (Process Quality Assurance).
"""
import os
import re
from typing import List, Dict, Any
from core import db_manager

def audit_cmmi_v3_level5(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits code, manifests, and documentation for CMMI V3.0 Level 5 compliance."""
    findings = []
    lines = content.splitlines()
    filename = os.path.basename(file_path)

    # 1. CMMI PQA / CAR: Swallowed exceptions check
    if re.search(r'except.*:\s*pass', content, re.DOTALL):
        findings.append({
            "cve_id": "CMMI-CAR-SWALLOWED-EXCEPTION",
            "severity": "HIGH",
            "file": file_path,
            "line": 1,
            "description": "CMMI V3.0 Level 5 CAR Violation: Swallowed exception block (except: pass). Defect prevention requires root-cause logging and handling."
        })

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

def run_cmmi_audit(target_dir: str = "/opt/centinela-ai") -> List[Dict[str, Any]]:
    """Scans target directory for CMMI V3.0 Level 5 process and quality violations."""
    all_findings = []
    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv"]):
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

    # Log to DB
    try:
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                cur.execute("""
                    INSERT INTO public.vulnerability_log 
                    (cve_id, severity, description, status, detected_at, scan_engine)
                    VALUES (%s, %s, %s, 'OPEN', NOW(), 'cmmi-audit')
                    ON CONFLICT DO NOTHING
                """, (item["cve_id"], item["severity"], item["description"]))
    except Exception as e:
        print(f"⚠️ [CMMI-Auditor] Error logging to DB: {e}")

    return all_findings

def run(asset_id: int = None, endpoint: str = "") -> List[Dict[str, Any]]:
    """Wrapper for auditor_ext compatibility."""
    print(f"📐 [CMMI-Auditor] Running CMMI V3.0 Level 5 Process & Quality Audit on: {endpoint or 'Target Workspace'}")
    return run_cmmi_audit()
