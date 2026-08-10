"""
Centinela Native OWASP LLM & AI Governance Auditor
Audits AI prompts, context windows, and RAG pipelines against OWASP Top 10 for LLMs.
"""
import os
import re
from typing import List, Dict, Any
from core import db_manager


def audit_llm_prompts_and_context(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Audits code for OWASP LLM security risks."""
    findings = []
    lines = content.splitlines()

    # 1. LLM01: Prompt Injection Risks (Unsanitised User Input interpolated directly in Prompt)
    prompt_inj_patterns = [
        (r'prompt\s*=\s*f["\'].*?\{.*?user.*?\}"', "OWASP-LLM01-PROMPT-INJECTION", "HIGH", "Potential Prompt Injection: User input directly interpolated into LLM prompt string without sanitization or Guardrails."),
        (r'contents\s*=\s*f["\'].*?\{', "OWASP-LLM01-PROMPT-INJECTION", "MEDIUM", "Dynamic prompt content string construction without boundary validation.")
    ]

    # 2. LLM02: Sensitive Information Disclosure (PII / Keys in Prompts)
    info_leak_patterns = [
        (r'(password|jwt|api_key|secret_key|credit_card)\s*[:=]\s*.*?(prompt|contents|messages)', "OWASP-LLM02-PII-PROMPT-LEAK", "HIGH", "Potential Data Leak: Sensitive credential or PII included in LLM prompt payload.")
    ]

    # 3. LLM06: Excessive Agency / Unchecked Code Execution
    excessive_agency_patterns = [
        (r'exec\s*\(\s*response', "OWASP-LLM06-EXCESSIVE-AGENCY", "CRITICAL", "OWASP LLM06 Excessive Agency: Dynamic execution of AI-generated string via eval()/exec() without human-in-the-loop or sandbox validation.")
    ]

    for idx, line in enumerate(lines, 1):
        for pattern, rule_id, severity, desc in prompt_inj_patterns + info_leak_patterns + excessive_agency_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "cve_id": rule_id,
                    "severity": severity,
                    "file": file_path,
                    "line": idx,
                    "description": f"{desc} Line {idx}: {line.strip()}"
                })

    return findings


def run_llm_governance_audit(target_dir: str = "/opt/centinela-ai") -> List[Dict[str, Any]]:
    """Scans target directory for LLM & AI safety risks."""
    all_findings = []

    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv"]):
            continue
        for file in files:
            if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx")):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    all_findings.extend(audit_llm_prompts_and_context(full_path, content))
                except Exception as e:
                    print(f"⚠️ [LLM-Auditor] Error reading {full_path}: {e}")

    # Persist findings in DB
    try:
        with db_manager.get_db_cursor() as cur:
            for item in all_findings:
                cur.execute("""
                    INSERT INTO public.vulnerability_log 
                    (cve_id, severity, description, status, detected_at)
                    VALUES (%s, %s, %s, 'OPEN', NOW())
                    ON CONFLICT DO NOTHING
                """, (item["cve_id"], item["severity"], item["description"]))
    except Exception as db_err:
        print(f"⚠️ [LLM-Auditor] Could not log findings to DB: {db_err}")

    return all_findings


def run(asset_id: int = None, endpoint: str = "") -> List[Dict[str, Any]]:
    """Wrapper function for auditor_ext compatibility."""
    print(f"🤖 [Auditor-LLM-Governance] Auditing AI/LLM endpoint or codebase: {endpoint}")
    return run_llm_governance_audit()
