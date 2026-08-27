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


def run_llm_governance_audit(target_dir: str = "/app", asset_id: int = None) -> List[Dict[str, Any]]:
    """Scans target directory for LLM & AI safety risks.

    Persistence fixed 2026-08-27: previously did a raw
    `INSERT ... (cve_id, severity, description, status, detected_at) ON CONFLICT DO NOTHING`
    with NO asset_id / url_path / scan_engine / fingerprint. Per CLAUDE.md gotcha #3 the
    `ON CONFLICT DO NOTHING` matched no constraint, so every run re-inserted every finding --
    confirmed live: 22 identical OWASP-LLM02-PII-PROMPT-LEAK rows, all NULL asset_id, all OPEN.
    Now routes through the shared log_finding_deduplicated() like every other native engine,
    with a real file:line url_path, and reconciles findings that stopped being detected.
    """
    all_findings = []

    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "__pycache__", ".venv", "data/remediation", "data/sonar_scans", "everything-claude-code", ".mvn"]):
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

    try:
        from core import deduplication_engine
        active_fingerprints = set()
        with db_manager.get_db_cursor() as cur:
            # Guard against dangling rows: only persist against an asset that actually exists.
            # auditor_ext.py dispatches AI-LLM-Endpoint assets here with ids that may be
            # synthetic/transient (99xxx range) and no matching infra_inventory row -- and this
            # auditor only ever scans local source (target_dir), never a remote endpoint, so
            # there is nothing meaningful to attribute to such an asset anyway.
            if asset_id is not None:
                cur.execute("SELECT 1 FROM public.infra_inventory WHERE id = %s", (asset_id,))
                if cur.fetchone() is None:
                    print(f"⚠️ [LLM-Auditor] asset_id {asset_id} not in infra_inventory -- "
                          f"returning {len(all_findings)} finding(s) without persisting.")
                    return all_findings
            for item in all_findings:
                rel_path = os.path.relpath(item["file"], target_dir) if item.get("file") else "unknown"
                location = f"{rel_path}:{item.get('line', 0)}"
                description = f"**Archivo:** `{rel_path}` (Línea {item.get('line', 0)})\n{item['description']}"
                active_fingerprints.add(
                    deduplication_engine.calculate_fingerprint(asset_id, item["cve_id"], location))
                deduplication_engine.log_finding_deduplicated(
                    cur, asset_id, item["cve_id"], item["severity"], description,
                    "llm-governance", url_path=location, open_status="OPEN", preserve_status=True
                )
            if asset_id is not None:
                resolved = deduplication_engine.reconcile_resolved_findings(
                    cur, asset_id, "llm-governance", active_fingerprints)
                if resolved:
                    print(f"✅ [LLM-Auditor] Reconciled {resolved} stale llm-governance finding(s) for asset {asset_id}.")
    except Exception as db_err:
        print(f"⚠️ [LLM-Auditor] Could not log findings to DB: {db_err}")

    return all_findings


def run(asset_id: int = None, endpoint: str = "") -> List[Dict[str, Any]]:
    """Wrapper function for auditor_ext compatibility."""
    print(f"🤖 [Auditor-LLM-Governance] Auditing AI/LLM endpoint or codebase: {endpoint}")
    return run_llm_governance_audit(asset_id=asset_id)
