"""
Quality Gates & Code Debt Evaluator (ISO 25010 & Kiuwan Standard)
Evaluates code maintainability, vulnerability thresholds, and quality gate pass/fail status.
"""
from typing import Dict, Any, List

class QualityGateRules:
    MAX_CRITICAL_VULNS = 0
    MAX_HIGH_VULNS = 2
    MAX_ISO25010_VIOLATIONS = 15
    MAX_COGNITIVE_COMPLEXITY = 25

def evaluate_asset_quality_gate(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates whether an asset passes Quality Gates for deployment.
    """
    critical_count = 0
    high_count = 0
    iso25010_count = 0
    complexity_count = 0

    for v in vulnerabilities:
        sev = str(v.get('severity', '')).upper()
        cve = str(v.get('cve_id', '')).upper()

        if sev in ('CRITICAL', 'CRÍTICO'):
            critical_count += 1
        elif sev in ('HIGH', 'ALTO'):
            high_count += 1

        if 'ISO25010' in cve or 'LONG-METHOD' in cve:
            iso25010_count += 1
        if 'COMPLEXITY' in cve:
            complexity_count += 1

    failed_reasons = []
    if critical_count > QualityGateRules.MAX_CRITICAL_VULNS:
        failed_reasons.append(f"Superó el límite de vulnerabilidades críticas ({critical_count} > {QualityGateRules.MAX_CRITICAL_VULNS})")
    if high_count > QualityGateRules.MAX_HIGH_VULNS:
        failed_reasons.append(f"Superó el límite de vulnerabilidades de severidad alta ({high_count} > {QualityGateRules.MAX_HIGH_VULNS})")
    if iso25010_count > QualityGateRules.MAX_ISO25010_VIOLATIONS:
        failed_reasons.append(f"Exceso de infracciones de mantenibilidad ISO 25010 ({iso25010_count} > {QualityGateRules.MAX_ISO25010_VIOLATIONS})")

    status = "PASSED" if len(failed_reasons) == 0 else "FAILED"
    grade = "A" if status == "PASSED" and high_count == 0 else ("B" if status == "PASSED" else "F")

    return {
        "status": status,
        "grade": grade,
        "metrics": {
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "iso25010_violations": iso25010_count,
            "complexity_violations": complexity_count
        },
        "failed_reasons": failed_reasons
    }
