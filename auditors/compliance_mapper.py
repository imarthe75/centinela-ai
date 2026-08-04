"""
Centinela Regulatory Compliance Control Mapper & Matrix Generator
Maps all vulnerability findings to ISO 27001:2022, NIST SP 800-53, PCI-DSS v4.0, SOC 2, and GDPR controls.
"""
from typing import Dict, Any, List
from core import db_manager


COMPLIANCE_MAPPING_MATRIX = {
    # SQL & Command Injections
    "SQL-INJECTION": {
        "ISO_27001": "A.8.28 (Secure Coding)",
        "NIST_800_53": "SI-10 (Information Input Validation)",
        "PCI_DSS": "Req 6.5.1 (Injection Flaws)",
        "SOC_2": "CC6.1 (Logical Access Security)",
        "GDPR": "Art 32 (Security of Processing)"
    },
    "CMD-INJECTION": {
        "ISO_27001": "A.8.28 (Secure Coding)",
        "NIST_800_53": "SI-10 (Information Input Validation)",
        "PCI_DSS": "Req 6.5.1 (Injection Flaws)",
        "SOC_2": "CC6.1 (Logical Access Security)",
        "GDPR": "Art 32 (Security of Processing)"
    },

    # Docker & Root Privilege Escalation
    "DOCKER-ROOT-USER": {
        "ISO_27001": "A.8.9 (Configuration Management)",
        "NIST_800_53": "CM-6 (Configuration Settings)",
        "PCI_DSS": "Req 2.2 (System Hardening Standards)",
        "SOC_2": "CC6.8 (Software & System Hardening)",
        "GDPR": "Art 32 (Security of Processing)"
    },

    # STRIDE & JWT Secrets
    "HARDCODED-SECRET": {
        "ISO_27001": "A.8.24 (Use of Cryptography)",
        "NIST_800_53": "SC-28 (Protection of Information at Rest)",
        "PCI_DSS": "Req 8.3 (Strong Authentication Credentials)",
        "SOC_2": "CC6.1 (Credentials Management)",
        "GDPR": "Art 32 (Cryptographic Protection)"
    },

    # STRIDE Non-Repudiation Audit Logs
    "STD-STRIDE-MISSING-AUDIT-LOG": {
        "ISO_27001": "A.8.15 (Logging Activities)",
        "NIST_800_53": "AU-3 (Audit Record Content)",
        "PCI_DSS": "Req 10.2 (Automated Audit Trails)",
        "SOC_2": "CC7.2 (System Monitoring)",
        "GDPR": "Art 30 (Records of Processing)"
    }
}


def map_vulnerabilities_to_compliance() -> Dict[str, Any]:
    """Generates regulatory compliance mapping matrix for all active findings."""
    mapped_matrix = {
        "ISO_27001": {},
        "NIST_800_53": {},
        "PCI_DSS": {},
        "SOC_2": {},
        "GDPR": {}
    }

    try:
        with db_manager.get_db_cursor(cursor_factory=db_manager.RealDictCursor) as cur:
            cur.execute("SELECT id, cve_id, severity, description FROM public.vulnerability_log WHERE status != 'RESOLVED'")
            vulns = cur.fetchall()

        for v in vulns:
            cve = v.get("cve_id", "")
            matched_key = None
            for key in COMPLIANCE_MAPPING_MATRIX:
                if key in cve:
                    matched_key = key
                    break

            if matched_key:
                controls = COMPLIANCE_MAPPING_MATRIX[matched_key]
                for framework, control in controls.items():
                    if control not in mapped_matrix[framework]:
                        mapped_matrix[framework][control] = []
                    mapped_matrix[framework][control].append({
                        "vuln_id": v["id"],
                        "cve_id": cve,
                        "severity": v["severity"]
                    })
    except Exception as e:
        print(f"⚠️ [Compliance-Mapper] Error mapping vulnerabilities: {e}")

    return mapped_matrix
