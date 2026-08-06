"""
MITRE ATT&CK® technique mapping for Centinela's own finding taxonomy.

Maps cve_id prefixes (Centinela's own rule IDs, real CVE-based findings, and ZAP's "Type:" text)
to real, verifiable ATT&CK technique IDs -- https://attack.mitre.org/techniques/. Only findings
with a real, defensible mapping get one; code-quality findings (STD-ISO25010-LONG-METHOD,
COGNITIVE-COMPLEXITY-EXCEEDED) and non-findings (SCAN-AUDIT, HEURISTIC-SECURITY-DEBT) are
deliberately left unmapped -- ATT&CK models adversary behavior, not code maintainability, and
forcing a technique onto something that isn't an attack technique would be exactly the kind of
plausible-looking-but-fake output this codebase has already had to fix elsewhere.
"""
from typing import Optional, Tuple

# (cve_id prefix or exact match, description substring to also match on) -> (technique_id, technique_name, tactic)
_RULES = [
    ("CMD-INJECTION-", None, "T1059", "Command and Scripting Interpreter", "Execution"),
    ("CODE-INJECTION-EVAL", None, "T1059", "Command and Scripting Interpreter", "Execution"),
    ("SQL-INJECTION-", None, "T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("SSRF-", None, "T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("SCA-CVE-", None, "T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("HARDCODED-SECRET", None, "T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
    ("DOCKER-MISSING-NON-ROOT-USER", None, "T1611", "Escape to Host", "Privilege Escalation"),
    ("DOCKER-ROOT-USER", None, "T1611", "Escape to Host", "Privilege Escalation"),
    ("BLOODHOUND-PATH-AD", None, "T1078.002", "Valid Accounts: Domain Accounts", "Privilege Escalation"),
    ("STD-STRIDE-JWT-INSECURE-ALG", None, "T1556", "Modify Authentication Process", "Credential Access"),
    ("STD-STRIDE-LOG-SENSITIVE-DATA", None, "T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
    # ZAP findings are matched by the same "Type:" text already used for the header-fix mapping.
    ("ZAP-", "x-powered-by", "T1592.002", "Gather Victim Host Information: Software", "Reconnaissance"),
    ("ZAP-", '"server" http response header', "T1592.002", "Gather Victim Host Information: Software", "Reconnaissance"),
    ("ZAP-", "strict-transport-security", "T1557", "Adversary-in-the-Middle", "Collection"),
    ("ZAP-", "x-frame-options", "T1189", "Drive-by Compromise", "Initial Access"),
    ("ZAP-", "anti-clickjacking", "T1189", "Drive-by Compromise", "Initial Access"),
    ("ZAP-", "sql injection", "T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("ZAP-", "cross site scripting", "T1189", "Drive-by Compromise", "Initial Access"),
]


def map_finding(cve_id: str, description: str = "") -> Optional[Tuple[str, str, str]]:
    """Returns (technique_id, technique_name, tactic) or None if this finding type has no
    defensible ATT&CK mapping (code-quality findings, informational scan messages, etc.)."""
    cve_u = str(cve_id or "").upper()
    desc_l = str(description or "").lower()

    for prefix, needle, tech_id, tech_name, tactic in _RULES:
        if not cve_u.startswith(prefix):
            continue
        if needle and needle not in desc_l:
            continue
        return (tech_id, tech_name, tactic)
    return None
