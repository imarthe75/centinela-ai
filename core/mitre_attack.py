"""
MITRE ATT&CK® technique mapping for Centinela's own finding taxonomy.

Maps cve_id prefixes (Centinela's own rule IDs, real CVE-based findings, ZAP's "Type:" text, and
now real SonarQube VULNERABILITY-type rule numbers -- see _SONAR_RULE_TECHNIQUE below) to real,
verifiable ATT&CK technique IDs -- https://attack.mitre.org/techniques/. Only findings with a
real, defensible mapping get one; code-quality findings (STD-ISO25010-LONG-METHOD,
COGNITIVE-COMPLEXITY-EXCEEDED, SonarQube CODE_SMELL/BUG issues) and non-findings (SCAN-AUDIT,
HEURISTIC-SECURITY-DEBT, SONARQUBE-QUALITY-GATE) are deliberately left unmapped -- ATT&CK models
adversary behavior, not code maintainability, and forcing a technique onto something that isn't
an attack technique would be exactly the kind of plausible-looking-but-fake output this codebase
has already had to fix elsewhere.
"""
import re
from typing import Optional, Tuple

# SonarQube issues (auditors/auditor_sonarqube.py) get cve_id "SONAR-{lang}-{ruleNumber}",
# e.g. "SONAR-python-S5332". SonarQube itself reuses the same bare rule NUMBER (e.g. "S5332")
# across its language plugins for the same underlying vulnerability class -- that's how
# SonarQube organizes its own rule taxonomy, not an assumption made here -- so matching on
# just the rule number, independent of language, is a real, grounded design choice rather than
# guesswork. Every entry below was confirmed present in real (non-hypothetical) VULNERABILITY-
# type issues from the first real GitLab repos scanned in this deployment (verified live via
# SonarQube's own /api/issues/search?types=VULNERABILITY) before being added -- 171 of the 225
# real VULNERABILITY issues present at the time matched one of these. Several other real rule
# numbers seen in that same data are deliberately excluded (S5443 world-writable dirs, S2245
# weak PRNG, S5122 permissive CORS, S2115 missing DB auth, S4790 weak hash algorithm, S5693
# oversized content-length limits, S2612 file permissions) -- each is a real weakness, but none
# maps cleanly onto a single ATT&CK technique without forcing it, so they stay unmapped, same
# restraint already applied below to STD-ISO25010-LONG-METHOD/HEURISTIC-SECURITY-DEBT.
_SONAR_RULE_TECHNIQUE = {
    # Cleartext transport / cert & hostname validation disabled / weak-or-obsolete TLS
    # protocol version -- all directly enable a real machine-in-the-middle attack. Same
    # technique already used below for ZAP's strict-transport-security finding, for the same
    # underlying risk.
    "S5332": ("T1557", "Adversary-in-the-Middle", "Collection"),   # insecure HTTP protocol
    "S4830": ("T1557", "Adversary-in-the-Middle", "Collection"),   # server cert validation disabled
    "S5527": ("T1557", "Adversary-in-the-Middle", "Collection"),   # server hostname verification disabled
    "S4423": ("T1557", "Adversary-in-the-Middle", "Collection"),   # weak/obsolete TLS protocol version

    # Hard-coded or exposed secrets/passwords/tokens -- same technique already used below for
    # HARDCODED-SECRET / STD-STRIDE-LOG-SENSITIVE-DATA.
    "S6437": ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),  # compromised secret
    "S6418": ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),  # hard-coded token
    "S2068": ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),  # hard-coded password
    "S6698": ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),  # Sonar secrets engine: password
    "S6470": ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),  # Dockerfile recursive COPY leaking secrets into the image

    # Container image running as root -- same mapping already used below for
    # DOCKER-MISSING-NON-ROOT-USER / DOCKER-ROOT-USER.
    "S6471": ("T1611", "Escape to Host", "Privilege Escalation"),

    # Output-encoding/auto-escaping disabled -- directly enables XSS, same mapping already used
    # below for ZAP's "cross site scripting" finding.
    "S5247": ("T1189", "Drive-by Compromise", "Initial Access"),   # template auto-escaping disabled
    "S6268": ("T1189", "Drive-by Compromise", "Initial Access"),   # Angular built-in sanitization disabled

    # Framework/version banner disclosure -- same mapping already used below for ZAP's
    # X-Powered-By/Server response header finding.
    "S5689": ("T1592.002", "Gather Victim Host Information: Software", "Reconnaissance"),

    # Binding a service to all network interfaces widens its externally-reachable attack
    # surface -- same tactic already used below for SCA-CVE-/SQL-INJECTION-/SSRF-.
    "S8392": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
}

_SONAR_RULE_NUMBER_RE = re.compile(r"-([A-Z]\d+)$")


def _map_sonarqube_finding(cve_u: str, desc_l: str) -> Optional[Tuple[str, str, str]]:
    # Only real VULNERABILITY-type SonarQube issues are attacker-technique-shaped --
    # CODE_SMELL/BUG are code-quality/correctness findings, not adversary behavior, same
    # restraint already applied to STD-ISO25010-LONG-METHOD/HEURISTIC-SECURITY-DEBT below.
    # "**SonarQube VULNERABILITY**" is the literal marker auditor_sonarqube.py's
    # _persist_issues() writes into every issue's description.
    if "sonarqube vulnerability" not in desc_l:
        return None
    match = _SONAR_RULE_NUMBER_RE.search(cve_u)
    if match and match.group(1) in _SONAR_RULE_TECHNIQUE:
        return _SONAR_RULE_TECHNIQUE[match.group(1)]
    return None


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

    if cve_u.startswith("SONAR-"):
        return _map_sonarqube_finding(cve_u, desc_l)

    for prefix, needle, tech_id, tech_name, tactic in _RULES:
        if not cve_u.startswith(prefix):
            continue
        if needle and needle not in desc_l:
            continue
        return (tech_id, tech_name, tactic)
    return None
