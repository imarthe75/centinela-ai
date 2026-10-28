# -*- coding: utf-8 -*-
"""
Registro declarativo de COBERTURA de Centinela contra los marcos que la plataforma dice cubrir.

Objetivo: responder "¿cubrimos todo?" con números y sin inflar. Para cada marco se define su UNIVERSO oficial
(todos los elementos, también los que ningún escáner puede medir) y se calcula cuántos tienen:
  * `native`   -> al menos una regla propia de Centinela que lo detecta (mapeo en RULE_MAP);
  * `external` -> solo un motor externo declarado (ZAP, Semgrep, SonarQube, Trivy...) que lo cubre CUANDO corre;
  * `none`     -> ningún detector.
Además cada universo marca qué elementos son, por naturaleza, no automatizables (`how`/`scanner_domain`), para no
presentar como "brecha de Centinela" algo que ningún escáner puede medir (p. ej. seguridad física de ISO).

Los mapeos regla -> elemento son un CRITERIO DE INGENIERÍA de Centinela, no una taxonomía normativa (p. ej. no es la
tabla oficial CWE -> OWASP). Universos verificados: WSTG v4.2 (97 pruebas, leído de wstg.owasp.org/v4.2 el 2026-10-01),
WCAG 2.1 A+AA (50 criterios), ISO/IEC 27001:2022 Anexo A (93 controles; nombres transcritos, verificar contra la norma
licenciada), OWASP Top 10:2021, API Security Top 10:2023, LLM Top 10:2025, ASVS 4.0 (14 capítulos), CMMI V3.0 (19 áreas).

Una prueba (tests/test_coverage_matrix.py) falla si el código emite un identificador de regla que este registro no
clasifica: así una regla nueva no puede quedar fuera de la cuenta de cobertura.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Tuple

# ----------------------------------------------------------------------------- universos
OWASP_TOP10_2021 = {
    "A01": "Broken Access Control", "A02": "Cryptographic Failures", "A03": "Injection", "A04": "Insecure Design",
    "A05": "Security Misconfiguration", "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures", "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures", "A10": "Server-Side Request Forgery",
}
OWASP_API_TOP10_2023 = {
    "API1": "Broken Object Level Authorization", "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization", "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization", "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery", "API8": "Security Misconfiguration", "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}
OWASP_LLM_TOP10_2025 = {
    "LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure", "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning", "LLM05": "Improper Output Handling", "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage", "LLM08": "Vector and Embedding Weaknesses", "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
OWASP_ASVS_4_CHAPTERS = {
    "V1": "Architecture, Design and Threat Modeling", "V2": "Authentication", "V3": "Session Management",
    "V4": "Access Control", "V5": "Validation, Sanitization and Encoding", "V6": "Stored Cryptography",
    "V7": "Error Handling and Logging", "V8": "Data Protection", "V9": "Communication", "V10": "Malicious Code",
    "V11": "Business Logic", "V12": "Files and Resources", "V13": "API and Web Service", "V14": "Configuration",
}
# WSTG v4.2: 97 pruebas (leídas de https://wstg.owasp.org/v4.2/ el 2026-10-01)
WSTG_42 = {
    "INFO-01": "Search Engine Discovery Reconnaissance for Information Leakage", "INFO-02": "Fingerprint Web Server",
    "INFO-03": "Review Webserver Metafiles for Information Leakage", "INFO-04": "Enumerate Applications on Webserver",
    "INFO-05": "Review Webpage Content for Information Leakage", "INFO-06": "Identify Application Entry Points",
    "INFO-07": "Map Execution Paths Through Application", "INFO-08": "Fingerprint Web Application Framework",
    "INFO-09": "Fingerprint Web Application", "INFO-10": "Map Application Architecture",
    "CONF-01": "Test Network Infrastructure Configuration", "CONF-02": "Test Application Platform Configuration",
    "CONF-03": "Test File Extensions Handling for Sensitive Information",
    "CONF-04": "Review Old Backup and Unreferenced Files for Sensitive Information",
    "CONF-05": "Enumerate Infrastructure and Application Admin Interfaces", "CONF-06": "Test HTTP Methods",
    "CONF-07": "Test HTTP Strict Transport Security", "CONF-08": "Test RIA Cross Domain Policy",
    "CONF-09": "Test File Permission", "CONF-10": "Test for Subdomain Takeover", "CONF-11": "Test Cloud Storage",
    "IDNT-01": "Test Role Definitions", "IDNT-02": "Test User Registration Process",
    "IDNT-03": "Test Account Provisioning Process", "IDNT-04": "Testing for Account Enumeration and Guessable User Account",
    "IDNT-05": "Testing for Weak or Unenforced Username Policy",
    "ATHN-01": "Credentials Transported over an Encrypted Channel", "ATHN-02": "Default Credentials",
    "ATHN-03": "Weak Lock Out Mechanism", "ATHN-04": "Bypassing Authentication Schema",
    "ATHN-05": "Vulnerable Remember Password", "ATHN-06": "Browser Cache Weaknesses", "ATHN-07": "Weak Password Policy",
    "ATHN-08": "Weak Security Question Answer", "ATHN-09": "Weak Password Change or Reset Functionalities",
    "ATHN-10": "Weaker Authentication in Alternative Channel",
    "AUTHZ-01": "Directory Traversal File Include", "AUTHZ-02": "Bypassing Authorization Schema",
    "AUTHZ-03": "Privilege Escalation", "AUTHZ-04": "Insecure Direct Object References",
    "SESS-01": "Session Management Schema", "SESS-02": "Cookies Attributes", "SESS-03": "Session Fixation",
    "SESS-04": "Exposed Session Variables", "SESS-05": "Cross Site Request Forgery", "SESS-06": "Logout Functionality",
    "SESS-07": "Session Timeout", "SESS-08": "Session Puzzling", "SESS-09": "Session Hijacking",
    "INPV-01": "Reflected Cross Site Scripting", "INPV-02": "Stored Cross Site Scripting", "INPV-03": "HTTP Verb Tampering",
    "INPV-04": "HTTP Parameter Pollution", "INPV-05": "SQL Injection", "INPV-06": "LDAP Injection", "INPV-07": "XML Injection",
    "INPV-08": "SSI Injection", "INPV-09": "XPath Injection", "INPV-10": "IMAP SMTP Injection", "INPV-11": "Code Injection",
    "INPV-12": "Command Injection", "INPV-13": "Format String Injection", "INPV-14": "Incubated Vulnerability",
    "INPV-15": "HTTP Splitting Smuggling", "INPV-16": "HTTP Incoming Requests", "INPV-17": "Host Header Injection",
    "INPV-18": "Server-side Template Injection", "INPV-19": "Server-Side Request Forgery",
    "ERRH-01": "Improper Error Handling", "ERRH-02": "Stack Traces",
    "CRYP-01": "Weak Transport Layer Security", "CRYP-02": "Padding Oracle",
    "CRYP-03": "Sensitive Information Sent via Unencrypted Channels", "CRYP-04": "Weak Encryption",
    "BUSL-01": "Business Logic Data Validation", "BUSL-02": "Ability to Forge Requests", "BUSL-03": "Integrity Checks",
    "BUSL-04": "Process Timing", "BUSL-05": "Number of Times a Function Can Be Used Limits",
    "BUSL-06": "Circumvention of Work Flows", "BUSL-07": "Defenses Against Application Misuse",
    "BUSL-08": "Upload of Unexpected File Types", "BUSL-09": "Upload of Malicious Files",
    "CLNT-01": "DOM-Based Cross Site Scripting", "CLNT-02": "JavaScript Execution", "CLNT-03": "HTML Injection",
    "CLNT-04": "Client-side URL Redirect", "CLNT-05": "CSS Injection", "CLNT-06": "Client-side Resource Manipulation",
    "CLNT-07": "Cross Origin Resource Sharing", "CLNT-08": "Cross Site Flashing", "CLNT-09": "Clickjacking",
    "CLNT-10": "WebSockets", "CLNT-11": "Web Messaging", "CLNT-12": "Browser Storage", "CLNT-13": "Cross Site Script Inclusion",
    "APIT-01": "GraphQL",
}
# WCAG 2.1 A+AA (50). how: estatico = detectable leyendo HTML/CSS/manifiestos; navegador = exige página renderizada
# (contraste, reflujo, foco real); manual = exige juicio humano. Clasificación de ingeniería de Centinela, no normativa.
WCAG_21_AA = {
    "1.1.1": ("Non-text Content", "A", "estatico"), "1.2.1": ("Audio-only and Video-only (Prerecorded)", "A", "manual"),
    "1.2.2": ("Captions (Prerecorded)", "A", "estatico"), "1.2.3": ("Audio Description or Media Alternative", "A", "manual"),
    "1.2.4": ("Captions (Live)", "AA", "manual"), "1.2.5": ("Audio Description (Prerecorded)", "AA", "manual"),
    "1.3.1": ("Info and Relationships", "A", "estatico"), "1.3.2": ("Meaningful Sequence", "A", "manual"),
    "1.3.3": ("Sensory Characteristics", "A", "manual"), "1.3.4": ("Orientation", "AA", "navegador"),
    "1.3.5": ("Identify Input Purpose", "AA", "estatico"), "1.4.1": ("Use of Color", "A", "manual"),
    "1.4.2": ("Audio Control", "A", "estatico"), "1.4.3": ("Contrast (Minimum)", "AA", "navegador"),
    "1.4.4": ("Resize text", "AA", "estatico"), "1.4.5": ("Images of Text", "AA", "manual"),
    "1.4.10": ("Reflow", "AA", "navegador"), "1.4.11": ("Non-text Contrast", "AA", "navegador"),
    "1.4.12": ("Text Spacing", "AA", "navegador"), "1.4.13": ("Content on Hover or Focus", "AA", "manual"),
    "2.1.1": ("Keyboard", "A", "estatico"), "2.1.2": ("No Keyboard Trap", "A", "manual"),
    "2.1.4": ("Character Key Shortcuts", "A", "manual"), "2.2.1": ("Timing Adjustable", "A", "manual"),
    "2.2.2": ("Pause, Stop, Hide", "A", "estatico"), "2.3.1": ("Three Flashes or Below Threshold", "A", "manual"),
    "2.4.1": ("Bypass Blocks", "A", "estatico"), "2.4.2": ("Page Titled", "A", "estatico"),
    "2.4.3": ("Focus Order", "A", "estatico"), "2.4.4": ("Link Purpose (In Context)", "A", "estatico"),
    "2.4.5": ("Multiple Ways", "AA", "manual"), "2.4.6": ("Headings and Labels", "AA", "estatico"),
    "2.4.7": ("Focus Visible", "AA", "estatico"), "2.5.1": ("Pointer Gestures", "A", "manual"),
    "2.5.2": ("Pointer Cancellation", "A", "manual"), "2.5.3": ("Label in Name", "A", "estatico"),
    "2.5.4": ("Motion Actuation", "A", "manual"), "3.1.1": ("Language of Page", "A", "estatico"),
    "3.1.2": ("Language of Parts", "AA", "navegador"), "3.2.1": ("On Focus", "A", "manual"),
    "3.2.2": ("On Input", "A", "manual"), "3.2.3": ("Consistent Navigation", "AA", "manual"),
    "3.2.4": ("Consistent Identification", "AA", "manual"), "3.3.1": ("Error Identification", "A", "manual"),
    "3.3.2": ("Labels or Instructions", "A", "estatico"), "3.3.3": ("Error Suggestion", "AA", "manual"),
    "3.3.4": ("Error Prevention (Legal, Financial, Data)", "AA", "manual"), "4.1.1": ("Parsing", "A", "estatico"),
    "4.1.2": ("Name, Role, Value", "A", "estatico"), "4.1.3": ("Status Messages", "AA", "navegador"),
}
# ISO/IEC 27001:2022 Anexo A (93). scope: org | personas | fisico | tecnologico.
# technical=True -> existe (o es concebible) una comprobación automática sobre código/configuración/red; es una marca de
# ALCANCE, no de cobertura: la cobertura real sale de RULE_MAP.
_ISO_ORG = {
    "5.1": "Policies for information security", "5.2": "Information security roles and responsibilities",
    "5.3": "Segregation of duties", "5.4": "Management responsibilities", "5.5": "Contact with authorities",
    "5.6": "Contact with special interest groups", "5.7": "Threat intelligence",
    "5.8": "Information security in project management", "5.9": "Inventory of information and other associated assets",
    "5.10": "Acceptable use of information and other associated assets", "5.11": "Return of assets",
    "5.12": "Classification of information", "5.13": "Labelling of information", "5.14": "Information transfer",
    "5.15": "Access control", "5.16": "Identity management", "5.17": "Authentication information", "5.18": "Access rights",
    "5.19": "Information security in supplier relationships",
    "5.20": "Addressing information security within supplier agreements",
    "5.21": "Managing information security in the ICT supply chain",
    "5.22": "Monitoring, review and change management of supplier services",
    "5.23": "Information security for use of cloud services",
    "5.24": "Information security incident management planning and preparation",
    "5.25": "Assessment and decision on information security events", "5.26": "Response to information security incidents",
    "5.27": "Learning from information security incidents", "5.28": "Collection of evidence",
    "5.29": "Information security during disruption", "5.30": "ICT readiness for business continuity",
    "5.31": "Legal, statutory, regulatory and contractual requirements", "5.32": "Intellectual property rights",
    "5.33": "Protection of records", "5.34": "Privacy and protection of PII",
    "5.35": "Independent review of information security",
    "5.36": "Compliance with policies, rules and standards for information security", "5.37": "Documented operating procedures",
}
_ISO_PEOPLE = {
    "6.1": "Screening", "6.2": "Terms and conditions of employment",
    "6.3": "Information security awareness, education and training", "6.4": "Disciplinary process",
    "6.5": "Responsibilities after termination or change of employment", "6.6": "Confidentiality or non-disclosure agreements",
    "6.7": "Remote working", "6.8": "Information security event reporting",
}
_ISO_PHYSICAL = {
    "7.1": "Physical security perimeters", "7.2": "Physical entry", "7.3": "Securing offices, rooms and facilities",
    "7.4": "Physical security monitoring", "7.5": "Protecting against physical and environmental threats",
    "7.6": "Working in secure areas", "7.7": "Clear desk and clear screen", "7.8": "Equipment siting and protection",
    "7.9": "Security of assets off-premises", "7.10": "Storage media", "7.11": "Supporting utilities", "7.12": "Cabling security",
    "7.13": "Equipment maintenance", "7.14": "Secure disposal or re-use of equipment",
}
_ISO_TECH = {
    "8.1": "User endpoint devices", "8.2": "Privileged access rights", "8.3": "Information access restriction",
    "8.4": "Access to source code", "8.5": "Secure authentication", "8.6": "Capacity management",
    "8.7": "Protection against malware", "8.8": "Management of technical vulnerabilities", "8.9": "Configuration management",
    "8.10": "Information deletion", "8.11": "Data masking", "8.12": "Data leakage prevention", "8.13": "Information backup",
    "8.14": "Redundancy of information processing facilities", "8.15": "Logging", "8.16": "Monitoring activities",
    "8.17": "Clock synchronization", "8.18": "Use of privileged utility programs",
    "8.19": "Installation of software on operational systems", "8.20": "Networks security",
    "8.21": "Security of network services", "8.22": "Segregation of networks", "8.23": "Web filtering",
    "8.24": "Use of cryptography", "8.25": "Secure development life cycle", "8.26": "Application security requirements",
    "8.27": "Secure system architecture and engineering principles", "8.28": "Secure coding",
    "8.29": "Security testing in development and acceptance", "8.30": "Outsourced development",
    "8.31": "Separation of development, test and production environments", "8.32": "Change management",
    "8.33": "Test information", "8.34": "Protection of information systems during audit testing",
}
# Controles donde una comprobación automática es concebible (alcance técnico del escáner)
_ISO_TECHNICAL_DOMAIN = {
    "5.7", "5.9", "5.15", "5.16", "5.17", "5.18", "5.23", "5.34",
    "8.1", "8.2", "8.3", "8.4", "8.5", "8.7", "8.8", "8.9", "8.11", "8.12", "8.15", "8.16", "8.17", "8.19", "8.20", "8.21",
    "8.24", "8.25", "8.26", "8.28", "8.29", "8.31", "8.32",
}
ISO_27001_2022 = {}
for _scope, _tbl in (("org", _ISO_ORG), ("personas", _ISO_PEOPLE), ("fisico", _ISO_PHYSICAL), ("tecnologico", _ISO_TECH)):
    for _id, _name in _tbl.items():
        ISO_27001_2022[_id] = {"name": _name, "scope": _scope, "technical": _id in _ISO_TECHNICAL_DOMAIN}

# CMMI V3.0 (19 áreas) -- el detalle de CÓMO medir cada una está en DECISIONS/0007.
CMMI_CA_19 = {
    "RDM": "Requirements Management", "PQA": "Process Quality Assurance", "PR": "Peer Reviews", "VV": "Verification and Validation",
    "TS": "Technical Solution", "PI": "Product Integration", "EST": "Estimating", "PLAN": "Planning",
    "MC": "Monitor and Control", "RSK": "Risk and Opportunity Management", "OT": "Organizational Training",
    "CM": "Configuration Management", "DAR": "Decision Analysis and Resolution", "CAR": "Causal Analysis and Resolution",
    "GOV": "Governance", "II": "Implementation Infrastructure", "MPM": "Managing Performance and Measurement",
    "PAD": "Process Asset Development", "PCM": "Process Management",
}

FRAMEWORKS = {
    "top10": ("OWASP Top 10:2021", OWASP_TOP10_2021),
    "api10": ("OWASP API Security Top 10:2023", OWASP_API_TOP10_2023),
    "llm10": ("OWASP LLM Top 10:2025", OWASP_LLM_TOP10_2025),
    "asvs": ("OWASP ASVS 4.0 (capítulos)", OWASP_ASVS_4_CHAPTERS),
    "wstg": ("OWASP WSTG v4.2", WSTG_42),
    "wcag": ("WCAG 2.1 A+AA", {k: v[0] for k, v in WCAG_21_AA.items()}),
    "iso": ("ISO/IEC 27001:2022 Anexo A", {k: v["name"] for k, v in ISO_27001_2022.items()}),
    "cmmi": ("CMMI V3.0 (19 áreas)", CMMI_CA_19),
}

# ----------------------------------------------------------------------------- identificadores sin hallazgo
# Marcadores de estado/telemetría de Centinela: no son hallazgos de seguridad y no cuentan para cobertura.
NON_FINDING = re.compile(
    r"^(SCAN-AUDIT|CIS-BENCHMARK-AUDIT|OS-PATCH-AUDIT|TLS-AUDIT|DNS-SECURITY-AUDIT|GITLAB-CONFIG-AUDIT|CMMI-GIT-HISTORY-CHECK|"
    r"SONARQUBE-QUALITY-GATE|AUTHZ-DAST-NO-CREDS|RUNTIME-SESSION-NOT-EXERCISED|HOST-CONTAINMENT-REQUEST|HEURISTIC-SECURITY-DEBT|CTI-IOC-MATCH.*|"
    r"CTI-PROPRIETARY-IOC-MATCH|BLOODHOUND-PATH.*|HEURISTIC-.*|NMAP-SCAN|TRIVY-REPO|CHECKOV-SCAN|PROWLER-CHECK|"
    r"LONG-METHOD|UNKNOWN-CVE|ZAP-ZAP-UNKNOWN)$"
)

# ----------------------------------------------------------------------------- mapeo regla -> elementos
# (regex sobre el id de la regla, {marco: [elementos]}). La PRIMERA coincidencia gana; ordenar de específico a general.
def _m(**kw):
    return {k: v for k, v in kw.items()}

RULE_MAP: List[Tuple[re.Pattern, Dict[str, List[str]]]] = [(re.compile(p), m) for p, m in [
    # --- autorización (OWASP A01 / CWE-862)
    (r"^AUTHZ-(NO-METHOD-AUTHZ|PREAUTHORIZE-COMMENTED-OUT|PUBLIC-SENSITIVE-READ|ONLY-AUTHENTICATED-WRITE|PERMITALL-WRITE|NO-RULE|NO-METHOD-ANNOTATIONS|INCONSISTENT-FAMILY|NAMESPACE-GAP)$",
     _m(top10=["A01"], api10=["API5"], wstg=["AUTHZ-02", "AUTHZ-03"], asvs=["V4"], iso=["5.15", "5.18", "8.3"])),
    (r"^AUTHZ-(CLIENT-SIDE-ONLY|CLIENT-SIDE-UI-GATE|ADMIN-BUNDLE-EXPOSED)$",
     _m(top10=["A01"], api10=["API5"], wstg=["AUTHZ-02"], asvs=["V4"], iso=["8.3"])),
    (r"^(AUTHZ-IDOR-PARAM-REVIEW|AUTHZ-DAST-IDOR|POTENTIAL-IDOR-NO-OWNERSHIP-CHECK)$",
     _m(top10=["A01"], api10=["API1"], wstg=["AUTHZ-04"], asvs=["V4"], iso=["5.15", "8.3"])),
    (r"^AUTHZ-DAST-(BROKEN-FUNCTION-LEVEL|INCONSISTENT-STATUS|DENY-LEAKS-BODY)$",
     _m(top10=["A01"], api10=["API5"], wstg=["AUTHZ-02", "AUTHZ-03"], asvs=["V4"], iso=["5.15", "8.3"])),
    (r"^(AUTHZ-CSRF-DISABLED|SPRINGBOOT-CSRF-DISABLED)$",
     _m(top10=["A01"], wstg=["SESS-05"], asvs=["V4"], iso=["8.26"])),
    (r"^(AUTHZ-TEST-ENDPOINT-EXPOSED|BACKDOOR-SANDBOX-CONTROLLER|FRONTEND-TEST-ROUTE-EXPOSED)$",
     _m(top10=["A05"], api10=["API8", "API9"], wstg=["CONF-05"], asvs=["V14"], iso=["8.31", "8.9"])),
    # --- identidad, contraseñas, sesión
    (r"^AUTH-ENDPOINT-NO-RATE-LIMIT$", _m(top10=["A07"], api10=["API2", "API4"], wstg=["ATHN-03"], asvs=["V2"], iso=["5.17", "8.5"])),
    (r"^PASSWORD-POLICY-NOT-ENFORCED$", _m(top10=["A07"], api10=["API2"], wstg=["ATHN-07"], asvs=["V2"], iso=["5.17", "8.5"])),
    (r"^STD-STRIDE-JWT-INSECURE-ALG$", _m(top10=["A02", "A07"], api10=["API2"], asvs=["V3", "V6"], iso=["8.24", "8.5"])),
    (r"^(INSECURE-COOKIE-FLAGS|WSTG-SESS-02-COOKIE-SAMESITE)$", _m(top10=["A05"], wstg=["SESS-02"], asvs=["V3"], iso=["8.26"])),
    (r"^(JWT-IN-URL-PARAM|FRONTEND-TOKEN-IN-URL)$", _m(top10=["A02"], api10=["API2"], wstg=["SESS-04"], asvs=["V3", "V8"], iso=["8.24"])),
    (r"^FRONTEND-JWT-LOCALSTORAGE$", _m(top10=["A02"], wstg=["CLNT-12"], asvs=["V3", "V8"], iso=["8.24"])),
    (r"^WSTG-ATHN-02-CLEARTEXT-LOGIN$", _m(top10=["A02", "A07"], wstg=["ATHN-01"], asvs=["V2", "V9"], iso=["8.24", "8.20"])),
    (r"^WSTG-AUTH-02-DEFAULT-CREDENTIALS$", _m(top10=["A07"], api10=["API2"], wstg=["ATHN-02"], asvs=["V2"], iso=["5.17", "8.5"])),
    # --- secretos
    (r"^(HARDCODED-SECRET|EXPANDED-CLOUD-SECRET|CICD-HARDCODED-SECRET|CONFIG-SECRET-LITERAL|SECRETS-.*|SECRET-.*|FRONTEND-EXPOSED-DB-CREDENTIAL)$",
     _m(top10=["A07", "A05"], api10=["API8"], asvs=["V2", "V14"], iso=["5.17", "8.9", "8.12"])),
    (r"^CONFIG-JWT-SECRET-LITERAL$", _m(top10=["A02", "A07"], api10=["API2"], asvs=["V2", "V6"], iso=["5.17", "8.24"])),
    # --- configuración peligrosa de Spring (A05 Security Misconfiguration). DevTools remoto = CVE-2026-40972 (CWE-208 timing -> RCE).
    (r"^SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE$", _m(top10=["A05"], asvs=["V14"], iso=["8.9", "8.32"])),
    (r"^FRONTEND-OIDC-INSECURE-CONFIG$", _m(top10=["A02", "A07"], asvs=["V9", "V2"], wstg=["CRYP-03"], iso=["8.24", "8.5"])),
    (r"^(SPRING-DEVTOOLS-REMOTE-ENABLED|SPRING-H2-CONSOLE-ENABLED|SPRING-ACTUATOR-SENSITIVE-EXPOSED)$",
     _m(top10=["A05", "A02"], api10=["API8"], asvs=["V14", "V6"], iso=["8.9", "8.31"])),
    # --- criptografía y transporte
    (r"^WEAK-CRYPTOGRAPHY$", _m(top10=["A02"], wstg=["CRYP-04"], asvs=["V6"], iso=["8.24"])),
    (r"^TIMING-UNSAFE-SECRET-COMPARISON$", _m(top10=["A02"], asvs=["V6"], iso=["8.24"])),  # sin prueba WSTG equivalente (CWE-208)
    (r"^(TLS-NOT-ENABLED|TLS-CERT-.*|TLS-LEGACY-PROTOCOL-ENABLED|TLS-WEAK-CIPHER-ENABLED|TLS-STATIC-RSA-KEX-ENABLED|OSINT-TLS-MISCONFIGURATION)$",
     _m(top10=["A02"], api10=["API8"], wstg=["CRYP-01"], asvs=["V9"], iso=["8.24", "8.20", "8.21"])),
    (r"^(DB-NO-TLS-ENCRYPTION|DB-UNENCRYPTED-CONN-STRING|JVM-GLOBAL-SSL-BYPASS)$", _m(top10=["A02"], wstg=["CRYP-01"], asvs=["V9"], iso=["8.24", "8.20"])),
    (r"^WSTG-CRYP-03-UNENCRYPTED-CHANNEL$", _m(top10=["A02"], wstg=["CRYP-03"], asvs=["V9"], iso=["8.24", "8.20"])),
    (r"^(CICD-TLS-VERIFICATION-DISABLED)$", _m(top10=["A02", "A08"], asvs=["V9"], iso=["8.24", "8.25"])),
    # --- inyección y entradas
    (r"^(SQL-INJECTION-.*|ORM-RAW-QUERY-INJECTION|SPRINGBOOT-NATIVE-QUERY-RISK)$", _m(top10=["A03"], wstg=["INPV-05"], asvs=["V5"], iso=["8.28"])),
    (r"^CMD-INJECTION-.*$", _m(top10=["A03"], wstg=["INPV-12"], asvs=["V5"], iso=["8.28"])),
    (r"^CODE-INJECTION-EVAL$", _m(top10=["A03"], wstg=["INPV-11", "CLNT-02"], asvs=["V5"], iso=["8.28"])),
    (r"^XXE-INSECURE-PARSER$", _m(top10=["A05"], wstg=["INPV-07"], asvs=["V5", "V13"], iso=["8.28"])),
    (r"^PATH-TRAVERSAL-RISK$", _m(top10=["A01"], wstg=["AUTHZ-01"], asvs=["V12"], iso=["8.28"])),
    (r"^SSRF-UNCHECKED-FETCH$", _m(top10=["A10"], api10=["API7"], wstg=["INPV-19"], asvs=["V12", "V13"], iso=["8.28"])),
    (r"^WSTG-INPV-17-HOST-HEADER-INJECTION$", _m(top10=["A03", "A05"], wstg=["INPV-17"], asvs=["V14"], iso=["8.26"])),
    (r"^(INSECURE-DESERIALIZATION|REDIS-JDK-SERIALIZATION)$", _m(top10=["A08"], asvs=["V5"], iso=["8.28"])),
    # --- cliente / navegador
    (r"^(ANGULAR-BYPASS-SECURITY-TRUST|REACT-DANGEROUSLY-SET-INNER-HTML)$", _m(top10=["A03"], wstg=["CLNT-01", "CLNT-03"], asvs=["V5"], iso=["8.28"])),
    (r"^(CORS-WILDCARD-ORIGIN|WSTG-CLNT-07-INSECURE-CORS)$", _m(top10=["A05"], api10=["API8"], wstg=["CLNT-07"], asvs=["V14"], iso=["8.26"])),
    (r"^WSTG-CLNT-04-OPEN-REDIRECT$", _m(top10=["A01"], wstg=["CLNT-04"], asvs=["V5"], iso=["8.26"])),
    (r"^WSTG-CLNT-09-DUPLICATE-OR-WEAK-FRAME-OPTIONS$", _m(top10=["A05"], wstg=["CLNT-09"], asvs=["V14"], iso=["8.26"])),
    # --- configuración, errores, información
    (r"^STACK-TRACE-EXPOSURE$", _m(top10=["A05"], wstg=["ERRH-02"], asvs=["V7"], iso=["8.26"])),
    (r"^WSTG-ERRH-01-API-SERVER-ERROR$", _m(top10=["A05"], api10=["API8"], wstg=["ERRH-01"], asvs=["V7"], iso=["8.26"])),
    (r"^WSTG-ERRH-01-VERBOSE-BACKEND-ERROR$", _m(top10=["A05"], wstg=["ERRH-01"], asvs=["V7"], iso=["8.26"])),
    (r"^WSTG-INFO-02-SERVER-BANNER-LEAK$", _m(top10=["A05"], api10=["API8"], wstg=["INFO-02"], asvs=["V14"], iso=["8.9"])),
    (r"^WSTG-INFO-03-METAFILE-LEAK$", _m(top10=["A05"], api10=["API8"], wstg=["INFO-03"], asvs=["V14"], iso=["8.9"])),
    (r"^WSTG-CONF-08-CROSSDOMAIN-WILDCARD$", _m(top10=["A05"], wstg=["CONF-08"], asvs=["V14"], iso=["8.26"])),
    (r"^WSTG-INFO-05-CONTENT-LEAK$", _m(top10=["A05"], wstg=["INFO-05"], asvs=["V14", "V8"], iso=["8.12"])),
    (r"^WSTG-ATHN-06-LOGIN-CACHEABLE$", _m(top10=["A07"], wstg=["ATHN-06"], asvs=["V8"], iso=["8.5"])),
    (r"^WSTG-INFO-08-FRAMEWORK-FINGERPRINT$", _m(top10=["A05"], wstg=["INFO-08"], asvs=["V14"], iso=["8.9"])),
    (r"^WSTG-CONF-04-SENSITIVE-FILES$", _m(top10=["A05"], wstg=["CONF-04"], asvs=["V14"], iso=["8.9", "8.12"])),
    (r"^WSTG-CONF-05-DEBUG-ENDPOINTS$", _m(top10=["A05"], api10=["API8"], wstg=["CONF-05"], asvs=["V14"], iso=["8.9"])),
    (r"^WSTG-CONF-06-DANGEROUS-HTTP-METHOD$", _m(top10=["A05"], api10=["API8"], wstg=["CONF-06"], asvs=["V13", "V14"], iso=["8.9"])),
    (r"^WSTG-CONF-07-INCOMPLETE-HSTS$", _m(top10=["A05"], wstg=["CONF-07"], asvs=["V9", "V14"], iso=["8.24"])),
    (r"^OSINT-MISSING-SECURITY-HEADERS$", _m(top10=["A05"], api10=["API8"], asvs=["V14"], iso=["8.9"])),
    (r"^OSINT-SUBDOMAIN-DISCOVERY$", _m(top10=["A05"], api10=["API9"], asvs=["V1"], iso=["5.9"])),
    (r"^OSINT-THREAT-INTEL-.*$", _m(iso=["5.7"])),
    # --- API / inventario
    (r"^API-SHADOW-ENDPOINT$", _m(top10=["A05"], api10=["API9"], asvs=["V13"], iso=["5.9"])),
    # --- integridad de datos, concurrencia, recursos
    (r"^(JPA-ENTITY-MISSING-VERSION|JPA-MULTI-WRITE-NO-TRANSACTIONAL)$", _m(top10=["A04"], asvs=["V11"], iso=["8.28"])),
    (r"^(FILE-UPLOAD-NO-VALIDATION)$", _m(top10=["A04"], api10=["API4"], wstg=["BUSL-08", "BUSL-09"], asvs=["V12"], iso=["8.28"])),
    (r"^(OOM-BYTE-ARRAY-STREAMING|BLOCKING-THREAD-SLEEP|ORM-N-PLUS-ONE-QUERY)$", _m(top10=["A04"], api10=["API4"], asvs=["V12"], iso=["8.28"])),
    # --- 2026-10-01: reglas añadidas por brechas que este registro mostró como detectables estáticamente
    # --- 2026-10-12: reglas de arquitectura/rendimiento (Spring Boot y Angular) a partir de prompts de auditoría de arquitectura; ver auditors/auditor_arch_rules.py
    (r"^(JPA-EAGER-FETCH|REPOSITORY-FINDALL-UNPAGINATED|JPA-QUERY-IN-LOOP|ANGULAR-HTTP-IN-LOOP)$", _m(top10=["A04"], api10=["API4"], asvs=["V12"], iso=["8.28"])),
    (r"^REQUESTBODY-WITHOUT-VALID$", _m(top10=["A04"], api10=["API3"], asvs=["V5"], iso=["8.28"])),
    (r"^ENTITY-RETURNED-FROM-CONTROLLER$", _m(top10=["A04"], api10=["API3"], asvs=["V13"], iso=["8.28"])),
    (r"^(CONTROLLER-INJECTS-REPOSITORY|ANGULAR-NESTED-SUBSCRIBE|ANGULAR-SUBSCRIBE-NO-CLEANUP|ANGULAR-VALUECHANGES-NO-DEBOUNCE|ANGULAR-EFFECT-HTTP|"
     r"ANGULAR-EFFECT-SELF-WRITE|ANGULAR-SIGNAL-MUTATION-IN-PLACE|ANGULAR-DOUBLE-LOAD-INIT-EFFECT|ANGULAR-SETTIMEOUT-WORKAROUND|TS-EXPLICIT-ANY|"
     r"ANGULAR-TEMPLATE-METHOD-IN-LOOP|ANGULAR-LAZYLOAD-PLUS-INIT-LOAD|ANGULAR-SUBMIT-NO-BUSY-GUARD)$", _m(iso=["8.28"])),
    (r"^DNS-(SPF-MULTIPLE|SPF-MISSING|SPF-PERMISSIVE|SPF-SOFTFAIL|SPF-TOO-MANY-LOOKUPS|DMARC-MISSING|DMARC-MONITOR-ONLY|DMARC-PARTIAL|MTASTS-MISSING|CAA-MISSING|DNSSEC-NOT-ENABLED)$",
     _m(top10=["A05"], iso=["5.14", "8.20"])),
    (r"^API-(ROUTE-NOT-IN-CONTRACT|CONTRACT-ROUTE-NOT-IMPLEMENTED|CONTRACT-MISMATCH|NO-CONTRACT|ENDPOINT-UNDOCUMENTED)$", _m(top10=["A05"], api10=["API9"], asvs=["V13"], iso=["5.9"])),
    (r"^SCA-LICENSE-(NETWORK-COPYLEFT|RESTRICTED|STRONG-COPYLEFT|UNKNOWN)$", _m(top10=["A06"], iso=["5.32"])),
    (r"^MASS-ASSIGNMENT-ENTITY-BINDING$", _m(top10=["A04"], api10=["API3"], asvs=["V5", "V13"], iso=["8.28"])),
    (r"^INSECURE-RANDOM-FOR-SECRET$", _m(top10=["A02"], asvs=["V6"], iso=["8.24"])),
    (r"^CRYPTO-CBC-NO-AUTHENTICATION$", _m(top10=["A02"], wstg=["CRYP-02"], asvs=["V6"], iso=["8.24"])),
    (r"^INSECURE-WEBSOCKET$", _m(top10=["A02"], wstg=["CLNT-10"], asvs=["V9"], iso=["8.24", "8.20"])),
    (r"^(POSTMESSAGE-WILDCARD-ORIGIN|POSTMESSAGE-NO-ORIGIN-CHECK)$", _m(top10=["A05"], wstg=["CLNT-11"], asvs=["V14"], iso=["8.26"])),
    (r"^CLIENT-SIDE-REDIRECT$", _m(top10=["A01"], wstg=["CLNT-04"], asvs=["V5"], iso=["8.26"])),
    (r"^FRONTEND-SENSITIVE-STORAGE$", _m(top10=["A02"], wstg=["CLNT-12"], asvs=["V8"], iso=["8.12"])),
    (r"^FRONTEND-(STOMP-DEBUG-LOGGING|TOKEN-IN-CONSOLE)$", _m(top10=["A09"], asvs=["V7"], iso=["8.15"])),
    (r"^DEPENDENCY-UNREACHABLE$", _m(top10=["A05"], iso=["5.30"])),
    (r"^RUNTIME-TOKEN-IN-CONSOLE$", _m(top10=["A09"], asvs=["V7"], iso=["8.15"])),
    (r"^RUNTIME-PII-IN-RESPONSE$", _m(top10=["A01"], api10=["API3"], asvs=["V4"], iso=["8.3"])),
    (r"^SMART-TESTS-ACCESS-CONTROL-FAILURE$", _m(top10=["A01"], asvs=["V4"], iso=["8.3"])),   # functional test, access-control category only
    (r"^RUNTIME-AUTH-ERRORS$", _m(asvs=["V3"], iso=["8.5"])),
    (r"^RUNTIME-SERVER-ERRORS$", _m(wstg=["ERRH-01"], top10=["A05"], iso=["8.9"])),
    (r"^RUNTIME-TOKEN-IN-STORAGE$", _m(top10=["A02"], wstg=["CLNT-12"], asvs=["V3"], iso=["8.24"])),
    (r"^SESSION-FIXATION-DISABLED$", _m(top10=["A07"], wstg=["SESS-03"], asvs=["V3"], iso=["8.26"])),
    (r"^GRAPHQL-INTROSPECTION-ENABLED$", _m(top10=["A05"], api10=["API8"], wstg=["APIT-01"], asvs=["V13"], iso=["8.9"])),
    (r"^SSTI-TEMPLATE-FROM-INPUT$", _m(top10=["A03"], wstg=["INPV-18"], asvs=["V5"], iso=["8.28"])),
    (r"^XPATH-INJECTION-CONCAT$", _m(top10=["A03"], wstg=["INPV-09"], asvs=["V5"], iso=["8.28"])),
    (r"^LDAP-INJECTION-CONCAT$", _m(top10=["A03"], wstg=["INPV-06"], asvs=["V5"], iso=["8.28"])),
    (r"^(SUPPLY-CHAIN-NO-LOCKFILE|SUPPLY-CHAIN-UNPINNED-DEPENDENCY|DOCKER-CURL-PIPE-SHELL)$", _m(top10=["A08", "A06"], asvs=["V10", "V14"], iso=["8.25"])),
    # --- logging
    (r"^(STD-STRIDE-MISSING-AUDIT-LOG|STRIDE-REPUDIATION)$", _m(top10=["A09"], asvs=["V7"], iso=["8.15"])),
    (r"^STD-STRIDE-LOG-SENSITIVE-DATA$", _m(top10=["A09"], asvs=["V7", "V8"], iso=["8.11", "8.15"])),
    (r"^(STRIDE-INFO-DISCLOSURE)$", _m(top10=["A02"], asvs=["V8"], iso=["8.12"])),
    (r"^(STRIDE-SPOOFING)$", _m(top10=["A07"], asvs=["V2"], iso=["5.17"])),
    # --- SCA / cadena de suministro
    (r"^(SCA-CVE-.*|SCA-GHSA-.*|CVE-\d{4}-\d+)$", _m(top10=["A06"], api10=["API10"], asvs=["V14"], iso=["8.8"])),
    (r"^(DOCKER-UNPINNED-BASE-IMAGE|CICD-UNPINNED-IMAGE|CICD-CURL-PIPE-SHELL|CICD-REMOTE-INCLUDE-INSECURE)$", _m(top10=["A08"], asvs=["V10", "V14"], iso=["8.25", "8.32"])),
    # --- contenedores / IaC / nube / DB / SO / CI-CD / GitLab
    (r"^(DOCKER-ROOT-USER|DOCKER-MISSING-NON-ROOT-USER|K8S-RUN-AS-ROOT|K8S-PRIVILEGED-CONTAINER|K8S-PRIVILEGE-ESCALATION|K8S-WRITABLE-ROOT-FS|K8S-HOSTPATH-MOUNT|K8S-AUTOMOUNT-TOKEN|CSPM-K8S-.*|CICD-DOCKER-PRIVILEGED)$",
     _m(top10=["A05"], asvs=["V14"], iso=["8.9"])),
    (r"^(TF-PUBLIC-S3-BUCKET|CSPM-AWS-S3-PUBLIC.*)$", _m(top10=["A05", "A01"], asvs=["V14"], iso=["8.9", "5.23"], wstg=["CONF-11"])),
    (r"^(TF-.*|CSPM-AWS-.*|CSPM-IAM-.*)$", _m(top10=["A05", "A01"], asvs=["V14"], iso=["8.9", "5.23"])),
    (r"^(DB-DEFAULT-PORT-EXPOSED|DB-BANNER-LEAK)$", _m(top10=["A05"], asvs=["V14"], iso=["8.9", "8.20"])),
    (r"^(OS-PATCH-SECURITY-UPDATES-PENDING|OS-EOL|OS-REBOOT-REQUIRED|OS-AUTO-UPDATES-DISABLED|OS-PACKAGE-INDEX-STALE)$", _m(top10=["A06"], asvs=["V14"], iso=["8.8", "8.19"])),
    (r"^CIS-1\.[12]\b.*$", _m(top10=["A05", "A07"], asvs=["V2", "V14"], iso=["8.5", "8.9", "8.2"])),   # SSH root / password auth
    (r"^CIS-2\.[12]\b.*$", _m(top10=["A05"], asvs=["V14"], iso=["8.3", "8.9"])),                         # permisos passwd/shadow
    (r"^CIS-(3\.1|5\.1)\b.*$", _m(top10=["A07"], asvs=["V2"], iso=["5.17", "8.5"])),                    # política/cuentas vacías
    (r"^CIS-(4\.1|6\.1)\b.*$", _m(top10=["A05"], asvs=["V14"], iso=["8.20", "8.9"])),                  # firewall / ip_forward
    (r"^CIS-5\.2\b.*$", _m(top10=["A09"], asvs=["V7"], iso=["8.15"])),                                  # auditd
    (r"^CIS-6\.2\b.*$", _m(top10=["A05"], asvs=["V14"], iso=["8.9"])),                                  # core dumps
    (r"^CIS-7\.1\b.*$", _m(top10=["A05"], asvs=["V14"], iso=["8.17"])),                                 # sincronización de tiempo
    (r"^CIS-.*$", _m(top10=["A05"], asvs=["V14"], iso=["8.9"])),
    (r"^(GITLAB-PROJECT-.*|CICD-NO-PIPELINE)$", _m(top10=["A05", "A08"], asvs=["V14"], iso=["8.4", "8.25", "8.32"])),
    # --- accesibilidad (no es ISO 27001)
    (r"^WCAG-2\.4\.1-NO-SKIP-LINK$", _m(wcag=["2.4.1"])),
    (r"^WCAG-1\.4\.4-VIEWPORT-ZOOM-DISABLED$", _m(wcag=["1.4.4"])),
    (r"^WCAG-2\.4\.2-MISSING-TITLE$", _m(wcag=["2.4.2"])),
    (r"^WCAG-4\.1\.2-IFRAME-NO-TITLE$", _m(wcag=["4.1.2"])),
    (r"^WCAG-1\.3\.5-INPUT-NO-AUTOCOMPLETE$", _m(wcag=["1.3.5"])),
    (r"^WCAG-2\.2\.2-MARQUEE-BLINK$", _m(wcag=["2.2.2"])),
    (r"^WCAG-1\.4\.2-AUTOPLAY-MEDIA$", _m(wcag=["1.4.2"])),
    (r"^WCAG-1\.2\.2-VIDEO-NO-CAPTIONS$", _m(wcag=["1.2.2"])),
    (r"^WCAG-4\.1\.1-DUPLICATE-ID$", _m(wcag=["4.1.1"])),
    (r"^WCAG-2\.4\.6-EMPTY-HEADING$", _m(wcag=["2.4.6"])),
    (r"^WCAG-2\.5\.3-LABEL-IN-NAME$", _m(wcag=["2.5.3"])),
    (r"^WCAG-2\.4\.7-FOCUS-OUTLINE-REMOVED$", _m(wcag=["2.4.7"])),
    (r"^WCAG-1\.1\.1-.*$", _m(wcag=["1.1.1"])),
    (r"^WCAG-1\.3\.1-.*$", _m(wcag=["1.3.1", "3.3.2", "4.1.2"])),
    (r"^WCAG-2\.4\.3-.*$", _m(wcag=["2.4.3"])),
    (r"^WCAG-2\.4\.4-.*$", _m(wcag=["2.4.4", "4.1.2"])),
    (r"^WCAG-3\.1\.1-.*$", _m(wcag=["3.1.1"])),
    (r"^WCAG-4\.1\.2-.*$", _m(wcag=["4.1.2", "2.1.1"])),
    (r"^ACCESSIBILITY-WCAG-MISSING-LABEL$", _m(wcag=["4.1.2", "2.4.4"])),
    # --- LLM
    (r"^OWASP-LLM01-.*$", _m(llm10=["LLM01"], iso=["8.28"])),
    (r"^OWASP-LLM02-.*$", _m(llm10=["LLM02"], iso=["5.34", "8.12"])),
    (r"^OWASP-LLM06-.*$", _m(llm10=["LLM06"], iso=["8.2"])),
    # --- calidad / proceso (CMMI) y código mantenible
    # NOTE: no `cmmi=` here on purpose. These code-hygiene rules are proxies, not the evidence the the organization manual asks for in
    # CAR (causal analysis) or PQA (human validation of AI output); CMMI coverage comes only from real evidence collectors
    # (auditors/auditor_cmmi_evidence.py, see cmmi_collectors()). Counting them here would inflate CAR to "covered".
    (r"^(CMMI-CAR-SWALLOWED-EXCEPTION)$", _m(top10=["A09"], asvs=["V7"], iso=["8.28"])),
    (r"^(CMMI-MSR-HARDCODED-SLEEP|CMMI-PQA-DEBT-TODO)$", _m(iso=["8.28"])),
    (r"^(STD-ISO25010-LONG-METHOD|COGNITIVE-COMPLEXITY-EXCEEDED|VALIDATION-REIMPLEMENTED)$", _m(iso=["8.28"])),
    (r"^(SWALLOWED-ERROR|DESTRUCTIVE-ACTION-NO-CONFIRM|NATIVE-BROWSER-DIALOG|SQL-TABLE-WITHOUT-PRIMARY-KEY|CICD-GATE-ALLOW-FAILURE|TEST-SKIPPED-WITHOUT-REASON)$",
     _m(iso=["8.28"])),
    # form behaviour observed at runtime by centinela-smart-tests (heuristics check); WCAG 3.3.1 stays "manual", so no wcag= here
    (r"^SMART-TESTS-FORM-(INVALID-SUBMITTED|NO-FIELD-ERROR)$", _m(iso=["8.28"])),
    # organisation database standard and Starter conventions (2026-10-27): code/schema conformance, same ISO bucket as the rules above
    (r"^(SQL-PK-NOT-UUID|SQL-TIMESTAMP-WITHOUT-TIMEZONE|SQL-JSON-NOT-JSONB|SQL-FLOAT-FOR-MONEY|TRANSACTIONAL-ON-CONTROLLER|FIELD-INJECTION-AUTOWIRED|"
     r"JPA-OBJECT-ARRAY-RESULT|FRONTEND-HARDCODED-API-URL)$", _m(iso=["8.28"])),
    # tables without the audit standard's canonical columns: the audit trail (8.15) cannot be kept for them
    (r"^SQL-TABLE-WITHOUT-AUDIT-COLUMNS$", _m(iso=["8.15", "8.28"])),
]]

# ----------------------------------------------------------------------------- motores externos (capacidad declarada)
# Cubren CUANDO el motor corre sobre el activo. No se verifica regla por regla: es capacidad declarada, no medida.
EXTERNAL_ENGINES: Dict[str, Dict[str, List[str]]] = {
    "OWASP ZAP (DAST activo/pasivo, solo en activos URL/SERVER)": {
        "wstg": ["INPV-01", "INPV-02", "INPV-05", "INPV-12", "INPV-19", "AUTHZ-01", "SESS-02", "SESS-05", "CLNT-07", "CLNT-09",
                 "CONF-07", "INFO-02", "ERRH-01", "ERRH-02", "ATHN-06"],
        "top10": ["A01", "A02", "A03", "A05", "A10"],
    },
    "Semgrep (p/owasp-top-ten y reglas por lenguaje)": {"top10": ["A01", "A02", "A03", "A05", "A07", "A08"]},
    "SonarQube (reglas de seguridad y hotspots)": {"top10": ["A01", "A02", "A03", "A05", "A07", "A09"]},
    "Trivy / OSV (dependencias e imágenes)": {"top10": ["A06"], "api10": ["API10"]},
    "Nuclei (plantillas de exposición)": {"top10": ["A05", "A06"], "wstg": ["INFO-02", "CONF-05"]},
    "Checkov (IaC)": {"top10": ["A05"]},
}

def cmmi_collectors() -> Dict[str, Dict[str, object]]:
    """Per CMMI area: how many of the manual's evidence items have a REAL collector today (auditors/auditor_cmmi_evidence.py).
    Derived from the code, never typed by hand; an area with 0 collectors is not covered, whatever older proxy rules say."""
    from auditors.auditor_cmmi_evidence import CMMI_AREA_ITEMS
    out = {}
    for area, spec in CMMI_AREA_ITEMS.items():
        keys = [it[0] for it in spec["items"] if it[5]]
        out[area] = {"items": len(spec["items"]), "with_collector": len(keys), "keys": keys}
    return out


# ----------------------------------------------------------------------------- API
# Rendered-DOM (axe-core 4.x) findings carry the WCAG criterion in the id: WCAG-<criterion>-AXE-<axe-rule>. Only criteria for which axe ships
# at least one rule AND a machine can decide count (listed from axe.getRules() on 2026-10-07). Reflow 1.4.10, non-text contrast 1.4.11 and
# status messages 4.1.3 have no axe rule; "manual" criteria stay uncovered even if axe flags a related symptom (partial signal != coverage).
AXE_DECIDABLE = {"1.1.1", "1.2.2", "1.3.1", "1.3.4", "1.3.5", "1.4.2", "1.4.3", "1.4.4", "1.4.12", "2.1.1", "2.2.2", "2.4.1", "2.4.2",
                 "2.4.4", "2.5.3", "3.1.1", "3.1.2", "3.3.2", "4.1.2"}
for _crit in sorted(AXE_DECIDABLE):
    assert WCAG_21_AA[_crit][2] != "manual", _crit
    RULE_MAP.append((re.compile(rf"^WCAG-{re.escape(_crit)}-AXE-.*$"), _m(wcag=[_crit])))


def classify_rule(rule_id: str) -> Optional[Dict[str, List[str]]]:
    """Elementos que la regla cubre, o None si no está clasificada. Los marcadores (NON_FINDING) devuelven {}."""
    rid = str(rule_id or "").upper()
    if NON_FINDING.match(rid):
        return {}
    for rx, mapping in RULE_MAP:
        if rx.match(rid):
            return mapping
    return None


def native_coverage() -> Dict[str, Dict[str, List[str]]]:
    """{marco: {elemento: [patrones de regla que lo cubren]}} construido solo desde RULE_MAP."""
    cov: Dict[str, Dict[str, List[str]]] = {k: {} for k in FRAMEWORKS}
    for rx, mapping in RULE_MAP:
        for fw, items in mapping.items():
            for it in items:
                cov[fw].setdefault(it, []).append(rx.pattern)
    for area, info in cmmi_collectors().items():       # CMMI is covered by evidence collectors, not by finding rules
        for key in info["keys"]:
            cov["cmmi"].setdefault(area, []).append(f"colector:{key}")
    return cov


def external_coverage() -> Dict[str, Dict[str, List[str]]]:
    out: Dict[str, Dict[str, List[str]]] = {k: {} for k in FRAMEWORKS}
    for engine, mapping in EXTERNAL_ENGINES.items():
        for fw, items in mapping.items():
            for it in items:
                out[fw].setdefault(it, []).append(engine)
    return out


def compute_coverage() -> Dict[str, dict]:
    """Resumen honesto por marco: total / nativo / solo externo / sin detector, más los elementos no automatizables."""
    native, external = native_coverage(), external_coverage()
    result = {}
    for fw, (title, universe) in FRAMEWORKS.items():
        ids = list(universe)
        nat = [i for i in ids if i in native[fw]]
        ext_only = [i for i in ids if i not in native[fw] and i in external[fw]]
        none = [i for i in ids if i not in native[fw] and i not in external[fw]]
        row = {"title": title, "total": len(ids), "native": len(nat), "external_only": len(ext_only), "none": len(none),
               "native_items": nat, "external_only_items": ext_only, "none_items": none}
        row["thin_native"] = [i for i in nat if len(native[fw][i]) == 1]   # cobertura nativa sostenida por UNA sola familia de reglas
        if fw == "wcag":
            row["not_static"] = {i: WCAG_21_AA[i][2] for i in none if WCAG_21_AA[i][2] != "estatico"}
            row["static_but_uncovered"] = [i for i in none if WCAG_21_AA[i][2] == "estatico"]
            row["by_how"] = {h: sum(1 for v in WCAG_21_AA.values() if v[2] == h) for h in ("estatico", "navegador", "manual")}
        if fw == "iso":
            tech = [i for i in ids if ISO_27001_2022[i]["technical"]]
            row["technical_domain"] = len(tech)
            row["technical_native"] = len([i for i in tech if i in native[fw]])
            row["technical_uncovered"] = [i for i in tech if i not in native[fw]]
            row["by_scope"] = {s: sum(1 for v in ISO_27001_2022.values() if v["scope"] == s)
                               for s in ("org", "personas", "fisico", "tecnologico")}
        if fw == "cmmi":
            col = cmmi_collectors()
            row["measured_today"] = {a: (f"{col[a]['with_collector']} de {col[a]['items']} ítems medibles" if col[a]["with_collector"] else "no evaluada")
                                     for a in ids}
        result[fw] = row
    return result


def unclassified(rule_ids: Iterable[str]) -> List[str]:
    return sorted({r for r in rule_ids if classify_rule(r) is None})


def to_markdown() -> str:
    cov = compute_coverage()
    native = native_coverage()
    lines = ["# Cobertura de Centinela por marco (generado desde `core/coverage_matrix.py`)", "",
             "> Cobertura **nativa** = existe una regla propia de Centinela que lo detecta. **Solo externo** = únicamente un motor externo "
             "declarado (cuando corre). **Sin detector** = nadie lo cubre. Los mapeos regla→elemento son criterio de ingeniería de Centinela, "
             "no una taxonomía normativa. Un elemento «cubierto» significa que existe un detector, **no** que el activo cumpla.", ""]
    lines += ["| Marco | Elementos | Nativa | Solo externo | Sin detector |", "|---|---:|---:|---:|---:|"]
    for fw, r in cov.items():
        lines.append(f"| {r['title']} | {r['total']} | {r['native']} | {r['external_only']} | {r['none']} |")
    lines.append("")
    for fw, (title, universe) in FRAMEWORKS.items():
        r = cov[fw]
        lines += [f"## {title}", ""]
        if fw == "wcag":
            lines.append(f"Automatización por naturaleza del criterio: {r['by_how']} (estático = HTML/CSS; navegador = página renderizada; manual = juicio humano).")
            lines.append("")
        if fw == "iso":
            lines.append(f"Por ámbito: {r['by_scope']}. Controles con alcance técnico concebible: **{r['technical_domain']}**, de los cuales con regla nativa: **{r['technical_native']}**. "
                         f"Sin regla pese a ser técnicos: {', '.join(r['technical_uncovered']) or '—'}.")
            lines.append("")
        if fw == "cmmi":
            lines.append("Ítems del manual con colector real hoy, por área: " + ", ".join(f"{a}: {s}" for a, s in r["measured_today"].items()) + ". Ver `DECISIONS/0007`.")
            lines.append("")
        lines += ["| Elemento | Nombre | Estado | Familias de regla |", "|---|---|---|---:|"]
        for it, name in universe.items():
            if it in native[fw]:
                st = "nativa"
            elif it in r["external_only_items"]:
                st = "solo externo"
            else:
                extra = ""
                if fw == "wcag":
                    extra = f" ({WCAG_21_AA[it][2]})"
                if fw == "iso":
                    extra = " (no técnico)" if not ISO_27001_2022[it]["technical"] else " (técnico, sin regla)"
                st = "sin detector" + extra
            depth = len(native[fw].get(it, [])) or ""
            lines.append(f"| {it} | {name} | {st} | {depth} |")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":  # python3 -m core.coverage_matrix > docs/COBERTURA_FRAMEWORKS.md
    print(to_markdown())
