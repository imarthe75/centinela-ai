"""
Centinela Regulatory Compliance Control Mapper & Matrix Generator
Maps all vulnerability findings to ISO 27001:2022, NIST SP 800-53, PCI-DSS v4.0, SOC 2, and GDPR controls.
"""
import re
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
    "ORM-RAW-QUERY-INJECTION": {
        "ISO_27001": "A.8.28 (Secure Coding)",
        "NIST_800_53": "SI-10 (Information Input Validation)",
        "PCI_DSS": "Req 6.5.1 (Injection Flaws)",
        "SOC_2": "CC6.1 (Logical Access Security)",
        "GDPR": "Art 32 (Security of Processing)"
    },
    "FRONTEND-EXPOSED-DB-CREDENTIAL": {
        "ISO_27001": "A.8.24 (Use of Cryptography)",
        "NIST_800_53": "SC-28 (Protection at Rest)",
        "PCI_DSS": "Req 8.3 (Strong Credentials)",
        "SOC_2": "CC6.1 (Credentials Management)",
        "GDPR": "Art 32 (Cryptographic Protection)"
    },
    "FRONTEND-JWT-LOCALSTORAGE": {
        "ISO_27001": "A.8.28 (Secure Coding)",
        "NIST_800_53": "AC-3 (Access Control)",
        "PCI_DSS": "Req 8.3 (Strong Authentication)",
        "SOC_2": "CC6.1 (Logical Access Security)",
        "GDPR": "Art 32 (Security of Processing)"
    },
    "REACT-DANGEROUSLY-SET-INNER-HTML": {
        "ISO_27001": "A.8.28 (Secure Coding)",
        "NIST_800_53": "SI-10 (Input Validation)",
        "PCI_DSS": "Req 6.5.7 (XSS Flaws)",
        "SOC_2": "CC6.1 (Logical Access Security)",
        "GDPR": "Art 32 (Security of Processing)"
    },
    "ANGULAR-BYPASS-SECURITY-TRUST": {
        "ISO_27001": "A.8.28 (Secure Coding)",
        "NIST_800_53": "SI-10 (Input Validation)",
        "PCI_DSS": "Req 6.5.7 (XSS Flaws)",
        "SOC_2": "CC6.1 (Logical Access Security)",
        "GDPR": "Art 32 (Security of Processing)"
    },
    "SPRINGBOOT-NATIVE-QUERY-RISK": {
        "ISO_27001": "A.8.28 (Secure Coding)",
        "NIST_800_53": "SI-10 (Input Validation)",
        "PCI_DSS": "Req 6.5.1 (Injection Flaws)",
        "SOC_2": "CC6.1 (Logical Access Security)",
        "GDPR": "Art 32 (Security of Processing)"
    },
    # Real ISO 25010 mapping, added 2026-08-25 alongside the new WCAG auditor: ISO/IEC 25010
    # explicitly lists "Accessibility" as a sub-characteristic of Usability -- a real, correct
    # control to cite here, not invented for this codebase. No NIST 800-53/PCI-DSS/SOC 2/GDPR
    # entry is listed for these: none of those frameworks have an accessibility-specific control
    # (they're security/privacy frameworks), so those columns are left absent rather than forced.
    "WCAG-1.1.1-IMG-MISSING-ALT": {"ISO_27001": "ISO 25010 (Usability — Accessibility)"},
    "WCAG-1.3.1-FORM-CONTROL-NO-LABEL": {"ISO_27001": "ISO 25010 (Usability — Accessibility)"},
    "WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT": {"ISO_27001": "ISO 25010 (Usability — Accessibility)"},
    "WCAG-3.1.1-HTML-MISSING-LANG": {"ISO_27001": "ISO 25010 (Usability — Accessibility)"},
    "WCAG-2.4.3-POSITIVE-TABINDEX": {"ISO_27001": "ISO 25010 (Usability — Accessibility)"},
    "WCAG-4.1.2-CLICKABLE-DIV-NO-ROLE": {"ISO_27001": "ISO 25010 (Usability — Accessibility)"},
    "CMMI-CAR-SWALLOWED-EXCEPTION": {
        "ISO_27001": "A.8.28 (Secure Coding)",
        "NIST_800_53": "SI-11 (Error Handling)",
        "PCI_DSS": "Req 10.2 (Automated Audit)",
        "SOC_2": "CC7.2 (System Monitoring)",
        "GDPR": "Art 32 (Resilience & Reliability)",
        "CMMI_V3": "CAR (Causal Analysis & Resolution Level 5)"
    },
    "CMMI-MSR-HARDCODED-SLEEP": {
        "ISO_27001": "ISO 25010 (Maintainability)",
        "NIST_800_53": "SC-5 (DoS Protection)",
        "PCI_DSS": "Req 2.2 (System Hardening)",
        "SOC_2": "CC7.2 (Monitoring)",
        "GDPR": "Art 32 (Performance)",
        # Real fix 2026-08-25: "MSR" is not a real CMMI V3.0 practice area code under C&A's own
        # ISACA-verified taxonomy (see compliance_mapper.py's CMMI_V3_PRACTICE_AREAS comment) --
        # the cve_id string itself is kept as-is for dedup/history continuity, but this label no
        # longer claims a fabricated area. Scored under PQA in evaluate_cmmi_v3_for_asset().
        "CMMI_V3": "PQA (Process Quality Assurance) -- proxy de higiene de código, sin área CMMI real dedicada a este antipatrón"
    },
    "CMMI-PQA-DEBT-TODO": {
        "ISO_27001": "A.8.9 (Configuration Management)",
        "NIST_800_53": "CM-6 (Configuration Settings)",
        "PCI_DSS": "Req 6.5 (Software Quality)",
        "SOC_2": "CC6.8 (Hardening)",
        "GDPR": "Art 32 (Quality Control)",
        "CMMI_V3": "PQA (Process Quality Assurance)"
    },
    "ORM-N-PLUS-ONE-QUERY": {
        "ISO_27001": "ISO 25010 (Performance Efficiency)",
        "NIST_800_53": "SC-5 (Denial of Service Protection)",
        "PCI_DSS": "Req 2.2 (System Hardening)",
        "SOC_2": "CC7.2 (Performance Monitoring)",
        "GDPR": "Art 32 (Availability & Resilience)"
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

    # Database Hardening & Security
    "DB-NO-TLS-ENCRYPTION": {
        "ISO_27001": "A.8.24 (Use of Cryptography)",
        "NIST_800_53": "SC-8 (Transmission Confidentiality and Integrity)",
        "PCI_DSS": "Req 4.1 (Protect Cardholder Data in Transit)",
        "SOC_2": "CC6.6 (Transmission Encryption)",
        "GDPR": "Art 32 (Encryption of Personal Data)"
    },
    "DB-DEFAULT-PORT-EXPOSED": {
        "ISO_27001": "A.8.9 (Configuration Management)",
        "NIST_800_53": "CM-6 (Configuration Settings)",
        "PCI_DSS": "Req 2.2 (System Hardening)",
        "SOC_2": "CC6.8 (System Hardening)",
        "GDPR": "Art 32 (Technical Measures)"
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
        "GDPR": {},
        "CMMI_V3": {}
    }

    try:
        from psycopg2.extras import RealDictCursor
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
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
                    if framework not in mapped_matrix:
                        mapped_matrix[framework] = {}
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



# Real bug fixed 2026-08-25, found while cross-checking this list against C&A's own methodology
# manual (Manual_Metodologia_CA_v2_COMPLETO.docx, Parte II cap. 10 -- its own CMMI mapping is
# explicitly verified against ISACA's CMMI Model Quick Reference Guide V3.0, a real external
# source, not invented for the manual). C&A's own tailored model applies 19 real areas: RDM, PQA,
# PR, VV, TS, PI, EST, PLAN, MC, RSK, OT, CM, DAR, CAR, GOV, II, MPM, PAD, PCM. Two of the codes
# this auditor used before did not survive that check: "SAM" (Supplier Agreement Management) is
# not one of C&A's 19 tailored areas at all -- they don't treat open-source dependency tracking
# as a formal supplier-agreement process. "MSR" is not a real CMMI V3.0 code under any taxonomy;
# the closest real area is MPM (Managing Performance and Measurement), but MPM's real evidence
# per the manual is org-level estimated-vs-actual delivery data, not a hardcoded Thread.sleep()
# in source -- there is no honest 1:1 mapping for that finding type at the code level, so its
# scoring is folded into PQA (code hygiene / technical debt) below instead of kept as its own
# fabricated area.
#
# A second, deeper problem surfaced doing this cross-check, not just wrong codes: even the
# letters that DID coincidentally match a real CMMI code (EST, PLAN) were measuring something
# textually similar but substantively different from what the manual defines. Real EST evidence
# is "estimación con supuestos... registro estimado-vs-real" (project estimation accuracy) --
# this auditor's old "EST" instead checked asset network reachability, which has nothing to do
# with estimation. Real PLAN evidence is "Plan de proyecto (desglose, cronograma, línea base)" --
# a project-management document this auditor has no way to see. Centinela is a security/code
# scanner: it can see source code and scan history, not C&A's project plans, estimates, risk
# registers, training logs, or peer-review sign-offs, which is where most of the 19 real areas
# actually live. Relabeling the same connectivity/last-scan checks under those two codes would
# have repeated the exact mistake, just with correct-looking labels -- the same "fake precision"
# problem already flagged elsewhere in this codebase for MITRE ATT&CK (see CLAUDE.md item 5).
#
# Fixed by keeping this auditor honest about its real, narrow scope: it evaluates only the areas
# where source code and scan history genuinely constitute evidence (a strict subset of the 19),
# using the manual's own area names/codes and staying within what its real evidence column
# describes, and it now explicitly lists the areas it does NOT evaluate (CMMI_V3_NOT_EVALUATED)
# instead of silently omitting them, so a report reader sees the coverage boundary instead of
# assuming full-19-area coverage from a 5-area score.
CMMI_V3_PRACTICE_AREAS = [
    {"code": "CAR", "name": "Causal Analysis and Resolution", "level": "Enabling / Supporting Implementation",
     "desc": "Análisis causal real: excepciones silenciadas (catch/except vacío) y fallas de inyección detectadas en código -- evidencia de que los defectos no se están enterrando sin diagnóstico."},
    {"code": "PQA", "name": "Process Quality Assurance", "level": "Doing / Ensuring Quality",
     "desc": "Higiene de código como proxy de aseguramiento de calidad: secretos/credenciales expuestas, deuda técnica declarada (TODO) y antipatrones de rendimiento (sleeps duros) sin resolver."},
    {"code": "CM", "name": "Configuration Management", "level": "Enabling / Supporting Implementation",
     "desc": "Evidencia real de control de versiones: para repositorios, historial Git verificable (no una carpeta cargada sin control de cambios)."},
    {"code": "MC", "name": "Monitor and Control", "level": "Managing / Planning & Managing Work",
     "desc": "Seguimiento operativo real: el activo está bajo monitoreo activo del pipeline SOAR (conectividad verificada o auditoría de hardening reciente) y tiene al menos una auditoría registrada."},
    {"code": "VV", "name": "Verification and Validation", "level": "Doing / Ensuring Quality",
     "desc": "Evidencia de verificación automatizada: escaneos de seguridad (SAST/SCA/DAST) o telemetría EDR con hallazgos o cobertura real registrada."},
]

# Areas from C&A's own 19-area tailored CMMI V3.0 model (see the manual citation above) that this
# auditor deliberately does NOT score, because their real evidence lives in project-management
# artifacts (plans, estimates, risk registers, training logs, peer-review sign-offs, requirements
# traceability matrices) that a source-code/vulnerability scanner has no visibility into. Listed
# here so a report can disclose the gap explicitly instead of a reader assuming these 5 areas are
# the whole model.
CMMI_V3_NOT_EVALUATED = [
    {"code": "RDM", "name": "Requirements Management", "reason": "Requiere matriz de trazabilidad de requerimientos -- no existe en el alcance de este escáner."},
    {"code": "PR", "name": "Peer Review", "reason": "Requiere identidad del revisor por cambio -- posible a futuro vía historial de Merge Requests de GitLab, no implementado aún."},
    {"code": "TS", "name": "Technical Solution", "reason": "Requiere documento de arquitectura/diseño detallado -- artefacto de proyecto, no derivable del código en sí."},
    {"code": "PI", "name": "Product Integration", "reason": "Requiere contratos de API y pruebas de integración documentadas -- fuera del alcance de un escáner de vulnerabilidades."},
    {"code": "EST", "name": "Estimating", "reason": "Requiere registro estimado-vs-real del Plan de proyecto -- dato de gestión de proyecto, no de código."},
    {"code": "PLAN", "name": "Planning", "reason": "Requiere el Plan de proyecto (desglose, cronograma, línea base) -- documento de gestión, no un artefacto que un escáner de código produzca o lea."},
    {"code": "RSK", "name": "Risk and Opportunity Management", "reason": "Requiere el registro de riesgos del proyecto -- no integrado con este escáner."},
    {"code": "OT", "name": "Organizational Training", "reason": "Requiere registro de capacitación del equipo -- dato de RH/organizacional."},
    {"code": "DAR", "name": "Decision Analysis and Resolution", "reason": "Requiere el registro de excepciones estructuradas (ruta 0B-3) -- proceso de gobernanza, no visible en el código."},
    {"code": "GOV", "name": "Governance", "reason": "Requiere actas de comité y certificación de fidelidad al catálogo tecnológico -- documentos organizacionales."},
    {"code": "II", "name": "Implementation Infrastructure", "reason": "Requiere evidencia de adopción del repositorio de activos organizacionales -- fuera del alcance por-activo de este escáner."},
    {"code": "MPM", "name": "Managing Performance and Measurement", "reason": "Requiere datos estimado-vs-real acumulados a nivel organizacional -- no un antipatrón de código individual."},
    {"code": "PAD", "name": "Process Asset Development", "reason": "Requiere plantillas/checklists/prompts versionados como activo organizacional -- no un artefacto por-proyecto."},
    {"code": "PCM", "name": "Process Management", "reason": "Requiere lecciones aprendidas consolidadas a nivel organizacional -- fuera del alcance por-activo de este escáner."},
]


def evaluate_cmmi_v3_for_asset(cur, asset: Dict[str, Any], vulns: list = None) -> Dict[str, Any]:
    """
    Evaluates CMMI v3.0 compliance for a single asset using an ALREADY-OPEN cursor.

    Deliberately takes a cursor rather than opening its own connection: this function is called
    both from get_cmmi_v3_asset_audit_report() (which owns its own cursor/connection) and from
    main.py's GET /api/inventory/{name}/details (which already holds an open cursor for the rest
    of that endpoint's work). A first version of this integration called
    get_cmmi_v3_asset_audit_report() -- which opens its own get_db_cursor() -- from inside that
    already-open outer cursor's `with` block. Confirmed live: under real load this deadlocked the
    single-worker uvicorn process solid (a thread holding one pooled connection blocked forever
    waiting for pool.getconn() to hand it a second one that only itself could ever release),
    taking the entire backend offline until a manual restart. Every caller must now pass its own
    cursor in rather than letting this function acquire one.

    `vulns`: pre-fetched vulnerability rows for this asset (optional). The fleet-wide report
    (get_cmmi_v3_asset_audit_report() with no filter) fetches every open vulnerability ONCE and
    passes each asset's slice in here, instead of this function running its own query per asset.
    Confirmed live: the original per-asset-query version took the single-worker backend offline
    under real concurrent traffic while auditing all 83 assets sequentially (83 blocking round
    trips in one request) -- a real, reproducible incident, not a hypothetical. When `vulns` is
    None (the single-asset callers), this still runs its own single query, which is cheap.
    """
    aid = asset["id"]
    aname = asset["asset_name"]
    atype = asset["asset_type"]

    if vulns is None:
        cur.execute("""
            SELECT cve_id, severity, description, status, scan_engine, url_path
            FROM public.vulnerability_log
            WHERE (asset_id = %s OR url_path ILIKE %s) AND status IN ('OPEN', 'NEW', 'CORRELATED')
        """, (aid, f"%{aname}%"))
        vulns = cur.fetchall()

    # Real bug fixed here 2026-08-12: category matching below used bare substrings (e.g. "SCA" in
    # cve_id for SAM/dependency findings) against the RAW vulns list, which includes Centinela's
    # own synthetic/system markers (SCAN-AUDIT, CIS-BENCHMARK-AUDIT, HEURISTIC-SECURITY-DEBT,
    # etc.) -- "SCA" is a substring of "SCAN-AUDIT" itself. Confirmed live: Cisco 4 ESXI (a
    # powered-off host that was never actually reached) showed SAM as "NO CUMPLE (1 dependencias
    # vulnerables)" citing SCAN-AUDIT as evidence of an outdated library, which SCAN-AUDIT has
    # nothing to do with -- a pure keyword collision, not a real SCA finding. All category checks
    # below now run against real_vulns (synthetic markers excluded) instead of the raw list.
    SYNTHETIC_MARKER_PREFIXES = ("CTI-IOC-MATCH", "BLOODHOUND-PATH")
    SYNTHETIC_MARKER_EXACT = {"HOST-CONTAINMENT-REQUEST", "SCAN-AUDIT", "HEURISTIC-SECURITY-DEBT", "CIS-BENCHMARK-AUDIT"}
    real_vulns = [
        v for v in vulns
        if str(v["cve_id"]).upper() not in SYNTHETIC_MARKER_EXACT
        and not str(v["cve_id"]).upper().startswith(SYNTHETIC_MARKER_PREFIXES)
    ]

    # Evaluate compliance per CMMI v3.0 Practice Area based on empirical evidence
    cmmi_compliance_details = []
    passed_count = 0

    # 1. CAR - Causal Analysis and Resolution (real code per manual: "Análisis causal sobre
    # defectos reales" -- a swallowed exception or an injection flaw IS a real, un-analyzed
    # defect at the point it's found).
    car_fails = [v for v in real_vulns if "INJECTION" in v["cve_id"] or "SWALLOWED" in v["cve_id"] or "CAR" in v["cve_id"]]
    if not car_fails:
        cmmi_compliance_details.append({
            "area": "CAR (Enabling)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": "Sin fallas de inyección ni supresión de excepciones. Causa raíz mitigada en código."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "CAR (Enabling)",
            "status": f"NO CUMPLE ({len(car_fails)} fallas)",
            "passed": False,
            "evidence": f"Detectadas {len(car_fails)} desviaciones graves de análisis de causa raíz ({car_fails[0]['cve_id']})."
        })

    # 2. PQA - Process Quality Assurance, code-hygiene proxy. Broadened 2026-08-25 to absorb the
    # former fabricated "MSR" bucket's evidence (SLEEP/COMPLEXITY/DEBT) -- there is no honest
    # per-finding CMMI area for a hardcoded sleep or an over-complex method under C&A's real
    # 19-area model, and PQA's own category (Doing / Ensuring Quality) is the closest real home
    # for "code hygiene debt" without inventing a new area. SCA/dependency findings (formerly the
    # fabricated "SAM" bucket) are deliberately NOT folded in here: an outdated third-party
    # library is a supply-chain/verification concern (already covered by VV's scan-evidence
    # check below), not a code-hygiene-debt concern the author of this code controls directly.
    pqa_fails = [v for v in real_vulns if any(
        kw in v["cve_id"] for kw in ("HARDCODED", "SECRET", "TODO", "SLEEP", "DEBT", "COMPLEXITY")
    )]
    if not pqa_fails:
        cmmi_compliance_details.append({
            "area": "PQA (Doing)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": "Sin credenciales expuestas, deuda técnica declarada (TODO) ni antipatrones de rendimiento (sleeps duros) sin resolver."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "PQA (Doing)",
            "status": f"NO CUMPLE ({len(pqa_fails)} violaciones de higiene de código)",
            "passed": False,
            "evidence": f"Halladas violaciones de higiene de código: credenciales expuestas, deuda técnica o antipatrones de rendimiento ({pqa_fails[0]['cve_id']})."
        })

    # Real, positive verification signals for this asset -- used by CM/MC/VV below and by the
    # is_verified gate at the end. cis_grade is only non-None after a genuinely successful SSH
    # connection (see auditor_cis_benchmarks.py's SIN_CONEXION handling); asset.get() is used
    # since not every caller's SELECT includes cis_grade.
    has_cis_grade = asset.get("cis_grade") is not None
    # Real bug fixed here: "GITLAB" in atype.upper() also matched asset_type == "GITLAB" itself
    # (the GitLab server host, e.g. "gitlab-casmart-server") -- that's a real host that genuinely
    # needs host-level verification like any other SERVER, not a code repository where "SAST/SCA
    # scanning doesn't need host reachability" applies. Confirmed live: gitlab-casmart-server
    # (confirmed SIN_CONEXION -- no SSH credentials available) got a free is_verified=True and a
    # fabricated 85.7% CMMI score purely from this substring collision. Only the actual
    # "GitLab-Repo" asset_type (real code repositories) should get this exception.
    is_gitlab_repo = str(atype).upper() == "GITLAB-REPO"
    status_upper = str(asset.get("status") or "").upper()
    is_genuinely_active = status_upper == "ACTIVE" or bool(asset.get("agent_id"))

    # 3. CM - Configuration Management (new 2026-08-25, real code per manual: "Historial de
    # versiones y release"). Only meaningful for code repositories -- a real Git history is
    # genuine, checkable evidence of version control; a SERVER/infra asset has no repo of its
    # own to check, so it's marked N/A here rather than forced to pass or fail on a question
    # that doesn't apply to it. Evidence comes from the CMMI-GIT-HISTORY-CHECK marker
    # auditor_cmmi_v3.py's check_git_history() logs on every real scan (same pattern as the
    # CIS-BENCHMARK-AUDIT completion marker) -- read from the RAW vulns list (not real_vulns,
    # which excludes markers) since it's a Info-severity marker, not a vulnerability.
    git_marker = next((v for v in vulns if str(v["cve_id"]).upper() == "CMMI-GIT-HISTORY-CHECK"), None)
    if git_marker:
        m = re.search(r"(\d+) commits reales", git_marker.get("description") or "")
        commit_count = int(m.group(1)) if m else 0
        has_git_history = commit_count > 1
    else:
        has_git_history = False
    if is_gitlab_repo:
        if has_git_history:
            cmmi_compliance_details.append({
                "area": "CM (Enabling)",
                "status": "CUMPLE (100%)",
                "passed": True,
                "evidence": "Historial de control de versiones (Git) verificado -- más de un commit real registrado."
            })
            passed_count += 1
        else:
            cmmi_compliance_details.append({
                "area": "CM (Enabling)",
                "status": "NO CUMPLE (Sin Historial Git Verificable)",
                "passed": False,
                "evidence": "No se pudo verificar un historial de control de versiones real (0 o 1 commit, o carpeta sin .git) -- posible carga directa de archivos sin control de cambios."
            })
    else:
        cmmi_compliance_details.append({
            "area": "CM (Enabling)",
            "status": "N/A (no aplica a este tipo de activo)",
            "passed": None,
            "evidence": "Gestión de configuración vía Git solo aplica a repositorios de código; este activo es infraestructura."
        })

    # 4. MC - Monitor and Control (replaces the former fabricated "EST"/"PLAN" connectivity and
    # last-audit checks, merged 2026-08-25). Real MC evidence per the manual is "seguimiento...
    # bitácora (desviación · causa · decisión)" -- ongoing operational monitoring. Both of the old
    # signals (is this asset reachable right now, has it ever been processed by the audit
    # pipeline) are genuinely sub-signals of "is this asset under active monitoring", which MC
    # means; neither one is honestly "estimación" (EST) or a "Plan de proyecto" (PLAN), the real
    # meanings of those two codes, which this scanner has no visibility into at all (see
    # CMMI_V3_NOT_EVALUATED above).
    if (is_genuinely_active or has_cis_grade) and asset.get("last_audit"):
        cmmi_compliance_details.append({
            "area": "MC (Managing)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": f"Monitoreo activo verificado: conectividad real ({asset['endpoint']}) o hardening exitoso, y al menos una auditoría registrada (última: {asset['last_audit']})."
        })
        passed_count += 1
    else:
        missing = []
        if not (is_genuinely_active or has_cis_grade):
            missing.append("sin agente activo ni auditoría de hardening exitosa")
        if not asset.get("last_audit"):
            missing.append("sin fecha de última auditoría registrada")
        cmmi_compliance_details.append({
            "area": "MC (Managing)",
            "status": "NO CUMPLE (Sin Monitoreo Verificado)",
            "passed": False,
            "evidence": f"No hay evidencia real de monitoreo activo sobre este activo ({asset['endpoint']}): {', '.join(missing)}."
        })

    # 5. VV - Verification and Validation / EDR
    # Real bug fixed here: last_scanned can be set even by a FAILED scan attempt (a connection
    # timeout still updates a "last attempted" timestamp in some engines), so this could pass
    # without a single real detection ever having happened. Now requires an actual positive
    # signal: a real (non-synthetic-marker) finding from any engine, a genuinely successful CIS
    # hardening grade, an active EDR agent, or GitLab-Repo (SAST/SCA scanning doesn't need host
    # network reachability at all, so it's a valid signal on its own for that asset type).
    if real_vulns or asset.get("agent_id") or is_gitlab_repo or has_cis_grade:
        cmmi_compliance_details.append({
            "area": "VV (Doing)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": "Escaneos de seguridad automatizados (SAST/SCA) o telemetría EDR activa, con evidencia real registrada."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "VV (Doing)",
            "status": "NO CUMPLE (Sin Verificación)",
            "passed": False,
            "evidence": "Activo sin escaneos periódicos exitosos ni telemetría EDR registrada."
        })

    # Real bug avoided here: dividing by the fixed len(CMMI_V3_PRACTICE_AREAS) would silently
    # punish (or, on a repo, silently never award) the CM area for asset types where it's
    # genuinely N/A ("passed": None, see CM above) -- a SERVER asset would always show 4/5 max
    # (80%) even with everything else passing, which is a fabricated ceiling, not a real score.
    # Excluding N/A entries from the denominator keeps the percentage meaningful for both asset
    # types instead of applying one asset type's evidence gap to the other's score.
    evaluated_areas = [d for d in cmmi_compliance_details if d["passed"] is not None]
    asset_score = round((passed_count / len(evaluated_areas)) * 100, 1) if evaluated_areas else None

    # Real bug fixed here: a never-reached asset (no EDR agent, no successful hardening scan, not
    # a GitLab repo, zero real findings from any engine) would still get a confident numeric CMMI
    # score -- every practice area above defaults to "CUMPLE" purely from the ABSENCE of negative
    # findings, which for an unreached host means nothing was ever actually checked, not that it's
    # genuinely compliant. Confirmed live: Cisco 4 ESXI (a powered-off host, confirmed via CIS
    # Benchmarks SIN_CONEXION) showed 85.7% CMMI compliance despite never having been reached.
    # is_verified surfaces this honestly so the frontend can show "Sin Verificar" instead of a
    # fabricated-looking percentage, and the fleet-wide average (get_cmmi_v3_asset_audit_report)
    # excludes unverified assets instead of letting them silently inflate/deflate it.
    #
    # Second real bug fixed 2026-08-14, found live by a direct user report on a freshly-added
    # workstation: `bool(asset.get("agent_id"))` used to count as its own sufficient "verified"
    # signal here, but a Wazuh agent enrolling only proves EDR telemetry connectivity -- it says
    # nothing about whether any ISO/CMMI-relevant audit (CIS hardening, SAST/SCA) has actually
    # run. Confirmed live: a brand-new AppServer asset showed CMMI/ISO 100% within seconds of
    # being added (the agent connects almost instantly) while its own card honestly showed
    # "CIS: NO EVALUADO" right next to it -- the two facts contradicted each other on the same
    # screen. agent_id is still real, valid evidence for the VV/EST *practice areas* above (a
    # narrower, correctly-scoped claim: "this host is reachable"), just not for the broader
    # "a compliance audit has actually happened" gate.
    is_verified = bool(real_vulns) or has_cis_grade or is_gitlab_repo

    return {
        "asset_name": aname,
        "asset_type": atype,
        "endpoint": asset["endpoint"],
        "cmmi_compliance_percentage": asset_score,
        "cmmi_maturity_level": (
            None if asset_score is None else
            "CMMI Nivel 5 (Optimizing)" if asset_score >= 90 else
            "CMMI Nivel 3 (Defined)" if asset_score >= 70 else
            "CMMI Nivel 1 (Initial)"
        ),
        "active_vulnerabilities_count": len(vulns),
        "areas_not_evaluated": CMMI_V3_NOT_EVALUATED,
        "practice_areas_breakdown": cmmi_compliance_details,
        "is_verified": is_verified
    }


def get_cmmi_v3_asset_audit_report(asset_id_filter: int = None) -> Dict[str, Any]:
    """
    Generates an exhaustive, truthful per-asset CMMI v3.0 audit report.
    Evaluates real code findings, pipeline controls, vault status, and EDR telemetry
    against CMMI v3.0 Practice Areas (Level 3 & Level 5 Benchmark).

    Opens its own cursor -- callers that already hold an open cursor (e.g. an endpoint that's
    mid-way through its own query) must call evaluate_cmmi_v3_for_asset(cur, asset) directly
    instead, passing their own cursor, to avoid a nested pool.getconn() deadlock (see that
    function's docstring for the real incident this caused).
    """
    report = {
        "benchmark_model": "CMMI v3.0 (Model 2024-2026 Enterprise)",
        "total_assets_audited": 0,
        "overall_cmmi_compliance_rate": 0.0,
        "practice_areas_evaluated": CMMI_V3_PRACTICE_AREAS,
        "practice_areas_not_evaluated": CMMI_V3_NOT_EVALUATED,
        "assets_audit": []
    }

    try:
        from psycopg2.extras import RealDictCursor
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            if asset_id_filter is not None:
                cur.execute("""
                    SELECT id, asset_name, asset_type, endpoint, status, agent_id, criticality, last_scanned, last_audit, cis_grade
                    FROM public.infra_inventory
                    WHERE id = %s
                """, (asset_id_filter,))
            else:
                cur.execute("""
                    SELECT id, asset_name, asset_type, endpoint, status, agent_id, criticality, last_scanned, last_audit, cis_grade
                    FROM public.infra_inventory
                    ORDER BY asset_name ASC
                """)
            assets = cur.fetchall()
            report["total_assets_audited"] = len(assets)

            # Single bulk query for every asset's open vulnerabilities, instead of one query per
            # asset (83 sequential blocking round trips) -- see evaluate_cmmi_v3_for_asset()'s
            # docstring for the real production outage this N+1 pattern caused. Matches the same
            # (asset_id = X OR url_path ILIKE '%name%') logic per-asset used to apply, just
            # evaluated in Python over one fetched result set instead of in SQL per asset.
            cur.execute("""
                SELECT asset_id, cve_id, severity, description, status, scan_engine, url_path
                FROM public.vulnerability_log
                WHERE status IN ('OPEN', 'NEW', 'CORRELATED')
            """)
            all_vulns = cur.fetchall()

            total_scores = []

            for asset in assets:
                aid = asset["id"]
                aname_lower = asset["asset_name"].lower()
                asset_vulns = [
                    v for v in all_vulns
                    if v["asset_id"] == aid or (v["url_path"] and aname_lower in v["url_path"].lower())
                ]
                asset_result = evaluate_cmmi_v3_for_asset(cur, asset, vulns=asset_vulns)
                # Unverified assets (never reached by any engine -- see is_verified's docstring
                # in evaluate_cmmi_v3_for_asset) are excluded from the fleet average, the same way
                # CIS Benchmarks' SIN_CONEXION assets are excluded from its own percentage instead
                # of silently averaging in a score for something that was never actually checked.
                if asset_result["is_verified"]:
                    total_scores.append(asset_result["cmmi_compliance_percentage"])
                report["assets_audit"].append(asset_result)

            if total_scores:
                report["overall_cmmi_compliance_rate"] = round(sum(total_scores) / len(total_scores), 1)

    except Exception as e:
        print(f"⚠️ [Compliance-Mapper] Error generating CMMI v3.0 audit report: {e}")

    return report


def compute_iso_control_coverage(vulns: list) -> Dict[str, Any]:
    """
    Real, control-universe-coverage ISO 27001/25010 score: percentage of the fixed, real set
    of ISO controls in COMPLIANCE_MAPPING_MATRIX with ZERO active violations among `vulns`.

    Single source of truth for this exact methodology, extracted so the fleet-wide KPI
    (main.py's GET /api/stats), the per-asset deep-details view
    (GET /api/inventory/{name}/details), and the per-asset bulk report
    (get_iso27001_asset_audit_report below, used by the inventory grid cards) all compute the
    IDENTICAL number for the same input instead of drifting into disagreeing formulas -- the
    exact failure mode already fixed once for this file (see get_asset_deep_details()'s own
    comment on the "third, inconsistent ad-hoc keyword formula" it replaced). Before this
    extraction, get_iso27001_asset_audit_report() had its own fourth, different formula (a
    hand-picked set of 6 pass/fail categories) that would have shown a different percentage
    for the same asset than the deep-details modal right next to it in the UI.
    """
    violated_controls = set()
    control_findings: Dict[str, list] = {}
    for v in vulns:
        cve = str(v.get("cve_id", ""))
        matched_key = next((k for k in COMPLIANCE_MAPPING_MATRIX if k in cve), None)
        control = COMPLIANCE_MAPPING_MATRIX[matched_key].get("ISO_27001", "A.8.16 (Monitoring & Controls)") if matched_key else "A.8.16 (Monitoring & Controls)"
        violated_controls.add(control)
        control_findings.setdefault(control, []).append(v)

    iso_control_universe = sorted(set(x["ISO_27001"] for x in COMPLIANCE_MAPPING_MATRIX.values()) | {"A.8.16 (Monitoring & Controls)"})
    score = round(100 * (1 - len(violated_controls) / len(iso_control_universe)), 1)

    breakdown = []
    for control in iso_control_universe:
        fails = control_findings.get(control)
        if fails:
            breakdown.append({
                "area": control, "status": f"NO CUMPLE ({len(fails)} hallazgos)", "passed": False,
                "evidence": f"{fails[0].get('cve_id', '')}: {str(fails[0].get('description', ''))[:120]}"
            })
        else:
            breakdown.append({
                "area": control, "status": "CUMPLE (100%)", "passed": True,
                "evidence": "Sin violaciones activas de este control."
            })

    return {
        "score": score,
        "breakdown": breakdown,
        "control_universe_size": len(iso_control_universe),
        "violated_count": len(violated_controls),
    }


def evaluate_iso27001_for_asset(cur, asset: Dict[str, Any], vulns: list = None) -> Dict[str, Any]:
    """
    Evaluates ISO 27001:2022/25010 compliance for a single asset, using an ALREADY-OPEN cursor
    -- same calling convention as evaluate_cmmi_v3_for_asset() (see that function's docstring
    for the real nested-cursor deadlock this avoids), and the SAME real scoring methodology
    already used by get_asset_deep_details()'s per-asset `iso_score` and GET /api/stats'
    fleet-wide `iso_compliance_percentage` -- see compute_iso_control_coverage()'s docstring.

    Replaces the inventory grid card's previous `Math.max(0, 100 - (vulnerability_count * 12))%`
    estimate (Dashboard.jsx), which saturated at a flat 0% for any asset with more than ~8 open
    findings -- true for nearly every real asset with SAST/SCA/SonarQube coverage, making the
    number uninformative for almost the entire fleet.
    """
    aid = asset["id"]
    aname = asset["asset_name"]
    atype = asset["asset_type"]

    if vulns is None:
        cur.execute("""
            SELECT cve_id, severity, description, status, scan_engine, url_path
            FROM public.vulnerability_log
            WHERE (asset_id = %s OR url_path ILIKE %s) AND status IN ('OPEN', 'NEW', 'CORRELATED')
        """, (aid, f"%{aname}%"))
        vulns = cur.fetchall()

    # Same synthetic-marker exclusion as evaluate_cmmi_v3_for_asset() -- these are Centinela's
    # own status markers, not real findings, and would otherwise collide on bare substrings
    # (see that function's docstring for the real Cisco 4 ESXI incident this class of bug caused).
    SYNTHETIC_MARKER_PREFIXES = ("CTI-IOC-MATCH", "BLOODHOUND-PATH")
    SYNTHETIC_MARKER_EXACT = {"HOST-CONTAINMENT-REQUEST", "SCAN-AUDIT", "HEURISTIC-SECURITY-DEBT",
                               "CIS-BENCHMARK-AUDIT", "SONARQUBE-QUALITY-GATE"}
    real_vulns = [
        v for v in vulns
        if str(v["cve_id"]).upper() not in SYNTHETIC_MARKER_EXACT
        and not str(v["cve_id"]).upper().startswith(SYNTHETIC_MARKER_PREFIXES)
    ]

    coverage = compute_iso_control_coverage(real_vulns)

    # Verification gate -- same reasoning as evaluate_cmmi_v3_for_asset()'s is_verified: an
    # asset never actually reached by any engine would otherwise get a confident 100% purely
    # from the ABSENCE of findings, which means nothing was checked, not that it's compliant.
    # agent_id deliberately excluded (see evaluate_cmmi_v3_for_asset()'s matching comment,
    # 2026-08-14): a Wazuh agent enrolling proves EDR connectivity, not that any ISO-relevant
    # audit (CIS hardening, SAST/SCA) has actually run against this asset.
    has_cis_grade = asset.get("cis_grade") is not None
    is_gitlab_repo = str(atype).upper() == "GITLAB-REPO"
    is_verified = bool(real_vulns) or has_cis_grade or is_gitlab_repo

    return {
        "asset_name": aname,
        "asset_type": atype,
        "endpoint": asset["endpoint"],
        "iso_compliance_percentage": coverage["score"],
        "active_vulnerabilities_count": len(vulns),
        "control_areas_breakdown": coverage["breakdown"],
        "is_verified": is_verified
    }


def get_iso27001_asset_audit_report(asset_id_filter: int = None) -> Dict[str, Any]:
    """
    Generates an exhaustive, truthful per-asset ISO 27001/25010 audit report -- see
    evaluate_iso27001_for_asset()'s docstring for what it replaces and why. Mirrors
    get_cmmi_v3_asset_audit_report()'s exact structure (bulk vulnerability fetch instead of
    one query per asset -- see evaluate_cmmi_v3_for_asset()'s docstring for the real production
    outage an N+1 version of this caused for CMMI).
    """
    report = {
        "benchmark_model": "ISO 27001:2022 (Annex A) + ISO/IEC 25010",
        "total_assets_audited": 0,
        "overall_iso_compliance_rate": 0.0,
        "control_areas_evaluated": sorted(set(v["ISO_27001"] for v in COMPLIANCE_MAPPING_MATRIX.values()) | {"A.8.16 (Monitoring & Controls)"}),
        "assets_audit": []
    }

    try:
        from psycopg2.extras import RealDictCursor
        with db_manager.get_db_cursor(cursor_factory=RealDictCursor) as cur:
            if asset_id_filter is not None:
                cur.execute("""
                    SELECT id, asset_name, asset_type, endpoint, status, agent_id, criticality, last_scanned, last_audit, cis_grade
                    FROM public.infra_inventory
                    WHERE id = %s
                """, (asset_id_filter,))
            else:
                cur.execute("""
                    SELECT id, asset_name, asset_type, endpoint, status, agent_id, criticality, last_scanned, last_audit, cis_grade
                    FROM public.infra_inventory
                    ORDER BY asset_name ASC
                """)
            assets = cur.fetchall()
            report["total_assets_audited"] = len(assets)

            cur.execute("""
                SELECT asset_id, cve_id, severity, description, status, scan_engine, url_path
                FROM public.vulnerability_log
                WHERE status IN ('OPEN', 'NEW', 'CORRELATED')
            """)
            all_vulns = cur.fetchall()

            total_scores = []

            for asset in assets:
                aid = asset["id"]
                aname_lower = asset["asset_name"].lower()
                asset_vulns = [
                    v for v in all_vulns
                    if v["asset_id"] == aid or (v["url_path"] and aname_lower in v["url_path"].lower())
                ]
                asset_result = evaluate_iso27001_for_asset(cur, asset, vulns=asset_vulns)
                if asset_result["is_verified"]:
                    total_scores.append(asset_result["iso_compliance_percentage"])
                report["assets_audit"].append(asset_result)

            if total_scores:
                report["overall_iso_compliance_rate"] = round(sum(total_scores) / len(total_scores), 1)

    except Exception as e:
        print(f"⚠️ [Compliance-Mapper] Error generating ISO 27001/25010 audit report: {e}")

    return report
