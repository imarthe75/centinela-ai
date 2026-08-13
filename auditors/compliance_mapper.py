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
        "CMMI_V3": "MSR (Measurement & Performance Level 5)"
    },
    "CMMI-PQA-DEBT-TODO": {
        "ISO_27001": "A.8.9 (Configuration Management)",
        "NIST_800_53": "CM-6 (Configuration Settings)",
        "PCI_DSS": "Req 6.5 (Software Quality)",
        "SOC_2": "CC6.8 (Hardening)",
        "GDPR": "Art 32 (Quality Control)",
        "CMMI_V3": "PQA (Process Quality Assurance Level 5)"
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


CMMI_V3_PRACTICE_AREAS = [
    {"code": "CAR", "name": "Causal Analysis and Resolution", "level": "Level 5", "desc": "Identificación de causa raíz de defectos y automatización de acciones correctivas."},
    {"code": "SAM", "name": "Supplier Agreement Management", "level": "Level 3-5", "desc": "Auditoría de componentes de terceros, librerías open-source y dependencias (SCA)."},
    {"code": "MSR", "name": "Managing Performance and Measurement", "level": "Level 5", "desc": "Métricas cuantitativas de desempeño de software, mantenibilidad y ausencia de parches duros."},
    {"code": "PQA", "name": "Process Quality Assurance", "level": "Level 3-5", "desc": "Aseguramiento de estándares de calidad de proceso, control de secretos y cero deuda técnica."},
    {"code": "EST", "name": "Estimating & Resource Management", "level": "Level 3", "desc": "Planificación y asignación adecuada de recursos de infraestructura y capacidad."},
    {"code": "PLAN", "name": "Planning & Project Execution", "level": "Level 3", "desc": "Trazabilidad de cambios mediante parches auditados y Merge Requests en control de versiones."},
    {"code": "VV", "name": "Verification and Validation", "level": "Level 3-5", "desc": "Pruebas de seguridad automatizadas (SAST/DAST/EDR) antes de paso a producción."}
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

    # 1. CAR (Level 5) - Causal Analysis & Remediation
    car_fails = [v for v in real_vulns if "INJECTION" in v["cve_id"] or "SWALLOWED" in v["cve_id"] or "CAR" in v["cve_id"]]
    if not car_fails:
        cmmi_compliance_details.append({
            "area": "CAR (Level 5)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": "Sin fallas de inyección ni supresión de excepciones. Causa raíz mitigada en código."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "CAR (Level 5)",
            "status": f"NO CUMPLE ({len(car_fails)} fallas)",
            "passed": False,
            "evidence": f"Detectadas {len(car_fails)} desviaciones graves de análisis de causa raíz ({car_fails[0]['cve_id']})."
        })

    # 2. SAM (Level 3-5) - Supplier Agreement Management / SCA
    sam_fails = [v for v in real_vulns if "SCA" in v["cve_id"] or "CVE" in v["cve_id"] or "DEP" in v["cve_id"]]
    if not sam_fails:
        cmmi_compliance_details.append({
            "area": "SAM (Level 3-5)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": "Librerías de terceros y paquetes open-source actualizados sin vulnerabilidades conocidas."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "SAM (Level 3-5)",
            "status": f"NO CUMPLE ({len(sam_fails)} dependencias vulnerables)",
            "passed": False,
            "evidence": f"Librerías desactualizadas detectadas ({sam_fails[0]['cve_id']}). Requiere actualización de componentes."
        })

    # 3. MSR (Level 5) - Measurement & Performance
    msr_fails = [v for v in real_vulns if "DEBT" in v["cve_id"] or "SLEEP" in v["cve_id"] or "COMPLEXITY" in v["cve_id"]]
    if not msr_fails:
        cmmi_compliance_details.append({
            "area": "MSR (Level 5)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": "Rendimiento optimizado. Ausencia de retardos duros (sleep) y complejidad de código bajo límites (<15)."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "MSR (Level 5)",
            "status": f"NO CUMPLE ({len(msr_fails)} ineficiencias)",
            "passed": False,
            "evidence": f"Detectados antipatrones de desempeño o complejidad excesiva ({msr_fails[0]['cve_id']})."
        })

    # 4. PQA (Level 3-5) - Process Quality Assurance
    pqa_fails = [v for v in real_vulns if "HARDCODED" in v["cve_id"] or "SECRET" in v["cve_id"] or "TODO" in v["cve_id"]]
    if not pqa_fails:
        cmmi_compliance_details.append({
            "area": "PQA (Level 3-5)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": "Aseguramiento de calidad verificado. Sin credenciales expuestas ni remanentes TODO/Mocks en fuentes."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "PQA (Level 3-5)",
            "status": f"NO CUMPLE ({len(pqa_fails)} violaciones de calidad)",
            "passed": False,
            "evidence": f"Halladas violaciones de aseguramiento de calidad o credenciales expuestas ({pqa_fails[0]['cve_id']})."
        })

    # Real, positive verification signals for this asset -- used by EST/VV below and by the
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

    # 5. EST (Level 3) - Resource Management / Connectivity
    # Real bug fixed here: this used to also pass on `asset["endpoint"]` being merely non-empty --
    # in practice nearly every asset has SOME endpoint string set (even a broken one like
    # "remote-agent" or an unreachable IP), so this almost never actually failed regardless of
    # real connectivity. Also fixed a case-sensitivity bug: compared status to lowercase "active"
    # while every real value in this column is uppercase ("ACTIVE"), so is_online was silently
    # False for every real asset even before the weak endpoint fallback papered over it.
    if is_genuinely_active or has_cis_grade:
        cmmi_compliance_details.append({
            "area": "EST (Level 3)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": f"Conectividad real verificada ({asset['endpoint']}): agente activo o auditoría de hardening exitosa."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "EST (Level 3)",
            "status": "NO CUMPLE (Sin Verificar)",
            "passed": False,
            "evidence": f"No hay evidencia real de que este activo ({asset['endpoint']}) haya respondido: sin agente activo ni auditoría de hardening exitosa."
        })

    # 6. PLAN (Level 3) - Planning & Git MR Version Control
    # Real bug fixed here: this always returned CUMPLE (100%) unconditionally, for every asset,
    # regardless of any real evidence -- a hardcoded result presented as a verified finding,
    # exactly what this project's own rules prohibit. last_audit is a real timestamp set when the
    # discovery/audit pipeline has actually processed this asset at least once; used here as
    # genuine (if imperfect) evidence of pipeline traceability instead of a constant.
    if asset.get("last_audit"):
        cmmi_compliance_details.append({
            "area": "PLAN (Level 3)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": f"Activo procesado por el pipeline de auditoría SOAR (última auditoría: {asset['last_audit']})."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "PLAN (Level 3)",
            "status": "NO CUMPLE (Sin Auditoría Registrada)",
            "passed": False,
            "evidence": "Este activo nunca ha sido procesado por el pipeline de auditoría SOAR (sin fecha de última auditoría)."
        })

    # 7. VV (Level 3-5) - Verification & Validation / EDR
    # Real bug fixed here: last_scanned can be set even by a FAILED scan attempt (a connection
    # timeout still updates a "last attempted" timestamp in some engines), so this could pass
    # without a single real detection ever having happened. Now requires an actual positive
    # signal: a real (non-synthetic-marker) finding from any engine, a genuinely successful CIS
    # hardening grade, an active EDR agent, or GitLab-Repo (SAST/SCA scanning doesn't need host
    # network reachability at all, so it's a valid signal on its own for that asset type).
    if real_vulns or asset.get("agent_id") or is_gitlab_repo or has_cis_grade:
        cmmi_compliance_details.append({
            "area": "VV (Level 3-5)",
            "status": "CUMPLE (100%)",
            "passed": True,
            "evidence": "Escaneos de seguridad automatizados (SAST/SCA) o telemetría EDR activa, con evidencia real registrada."
        })
        passed_count += 1
    else:
        cmmi_compliance_details.append({
            "area": "VV (Level 3-5)",
            "status": "NO CUMPLE (Sin Verificación)",
            "passed": False,
            "evidence": "Activo sin escaneos periódicos exitosos ni telemetría EDR registrada."
        })

    asset_score = round((passed_count / len(CMMI_V3_PRACTICE_AREAS)) * 100, 1)

    # Real bug fixed here: a never-reached asset (no EDR agent, no successful hardening scan, not
    # a GitLab repo, zero real findings from any engine) would still get a confident numeric CMMI
    # score -- every practice area above defaults to "CUMPLE" purely from the ABSENCE of negative
    # findings, which for an unreached host means nothing was ever actually checked, not that it's
    # genuinely compliant. Confirmed live: Cisco 4 ESXI (a powered-off host, confirmed via CIS
    # Benchmarks SIN_CONEXION) showed 85.7% CMMI compliance despite never having been reached.
    # is_verified surfaces this honestly so the frontend can show "Sin Verificar" instead of a
    # fabricated-looking percentage, and the fleet-wide average (get_cmmi_v3_asset_audit_report)
    # excludes unverified assets instead of letting them silently inflate/deflate it.
    is_verified = bool(real_vulns) or has_cis_grade or bool(asset.get("agent_id")) or is_gitlab_repo

    return {
        "asset_name": aname,
        "asset_type": atype,
        "endpoint": asset["endpoint"],
        "cmmi_compliance_percentage": asset_score,
        "cmmi_maturity_level": "CMMI Nivel 5 (Optimizing)" if asset_score >= 90 else "CMMI Nivel 3 (Defined)" if asset_score >= 70 else "CMMI Nivel 1 (Initial)",
        "active_vulnerabilities_count": len(vulns),
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
    has_cis_grade = asset.get("cis_grade") is not None
    is_gitlab_repo = str(atype).upper() == "GITLAB-REPO"
    is_verified = bool(real_vulns) or has_cis_grade or bool(asset.get("agent_id")) or is_gitlab_repo

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
