"""
What each scan engine has REALLY produced -- as opposed to "the binary is installed".

Until 2026-10-12 /api/health reported engines as Online merely because their executables exist (e.g. "Secrets Scanner (TruffleHog)"), while the
database held 0 rows from them (the fleet pipeline never called them). This module answers from vulnerability_log: rows, last detection, and a state:

  ACTIVO        the engine is expected to run on a schedule and has a detection within its window
  OBSOLETO      expected on a schedule, but its newest row is older than the window
  SIN_DATOS     expected on a schedule, and it has NEVER written a row. For an engine that only writes when it finds something, this is ambiguous
                (not running vs. nothing to report) -- the label says so instead of claiming either
  BAJO_DEMANDA  runs only when a person asks for it / opt-in by design: no staleness judgement
  DESACTIVADO   knowingly off (reason given)
"""
from typing import Any, Dict, List, Optional

# engine -> (label, mode, window_days, note)
REGISTRY: Dict[str, tuple] = {
    "sonarqube": ("SonarQube (calidad y seguridad de código)", "scheduled", 3, ""),
    "sast-native": ("SAST nativo (incluye reglas de arquitectura)", "scheduled", 3, ""),
    "semgrep": ("Semgrep (SAST multilenguaje)", "scheduled", 3, ""),
    "sca-native": ("SCA nativo (OSV.dev)", "scheduled", 3, ""),
    "sca-license": ("Licencias de dependencias (syft)", "scheduled", 3, "solo escribe si hay licencias de riesgo"),
    "standards-audit": ("Estándares (ISO 25010 / STRIDE)", "scheduled", 3, ""),
    "authz-static": ("Autorización estática (@PreAuthorize)", "scheduled", 3, ""),
    "accessibility-wcag": ("Accesibilidad WCAG estática", "scheduled", 3, ""),
    "cmmi-audit": ("CMMI (5 áreas evaluables)", "scheduled", 3, ""),
    "gitlab-config": ("Configuración de GitLab y CI/CD", "scheduled", 3, ""),
    "api-contract": ("Contrato de API (rutas vs OpenAPI)", "scheduled", 3, "solo escribe si hay deriva o falta de contrato"),
    "secrets": ("Secretos en el historial git (TruffleHog)", "scheduled", 10, "semanal por proyecto; solo escribe si encuentra secretos"),
    "zap": ("DAST (OWASP ZAP)", "scheduled", 7, ""),
    "wstg-perimeter": ("WSTG perimetral", "scheduled", 7, ""),
    "nuclei-ext": ("Nuclei", "scheduled", 7, ""),
    "tls-audit": ("Postura TLS", "scheduled", 10, ""),
    "os-patch": ("Parches del SO", "scheduled", 10, ""),
    "cis-benchmark": ("CIS Benchmarks (hardening)", "scheduled", 10, ""),
    "db-hardening": ("Hardening de bases de datos", "scheduled", 10, ""),
    "dns-security": ("DNS y autenticación de correo", "on_demand", None, "sin dominios públicos registrados: no hay nada que auditar (decisión del dueño, 12-oct-2026)"),
    "wcag-render": ("Accesibilidad renderizada (axe)", "scheduled", 7, "solo la página de entrada"),
    "authz-dast": ("Control de acceso dinámico (multi-rol)", "on_demand", None, "requiere credenciales multi-rol en Vault"),
    "runtime-session": ("Sesión en navegador (consola, datos personales, 401/403)", "on_demand", None, "requiere credenciales de prueba por perfil (Vault)"),
    "smart-tests": ("Pruebas funcionales (centinela-smart-tests)", "on_demand", None, "solo fallos de control de acceso enviados por centinela-smart-tests"),
    "dependency-probe": ("Dependencias externas de la configuración", "scheduled", 3, "solo escribe si una dependencia declarada no responde"),
    "trivy-image": ("Imágenes de contenedor propias (Trivy)", "on_demand", None, "scripts/scan_own_images.py"),
    "osint-passive": ("OSINT pasivo", "on_demand", None, ""),
    "ffuf": ("Descubrimiento de rutas (ffuf)", "on_demand", None, ""),
    "api-fuzz": ("Fuzzing de API (Schemathesis)", "on_demand", None, "opt-in: SCHEMATHESIS_TARGETS; nunca contra la pila de Centinela"),
    "llm-governance": ("Gobernanza LLM", "on_demand", None, ""),
    "shadow-api-native": ("APIs sombra de la propia plataforma", "on_demand", None, ""),
    "trivy-config": ("Configuración insegura de Dockerfile/Kubernetes (trivy config)", "scheduled", 7, "Dockerfile, Kubernetes y Terraform"),
    "heuristics-engine": ("Motor de heurísticas (correlación temporal)", "on_demand", None, "genera hallazgos derivados de otros eventos"),
    "iac-native": ("IaC nativo (Dockerfile/K8s/Terraform)", "on_demand", None, ""),
    "spiderfoot": ("SpiderFoot (OSINT)", "on_demand", None, ""),
    "claude-code-manual-review": ("Revisión manual asistida", "on_demand", None, "hallazgos cargados a mano tras una revisión"),
    "checkov": ("Checkov (IaC)", "on_demand", None, "solo en la ruta antigua de repositorios locales"),
}


def classify(mode: str, window_days: Optional[int], rows_total: int, days_since: Optional[float]) -> str:
    if mode == "disabled":
        return "DESACTIVADO"
    if mode == "on_demand":
        return "BAJO_DEMANDA"
    if rows_total == 0 or days_since is None:
        return "SIN_DATOS"
    return "ACTIVO" if days_since <= (window_days or 7) else "OBSOLETO"


def compute(rows: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """rows: {engine: {open, total, days_since}} as read from the DB. Returns one entry per registered engine plus any unregistered engine seen."""
    out = []
    for eng, (label, mode, window, note) in REGISTRY.items():
        r = rows.get(eng) or {"open": 0, "total": 0, "days_since": None}
        out.append({"engine": eng, "label": label, "mode": mode, "state": classify(mode, window, r["total"], r["days_since"]), "open": r["open"],
                    "total": r["total"], "days_since_last": None if r["days_since"] is None else round(r["days_since"], 1), "note": note})
    for eng, r in rows.items():
        if eng and eng not in REGISTRY:
            out.append({"engine": eng, "label": eng, "mode": "unregistered", "state": "NO_REGISTRADO", "open": r["open"], "total": r["total"],
                        "days_since_last": None if r["days_since"] is None else round(r["days_since"], 1), "note": "motor presente en la BD pero no declarado en core/engine_status.py"})
    return out


def read_rows(cur) -> Dict[str, Dict[str, Any]]:
    cur.execute("""SELECT scan_engine,
                          count(*) FILTER (WHERE status NOT IN ('RESOLVED','SUPPRESSED')),
                          count(*),
                          EXTRACT(EPOCH FROM (now() - max(detected_at))) / 86400.0
                   FROM vulnerability_log WHERE scan_engine IS NOT NULL GROUP BY 1""")
    return {e: {"open": o, "total": t, "days_since": d} for e, o, t, d in cur.fetchall()}


def health_summary(entries: List[Dict[str, Any]]) -> str:
    """One status string for /api/health, in the vocabulary the dashboard already colours (Online / Stale / No Data)."""
    sched = [e for e in entries if e["mode"] == "scheduled"]
    bad = [e for e in sched if e["state"] in ("OBSOLETO", "SIN_DATOS")]
    if not bad:
        return "Online"
    names = ", ".join(e["engine"] for e in bad[:6]) + (f" y {len(bad) - 6} más" if len(bad) > 6 else "")
    return f"Stale ({len(sched) - len(bad)} de {len(sched)} motores programados con datos recientes; sin datos/obsoletos: {names})"
