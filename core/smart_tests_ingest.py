"""Ingestion of functional-test results from centinela-smart-tests (ADR-0015). Only failures with security impact become findings:
everything else stays in centinela-smart-tests.

Accepted item: a `centinela_core.results.CaseResult` with status FAILED, `security_relevant=True`, evidence (the model enforces it) and
`meta.category` in one of the SUPPORTED categories below (a few aliases are tolerated). Any other category is rejected with the reason,
not stored. `meta.severity` (CRITICAL/HIGH/MEDIUM/LOW) overrides the category's default; anything else falls back to that default.
The asset must already exist (by exact name): this endpoint never creates assets.
Location (`url_path`) = `smart-tests:<project>:<case_id>`, so re-running the same case updates the same finding (deduplicated by
fingerprint) instead of adding rows.

Supported categories map to a genuine security concern each — adding a new one here is the only change needed for
centinela-smart-tests to start sending that failure type (and the sender must tag the case with that `meta.category`).

OBSERVATION categories (ADR-0002 of centinela-smart-tests): the generic checks also report usability and accessibility failures seen
on the running application. They are NOT security failures (no `security_relevant`), and they are stored under the static detector's
own rule id in `meta.rule` (usability: a fixed allowlist; accessibility: `WCAG-<criterion>-AXE-<rule>` with a WCAG 2.1 A/AA criterion),
so the same problem seen in code and at runtime reads as the same rule. Anything outside those lists is rejected, never guessed.
"""
import re
from typing import Any, Dict, List, Tuple

from centinela_core.results import CaseResult, ResultError, Status

from core import deduplication_engine as de

ENGINE = "smart-tests"

# category -> (rule_id, default_severity, Spanish label for the description, CWE reference)
CATEGORIES: Dict[str, Tuple[str, str, str, str]] = {
    "access_control":          ("SMART-TESTS-ACCESS-CONTROL-FAILURE",     "HIGH",   "control de acceso",            "CWE-284"),
    "authentication":          ("SMART-TESTS-AUTHENTICATION-FAILURE",     "HIGH",   "autenticación",                "CWE-287"),
    "session_management":      ("SMART-TESTS-SESSION-MANAGEMENT-FAILURE", "HIGH",   "gestión de sesión",            "CWE-384"),
    "sensitive_data_exposure": ("SMART-TESTS-SENSITIVE-DATA-EXPOSURE",    "HIGH",   "exposición de datos sensibles", "CWE-200"),
    "input_validation":        ("SMART-TESTS-INPUT-VALIDATION-FAILURE",   "MEDIUM", "validación de entrada",        "CWE-20"),
    "data_integrity":          ("SMART-TESTS-DATA-INTEGRITY-FAILURE",     "MEDIUM", "integridad de datos",          "CWE-345"),
    "audit_logging":           ("SMART-TESTS-AUDIT-LOGGING-GAP",          "MEDIUM", "registro de auditoría",        "CWE-778"),
}

# Tolerated spellings a sender might use; each maps to a real supported category. Kept small and explicit so a typo can't
# silently become a different category — an unlisted value is rejected, never guessed.
ALIASES: Dict[str, str] = {
    "authz": "access_control",
    "authorization": "access_control",
    "rbac": "access_control",
    "authn": "authentication",
    "login": "authentication",
    "session": "session_management",
    "data_exposure": "sensitive_data_exposure",
    "pii": "sensitive_data_exposure",
    "validation": "input_validation",
    "integrity": "data_integrity",
    "uniqueness": "data_integrity",
    "logging": "audit_logging",
    "audit": "audit_logging",
    "bitacora": "audit_logging",
}

USABILITY_RULES = {"ANGULAR-SUBMIT-NO-BUSY-GUARD", "DESTRUCTIVE-ACTION-NO-CONFIRM", "NATIVE-BROWSER-DIALOG",
                   "SMART-TESTS-FORM-INVALID-SUBMITTED", "SMART-TESTS-FORM-NO-FIELD-ERROR"}
_AXE_RULE = re.compile(r"^WCAG-(\d\.\d\.\d+)-AXE-[A-Z0-9-]{2,60}$")
OBSERVATION_CATEGORIES = {"usability": "usabilidad", "accessibility": "accesibilidad"}

# Back-compat: some callers/tests reference these names directly.
SUPPORTED_CATEGORIES = {k: v[0] for k, v in CATEGORIES.items()}
RULE_ACCESS_CONTROL = CATEGORIES["access_control"][0]
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
MAX_ITEMS = 200


class IngestError(ValueError):
    pass


def _resolve_category(raw_cat: str) -> str:
    """Normalises a sender-supplied category to a supported key, or returns "" if unsupported."""
    cat = (raw_cat or "").strip().lower()
    if cat in CATEGORIES:
        return cat
    return ALIASES.get(cat, "")


def _observation_rule(category: str, raw_rule: str) -> str:
    """The rule id for an observation finding, or "" when it is not an accepted one."""
    rule = (raw_rule or "").strip().upper()
    if category == "usability":
        return rule if rule in USABILITY_RULES else ""
    m = _AXE_RULE.match(rule)
    if not m:
        return ""
    from core.coverage_matrix import WCAG_21_AA
    return rule if m.group(1) in WCAG_21_AA else ""


def _observation_description(r: CaseResult, run: Dict[str, Any], category: str, rule: str) -> str:
    ev = "; ".join(f"{e.kind}: {e.value}" + (f" ({e.note[:160]})" if e.note else "") for e in r.evidence[:6])
    parts = [
        f"**Observado en ejecución: hallazgo de {OBSERVATION_CATEGORIES[category]}** (`{rule}`) — comprobación `{r.case_id}` "
        f"({r.criterion or 's/criterio'}) del proyecto `{run.get('project', '?')}`, ciclo `{run.get('cycle', '?')}`, ejecutada por "
        f"centinela-smart-tests ({run.get('finished', '?')}) sobre la aplicación desplegada, con sesión iniciada.",
        f"Observado: {r.detail}" if r.detail else "",
        f"Evidencia: {ev}" if ev else "",
        "Límite: observación en un ambiente no productivo con perfiles de prueba; la evidencia completa (capturas) está en el reporte de "
        "centinela-smart-tests.",
    ]
    return "\n\n".join(p for p in parts if p)


def _description(r: CaseResult, run: Dict[str, Any], category: str) -> str:
    rule, _sev, label, cwe = CATEGORIES[category]
    ev = "; ".join(f"{e.kind}: {e.value}" + (f" ({e.note[:160]})" if e.note else "") for e in r.evidence[:6])
    parts = [
        f"**Prueba funcional fallida con impacto en {label}** ({cwe}) — caso `{r.case_id}` ({r.criterion or 's/criterio'}) del proyecto "
        f"`{run.get('project', '?')}`, ciclo `{run.get('cycle', '?')}`, ejecutado por centinela-smart-tests ({run.get('finished', '?')}).",
        f"Observado: {r.detail}" if r.detail else "",
        f"Evidencia: {ev}" if ev else "",
        f"Sustitución declarada en la ejecución: {r.substitution}" if r.substitution else "",
        "Límite: resultado de una prueba funcional con perfiles de prueba en un ambiente no productivo; la evidencia completa está en el "
        "reporte de centinela-smart-tests.",
    ]
    return "\n\n".join(p for p in parts if p)


def validate(payload: Dict[str, Any]) -> Tuple[List[Tuple[CaseResult, str, str]], List[Dict[str, str]]]:
    """Returns ([(result, rule_id, severity)], [{case_id, reason}]) without touching the database."""
    if not isinstance(payload, dict):
        raise IngestError("el cuerpo debe ser un objeto JSON")
    if not (payload.get("asset_name") or "").strip():
        raise IngestError("falta asset_name")
    items = payload.get("results")
    if not isinstance(items, list) or not items:
        raise IngestError("results debe ser una lista no vacía")
    if len(items) > MAX_ITEMS:
        raise IngestError(f"máximo {MAX_ITEMS} resultados por envío")
    accepted, rejected = [], []
    for raw in items:
        cid = str((raw or {}).get("case_id", "?"))
        try:
            r = CaseResult.from_dict(raw)
        except (ResultError, TypeError) as e:
            rejected.append({"case_id": cid, "reason": f"resultado inválido: {e}"})
            continue
        raw_cat = str((r.meta or {}).get("category", ""))
        obs_cat = raw_cat.strip().lower()
        if r.status is Status.FAILED and not r.security_relevant and obs_cat in OBSERVATION_CATEGORIES:
            rule = _observation_rule(obs_cat, str((r.meta or {}).get("rule", "")))
            if not rule:
                rejected.append({"case_id": cid, "reason": f"regla de {obs_cat} no aceptada: {(r.meta or {}).get('rule') or '(vacía)'}"})
                continue
            sev = str((r.meta or {}).get("severity", "LOW")).upper()
            accepted.append((r, rule, sev if sev in SEVERITIES else "LOW"))
            continue
        if r.status is not Status.FAILED or not r.security_relevant:
            rejected.append({"case_id": cid, "reason": "solo se aceptan casos FAILED relevantes para seguridad, o de usabilidad/accesibilidad"})
            continue
        cat = _resolve_category(raw_cat)
        if not cat:
            rejected.append({"case_id": cid, "reason": f"categoría no soportada: {raw_cat.strip() or '(vacía)'}; soportadas: {sorted(CATEGORIES)}"})
            continue
        rule, default_sev, _label, _cwe = CATEGORIES[cat]
        sev = str((r.meta or {}).get("severity", default_sev)).upper()
        accepted.append((r, rule, sev if sev in SEVERITIES else default_sev))
    return accepted, rejected


def ingest(cur, payload: Dict[str, Any]) -> Dict[str, Any]:
    accepted, rejected = validate(payload)
    cur.execute("SELECT id FROM public.infra_inventory WHERE asset_name = %s", (payload["asset_name"].strip(),))
    row = cur.fetchone()
    if not row:
        raise LookupError(f"el activo «{payload['asset_name']}» no existe en el inventario")
    asset_id = row[0] if not isinstance(row, dict) else row["id"]
    run = payload.get("run") or {}
    project = str(run.get("project") or "sin-proyecto")[:60]
    findings = []
    for r, rule, sev in accepted:
        loc = f"smart-tests:{project}:{r.case_id}"
        raw_cat = str((r.meta or {}).get("category", "")).strip().lower()
        if not r.security_relevant and raw_cat in OBSERVATION_CATEGORIES:
            desc = _observation_description(r, run, raw_cat, rule)
        else:
            desc = _description(r, run, _resolve_category(raw_cat))
        outcome = de.log_finding_deduplicated(cur, asset_id, rule, sev, desc, url_path=loc, scan_engine=ENGINE, preserve_status=True)
        findings.append({"case_id": r.case_id, "rule": rule, "severity": sev, "outcome": outcome[0] if isinstance(outcome, tuple) else outcome})
    return {"accepted": len(accepted), "rejected": rejected, "findings": findings, "asset_id": str(asset_id)}
