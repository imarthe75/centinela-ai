"""
Centinela-AI — runtime session audit (scan_engine: runtime-session). The automatic counterpart of a manual QA run with a browser extension that
reads the console: it logs in with the TEST credentials stored for each profile of an application (core/test_credentials.py, Vault) and reports
what the browser exposes while a user works. Deterministic: no AI model, no clicks beyond the login submit.

Findings (the secret/personal values never leave the browser container: the worker masks them):
  RUNTIME-TOKEN-IN-CONSOLE      HIGH    a JWT / bearer token is printed in the browser console
  RUNTIME-PII-IN-RESPONSE       HIGH    a non-admin profile receives JSON containing CURP / RFC / emails (count per endpoint, masked sample)
  RUNTIME-AUTH-ERRORS           MEDIUM  several 401/403 answers while a logged-in user works (e.g. a token refresh that fails intermittently)
  RUNTIME-SERVER-ERRORS         MEDIUM  5xx answers while browsing
  RUNTIME-TOKEN-IN-STORAGE      LOW     a JWT sits in localStorage/sessionStorage (key names only)
  RUNTIME-SESSION-NOT-EXERCISED INFO    marker: the login did not complete, so nothing behind it was audited (says why)

Limits stated in every finding: it sees only the routes it was given/visited; PII in a response is reported for non-admin profiles, but whether that
profile is ENTITLED to the data is a decision for the application owner. It runs in the Dockerfile.a11y sibling container (Chromium never enters the main images).
"""
import logging
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from centinela_core import browser

from core import db_manager, deduplication_engine as de, test_credentials as tc

logger = logging.getLogger(__name__)
ENGINE = "runtime-session"
IMAGE = "centinela-a11y:latest"
NETWORK = "aura-network"
_WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runtime_session_worker.py")


def _path(url: str) -> str:
    u = urlparse(url)
    return re.sub(r"/\d{2,}(?=/|$)", "/{id}", u.path or "/")


def findings_from_result(res: Dict[str, Any], role: str, kind: str, login_url: str) -> List[Dict[str, Any]]:
    """Pure: the worker's JSON -> findings. `role`/`kind` come from the credential profile."""
    scope = f"_Perfil de prueba: {role}. Ejecución con Chromium, solo las rutas visitadas._"
    out: List[Dict[str, Any]] = []
    if not res.get("login_ok"):
        why = "; ".join(res.get("errors", [])[:2]) or "la página de inicio de sesión sigue visible tras enviar el formulario"
        return [{"cve_id": "RUNTIME-SESSION-NOT-EXERCISED", "severity": "INFO", "url_path": login_url,
                 "description": f"No se pudo iniciar sesión como «{role}», así que no se auditó nada tras el login: {why}. Revisa la URL de inicio de sesión, los campos y la credencial. {scope}"}]
    secrets = [c for c in res.get("console", []) if c.get("secret")]
    if secrets:
        out.append({"cve_id": "RUNTIME-TOKEN-IN-CONSOLE", "severity": "HIGH", "url_path": _path(secrets[0].get("url", login_url)),
                    "description": (f"La consola del navegador muestra un token de sesión en {len(secrets)} mensaje(s) (valor enmascarado: `{secrets[0]['secret']}`). Cualquiera con acceso al equipo, o una extensión "
                                    f"maliciosa, puede copiarlo y reutilizar la sesión (CWE-532). Quitar los registros de depuración (p. ej. `debug` de STOMP) en QA y en producción. {scope}")})
    if kind != "admin":
        by_url: Dict[str, List[Dict[str, Any]]] = {}
        for p in res.get("pii", []):
            by_url.setdefault(_path(p["url"]), []).append(p)
        for path, items in by_url.items():
            kinds = ", ".join(f"{i['count']} × **{i['kind']}** (muestra `{i['sample']}`)" for i in items)
            out.append({"cve_id": "RUNTIME-PII-IN-RESPONSE", "severity": "HIGH", "url_path": path,
                        "description": (f"`{path}` devolvió datos personales al perfil «{role}»: {kinds}. Verifica que este perfil tenga derecho a ver esos datos de otras personas; "
                                        f"si no, es un control de acceso roto con exposición de datos (OWASP A01). {scope}")})
    denied: Dict[str, int] = {}
    errors5: Dict[str, int] = {}
    for r in res.get("responses", []):
        if r["status"] in (401, 403):
            denied[_path(r["url"])] = denied.get(_path(r["url"]), 0) + 1
        elif r["status"] >= 500:
            errors5[_path(r["url"])] = errors5.get(_path(r["url"]), 0) + 1
    for path, n in denied.items():
        if n >= 3:
            out.append({"cve_id": "RUNTIME-AUTH-ERRORS", "severity": "MEDIUM", "url_path": path,
                        "description": f"`{path}` respondió 401/403 {n} veces mientras el perfil «{role}» trabajaba con la sesión iniciada. Si es un refresco de token, explica los cierres de sesión inesperados (tiempo de vida del token frente al intervalo de renovación). {scope}"})
    for path, n in errors5.items():
        out.append({"cve_id": "RUNTIME-SERVER-ERRORS", "severity": "MEDIUM", "url_path": path,
                    "description": f"`{path}` respondió error del servidor (5xx) {n} vez/veces al perfil «{role}». {scope}"})
    for s in res.get("storage", []):
        out.append({"cve_id": "RUNTIME-TOKEN-IN-STORAGE", "severity": "LOW", "url_path": _path(login_url),
                    "description": f"Hay un JWT guardado en `{s['area']}` (clave `{s['key']}`): lo puede leer cualquier script de la página (riesgo XSS). {scope}"})
    return out


def run_worker(cfg: Dict[str, Any], timeout: int = 240) -> Dict[str, Any]:
    """Run the browser container (centinela_core.browser). The credentials travel on its stdin, never in argv/env
    (so `docker inspect`/`ps` do not show them); on timeout the container is removed by name instead of left running."""
    out = browser.run_script_file(_WORKER, cfg, IMAGE, network=NETWORK, timeout=timeout, name_prefix="runtime-session")
    out.pop("_stderr", None)
    return out


def run_runtime_session_audit(asset_name: str, asset_id: Optional[str], routes: Optional[List[str]] = None, client=None) -> List[Dict[str, Any]]:
    """Use every profile that has credentials. No credentials -> an honest empty result (nothing is invented)."""
    raw = tc.read_raw(asset_name, client)
    app_login = raw.get("app_login") or {}
    ui = raw.get("login_ui") or {}
    login_url = ui.get("url") or raw.get("base_url") or ""
    roles = [r for r in raw.get("roles", []) if r.get("username") and r.get("password")]
    if not roles or not login_url:
        logger.info("runtime-session: %s has no profile with credentials or no login URL; nothing exercised", asset_name)
        return []
    findings: List[Dict[str, Any]] = []
    for r in roles:
        cfg = {"login_url": login_url, "username": r["username"], "password": r["password"], "routes": routes or ui.get("routes", []),
               "user_selector": ui.get("user_selector"), "pass_selector": ui.get("pass_selector"), "submit_selector": ui.get("submit_selector")}
        try:
            res = run_worker(cfg)
        except Exception:
            logger.error("runtime-session worker failed for %s / %s", asset_name, r.get("name"), exc_info=True)
            continue
        findings += findings_from_result(res, r.get("name", "?"), r.get("kind", "user"), login_url)
    if asset_id is not None:
        _persist(findings, asset_id)
    return findings


def _persist(findings: List[Dict[str, Any]], asset_id: str) -> None:
    active = set()
    with db_manager.get_db_cursor() as cur:
        for f in findings:
            loc = f["url_path"]
            active.add(de.calculate_fingerprint(asset_id, f["cve_id"], loc))
            de.log_finding_deduplicated(cur, asset_id, f["cve_id"], f["severity"], f["description"], url_path=loc, scan_engine=ENGINE, preserve_status=True)
        de.reconcile_resolved_findings(cur, asset_id, ENGINE, active)


def run(asset_id: str, endpoint: str = ""):
    """auditor_ext entrypoint: no-op (honest, logged) unless the asset has stored test credentials and a browser login URL."""
    name = None
    with db_manager.get_db_cursor() as cur:
        cur.execute("SELECT asset_name FROM public.infra_inventory WHERE id = %s", (asset_id,))
        row = cur.fetchone()
        name = row[0] if row else None
    if not name:
        return []
    return run_runtime_session_audit(name, asset_id)
