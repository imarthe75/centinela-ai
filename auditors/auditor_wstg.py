"""
Centinela-AI — OWASP WSTG v4.2 & ASVS v4.0 Native Perimeter & Posture Auditor
Scan Engine: wstg-perimeter

Audits web applications, reverse proxies, and microservices against the OWASP Web Security
Testing Guide (WSTG v4.2) and OWASP Application Security Verification Standard (ASVS v4.0).

STRICT NON-DESTRUCTIVE / ZERO BRUTE-FORCE CONTRACT:
  Centinela is an automated compliance, posture, and remediation system. Under NO circumstances
  does this auditor perform dictionary attacks, password brute-forcing, credential stuffing,
  directory wordlist blasting, or denial-of-service traffic.
  Every check is implemented as a deterministic protocol assertion using 1 to 2 targeted,
  safe HTTP probes per vector.

Coverage & Rule Identifiers:
  1. WSTG-ATHN-02-CLEARTEXT-LOGIN: Credentials transported over unencrypted HTTP channel.
  2. WSTG-CRYP-03-UNENCRYPTED-CHANNEL: Sensitive cookies or application data transported over unencrypted HTTP.
  3. WSTG-INPV-17-HOST-HEADER-INJECTION: Host / X-Forwarded-Host injection reflected in redirection Location.
  4. WSTG-CONF-06-DANGEROUS-HTTP-METHOD: Dangerous or unneeded HTTP methods (e.g. CONNECT / TRACE) accepted.
  5. WSTG-CLNT-04-OPEN-REDIRECT: Unvalidated parameter redirection to arbitrary external domains.
  6. WSTG-INFO-02-SERVER-BANNER-LEAK: Verbose server banner and version leak in Server header or error pages.
  7. WSTG-INFO-08-FRAMEWORK-FINGERPRINT: Framework and library version signatures exposed in bundles/comments.
  8. WSTG-ERRH-01-VERBOSE-BACKEND-ERROR: Internal backend error codes and debug structures exposed in 4xx/5xx responses.
  9. WSTG-CLNT-07-INSECURE-CORS: Insecure CORS origin reflection and credential exposure.
  10. WSTG-CONF-04-SENSITIVE-FILES: Backup and unreferenced configuration files exposed.
  11. WSTG-CONF-05-DEBUG-ENDPOINTS: Exposure of observability, metrics or API debug interfaces.
  12. WSTG-SESS-02-COOKIE-SAMESITE: Insecure cookie SameSite configuration or missing attribute.
  13. WSTG-CONF-07-INCOMPLETE-HSTS: Missing or sub-optimal Strict-Transport-Security policy.
  14. WSTG-CLNT-09-DUPLICATE-OR-WEAK-FRAME-OPTIONS: Duplicate X-Frame-Options or missing CSP frame-ancestors.
  15. WSTG-AUTH-02-DEFAULT-CREDENTIALS: Deployment out-of-the-box factory credentials check (exactly 1 non-destructive attempt).
      NOTE (2026-10-01): ids 1 and 15 predate the official numbering; against WSTG v4.2 they correspond to ATHN-01
      (credentials over an encrypted channel) and ATHN-02 (default credentials) -- core/coverage_matrix.py maps them
      correctly; the stored rule ids are kept so existing findings/fingerprints are not orphaned.
  16. WSTG-INFO-03-METAFILE-LEAK: robots.txt Disallow entries that enumerate sensitive paths (1 request).
  17. WSTG-CONF-08-CROSSDOMAIN-WILDCARD: crossdomain.xml / clientaccesspolicy.xml allowing any domain (2 requests).
  18. WSTG-INFO-05-CONTENT-LEAK: HTML comments with credentials/TODOs or private IPs in the served page (reuses the base GET).
  19. WSTG-ATHN-06-LOGIN-CACHEABLE: a page with a password field served without no-store/no-cache (reuses the base GET).
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

try:
    from core import db_manager, deduplication_engine
except ImportError:
    db_manager = None
    deduplication_engine = None

logger = logging.getLogger(__name__)

_SCAN_ENGINE = "wstg-perimeter"
_DEFAULT_TIMEOUT = 5.0
_CANARY_DOMAIN = "canary-centinela-eval.internal"
_CORS_EVIL_ORIGIN = "https://canary-evil.internal"

# Regex patterns for version banner detection
_SERVER_VERSION_RE = re.compile(
    r"\b(nginx|apache|iis|openresty|caddy|lighttpd|envoy|gunicorn|uvicorn|werkzeug)/([0-9]+\.[0-9]+(\.[0-9]+)?)",
    re.IGNORECASE,
)
_HTML_BANNER_RE = re.compile(
    r"<center>\s*(nginx|apache|caddy|iis)/([0-9]+\.[0-9]+(\.[0-9]+)?)\s*</center>",
    re.IGNORECASE,
)

# Known frontend library signatures for static bundle inspection
_FRAMEWORK_SIGNATURES = [
    (re.compile(r"jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE), "jQuery"),
    (re.compile(r"lodash[/-]([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE), "Lodash"),
    (re.compile(r"react[/-]([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE), "React"),
    (re.compile(r"vue[/-]([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE), "Vue.js"),
    (re.compile(r"angular[/-]([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE), "Angular"),
    (re.compile(r"ace-builds[/-]([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE), "Ace Editor"),
]

# Sensitive file probes (deterministic, strictly non-destructive list)
_SENSITIVE_FILES_PROBES = [
    ("/.env", re.compile(r"(DB_PASSWORD|SECRET_KEY|POSTGRES_|AWS_|TOKEN=)", re.IGNORECASE)),
    ("/.git/HEAD", re.compile(r"ref:\s*refs/heads/")),
    ("/docker-compose.yml", re.compile(r"(services:|version:\s*['\"]?[0-9])")),
    ("/superset_config.py.bak", re.compile(r"(SECRET_KEY|SQLALCHEMY_DATABASE_URI)")),
    ("/web.config", re.compile(r"<configuration>.*<system\.web>", re.DOTALL | re.IGNORECASE)),
]

# Debug & Metrics endpoints
_DEBUG_ENDPOINTS = [
    ("/actuator/env", re.compile(r"\"propertySources\"|\"activeProfiles\"")),
    ("/metrics", re.compile(r"(# HELP|# TYPE|jvm_|process_|http_requests_total)")),
    ("/swagger-ui.html", re.compile(r"(swagger-ui|springdoc|openapi)", re.IGNORECASE)),
    ("/debug", re.compile(r"(Werkzeug Debugger|Traceback|Console)", re.IGNORECASE)),
]


def _build_url(base: str, path: str) -> str:
    """Builds an absolute URL joining base and path safely."""
    if not base.endswith("/") and not path.startswith("/"):
        return f"{base}/{path}"
    if base.endswith("/") and path.startswith("/"):
        return f"{base[:-1]}{path}"
    return f"{base}{path}"


class _ProbeDisabled(Exception):
    """Control-flow marker: the opt-in default-credential probe is not enabled."""


def audit_url_wstg(
    target_url: str,
    asset_id: Optional[str] = None,
    session: Optional[requests.Session] = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> List[Dict[str, Any]]:
    """
    Executes deterministic protocol assertions against target_url without brute force.
    Returns the list of confirmed vulnerability finding dictionaries.
    """
    findings: List[Dict[str, Any]] = []
    base_resp_for_content = None  # set by the transport block; reused by the page-content checks (no extra request)
    sess = session or requests.Session()
    sess.headers.update({"User-Agent": "Centinela-AI/3.0 WSTG-Auditor (+https://centinela.example.gob.mx)"})

    parsed = urlparse(target_url)
    is_http = parsed.scheme.lower() == "http"
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    logger.info("Starting OWASP WSTG v4.2 posture audit on %s (Asset ID: %s)", target_url, asset_id)

    # -------------------------------------------------------------------------
    # 1. WSTG-ATHN-02 & WSTG-CRYP-03: Transport Layer Security & Plaintext Login
    # -------------------------------------------------------------------------
    try:
        resp_base = sess.get(target_url, allow_redirects=False, timeout=timeout, verify=False)
        base_resp_for_content = resp_base

        # A) Check if HTTP plain channel does not redirect to HTTPS
        if is_http:
            location = resp_base.headers.get("Location", "")
            is_redirect_to_https = (
                resp_base.status_code in (301, 302, 307, 308) and location.startswith("https://")
            )
            if not is_redirect_to_https:
                findings.append({
                    "cve_id": "WSTG-ATHN-02-CLEARTEXT-LOGIN",
                    "severity": "HIGH",
                    "url_path": target_url,
                    "description": (
                        f"El portal `{target_url}` está expuesto mediante HTTP en texto claro (puerto {parsed.port or 80}) "
                        "sin forzar redirección estricta (301/308) hacia HTTPS. Un atacante en la misma red puede "
                        "interceptar credenciales de autenticación en tránsito (OWASP WSTG-ATHN-02, CWE-319, NIST SP 800-52)."
                    ),
                })

        # B) Check unencrypted cookies or sensitive transport
        set_cookie = resp_base.headers.get("Set-Cookie", "")
        if any(tok in set_cookie.lower() for tok in ("session", "token", "auth")):
            cookie_secure = "secure" in set_cookie.lower()
            if is_http and not cookie_secure:
                findings.append({
                    "cve_id": "WSTG-CRYP-03-UNENCRYPTED-CHANNEL",
                    "severity": "HIGH",
                    "url_path": target_url,
                    "description": (
                        f"La cookie de sesión emitida por `{target_url}` carece del atributo `Secure` y es "
                        "transmitida a través de un canal HTTP sin cifrado TLS/HTTPS. Facilita ataques de "
                        "intercepción Man-in-the-Middle y robo de sesión (OWASP WSTG-CRYP-03, CWE-319, ASVS V9.1.2)."
                    ),
                })

            # Check Cookie SameSite attribute (WSTG-SESS-02)
            if "samesite" not in set_cookie.lower() or "samesite=none" in set_cookie.lower() and not cookie_secure:
                findings.append({
                    "cve_id": "WSTG-SESS-02-COOKIE-SAMESITE",
                    "severity": "MEDIUM",
                    "url_path": target_url,
                    "description": (
                        f"La cookie de sesión emitida por `{target_url}` carece del atributo `SameSite=Lax/Strict` o "
                        "utiliza `SameSite=None` sin flag `Secure`. Facilita ataques de Cross-Site Request Forgery (CSRF) "
                        "en navegadores modernos (OWASP WSTG-SESS-02, CWE-1275, ASVS V3.4.3)."
                    ),
                })

        # C) Check HSTS (WSTG-CONF-07)
        hsts_header = resp_base.headers.get("Strict-Transport-Security", "")
        if not is_http:
            if not hsts_header:
                findings.append({
                    "cve_id": "WSTG-CONF-07-INCOMPLETE-HSTS",
                    "severity": "MEDIUM",
                    "url_path": target_url,
                    "description": (
                        f"El servicio HTTPS `{target_url}` no implementa la cabecera Strict-Transport-Security (HSTS). "
                        "Los clientes pueden ser vulnerables a ataques de SSL Stripping en conexiones iniciales (OWASP WSTG-CONF-07, CWE-319, ASVS V9.2.1)."
                    ),
                })
            else:
                m_age = re.search(r"max-age=(\d+)", hsts_header, re.IGNORECASE)
                age_val = int(m_age.group(1)) if m_age else 0
                if age_val < 31536000 or "includesubdomains" not in hsts_header.lower():
                    findings.append({
                        "cve_id": "WSTG-CONF-07-INCOMPLETE-HSTS",
                        "severity": "LOW",
                        "url_path": target_url,
                        "description": (
                            f"La cabecera HSTS en `{target_url}` (`{hsts_header}`) es incompleta: se requiere `max-age` >= 31536000 (1 año) "
                            "y la directiva `includeSubDomains` para blindar subdominios (OWASP WSTG-CONF-07, ASVS V9.2.1)."
                        ),
                    })

        # D) Check Clickjacking & duplicate X-Frame-Options (WSTG-CLNT-09)
        x_frame = resp_base.headers.get("X-Frame-Options", "")
        csp = resp_base.headers.get("Content-Security-Policy", "")
        if "," in x_frame:  # Duplicate header sent by both Nginx and Flask
            findings.append({
                "cve_id": "WSTG-CLNT-09-DUPLICATE-OR-WEAK-FRAME-OPTIONS",
                "severity": "LOW",
                "url_path": target_url,
                "description": (
                    f"La cabecera `X-Frame-Options` se encuentra duplicada (`{x_frame}`) al ser emitida simultáneamente "
                    "por el servidor web y el backend. Puede causar que navegadores estrictos la ignoren. "
                    "Se recomienda consolidar en el proxy inverso o migrar a CSP `frame-ancestors 'self'` (OWASP WSTG-CLNT-09, ASVS V14.4.7)."
                ),
            })
        elif not x_frame and "frame-ancestors" not in csp:
            findings.append({
                "cve_id": "WSTG-CLNT-09-DUPLICATE-OR-WEAK-FRAME-OPTIONS",
                "severity": "MEDIUM",
                "url_path": target_url,
                "description": (
                    f"El portal `{target_url}` no implementa protección contra Clickjacking (ausencia de `X-Frame-Options` y `CSP frame-ancestors`). "
                    "Permite que la aplicación sea embebida en iframes de sitios atacantes para captura fraudulenta de clics (OWASP WSTG-CLNT-09, CWE-1021)."
                ),
            })

        # ---------------------------------------------------------------------
        # 2. WSTG-INFO-02: Server Banner Leak in Headers & Error Page Bodies
        # ---------------------------------------------------------------------
        server_header = resp_base.headers.get("Server", "")
        if server_header:
            m_srv = _SERVER_VERSION_RE.search(server_header)
            if m_srv:
                findings.append({
                    "cve_id": "WSTG-INFO-02-SERVER-BANNER-LEAK",
                    "severity": "LOW",
                    "url_path": target_url,
                    "description": (
                        f"El servidor expone la versión técnica exacta en la cabecera Server: `{server_header}`. "
                        f"Componente detectado: {m_srv.group(1)} versión {m_srv.group(2)}. Facilita actividades de "
                        "reconocimiento y selección de exploits orientados (OWASP WSTG-INFO-02, CWE-200, ASVS V14.3.1)."
                    ),
                })

        if resp_base.status_code >= 400:
            m_html = _HTML_BANNER_RE.search(resp_base.text)
            if m_html:
                findings.append({
                    "cve_id": "WSTG-INFO-02-SERVER-BANNER-LEAK",
                    "severity": "LOW",
                    "url_path": target_url,
                    "description": (
                        f"La página de error HTML del servidor `{target_url}` expone el banner de versión: "
                        f"`{m_html.group(1)}/{m_html.group(2)}`. Requiere desactivar server_tokens y personalizar "
                        "las páginas de error (OWASP WSTG-INFO-02, CWE-200)."
                    ),
                })

        # ---------------------------------------------------------------------
        # 3. WSTG-INFO-08: Web Application Framework Fingerprint in Assets
        # ---------------------------------------------------------------------
        script_matches = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", resp_base.text, re.IGNORECASE)
        for script_src in script_matches:
            for pattern, lib_name in _FRAMEWORK_SIGNATURES:
                m_lib = pattern.search(script_src)
                if m_lib:
                    findings.append({
                        "cve_id": "WSTG-INFO-08-FRAMEWORK-FINGERPRINT",
                        "severity": "LOW",
                        "url_path": script_src,
                        "description": (
                            f"El recurso estático `{script_src}` expone la versión del framework/librería: "
                            f"{lib_name} v{m_lib.group(1)}. Permite enumerar componentes de frontend y verificar "
                            "versiones con fin de soporte (OWASP WSTG-INFO-08, CWE-200, ASVS V14.3.2)."
                        ),
                    })

    except Exception as e:
        logger.error("Error evaluating base URL %s: %s", target_url, e, exc_info=True)

    # -------------------------------------------------------------------------
    # 4. WSTG-INPV-17: Host Header Injection Probe (Safe Non-Destructive Probe)
    # -------------------------------------------------------------------------
    try:
        probe_path = _build_url(target_url, "/login/?centinela_host_test=1")
        injection_headers = {
            "Host": _CANARY_DOMAIN,
            "X-Forwarded-Host": _CANARY_DOMAIN,
            "X-Host": _CANARY_DOMAIN,
            "X-Forwarded-Server": _CANARY_DOMAIN,
        }
        resp_host = sess.get(probe_path, headers=injection_headers, allow_redirects=False, timeout=timeout, verify=False)
        loc = resp_host.headers.get("Location", "")
        if _CANARY_DOMAIN in loc:
            findings.append({
                "cve_id": "WSTG-INPV-17-HOST-HEADER-INJECTION",
                "severity": "MEDIUM",
                "url_path": probe_path,
                "description": (
                    f"Al inyectar cabeceras `Host` / `X-Forwarded-Host: {_CANARY_DOMAIN}`, el servidor reflejó "
                    f"dicho valor no confiable en la cabecera de redirección `Location: {loc}` (HTTP {resp_host.status_code}). "
                    "Esta condición permite ataques de envenenamiento de caché, phishing y derivación de peticiones "
                    "(OWASP WSTG-INPV-17, CWE-644, ASVS V5.1.4, V14.4.1)."
                ),
            })
    except Exception as e:
        logger.error("Error evaluating host header injection on %s: %s", target_url, e, exc_info=True)

    # -------------------------------------------------------------------------
    # 5. WSTG-CONF-06: Dangerous HTTP Methods (CONNECT / TRACE Probe)
    # -------------------------------------------------------------------------
    try:
        connect_req = requests.Request(
            method="CONNECT",
            url=target_url,
            headers={"Host": f"{_CANARY_DOMAIN}:443"},
        ).prepare()
        resp_connect = sess.send(connect_req, timeout=timeout, verify=False, allow_redirects=False)
        if resp_connect.status_code not in (400, 403, 405, 501):
            findings.append({
                "cve_id": "WSTG-CONF-06-DANGEROUS-HTTP-METHOD",
                "severity": "MEDIUM",
                "url_path": target_url,
                "description": (
                    f"La infraestructura web procesó el método HTTP `CONNECT` respondiendo con código HTTP {resp_connect.status_code} "
                    "en lugar de rechazarlo con 405 Method Not Allowed o 400 Bad Request. El procesamiento innecesario de CONNECT "
                    "incrementa la superficie de ataque y puede ser abusado como mecanismo de tunneling o proxy arbitrario "
                    "(OWASP WSTG-CONF-06, CWE-749, ASVS V14.5.1)."
                ),
            })
    except Exception as e:
        logger.debug("CONNECT probe was reset or rejected as expected: %s", e)

    # -------------------------------------------------------------------------
    # 6. WSTG-CLNT-04: Client Side URL Redirect / Open Redirect
    # -------------------------------------------------------------------------
    try:
        redirect_payloads = [
            f"http://{_CANARY_DOMAIN}/auth/callback",
            f"//{_CANARY_DOMAIN}/welcome",
        ]
        for payload in redirect_payloads:
            redirect_test_url = _build_url(target_url, f"/login/?next={payload}")
            resp_redir = sess.get(redirect_test_url, allow_redirects=False, timeout=timeout, verify=False)
            loc = resp_redir.headers.get("Location", "")
            # A real open redirect sends the user to the canary HOST. Matching the canary anywhere in
            # Location flagged every http->https redirect that merely echoes the query string
            # (`Location: https://same-host/login/?next=http://canary/...`) -- a false positive.
            if (urlparse(loc).hostname or "").lower() == _CANARY_DOMAIN.lower():
                findings.append({
                    "cve_id": "WSTG-CLNT-04-OPEN-REDIRECT",
                    "severity": "LOW",
                    "url_path": redirect_test_url,
                    "description": (
                        f"El parámetro de redirección `next={payload}` en `{redirect_test_url}` no valida "
                        f"el dominio destino y emite una redirección a un destino externo: `Location: {loc}`. "
                        "Habilita campañas de phishing redirigiendo usuarios a portales maliciosos tras una interacción "
                        "aparentemente legítima (OWASP WSTG-CLNT-04, CWE-601, ASVS V5.1.5)."
                    ),
                })
                break
    except Exception as e:
        logger.error("Error evaluating open redirect on %s: %s", target_url, e, exc_info=True)

    # -------------------------------------------------------------------------
    # 7. WSTG-ERRH-01: Improper Error Handling / Internal Component Leaks
    # -------------------------------------------------------------------------
    try:
        error_probe_url = _build_url(target_url, "/superset/log/?explode=events")
        resp_err = sess.request("PATCH", error_probe_url, timeout=timeout, verify=False)

        if resp_err.status_code not in (405, 500):
            resp_err = sess.request("PURGE", target_url, timeout=timeout, verify=False)

        err_body = resp_err.text
        if resp_err.status_code in (405, 500, 502):
            is_internal_leak = any(
                indicator in err_body
                for indicator in (
                    "GENERIC_BACKEND_ERROR",
                    "issue_codes",
                    "Issue 1011",
                    "Superset ha encontrado un error",
                    "Traceback (most recent call last)",
                    "Flask-AppBuilder",
                    "werkzeug.exceptions",
                )
            )
            if is_internal_leak:
                findings.append({
                    "cve_id": "WSTG-ERRH-01-VERBOSE-BACKEND-ERROR",
                    "severity": "LOW",
                    "url_path": f"{resp_err.request.method} {resp_err.url}",
                    "description": (
                        f"Al recibir solicitudes con métodos HTTP inesperados ({resp_err.request.method}), el backend respondió con "
                        f"código HTTP {resp_err.status_code} exponiendo estructuras internas en formato JSON: identificadores de error, "
                        "referencias al framework (Apache Superset / Flask) o códigos de incidencia interna (Issue 1011). "
                        "El proxy inverso debe interceptar errores (`proxy_intercept_errors on;`) y retornar respuestas neutrales "
                        "(OWASP WSTG-ERRH-01, CWE-209, ASVS V7.4.1, V7.4.2)."
                    ),
                })
    except Exception as e:
        logger.error("Error evaluating improper error handling on %s: %s", target_url, e, exc_info=True)

    # -------------------------------------------------------------------------
    # 8. WSTG-CLNT-07: Insecure CORS Origin Reflection & Credentials
    # -------------------------------------------------------------------------
    try:
        cors_headers = {"Origin": _CORS_EVIL_ORIGIN}
        resp_cors = sess.options(target_url, headers=cors_headers, timeout=timeout, verify=False)
        allow_orig = resp_cors.headers.get("Access-Control-Allow-Origin", "")
        allow_cred = resp_cors.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if allow_orig == _CORS_EVIL_ORIGIN and allow_cred:
            findings.append({
                "cve_id": "WSTG-CLNT-07-INSECURE-CORS",
                "severity": "HIGH",
                "url_path": target_url,
                "description": (
                    f"El servidor refleja dinámicamente el origen malicioso `{_CORS_EVIL_ORIGIN}` en `Access-Control-Allow-Origin` "
                    "con `Access-Control-Allow-Credentials: true`. Permite a sitios web externos autenticarse y extraer "
                    "información privada del usuario de la sesión activa (OWASP WSTG-CLNT-07, CWE-942, ASVS V14.4.6)."
                ),
            })
    except Exception as e:
        logger.error("Error evaluating CORS on %s: %s", target_url, e, exc_info=True)

    # -------------------------------------------------------------------------
    # 9. WSTG-CONF-04: Backup & Unreferenced Sensitive Files Probe (Deterministic)
    # -------------------------------------------------------------------------
    for path, sig in _SENSITIVE_FILES_PROBES:
        try:
            file_url = _build_url(target_url, path)
            resp_file = sess.get(file_url, allow_redirects=False, timeout=timeout, verify=False)
            if resp_file.status_code == 200 and sig.search(resp_file.text):
                findings.append({
                    "cve_id": "WSTG-CONF-04-SENSITIVE-FILES",
                    "severity": "HIGH",
                    "url_path": file_url,
                    "description": (
                        f"El archivo sensible o de respaldo `{path}` está públicamente accesible con HTTP 200 en `{file_url}`. "
                        "Filtra configuraciones críticas, credenciales de conexión o repositorios de código fuente "
                        "(OWASP WSTG-CONF-04, CWE-552, ASVS V14.3.3)."
                    ),
                })
        except Exception as e:
            logger.debug("Sensitive file check on %s failed: %s", path, e)

    # -------------------------------------------------------------------------
    # 10. WSTG-CONF-05: Debug & Metric Endpoints Exposure Probe
    # -------------------------------------------------------------------------
    for path, sig in _DEBUG_ENDPOINTS:
        try:
            debug_url = _build_url(target_url, path)
            resp_dbg = sess.get(debug_url, allow_redirects=False, timeout=timeout, verify=False)
            if resp_dbg.status_code == 200 and sig.search(resp_dbg.text):
                findings.append({
                    "cve_id": "WSTG-CONF-05-DEBUG-ENDPOINTS",
                    "severity": "MEDIUM",
                    "url_path": debug_url,
                    "description": (
                        f"El endpoint de diagnóstico, métricas o interfaz Swagger `{path}` está expuesto públicamente sin autenticación en `{debug_url}`. "
                        "Permite a atacantes perfilar la infraestructura, monitorear la salud del sistema o descubrir APIs internas "
                        "(OWASP WSTG-CONF-05, CWE-200, ASVS V14.5.3)."
                    ),
                })
        except Exception as e:
            logger.debug("Debug endpoint check on %s failed: %s", path, e)

    # -------------------------------------------------------------------------
    # 16-19. 2026-10-01: metafiles, cross-domain policy, page-content leakage, login-page caching.
    # Same contract as every check here: deterministic protocol assertions, 1-2 safe GETs, no wordlists.
    # -------------------------------------------------------------------------
    sensitive_path_re = re.compile(r"(admin|backup|bak|private|internal|config|secret|dump|staging|\.git|phpmyadmin|manager|console|db/|database)", re.IGNORECASE)
    try:  # WSTG-INFO-03
        r = sess.get(_build_url(target_url, "/robots.txt"), allow_redirects=False, timeout=timeout, verify=False)
        if r.status_code == 200 and "disallow" in r.text.lower() and "<html" not in r.text[:200].lower():
            leaked = [ln.split(":", 1)[1].strip() for ln in r.text.splitlines()
                      if ln.lower().startswith("disallow:") and ":" in ln and sensitive_path_re.search(ln.split(":", 1)[1])]
            if leaked:
                findings.append({
                    "cve_id": "WSTG-INFO-03-METAFILE-LEAK", "severity": "LOW", "url_path": _build_url(target_url, "/robots.txt"),
                    "description": (f"`robots.txt` enumera rutas sensibles ({', '.join(leaked[:6])}): en lugar de ocultarlas, le indica a un atacante "
                                    "dónde mirar. La protección debe ser de autenticación, no de «no indexar» (OWASP WSTG-INFO-03, CWE-200)."),
                })
    except Exception as e:
        logger.debug("robots.txt check failed: %s", e)

    for xml_path in ("/crossdomain.xml", "/clientaccesspolicy.xml"):
        try:  # WSTG-CONF-08
            r = sess.get(_build_url(target_url, xml_path), allow_redirects=False, timeout=timeout, verify=False)
            if r.status_code == 200 and re.search(r"""(allow-access-from|domain)\s+[^>]*(domain|uri)\s*=\s*["']\*["']""", r.text, re.IGNORECASE):
                findings.append({
                    "cve_id": "WSTG-CONF-08-CROSSDOMAIN-WILDCARD", "severity": "MEDIUM", "url_path": _build_url(target_url, xml_path),
                    "description": (f"`{xml_path}` permite el acceso desde cualquier dominio (`*`): cualquier sitio puede leer respuestas autenticadas "
                                    "del usuario desde clientes Flash/Silverlight/RIA (OWASP WSTG-CONF-08, CWE-942)."),
                })
        except Exception as e:
            logger.debug("%s check failed: %s", xml_path, e)

    if base_resp_for_content is not None and base_resp_for_content.status_code == 200 \
            and "html" in base_resp_for_content.headers.get("Content-Type", "text/html").lower():
        body = base_resp_for_content.text or ""
        # WSTG-INFO-05: comments with credentials/TODOs, and private IPs
        risky = [c for c in re.findall(r"<!--(.*?)-->", body, re.DOTALL)
                 if re.search(r"(password|passwd|contrase|secret|api[_-]?key|token|credencial|usuario\s*:|user\s*:|todo|fixme|hack)", c, re.IGNORECASE)]
        priv_ips = sorted(set(re.findall(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", body)))
        if risky or priv_ips:
            what = []
            if risky:
                what.append(f"{len(risky)} comentario(s) HTML con credenciales/TODO")
            if priv_ips:
                what.append(f"IP(s) privada(s) {', '.join(priv_ips[:3])}")
            findings.append({
                "cve_id": "WSTG-INFO-05-CONTENT-LEAK", "severity": "MEDIUM" if risky else "LOW", "url_path": target_url,
                "description": (f"La página servida filtra información interna: {'; '.join(what)}. Quien lea el código fuente de la página la obtiene "
                                "sin autenticarse (OWASP WSTG-INFO-05, CWE-615/CWE-200)."),
            })
        # WSTG-ATHN-06: a page with a password field must not be cacheable
        if re.search(r"""<input\b[^>]*type\s*=\s*["']?password""", body, re.IGNORECASE):
            cc = (base_resp_for_content.headers.get("Cache-Control", "") + " " + base_resp_for_content.headers.get("Pragma", "")).lower()
            if not any(t in cc for t in ("no-store", "no-cache")):
                findings.append({
                    "cve_id": "WSTG-ATHN-06-LOGIN-CACHEABLE", "severity": "LOW", "url_path": target_url,
                    "description": ("La página con formulario de contraseña se sirve sin `Cache-Control: no-store`: el navegador o un proxy compartido pueden "
                                    "conservar la página y sus datos (OWASP WSTG-ATHN-06, CWE-525)."),
                })

    # -------------------------------------------------------------------------
    # 11. WSTG-AUTH-02: Default Credentials Check (EXACTLY 1 attempt) -- OPT-IN ONLY.
    # A login attempt against a production system can trip lockouts/alerting on the target, so it
    # never runs unless the operator explicitly sets WSTG_DEFAULT_CRED_PROBE=1.
    # -------------------------------------------------------------------------
    try:
        if os.getenv("WSTG_DEFAULT_CRED_PROBE", "0") != "1":
            raise _ProbeDisabled()
        login_url = _build_url(target_url, "/login/")
        # Exact 1 probe with factory default admin credentials
        probe_data = {"username": "admin", "password": "admin"}
        resp_login = sess.post(login_url, data=probe_data, allow_redirects=False, timeout=timeout, verify=False)
        loc_header = resp_login.headers.get("Location", "")
        set_cookie_header = resp_login.headers.get("Set-Cookie", "")

        # If it redirects to welcome or dashboard, or sets authenticated session without error
        if resp_login.status_code in (302, 303) and any(p in loc_header.lower() for p in ("welcome", "dashboard", "home", "admin")):
            findings.append({
                "cve_id": "WSTG-AUTH-02-DEFAULT-CREDENTIALS",
                "severity": "CRITICAL",
                "url_path": login_url,
                "description": (
                    f"El portal `{login_url}` permite el inicio de sesión con las credenciales por defecto de fábrica (`admin:admin`). "
                    "Cualquier atacante puede tomar control administrativo total de la plataforma de manera inmediata "
                    "(OWASP WSTG-AUTH-02, CWE-798, ASVS V2.1.1)."
                ),
            })
    except _ProbeDisabled:
        pass
    except Exception as e:
        logger.debug("Default credential probe failed: %s", e)

    # Persist findings in database deduplicated
    _persist_wstg_findings(findings, asset_id, origin=base_origin)
    logger.info("WSTG audit complete on %s: %d finding(s) detected.", target_url, len(findings))
    return findings


def _persist_wstg_findings(findings: List[Dict[str, Any]], asset_id: Optional[str], origin: Optional[str] = None) -> None:
    """Persists WSTG findings using the central deduplication engine."""
    if asset_id is None or db_manager is None or deduplication_engine is None:
        return
    try:
        active_fingerprints = set()
        with db_manager.get_db_cursor() as cur:
            for item in findings:
                loc = item["url_path"]
                active_fingerprints.add(
                    deduplication_engine.calculate_fingerprint(asset_id, item["cve_id"], loc)
                )
                deduplication_engine.log_finding_deduplicated(
                    cur,
                    asset_id,
                    item["cve_id"],
                    item["severity"],
                    item["description"],
                    _SCAN_ENGINE,
                    url_path=loc,
                    open_status="OPEN",
                    preserve_status=True,
                )
            # Scope to the origin actually scanned: one asset (SERVER/AppServer) is audited once
            # per web port, and each call only knows its own port's findings.
            reconciled = deduplication_engine.reconcile_resolved_findings(
                cur, asset_id, _SCAN_ENGINE, active_fingerprints, url_origin=origin
            )
            if reconciled:
                logger.info("Reconciled %d resolved WSTG finding(s) for asset %s.", reconciled, asset_id)
    except Exception as e:
        logger.error("Error persisting WSTG findings for asset %s: %s", asset_id, e, exc_info=True)
