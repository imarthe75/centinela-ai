"""
Emit the updated (2026-08-31) Cita en Línea + Solicitud Web security report in Centinela-AI's
own PDF house style, from the fresh scan export citas_solicitud_scan_2026-08-31.json.

The report is organised around the split the user asked for:
  PARTE A — Vulnerabilidades RESOLUBLES SIN actualizar versiones de librerías
            (cambio de código / configuración / regla de autorización / cabecera / validación)
  PARTE B — Vulnerabilidades que SÍ requieren subir versión de una dependencia
            (SCA / CVE de librería) — se listan con paquete y versión objetivo, para planearlas

Run inside centinela-backend (needs weasyprint + main.CIVIKA_PDF_STYLES).
Output: /app/docs/reportes/Reporte_Citas_SolicitudWeb_Centinela_2026-08-31.pdf
"""
import sys, os, re, json, html
sys.path.insert(0, "/app")
from datetime import datetime
import main as centinela

SRC = "/app/scratch/citas_solicitud_scan_2026-08-31.json"
OUT = "/app/docs/reportes/Reporte_Citas_SolicitudWeb_Centinela_2026-08-31.pdf"

PRETTY = {
    "edomex-casmart/siat-atencion-citas/backend":  "SIAT · Atención de Citas — Backend (API REST)",
    "edomex-casmart/siat-atencion-citas/frontend": "SIAT · Atención de Citas — Frontend (SPA)",
    "edomex-casmart/sideco-solicitud-web/backend":  "SIDECO · Solicitud Web — Backend (API REST)",
    "edomex-casmart/sideco-solicitud-web/frontend": "SIDECO · Solicitud Web — Frontend (SPA)",
}

# ---- explanations per finding family (qué significa / cómo se resuelve SIN actualizar libs) ----
GUIDE = {
    "AUTHZ-INCONSISTENT-FAMILY": dict(
        titulo="Escalación de privilegios — control de acceso inconsistente",
        significa=("Un endpoint que administra identidad (usuarios / roles / permisos) está protegido solo "
                   "con «sesión iniciada», mientras que endpoints hermanos de la misma aplicación sí exigen rol "
                   "de administrador. Un usuario autenticado sin privilegios llega a una función administrativa. "
                   "Es exactamente el hallazgo del retest de SIDECO (cuenta TcsCSA2)."),
        resolver=("NO requiere actualizar librerías. Añadir la regla que falta en la configuración de Spring "
                  "Security, o una anotación a nivel de método:"),
        code=("// Opción 1 — regla de URL en ResourceServerConfig / WebSecurityConfig\n"
              ".antMatchers(\"/v1/usr/**\").access(\"@roleSecurity.isAdmin(authentication)\")\n"
              "// (colocarla ANTES del .antMatchers(\"/v1/**\").authenticated())\n\n"
              "// Opción 2 — a nivel de método en el controlador (defensa en profundidad)\n"
              "@PreAuthorize(\"hasRole('ADMIN')\")\n"
              "@GetMapping(\"/getUsuarios\")\n"
              "public ResponseEntity<?> getUsuarios() { ... }"),
    ),
    "AUTHZ-CLIENT-SIDE-ONLY": dict(
        titulo="Módulo de administración protegido solo en el navegador",
        significa=("La ruta del módulo admin de la SPA se protege únicamente con un guard de Angular "
                   "(`canActivate`). El backend que consume ese módulo no verifica rol, así que interceptando "
                   "la respuesta y reescribiendo 403→200 se renderiza el módulo y sus llamadas funcionan. "
                   "CWE-602."),
        resolver=("NO requiere actualizar librerías. El guard del front se conserva por UX, pero el control real "
                  "debe estar en el backend: cada endpoint que consume el módulo admin necesita `@PreAuthorize` "
                  "o una regla de URL con rol. Verificar la lista completa de endpoints del módulo, no solo "
                  "algunos."),
        code=("// backend — cada endpoint consumido por el módulo catalogos-admin:\n"
              "@PreAuthorize(\"hasRole('ADMIN')\")\n"
              "// + prueba: repetir la petición con un token de rol NO-admin y confirmar 403 real\n"
              "//   (no solo que el front oculte el menú)"),
    ),
    "AUTHZ-PERMITALL-WRITE": dict(
        titulo="Operación de escritura pública (permitAll)",
        significa=("Un verbo POST/PUT/DELETE está cubierto por una regla `permitAll()`; cualquiera sin "
                   "autenticarse puede invocarlo."),
        resolver="NO requiere actualizar librerías. Cambiar la decisión de la regla o mover el endpoint fuera del bloque permitAll.",
        code=(".antMatchers(HttpMethod.POST, \"/ruta/afectada\").authenticated()   // o .access(\"...isAdmin...\")\n"
              "// revisar que el patrón permitAll no sea más amplio de lo necesario (p. ej. \"/**\")"),
    ),
    "AUTHZ-ONLY-AUTHENTICATED-WRITE": dict(
        titulo="Escritura sensible sin verificación de rol",
        significa="El endpoint muta datos sensibles y solo exige `.authenticated()`. Falta el chequeo de rol.",
        resolver="NO requiere actualizar librerías. Añadir rol en la regla de URL o `@PreAuthorize` en el método.",
        code="@PreAuthorize(\"hasRole('ADMIN')\")  // o hasAnyRole('ADMIN','GESTOR') según el negocio",
    ),
    "AUTHZ-NAMESPACE-GAP": dict(
        titulo="Prefijo de rutas sin cobertura de seguridad",
        significa=("Los `antMatchers` cubren un prefijo (p. ej. `/v1/**`) pero hay controladores o llamadas del "
                   "front bajo otro (`/api/**`) que ninguna regla contempla. Una ruta directa o un rewrite de "
                   "proxy evita el control de acceso."),
        resolver="NO requiere actualizar librerías. Unificar el prefijo o añadir una regla `anyRequest().authenticated()` como red de seguridad.",
        code=(".authorizeRequests()\n"
              "   .antMatchers(\"/v1/**\").authenticated()\n"
              "   .antMatchers(\"/api/**\").authenticated()   // añadir el prefijo faltante\n"
              "   .anyRequest().authenticated();               // catch-all defensivo"),
    ),
    "AUTHZ-CSRF-DISABLED": dict(
        titulo="Protección CSRF deshabilitada",
        significa=("`.csrf().disable()` en la configuración. Aceptable solo si TODO el acceso es por Bearer token "
                   "en cabecera; si hay cookie de sesión o form-login, queda expuesto a CSRF."),
        resolver=("NO requiere actualizar librerías. Si el API es 100% stateless con Bearer token, dejar CSRF "
                  "desactivado y documentarlo; si usa cookie/sesión, reactivar CSRF con repositorio de token."),
        code=("// API stateless: mantener disable() PERO forzar SessionCreationPolicy.STATELESS\n"
              "http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);\n"
              "// API con sesión: \n"
              "http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());"),
    ),
    "AUTHZ-NO-METHOD-ANNOTATIONS": dict(
        titulo="Autorización solo por lista de URLs (frágil)",
        significa=("Muchos controladores y 0 anotaciones `@PreAuthorize`. Cualquier endpoint nuevo o renombrado "
                   "queda sin protección hasta que alguien recuerde añadir la regla."),
        resolver="NO requiere actualizar librerías. Habilitar `@EnableGlobalMethodSecurity(prePostEnabled = true)` y anotar los controladores sensibles.",
        code="@EnableGlobalMethodSecurity(prePostEnabled = true)   // sobre la clase de configuración",
    ),
    "AUTHZ-IDOR-PARAM-REVIEW": dict(
        titulo="Posible IDOR / BOLA — id del sujeto en la ruta",
        significa=("El controlador recibe el identificador del usuario como parámetro de ruta y solo exige "
                   "`.authenticated()`. Si no comprueba que el recurso pertenece a quien lo pide, un usuario "
                   "puede leer/modificar datos de otro cambiando el id."),
        resolver=("NO requiere actualizar librerías. Añadir la comprobación de pertenencia en el servicio, "
                  "comparando el id de la ruta con el del token."),
        code=("Long idToken = usuarioService.idDe(SecurityContextHolder.getContext().getAuthentication());\n"
              "if (!idToken.equals(idUsuarioRuta) && !esAdmin()) {\n"
              "    return new ResponseEntity<>(HttpStatus.FORBIDDEN);\n"
              "}"),
    ),
    "AUTHZ-CLIENT-SIDE-UI-GATE": dict(
        titulo="Función sensible ocultada solo del lado del cliente",
        significa="Un `*ngIf` sobre un chequeo de rol decide la visibilidad. Editando el DOM o la respuesta se ve igual.",
        resolver="NO requiere actualizar librerías. El `*ngIf` puede quedarse por UX; el backend debe rechazar la operación con 403.",
        code="// backend: @PreAuthorize en el endpoint correspondiente — no confiar en el *ngIf",
    ),
    "AUTHZ-ADMIN-BUNDLE-EXPOSED": dict(
        titulo="Componentes admin entregados a todos los clientes",
        significa="El módulo admin se compila en el bundle de la SPA; si su única protección es un guard, se puede renderizar manipulando la respuesta.",
        resolver="NO requiere actualizar librerías. El control debe estar en el servidor; opcionalmente separar el módulo admin en un bundle lazy con endpoint protegido.",
        code="// prioridad: proteger los endpoints en backend; la separación de bundle es defensa adicional",
    ),
    "SSRF": dict(
        titulo="Server-Side Request Forgery",
        significa="La aplicación hace una petición HTTP a una URL influida por el usuario; puede alcanzar servicios internos.",
        resolver="NO requiere actualizar librerías. Validar el host destino contra una allowlist antes de la petición.",
        code=("URI u = URI.create(entrada);\n"
              "if (!ALLOWLIST.contains(u.getHost())) throw new IllegalArgumentException(\"host no permitido\");"),
    ),
    "CODE-INJECTION-EVAL": dict(
        titulo="Ejecución dinámica de código (eval)",
        significa="Uso de eval()/Function()/exec sobre datos que pueden venir del usuario → ejecución arbitraria.",
        resolver="NO requiere actualizar librerías. Sustituir por un parseo explícito (JSON.parse, un switch, un mapa de funciones).",
        code="// en vez de eval(expr): usar JSON.parse(expr) o un diccionario {clave: () => ...}",
    ),
    "HARDCODED-SECRET": dict(
        titulo="Secreto embebido en el código",
        significa="Una credencial/clave está escrita en el repositorio; cualquiera con acceso al código la tiene.",
        resolver="NO requiere actualizar librerías. Mover el valor a variable de entorno / Vault y rotar el secreto expuesto.",
        code="// application.yml:  password: ${DB_PASSWORD}\n// + rotar el secreto que ya quedó en el historial git",
    ),
    "SECRETS": dict(
        titulo="Secreto detectado por el escáner de secretos",
        significa="TruffleHog/git-secrets encontró un patrón de credencial en el árbol o en el historial.",
        resolver="NO requiere actualizar librerías. Rotar el secreto y purgarlo del historial (git filter-repo / BFG).",
        code="git filter-repo --path <archivo> --invert-paths   # y rotar la credencial",
    ),
}
# scan_engine -> familia genérica cuando el cve_id no está en GUIDE
ENGINE_FAMILY = {
    "wcag-accessibility": dict(
        titulo="Accesibilidad (WCAG 2.1)",
        significa="Barrera de accesibilidad — requisito legal para los sistemas del sector público del Estado de México.",
        resolver="NO requiere actualizar librerías. Cambios de marcado (alt, label, role, lang, tabindex).",
        code="<img src=... alt=\"descripción\">   |   <label for=\"campo\">…</label><input id=\"campo\">",
    ),
    "authz-static": dict(
        titulo="Control de acceso (análisis estático)",
        significa="Debilidad en la autorización de endpoints o del módulo administrativo.",
        resolver="NO requiere actualizar librerías. Regla de Spring Security o anotación de método.",
        code="@PreAuthorize(\"hasRole('ADMIN')\")",
    ),
}


def esc(s):
    return html.escape(str(s or ""))


def sev_badge(sev):
    return f'<span class="badge badge-{esc(sev).lower()}">{esc(sev)}</span>'


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def guide_for(cve_id, scan_engine):
    cid = (cve_id or "").upper()
    for key, g in GUIDE.items():
        if cid.startswith(key):
            return g
    return ENGINE_FAMILY.get((scan_engine or "").lower())


def clean_desc(d):
    d = re.sub(r"\*\*(.+?)\*\*", r"\1", d or "")
    d = re.sub(r"`([^`]+)`", r"\1", d)
    return d.strip()


def render_no_upgrade(items):
    # group by (guide title or cve_id)
    groups = {}
    for it in items:
        g = guide_for(it["cve_id"], it["scan_engine"])
        key = g["titulo"] if g else it["cve_id"]
        groups.setdefault(key, {"guide": g, "cve_ids": set(), "rows": []})
        groups[key]["cve_ids"].add(it["cve_id"])
        groups[key]["rows"].append(it)
    out = []
    for key, grp in sorted(groups.items(),
                           key=lambda kv: min(SEV_ORDER.get(r["severity"], 5) for r in kv[1]["rows"])):
        rows = grp["rows"]
        g = grp["guide"]
        worst = min(rows, key=lambda r: SEV_ORDER.get(r["severity"], 5))["severity"]
        cls = {"CRITICAL": "card-crit", "HIGH": "card-warn", "MEDIUM": "card-tech", "LOW": "card-tech"}.get(worst, "card-tech")
        locs = "".join(
            f'<div><code>{esc(r["location"] or "—")}</code> &nbsp;{sev_badge(r["severity"])} '
            f'<span style="color:#64748b">{esc(r["cve_id"])}</span></div>'
            for r in sorted(rows, key=lambda r: SEV_ORDER.get(r["severity"], 5))[:40]
        )
        block = [f'<div class="card {cls}">',
                 f'<h3>{esc(key)} &nbsp; <span style="font-weight:400;color:#64748b">({len(rows)} hallazgo(s))</span></h3>']
        if g:
            block.append(f'<p><b>Qué se encontró:</b> {esc(clean_desc(rows[0]["description"]))[:600]}</p>')
            block.append(f'<p><b>Qué significa:</b> {esc(g["significa"])}</p>')
            block.append(f'<p><b>Cómo se resuelve (sin actualizar librerías):</b> {esc(g["resolver"])}</p>')
            block.append(f'<pre>{esc(g["code"])}</pre>')
        else:
            block.append(f'<p><b>Qué se encontró:</b> {esc(clean_desc(rows[0]["description"]))[:600]}</p>')
            block.append('<p><b>Cómo se resuelve:</b> cambio de código o configuración; no depende de actualizar una dependencia.</p>')
        block.append(f'<div style="margin-top:6px;font-size:8px"><b>Ubicaciones:</b>{locs}</div>')
        block.append('</div>')
        out.append("".join(block))
    return "".join(out)


_PKG_RE = re.compile(r"Paquete:\s*\*?\*?\s*([A-Za-z0-9_.\-]+(?::[A-Za-z0-9_.\-]+)?)")
_INST_RE = re.compile(r"instalada:\s*\*?\*?\s*([A-Za-z0-9_.\-]+)")
_SAFE_RE = re.compile(r"segura:\s*\*?\*?\s*([A-Za-z0-9_.\-]+)")
_MANIF_RE = re.compile(r"Manifiesto:\s*\*?\*?\s*([A-Za-z0-9_./\-]+)")


def _demark(s):
    return re.sub(r"\*\*|`", "", s or "")


def _ver_key(v):
    parts = re.split(r"[.\-]", re.sub(r"(?i)\.release|\.final", "", v or ""))
    key = []
    for p in parts:
        key.append((0, int(p)) if p.isdigit() else (1, p))
    return key


def render_upgrade(items):
    if not items:
        return '<div class="card card-ok"><p>Sin CVEs de dependencias pendientes en esta base de código.</p></div>'
    # group by package -> one planning row per library, with the CVE list and the highest
    # "safe version" any advisory reported (the SCA engine emits one row per CVE, and OSV's
    # multi-branch advisories can report different fixed versions per release line).
    pkgs = {}
    ungrouped = []
    for it in items:
        d = _demark(it["description"] or "")
        mp = _PKG_RE.search(d)
        if not mp:
            ungrouped.append(it)
            continue
        pkg = mp.group(1)
        g = pkgs.setdefault(pkg, {"inst": None, "manif": None, "safe": [], "cves": [], "sev": []})
        mi = _INST_RE.search(d); ms = _SAFE_RE.search(d); mm = _MANIF_RE.search(d)
        if mi and not g["inst"]:
            g["inst"] = mi.group(1)
        if mm and not g["manif"]:
            g["manif"] = mm.group(1)
        if ms:
            g["safe"].append(ms.group(1))
        g["cves"].append(re.sub(r"^SCA-?", "", it["cve_id"]) or it["cve_id"])
        g["sev"].append(it["severity"])

    rows = []
    for pkg, g in sorted(pkgs.items(), key=lambda kv: min(SEV_ORDER.get(s, 5) for s in kv[1]["sev"])):
        worst = min(g["sev"], key=lambda s: SEV_ORDER.get(s, 5))
        try:
            safe = max((s for s in g["safe"] if s), key=_ver_key) if g["safe"] else "—"
        except Exception:
            safe = g["safe"][0] if g["safe"] else "—"
        cves = ", ".join(sorted(set(g["cves"])))
        rows.append(
            f'<tr><td>{sev_badge(worst)}</td><td><code>{esc(pkg)}</code><br>'
            f'<span style="font-size:7.5px;color:#64748b">{esc(g["manif"] or "")}</span></td>'
            f'<td><code>{esc(g["inst"] or "?")}</code> &rarr; <code>&ge;{esc(safe)}</code></td>'
            f'<td style="font-size:8px">{esc(cves)}</td></tr>')
    for it in ungrouped:
        rows.append(
            f'<tr><td>{sev_badge(it["severity"])}</td><td><code>{esc(it["cve_id"])}</code></td>'
            f'<td>—</td><td style="font-size:8px">{esc(clean_desc(it["description"]))[:200]}</td></tr>')

    n_pkg = len(pkgs) + len(ungrouped)
    return (f'<p>Las {len(items)} vulnerabilidades de dependencias se consolidan en <b>{n_pkg} '
            f'librería(s)</b> a actualizar. <b>Mientras no sea posible actualizar</b>: la ruta afectada puede '
            f'restringirse en el reverse-proxy, la función deshabilitarse si no se usa, o el servicio aislarse '
            f'en red — el servidor de desarrollo aislado ya reduce la exposición real.</p>'
            f'<table><thead><tr><th>Sev.</th><th>Librería / manifiesto</th><th>Instalada &rarr; objetivo</th>'
            f'<th>CVE</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')


def main():
    data = json.load(open(SRC, encoding="utf-8"))
    gen = datetime.now().strftime("%d/%m/%Y %H:%M")
    parts = []

    # ---- executive summary
    tot_up = sum(len(a["needs_version_bump"]) for a in data["assets"])
    tot_no = sum(len(a["fixable_without_upgrade"]) for a in data["assets"])
    parts.append('<span class="section-label label-exec">Resumen ejecutivo</span>')
    parts.append("<h1>Reporte de Seguridad — Cita en Línea y Solicitud Web</h1>")
    parts.append(f"<p>Análisis con Centinela-AI de <b>siat-atencion-citas</b> y <b>sideco-solicitud-web</b> "
                 f"(backend y frontend), sobre el código actualizado por el equipo de desarrollo el fin de "
                 f"semana. Fecha del análisis: <b>{gen}</b>.</p>")
    parts.append('<div class="kpi-grid">'
                 f'<div class="kpi-card"><div class="kpi-num">{len(data["assets"])}</div><div class="kpi-label">Bases de código</div></div>'
                 f'<div class="kpi-card kpi-crit"><div class="kpi-num">{tot_no}</div><div class="kpi-label">Resolubles SIN actualizar librerías</div></div>'
                 f'<div class="kpi-card kpi-high"><div class="kpi-num">{tot_up}</div><div class="kpi-label">Requieren subir versión</div></div>'
                 f'<div class="kpi-card"><div class="kpi-num">{tot_no + tot_up}</div><div class="kpi-label">Total abiertas</div></div>'
                 '</div>')
    parts.append('<div class="card card-exec"><p><b>Lectura para dirección:</b> la mayor parte de los hallazgos '
                 'de mayor severidad (control de acceso, secretos en configuración, validación de entrada) <b>no '
                 'dependen de actualizar ninguna librería</b> — se corrigen con cambios de código o de configuración '
                 'y pueden abordarse de inmediato (Parte A). El bloque que sí exige subir versiones de dependencias '
                 'se aísla en la Parte B de cada sistema para planearlo por separado.</p></div>')
    parts.append(f'<div class="card card-tech"><p><b>Alcance de este análisis:</b> {esc(data.get("scope_note", ""))}</p></div>')

    for a in data["assets"]:
        name = PRETTY.get(a["path"], a["path"])
        no_up = a["fixable_without_upgrade"]
        up = a["needs_version_bump"]
        parts.append('<hr class="divider">')
        parts.append(f'<h2>{esc(name)}</h2>')
        parts.append(f'<p style="font-size:8.5px;color:#64748b">Repositorio <code>{esc(a["path"])}</code> · '
                     f'rama <code>{esc(a["branch"])}</code> · asset {a["asset_id"]} · '
                     f'{a["total_open"]} vulnerabilidades abiertas</p>')
        parts.append('<span class="section-label label-tech">Parte A — Resolubles sin actualizar librerías '
                     f'({len(no_up)})</span>')
        parts.append(render_no_upgrade(no_up) if no_up else
                     '<div class="card card-ok"><p>Nada en esta categoría.</p></div>')
        parts.append('<span class="section-label label-tech">Parte B — Requieren subir versión de dependencia '
                     f'({len(up)})</span>')
        parts.append(render_upgrade(up))

    body = "\n".join(parts)
    full = (f"<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>"
            f"<title>Reporte Citas y Solicitud Web — Centinela-AI</title>"
            f"<style>{centinela.CIVIKA_PDF_STYLES}\npre{{white-space:pre-wrap}}</style></head><body>"
            f"{centinela.build_pdf_header('Cita en Línea y Solicitud Web', 'Clasificación por tipo de remediación · rama develop', gen)}"
            f"{body}"
            f"<div class='pdf-footer-bar'>Centinela-AI | CASMARTS Ecosistema de Seguridad | Clasificación: CONFIDENCIAL | "
            f"Análisis {gen} · CVSS v3 · OWASP · CWE</div></body></html>")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    pdf = centinela.render_pdf_with_weasyprint(full)
    with open(OUT, "wb") as f:
        f.write(pdf)
    print(f"  ✓ {OUT}  ({len(pdf)//1024} KB)")


if __name__ == "__main__":
    main()
    os._exit(0)
