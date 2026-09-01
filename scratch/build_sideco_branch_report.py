# -*- coding: utf-8 -*-
"""
Reporte de avance de la rama `develop-damc-seguridad` de sideco-solicitud-web/backend
vs `develop`. Mismo formato detallado: por hallazgo -- qué encontramos / en qué afecta /
cómo se corrige sin actualizar librerías + código + ubicación (archivo:línea) -- con estado
Corregido / Pendiente / Nuevo.
"""
import json, html, re, collections, datetime

SRC = "/tmp/claude-1000/-opt-centinela-ai/d6ed2905-f3a4-419f-a872-39919860cf03/scratchpad/sideco_backend_branch_2026-09-01.json"
OUT = "/tmp/claude-1000/-opt-centinela-ai/d6ed2905-f3a4-419f-a872-39919860cf03/scratchpad/reporte_sideco_branch_2026-09-01.html"

def G(t, e, a, r, c): return dict(t=t, enc=e, afecta=a, resolver=r, code=c)
GUIDE = {
 "SONAR-java-S6437": G(
  "Secreto / credencial embebida en el código o configuración",
  "Credencial, token o llave escrita literalmente en el repositorio "
  "(<code>application-*.yml</code> o una constante Java).",
  "Cualquiera con acceso al código —o al historial de git— tiene la credencial. Si es la llave de cifrado, "
  "compromete todo lo que la app protege.",
  "Sí, sin librerías nuevas. Mover el valor a variable de entorno / Vault y <b>rotar</b> el secreto expuesto.",
  "# application.yml\nspring:\n  datasource:\n    password: ${DB_PASSWORD}\n"
  "// llaves: NO en el código\n@Value(\"${encryption.secret-key}\") ..."),
 "SONAR-java-S5542": G(
  "Cifrado con modo/relleno inseguro (AES/ECB)",
  "<code>Cipher.getInstance(\"AES\")</code> sin especificar modo resuelve a <b>AES/ECB</b>.",
  "ECB no oculta patrones: bloques de texto claro iguales producen bloques cifrados iguales.",
  "Sí, sin librerías nuevas (JCE del JDK). Usar un modo autenticado con IV explícito.",
  "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
  "byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);\n"
  "c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));\n"
  "// y prepender el IV al texto cifrado para poder descifrar"),
 "java.lang.security.audit.crypto.use-of-default-aes": G(
  "AES sin configuración (modo por defecto = ECB)",
  "<code>Cipher.getInstance(\"AES\")</code> sin especificar modo ni relleno.",
  "El modo por defecto es ECB, que filtra estructura del texto claro.",
  "Sí, sin librerías nuevas. Especificar <code>AES/GCM/NoPadding</code> con IV aleatorio por operación.",
  "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
  "byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);\n"
  "c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));"),
 "SPRINGBOOT-NATIVE-QUERY-RISK": G(
  "Consulta nativa concatenada (riesgo de SQL injection)",
  "Un <code>@Query(nativeQuery = true)</code> o consulta construida por concatenación de cadenas.",
  "Si algún fragmento proviene del usuario, permite inyección SQL: leer o alterar toda la base de datos.",
  "Sí, sin librerías nuevas. Usar parámetros nombrados / binding, nunca concatenación.",
  "@Query(value = \"SELECT * FROM tabla WHERE id = :id\", nativeQuery = true)\nList<T> find(@Param(\"id\") Long id);"),
 "SONAR-java-S4036": G(
  "Ejecutable resuelto por la variable PATH",
  "Se invoca un binario por nombre y se resuelve vía el PATH del proceso.",
  "Un PATH manipulado hace que se ejecute otro binario con los privilegios de la app.",
  "Sí, sin librerías nuevas. Usar la ruta absoluta al ejecutable.",
  "new ProcessBuilder(\"/usr/bin/soffice\", ...)   // no solo \"soffice\""),
 "java.spring.security.injection.tainted-file-path": G(
  "Path traversal — ruta de archivo controlada por el usuario",
  "Un parámetro del usuario entra en una ruta de archivo sin sanear (<code>DocumentosController</code>).",
  "Con <code>../</code> el atacante lee o escribe archivos fuera del directorio previsto.",
  "Sí, sin librerías nuevas. Quedarse sólo con el nombre de archivo y resolver contra un directorio base fijo.",
  "String safe = Paths.get(entrada).getFileName().toString();\n"
  "Path p = BASE_DIR.resolve(safe).normalize();\n"
  "if (!p.startsWith(BASE_DIR)) throw new SecurityException();"),
 "html.security.plaintext-http-link": G(
  "Enlace / recurso http:// en una plantilla HTML",
  "Un <code>href</code>/<code>src</code> <code>http://</code> en una plantilla de correo.",
  "Contenido mixto y manipulable en tránsito; permite redirigir al usuario a un sitio falso.",
  "Sí, sin librerías nuevas. Cambiar a <code>https://</code> o a URL relativa de protocolo.",
  "<a href=\"https://...\">   <!-- no http:// -->"),
 "SONAR-java-S2612": G(
  "Permisos de archivo demasiado abiertos",
  "El código crea archivos o directorios world-readable/writable (equivalente a <code>chmod 777</code>).",
  "Otro proceso o usuario de la máquina puede leer o alterar los .odt / PDF generados con datos personales.",
  "Sí, sin librerías nuevas. Fijar permisos restrictivos al crear el archivo.",
  "Files.createFile(p, PosixFilePermissions.asFileAttribute(\n    PosixFilePermissions.fromString(\"rw-------\")));"),
 "SONAR-java-S5693": G(
  "Límite de tamaño de petición excesivo (~2 GB)",
  "El límite de contenido está en ~2 147 483 648 bytes, frente al recomendado ~8 MB.",
  "Facilita agotar memoria o disco del servidor con una sola petición (denegación de servicio).",
  "Sí, sin librerías nuevas. Bajar el límite a lo que necesita el negocio.",
  "spring:\n  servlet:\n    multipart:\n      max-file-size: 8MB\n      max-request-size: 10MB"),
 "AUTHZ-CSRF-DISABLED": G(
  "Protección CSRF deshabilitada",
  "<code>.csrf().disable()</code> en la configuración de seguridad.",
  "Si la app autentica con cookie de sesión o form-login, un sitio de terceros puede forzar peticiones en "
  "nombre del usuario. Aceptable sólo si TODO el acceso es Bearer token en cabecera.",
  "Sí, sin librerías nuevas. Si es 100% stateless, forzar STATELESS y documentarlo; si usa sesión, reactivar CSRF.",
  "http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);\n"
  "// o: http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());"),
 "AUTHZ-PERMITALL-WRITE": G(
  "Operación de escritura pública (permitAll)",
  "Un verbo POST/PUT/DELETE queda cubierto por una regla <code>permitAll()</code>.",
  "Cualquiera sin autenticarse puede invocarlo. Si es un endpoint de captación ciudadana intencionalmente "
  "público (p. ej. <code>/recepcion/agregarSolicitud</code>), documentarlo y añadir rate-limiting + CAPTCHA.",
  "Sí, sin librerías nuevas. Confirmar que es intencional; si no, exigir autenticación.",
  ".antMatchers(HttpMethod.POST, \"/recepcion/agregarSolicitud\").permitAll()   // documentar + rate-limit\n"
  "// cualquier otro POST público -> .authenticated()"),
 "STD-STRIDE-MISSING-AUDIT-LOG": G(
  "Endpoint de escritura sin bitácora de auditoría",
  "Una operación que crea / modifica / borra datos no deja registro de quién y cuándo.",
  "Ante un abuso no hay forma de investigar qué pasó.",
  "Sí, sin librerías nuevas. Añadir una línea de auditoría con usuario, acción, recurso y timestamp.",
  "auditLog.info(\"{} {} recurso={} ts={}\", usuario, \"CREATE\", idRecurso, Instant.now());"),
 "WCAG-3.1.1-HTML-MISSING-LANG": G(
  "&lt;html&gt; sin atributo lang (plantilla de correo)",
  "La etiqueta <code>&lt;html&gt;</code> de la plantilla no declara el idioma.",
  "Un lector de pantalla no sabe con qué pronunciación leer el correo; requisito WCAG 3.1.1.",
  "Sí, sin librerías nuevas. Añadir <code>lang=\"es\"</code>.",
  "<html lang=\"es\">"),
 "SCA-CVE-2022-22965": G(
  "Spring4Shell (CVE-2022-22965)",
  "Versión de Spring Framework vulnerable a ejecución remota de código vía data binding.",
  "RCE sin autenticar en el peor caso. Sólo se corrige subiendo Spring.",
  None, None),
}
# cómo se corrigió (para las tarjetas CORREGIDO) -- específico del commit 46bc15a
FIXNOTE = {
 "SONAR-java-S6437":
  "El commit <code>46bc15a</code> movió los <code>password</code>/<code>client-secret</code> de los "
  "<code>application-*.yml</code> a variables de entorno (<code>${...}</code>) y la llave de "
  "<code>EncryptionUtil</code> a <code>@Value(\"${encryption.secret-key}\")</code> con validación de que "
  "esté configurada. <b>Pendiente operativo:</b> rotar los secretos que ya quedaron en el historial de git.",
 "SONAR-java-S5542":
  "<code>EncryptionUtil</code> pasó de <code>Cipher.getInstance(\"AES\")</code> (ECB) a "
  "<code>\"AES/GCM/NoPadding\"</code>. <b>Ojo:</b> GCM necesita un IV/nonce único por operación; en el "
  "diff no se ve que se genere y se prependa un IV — verificar que <code>encrypt</code>/<code>decrypt</code> "
  "sigan siendo compatibles y que no se reutilice IV (reutilizar IV en GCM rompe la confidencialidad).",
 "java.lang.security.audit.crypto.use-of-default-aes":
  "Mismo cambio que arriba: transformación explícita <code>AES/GCM/NoPadding</code>. Revisar el manejo del IV.",
 "SPRINGBOOT-NATIVE-QUERY-RISK":
  "El commit eliminó varias <code>@Query(nativeQuery=true)</code> concatenadas de "
  "<code>UsuarioRepository</code> (<code>consultarUsuariosByRol</code>, <code>updateEstatus</code>, "
  "<code>obtenerCorreoDelUsuario</code>).",
 "SONAR-java-S4036":
  "Resuelto en <code>ExportPDF.java</code> (invocación del conversor por ruta).",
}
PENDNOTE = {
 "java.spring.security.injection.tainted-file-path":
  "<b>Corrección parcial.</b> El commit <code>46bc15a</code> sí añadió sanitización para la ruta del PDF "
  "generado en <code>DocumentosController</code> (líneas ~141-160: <code>getFileName()</code> + "
  "<code>startsWith(baseDir)</code>). Semgrep sigue marcando <b>otro sink en la misma clase</b> "
  "(<code>DocumentosController.java:147</code>, la ruta del ODT/plantilla antes del PDF) — falta aplicar "
  "el mismo patrón ahí.",
 "AUTHZ-PERMITALL-WRITE":
  "Sobre <code>SolicitudRecepcionController</code> (captación de solicitudes web). Si es intencionalmente "
  "público, documentarlo y añadir rate-limiting/CAPTCHA; si no, exigir autenticación.",
}

STATUS = {"corregido": ("Corregido","st-fixed","✓"), "pendiente": ("Pendiente","st-pend","●"), "nuevo": ("Nuevo","st-new","!")}
SEV = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
def esc(s): return html.escape(str(s or ""))
def pill(st):
    l,c,s = STATUS[st]; return f'<span class="pill {c}">{s} {l}</span>'
def fam_key(cve):
    for k in GUIDE:
        if cve.upper().startswith(k.upper()) or cve.startswith(k): return k
    return cve
def relloc(loc):
    return re.sub(r"^/tmp/centinela_gitlab_scans/[^/]+/", "", (loc or "").strip())
def clean(d):
    d=re.sub(r"\*\*(.+?)\*\*",r"\1",d or ""); d=re.sub(r"`([^`]+)`",r"\1",d)
    d=re.sub(r"^\[[^\]]+\]\s*","",d); d=re.sub(r"\*\*Archivo:.*?\)\s*","",d,flags=re.S)
    return re.sub(r"\s+"," ",d).strip()
_PKG=re.compile(r"Paquete:\s*\*?\*?\s*([A-Za-z0-9_.\-]+(?::[A-Za-z0-9_.\-]+)?)")
_INST=re.compile(r"instalada:\s*\*?\*?\s*([A-Za-z0-9_.\-]+)")
_SAFE=re.compile(r"segura:\s*\*?\*?\s*([A-Za-z0-9_.\-]+)")
_MANI=re.compile(r"Manifiesto:\s*\*?\*?\s*([A-Za-z0-9_./\-]+)")
def vkey(v):
    o=[]
    for p in re.split(r"[.\-]", re.sub(r"(?i)\.release|\.final","",v or "")): o.append((0,int(p)) if p.isdigit() else (1,p))
    return o

def render_block(rows, st):
    """rows already filtered to one status; group by family; dedupe locations."""
    rows = [r for r in rows if not r["is_sca"]]
    if not rows:
        return '<p class="ok">Nada en esta categoría.</p>'
    groups=collections.defaultdict(list)
    for r in rows: groups[fam_key(r["cve"])].append(r)
    out=[]
    for key, rs in sorted(groups.items(), key=lambda kv:(min(SEV.get(x["sev"],5) for x in kv[1]), -len(kv[1]))):
        g=GUIDE.get(key); worst=min(rs,key=lambda x:SEV.get(x["sev"],5))["sev"]
        # dedupe locations by (relative path)
        seen=set(); ulocs=[]
        for r in sorted(rs, key=lambda x:(SEV.get(x["sev"],5), relloc(x["loc"]))):
            rl=relloc(r["loc"])
            if rl in seen: continue
            seen.add(rl); ulocs.append((rl, r["sev"]))
        title = g["t"] if g else clean(rs[0]["cve"])
        card=[f'<article class="finding f-{worst.lower()}">',
              f'<h4>{esc(title)}</h4><div class="chips">{pill(st)}<span class="pc">×{len(ulocs)}</span></div>']
        if g:
            card.append(f'<p><b>Qué encontramos.</b> {g["enc"]}</p>')
            card.append(f'<p><b>En qué afecta.</b> {g["afecta"]}</p>')
            if st!="corregido":
                card.append(f'<p><b>¿Se corrige sin actualizar librerías?</b> {g["resolver"]}</p>')
                if g["code"]:
                    card.append(f'<pre><code>{esc(g["code"])}</code></pre>')
        else:
            card.append(f'<p><b>Qué encontramos.</b> {esc(clean(rs[0]["desc"]))[:400]}</p>')
        if st=="corregido" and key in FIXNOTE:
            card.append(f'<p class="note note-fix"><b>Cómo se corrigió.</b> {FIXNOTE[key]}</p>')
        if st=="pendiente" and key in PENDNOTE:
            card.append(f'<p class="note">{PENDNOTE[key]}</p>')
        locs="".join(f'<li><code>{esc(rl)}</code><span class="sv sv-{sv.lower()}">{esc(sv)}</span></li>' for rl,sv in ulocs)
        card.append(f'<div class="where"><div class="wl">Dónde ({len(ulocs)})</div><ul>{locs}</ul></div>')
        card.append('</article>')
        out.append("".join(card))
    return "".join(out)

def render_B(pend):
    rows=[r for r in pend if r["is_sca"]]
    if not rows: return '<p class="ok">Sin CVEs de dependencias pendientes.</p>'
    pk={}
    for r in rows:
        d=re.sub(r"\*\*|`","",r["desc"] or ""); mp=_PKG.search(d)
        if not mp: continue
        g=pk.setdefault(mp.group(1),{"inst":None,"mani":None,"safe":[],"cve":set(),"sev":[]})
        mi,ms,mm=_INST.search(d),_SAFE.search(d),_MANI.search(d)
        if mi and not g["inst"]: g["inst"]=mi.group(1)
        if mm and not g["mani"]: g["mani"]=mm.group(1)
        if ms: g["safe"].append(ms.group(1))
        g["cve"].add(re.sub(r"^SCA-?","",r["cve"])); g["sev"].append(r["sev"])
    trs=[]
    for name,g in sorted(pk.items(), key=lambda kv:min(SEV.get(s,5) for s in kv[1]["sev"])):
        worst=min(g["sev"], key=lambda s:SEV.get(s,5))
        try: safe=max((s for s in g["safe"] if s), key=vkey) if g["safe"] else "—"
        except Exception: safe=g["safe"][0] if g["safe"] else "—"
        trs.append(f'<tr><td><span class="sv sv-{worst.lower()}">{esc(worst)}</span></td>'
                   f'<td><code>{esc(name)}</code><br><span class="mani">{esc(g["mani"] or "")}</span></td>'
                   f'<td class="ver"><code>{esc(g["inst"] or "?")}</code> &rarr; <code>&ge;{esc(safe)}</code></td>'
                   f'<td class="cves">{esc(", ".join(sorted(g["cve"])))}</td></tr>')
    return (f'<p>Estas {len(rows)} vulnerabilidades <b>sólo se resuelven subiendo la versión de la librería</b> '
            f'(la rama no las tocó). Mientras tanto: restringir la ruta en el reverse-proxy o aislar el servicio.</p>'
            f'<div class="tw"><table><thead><tr><th>Sev.</th><th>Librería / manifiesto</th>'
            f'<th>Instalada &rarr; objetivo</th><th>CVE</th></tr></thead><tbody>{"".join(trs)}</tbody></table></div>')

def main():
    D=json.load(open(SRC,encoding="utf-8"))
    for k in ("corregido","pendiente","nuevo"):
        for r in D[k]:
            r["is_sca"] = str(r.get("engine","")).lower() in ("sca-native","sca","trivy","grype","osv") or str(r.get("cve","")).upper().startswith(("SCA-","CVE-","GHSA-"))
    c=D["counts"]; gen=datetime.datetime.now().strftime("1 de septiembre de 2026, %H:%M")
    hp=(D.get("branch_head") or "").split(" ")
    head_short=esc(hp[0]) if hp else "—"; head_msg=esc(" ".join(hp[4:])) if len(hp)>4 else ""

    # distinct-file counts for headline
    def nfiles(rows, sca=False):
        return len({relloc(r["loc"]) + "|" + fam_key(r["cve"]) for r in rows if r["is_sca"]==sca})
    cor_n=nfiles(D["corregido"]); pen_n=nfiles(D["pendiente"]); pen_b=len([r for r in D["pendiente"] if r["is_sca"]])

    HTML=f'''<title>Avance rama develop-damc-seguridad</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400;6..72,500;6..72,600&family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap">
<style>
:root{{
  --ground:#f6f7f9;--surface:#fff;--ink:#1b2733;--ink-soft:#5b6b7b;--ink-faint:#8593a1;
  --brand:#1a3a5c;--brand-soft:#e7edf3;--rule:#e0e5ea;
  --a:#2f7d4e;--a-bg:#eef7f0;--a-rule:#cfe6d6;--b:#b26b12;--b-bg:#fdf5ea;--b-rule:#f0dcc0;
  --fixed:#2f7d4e;--pend:#b26b12;--new:#b23b2f;--new-bg:#fceeec;--new-rule:#f0cfca;
  --crit:#b83227;--high:#c9770d;--med:#9a7a1c;--low:#3f7d4f;--info:#2a6f9e;
  --code-bg:#0f1b28;--code-ink:#dbe4ec;
}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{
  --ground:#0d141c;--surface:#141d27;--ink:#e4e9ee;--ink-soft:#9fadba;--ink-faint:#71818f;
  --brand:#6ea3cf;--brand-soft:#1a2836;--rule:#26313d;
  --a:#5fb27e;--a-bg:#14241b;--a-rule:#2b4636;--b:#d29a54;--b-bg:#2a2013;--b-rule:#4a3a20;
  --fixed:#5fb27e;--pend:#d29a54;--new:#e0685c;--new-bg:#2a1613;--new-rule:#4a2620;
  --crit:#e0685c;--high:#e0a24f;--med:#cdb262;--low:#77b98c;--info:#68a8d0;
  --code-bg:#0a1119;--code-ink:#cbd6e0;
}}}}
:root[data-theme="dark"]{{
  --ground:#0d141c;--surface:#141d27;--ink:#e4e9ee;--ink-soft:#9fadba;--ink-faint:#71818f;
  --brand:#6ea3cf;--brand-soft:#1a2836;--rule:#26313d;
  --a:#5fb27e;--a-bg:#14241b;--a-rule:#2b4636;--b:#d29a54;--b-bg:#2a2013;--b-rule:#4a3a20;
  --fixed:#5fb27e;--pend:#d29a54;--new:#e0685c;--new-bg:#2a1613;--new-rule:#4a2620;
  --crit:#e0685c;--high:#e0a24f;--med:#cdb262;--low:#77b98c;--info:#68a8d0;
  --code-bg:#0a1119;--code-ink:#cbd6e0;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--ground);color:var(--ink);font-family:"DM Sans",system-ui,sans-serif;font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased}}
.wrap{{max-width:840px;margin:0 auto;padding:0 22px 90px}}
code{{font-family:"DM Mono",ui-monospace,monospace;font-size:.86em;background:var(--brand-soft);padding:1px 5px;border-radius:4px}}
.masthead{{border-bottom:2px solid var(--brand);padding:44px 0 18px}}
.eyebrow{{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--brand);font-weight:600}}
h1{{font-family:"Newsreader",Georgia,serif;font-weight:500;font-size:31px;line-height:1.15;margin:.3em 0;text-wrap:balance;letter-spacing:-.01em}}
.lede{{color:var(--ink-soft);max-width:64ch;margin:0}}
.runline{{margin-top:12px;font-size:12.5px;color:var(--ink-faint)}}
.commit{{font-size:12px;color:var(--ink-faint);margin:14px 0 0}} .commit span{{color:var(--ink-soft)}}
.kpis{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:22px 0 6px}}
.kpi{{background:var(--surface);border:1px solid var(--rule);border-radius:10px;padding:14px}}
.kpi .n{{font-family:"Newsreader",Georgia,serif;font-size:29px;font-weight:600;line-height:1;font-variant-numeric:tabular-nums}}
.kpi .l{{font-size:11.5px;color:var(--ink-soft);margin-top:6px}}
.kpi.k-f .n{{color:var(--fixed)}} .kpi.k-p .n{{color:var(--pend)}} .kpi.k-n .n{{color:var(--new)}}
.callout{{background:var(--brand-soft);border:1px solid var(--rule);border-left:3px solid var(--brand);border-radius:8px;padding:13px 15px;margin:20px 0;font-size:13px;color:var(--ink-soft)}}
.callout b{{color:var(--ink)}}
.pill{{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;border-radius:20px;border:1px solid transparent;white-space:nowrap}}
.st-fixed{{background:var(--a-bg);color:var(--fixed);border-color:var(--a-rule)}}
.st-pend{{background:var(--b-bg);color:var(--pend);border-color:var(--b-rule)}}
.st-new{{background:var(--new-bg);color:var(--new);border-color:var(--new-rule)}}
.pc{{font-family:"DM Mono",monospace;font-size:10px;color:var(--ink-faint);margin-left:3px}}
.block{{border-radius:12px;padding:6px 16px 16px;margin:16px 0;border:1px solid var(--rule)}}
.b-fixed{{background:var(--a-bg);border-color:var(--a-rule)}} .b-pend{{background:var(--b-bg);border-color:var(--b-rule)}}
.bl{{font-size:11px;letter-spacing:.13em;text-transform:uppercase;font-weight:700;padding:12px 0 8px}}
.b-fixed .bl{{color:var(--fixed)}} .b-pend .bl{{color:var(--pend)}}
.bl .sub{{display:block;font-weight:500;letter-spacing:.02em;text-transform:none;font-size:11px;color:var(--ink-faint);margin-top:2px}}
.ok{{color:var(--ink-soft);font-style:italic;font-size:13.5px;margin:6px 0}}
.finding{{background:var(--surface);border:1px solid var(--rule);border-radius:10px;border-left:3px solid var(--ink-faint);padding:14px 16px;margin:12px 0}}
.finding.f-critical{{border-left-color:var(--crit)}} .finding.f-high{{border-left-color:var(--high)}}
.finding.f-medium{{border-left-color:var(--med)}} .finding.f-low{{border-left-color:var(--low)}}
.finding h4{{margin:0 0 6px;font-size:15px;font-weight:700;text-wrap:balance}}
.chips{{margin-bottom:8px;display:flex;flex-wrap:wrap;gap:4px;align-items:center}}
.finding p{{margin:6px 0;font-size:13.5px}} .finding p b{{font-weight:600;color:var(--ink)}}
.finding p code,.where code,.note code{{background:var(--brand-soft)}}
pre{{background:var(--code-bg);color:var(--code-ink);border-radius:8px;padding:12px 14px;overflow-x:auto;font-size:12px;line-height:1.6;margin:10px 0 4px}}
pre code{{background:transparent;color:inherit;padding:0;font-size:12px}}
.where{{margin-top:10px;border-top:1px solid var(--rule);padding-top:8px}}
.wl{{font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-faint);margin-bottom:4px}}
.where ul{{list-style:none;margin:0;padding:0}}
.where li{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:3px 0;font-size:11.5px}}
.where code{{color:var(--ink-soft);font-size:10.5px}}
.sv{{font-size:9px;font-weight:700;letter-spacing:.05em;padding:1px 5px;border-radius:4px;text-transform:uppercase;color:#fff}}
.sv-critical{{background:var(--crit)}} .sv-high{{background:var(--high)}} .sv-medium{{background:var(--med)}}
.sv-low{{background:var(--low)}} .sv-info{{background:var(--info)}}
.note{{font-size:12.5px;color:var(--ink-soft);background:var(--brand-soft);border:1px solid var(--rule);border-radius:8px;padding:10px 12px;margin:8px 0 2px}}
.note-fix{{border-left:3px solid var(--fixed)}}
.tw{{overflow-x:auto;margin:10px 0}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
th{{text-align:left;font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-soft);padding:8px 9px;border-bottom:1px solid var(--rule);white-space:nowrap}}
td{{padding:9px 9px;border-bottom:1px solid var(--rule);vertical-align:top}}
td.ver{{white-space:nowrap;font-variant-numeric:tabular-nums}}
td.cves{{font-family:"DM Mono",monospace;font-size:10px;color:var(--ink-soft);line-height:1.6}}
.mani{{font-size:10px;color:var(--ink-faint)}}
footer{{margin-top:56px;padding-top:18px;border-top:1px solid var(--rule);font-size:11.5px;color:var(--ink-faint);line-height:1.7}}
</style>
<div class="wrap">
  <header class="masthead">
    <div class="eyebrow">Centinela-AI · CASMARTS · Confidencial</div>
    <h1>Rama <code>develop-damc-seguridad</code> — sideco-solicitud-web/backend</h1>
    <p class="lede">Escaneo de la rama de seguridad de Daniel Miranda comparada contra <code>develop</code>.
      Cada hallazgo indica qué encontramos, en qué afecta, cómo se corrige sin actualizar librerías, el
      código de la corrección y la ubicación exacta (archivo:línea), con su estado
      <span class="pill st-fixed">✓ Corregido</span> <span class="pill st-pend">● Pendiente</span>.</p>
    <p class="commit">Rama HEAD <code>{head_short}</code> · <span>{head_msg}</span> · base: <code>develop</code></p>
    <div class="runline">Re-análisis {gen} · SAST · SCA/OSV · STRIDE · Semgrep · SonarQube · Control de acceso · activo separado (no altera el seguimiento de develop)</div>
  </header>
  <div class="kpis">
    <div class="kpi k-f"><div class="n">{cor_n}</div><div class="l">Corregidos por el commit</div></div>
    <div class="kpi k-p"><div class="n">{pen_n}</div><div class="l">Aún pendientes ({pen_b} de dependencias)</div></div>
    <div class="kpi k-n"><div class="n">{c["nue"]}</div><div class="l">Nuevos / regresiones</div></div>
  </div>
  <div class="callout">
    <b>Veredicto.</b> El commit <code>{head_short}</code> es una remediación sólida: corrige los secretos
    hardcodeados (llave AES + <code>client-secret</code> + <code>password</code> de los YAML), el cifrado
    AES/ECB, varias consultas SQL nativas concatenadas y una resolución de ejecutable por PATH.
    <b>Sin regresiones.</b> Quedan pendientes CSRF/permitAll del controlador de captación, permisos de
    archivo del generador de .odt, el límite de tamaño de petición, 3 enlaces http:// en plantillas de
    correo, y un segundo sink de path traversal en <code>DocumentosController</code>. Revisar además el
    manejo del IV en el nuevo cifrado GCM (ver nota en la tarjeta de AES).
  </div>

  <div class="block b-fixed"><div class="bl">Corregido por la rama</div>
    {render_block(D["corregido"], "corregido")}
  </div>

  <div class="block b-pend"><div class="bl">Pendiente — resoluble sin actualizar librerías
     <span class="sub">cambio de código o configuración</span></div>
    {render_block(D["pendiente"], "pendiente")}
  </div>

  <div class="block b-pend"><div class="bl">Pendiente — requiere subir versión de dependencia</div>
    {render_B(D["pendiente"])}
  </div>

  <footer>
    Método: la rama se clonó y escaneó en un activo separado; cada motor de Centinela compara la huella de
    cada hallazgo (a nivel familia+archivo) contra el estado de <code>develop</code>. «Corregido» = el archivo
    ya no reproduce ese tipo de hallazgo en la rama. El PDF con la marca de Centinela está en
    <code>/opt/centinela-ai/docs/reportes/Reporte_SIDECO_backend_rama-seguridad_2026-09-01.pdf</code>.
    Clasificación: CONFIDENCIAL — uso interno.
  </footer>
</div>'''
    open(OUT,"w",encoding="utf-8").write(HTML)
    print("wrote", OUT, len(HTML))

if __name__ == "__main__":
    main()
