# -*- coding: utf-8 -*-
"""Detailed remediation-progress report: same card format as the 31-ago report
(qué encontramos / en qué afecta / se corrige sin actualizar librerías + código + dónde),
now with a CORREGIDO / PENDIENTE / NUEVO status on every finding, from compare_v2.json."""
import json, html, re, collections, datetime

SRC = "/tmp/claude-1000/-opt-centinela-ai/d6ed2905-f3a4-419f-a872-39919860cf03/scratchpad/compare_v2.json"
OUT = "/tmp/claude-1000/-opt-centinela-ai/d6ed2905-f3a4-419f-a872-39919860cf03/scratchpad/avance_remediacion_2026-09-01.html"

PRETTY = {
 "edomex-casmart/siat-atencion-citas/backend":  ("SIAT · Atención de Citas", "Backend — API REST (Java / Spring)"),
 "edomex-casmart/siat-atencion-citas/frontend": ("SIAT · Atención de Citas", "Frontend — SPA (Java webapp)"),
 "edomex-casmart/sideco-solicitud-web/backend":  ("SIDECO · Solicitud Web", "Backend — API REST (Java / Spring)"),
 "edomex-casmart/sideco-solicitud-web/frontend": ("SIDECO · Solicitud Web", "Frontend — SPA (Angular)"),
}

def G(t, e, a, r, c): return dict(t=t, enc=e, afecta=a, resolver=r, code=c)
# t=título · enc="qué encontramos" · afecta="en qué afecta" · resolver="cómo, sin actualizar" · code
GUIDE = {
 "AUTHZ-INCONSISTENT-FAMILY": G(
  "Escalación de privilegios — endpoint de identidad sin control de rol",
  "Un endpoint que administra identidad (usuarios / roles / permisos / menús) queda cubierto sólo por la regla "
  "final <code>.antMatchers(\"/v1/**\").authenticated()</code>, mientras endpoints hermanos de la misma app sí "
  "exigen rol admin (<code>@roleSecurity.isAdmin</code>). Es el patrón del retest de SIDECO: la cuenta TcsCSA2 "
  "(sin privilegios) recibía HTTP 200 en <code>getUsuarios</code>.",
  "Cualquier cuenta con sesión iniciada —aunque sea un ciudadano— llega a funciones administrativas: listar "
  "usuarios, editar sus atributos, asignar roles con privilegios elevados. OWASP A01:2021 / API5:2023.",
  "Sí, sin librerías nuevas. Añadir la regla que falta antes del catch-all, o —mejor— anotación a nivel de método.",
  "// ResourceServerConfig — ANTES de .antMatchers(\"/v1/**\").authenticated()\n"
  ".antMatchers(\"/v1/usr/**\").access(\"@roleSecurity.isAdmin(authentication)\")\n\n"
  "// o a nivel de método (defensa en profundidad)\n@PreAuthorize(\"hasRole('ADMIN')\")\n"
  "@GetMapping(\"/getUsuarios\") public ResponseEntity<?> getUsuarios() { ... }"),
 "AUTHZ-PERMITALL-WRITE": G(
  "Operación de escritura pública (permitAll)",
  "Un verbo POST/PUT/DELETE queda cubierto por una regla <code>permitAll()</code>.",
  "Cualquiera sin autenticarse puede invocar una operación que muta datos.",
  "Sí, sin librerías nuevas. Cambiar la decisión de la regla o sacar el endpoint del bloque permitAll.",
  ".antMatchers(HttpMethod.POST, \"/v1/ruta/afectada\").authenticated()   // o .access(\"...isAdmin...\")"),
 "AUTHZ-IDOR-PARAM-REVIEW": G(
  "Posible IDOR / BOLA — id del sujeto en la ruta",
  "El controlador recibe el identificador del usuario como parámetro de ruta y sólo exige "
  "<code>.authenticated()</code>. No se ve comprobación de pertenencia.",
  "Un usuario puede leer o modificar datos de otro cambiando el id en la URL.",
  "Sí, sin librerías nuevas. Comprobar en el servicio que el recurso pertenece a quien lo pide.",
  "Long idToken = usuarioService.idDe(SecurityContextHolder.getContext().getAuthentication());\n"
  "if (!idToken.equals(idUsuarioRuta) && !esAdmin())\n    return new ResponseEntity<>(HttpStatus.FORBIDDEN);"),
 "AUTHZ-CSRF-DISABLED": G(
  "Protección CSRF deshabilitada",
  "<code>.csrf().disable()</code> en la configuración de seguridad.",
  "Si la app autentica con cookie de sesión o form-login, un sitio de terceros puede forzar peticiones en "
  "nombre del usuario. Aceptable sólo si TODO el acceso es por Bearer token en cabecera.",
  "Sí, sin librerías nuevas. Si es 100% stateless, forzar STATELESS y documentarlo; si usa sesión, reactivar CSRF.",
  "// API stateless:\nhttp.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);\n"
  "// API con sesión:\nhttp.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());"),
 "SPRINGBOOT-NATIVE-QUERY-RISK": G(
  "Consulta nativa concatenada (riesgo de SQL injection)",
  "Un <code>@Query(nativeQuery = true)</code> o una consulta construida por concatenación de cadenas.",
  "Si algún fragmento proviene del usuario, permite inyección SQL: leer/alterar toda la base de datos.",
  "Sí, sin librerías nuevas. Usar parámetros nombrados / binding, nunca concatenación de strings.",
  "@Query(value = \"SELECT * FROM usr WHERE id = :id\", nativeQuery = true)\n"
  "List<Usr> find(@Param(\"id\") Long id);"),
 "STD-STRIDE-MISSING-AUDIT-LOG": G(
  "Endpoint de escritura sin bitácora de auditoría",
  "Una operación que crea / modifica / borra datos no deja registro de quién y cuándo.",
  "Ante un abuso (p. ej. la escalación de privilegios de arriba) no hay forma de investigar qué pasó.",
  "Sí, sin librerías nuevas. Añadir una línea de auditoría con usuario, acción, recurso y timestamp.",
  "auditLog.info(\"{} {} recurso={} ts={}\", usuario, \"UPDATE\", idRecurso, Instant.now());"),
 "STD-STRIDE-LOG-SENSITIVE-DATA": G(
  "Dato sensible escrito a la bitácora",
  "Una sentencia de log interpola un valor sensible (token, contraseña).",
  "El valor queda en archivos de log en claro; cualquiera con acceso a logs lo obtiene.",
  "Sí, sin librerías nuevas. Quitar el valor del log o enmascararlo.",
  "log.debug(\"token CSRF emitido para {}\", usuario);   // no el valor del token"),
 "SONAR-java-S6437": G(
  "Secreto / credencial embebida en el código o configuración",
  "SonarQube encontró una credencial o clave escrita literalmente en el repositorio "
  "(<code>application-*.yml</code>, <code>EncryptionUtil.java</code>, <code>Gateway/application.yml</code>).",
  "Cualquiera con acceso al código —o al historial de git— tiene la credencial. Si es la llave de cifrado, "
  "puede descifrar todo lo que la app protege.",
  "Sí, sin librerías nuevas. Mover el valor a variable de entorno / Vault y <b>rotar</b> el secreto expuesto "
  "(sigue en el historial de git aunque se borre del archivo).",
  "# application.yml\nspring:\n  datasource:\n    password: ${DB_PASSWORD}\n"
  "// EncryptionUtil: la llave NO va en el código\nbyte[] KEY = System.getenv(\"APP_ENC_KEY\").getBytes();"),
 "SONAR-java-S2612": G(
  "Permisos de archivo demasiado abiertos",
  "El código crea archivos o directorios con permisos world-readable/writable "
  "(equivalente a <code>chmod 777</code>).",
  "Otro proceso o usuario de la máquina puede leer o alterar esos archivos (p. ej. los .odt / .pdf generados "
  "con datos personales del ciudadano).",
  "Sí, sin librerías nuevas. Fijar permisos restrictivos al crear el archivo.",
  "Files.createFile(p, PosixFilePermissions.asFileAttribute(\n"
  "    PosixFilePermissions.fromString(\"rw-------\")));"),
 "SONAR-java-S5542": G(
  "Cifrado con modo/relleno inseguro (AES/ECB)",
  "<code>Cipher.getInstance(\"AES\")</code> sin especificar modo resuelve a <b>AES/ECB</b>.",
  "ECB no oculta patrones: bloques de texto claro iguales producen bloques cifrados iguales, se filtra "
  "estructura de los datos protegidos.",
  "Sí, sin librerías nuevas (usa el JCE del JDK). Cambiar a un modo autenticado.",
  "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");   // en vez de \"AES\"\n"
  "// RSA: \"RSA/ECB/OAEPWithSHA-256AndMGF1Padding\""),
 "java.lang.security.audit.crypto.use-of-default-aes": G(
  "AES sin configuración (Semgrep) — mismo problema que S5542",
  "<code>Cipher.getInstance(\"AES\")</code> en <code>EncryptionUtil.java</code>: modo y relleno por defecto = ECB.",
  "Igual que arriba: ECB filtra patrones del texto claro.",
  "Sí, sin librerías nuevas. Especificar <code>AES/GCM/NoPadding</code> y un IV aleatorio por operación.",
  "SecureRandom rnd = new SecureRandom(); byte[] iv = new byte[12]; rnd.nextBytes(iv);\n"
  "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
  "c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));"),
 "SONAR-java-S5693": G(
  "Límite de tamaño de petición excesivo (~2 GB)",
  "El límite de contenido está en ~2 147 483 648 bytes, frente al recomendado ~8 MB.",
  "Facilita agotar memoria o disco del servidor con una sola petición (denegación de servicio).",
  "Sí, sin librerías nuevas. Bajar el límite a lo que realmente necesita el negocio.",
  "spring:\n  servlet:\n    multipart:\n      max-file-size: 8MB\n      max-request-size: 10MB"),
 "SONAR-java-S4036": G(
  "Ejecutable resuelto por la variable PATH",
  "Se invoca un binario por nombre (p. ej. <code>pdftoppm</code>) y se resuelve vía el PATH del proceso.",
  "Un PATH manipulado hace que se ejecute otro binario con los privilegios de la app.",
  "Sí, sin librerías nuevas. Usar la ruta absoluta al ejecutable.",
  "new ProcessBuilder(\"/usr/bin/pdftoppm\", ...)   // no solo \"pdftoppm\""),
 "SONAR-typescript-S5332": G(
  "Comunicación en texto plano (http://)",
  "Una URL <code>http://</code> embebida en el código del frontend (típicamente el <code>apiUrl</code>).",
  "Si el tráfico pasa por una red no confiable, es interceptable y modificable (contraseñas, tokens, datos "
  "personales en claro).",
  "Sí, sin librerías nuevas. Cambiar a <code>https://</code> o a ruta relativa (hereda el esquema de la página).",
  "// environment.ts\napiUrl: 'https://<host>/wsbev1'   // no 'http://...'"),
 "SONAR-javascript-S2819": G(
  "postMessage / origen sin validar",
  "Se usa <code>window.postMessage</code> con destino <code>\"*\"</code> o sin comprobar <code>event.origin</code> al recibir.",
  "Cualquier ventana o iframe de otro origen puede leer el mensaje o inyectar uno.",
  "Sí, sin librerías nuevas. Fijar el origen destino y validar el origen al recibir.",
  "win.postMessage(data, 'https://mi-dominio');   // no '*'\n"
  "window.addEventListener('message', e => { if (e.origin !== 'https://mi-dominio') return; ... });"),
 "javascript.browser.security.wildcard-postmessage": G(
  "postMessage con comodín '*' (Semgrep) — mismo problema",
  "El destino de <code>window.postMessage()</code> es <code>\"*\"</code>.",
  "Cualquier origen puede recibir el mensaje: posible fuga de información.",
  "Sí, sin librerías nuevas. Especificar el origen destino exacto.",
  "win.postMessage(payload, 'https://10.4.2.185');   // no '*'"),
 "SONAR-typescript-S2245": G(
  "Aleatoriedad predecible (Math.random)",
  "<code>Math.random()</code> se usa para un valor con implicación de seguridad.",
  "Sus valores son predecibles: un atacante puede adivinar tokens o identificadores.",
  "Sí, sin librerías nuevas. Usar <code>crypto.getRandomValues</code>.",
  "const b = new Uint8Array(16); crypto.getRandomValues(b);"),
 "java.spring.security.injection.tainted-file-path": G(
  "Path traversal — ruta de archivo controlada por el usuario",
  "Un parámetro del usuario entra en una ruta de archivo sin sanear "
  "(<code>DocumentosController</code>).",
  "Con <code>../</code> el atacante lee o escribe archivos fuera del directorio previsto (config, claves, "
  "documentos de otros expedientes).",
  "Sí, sin librerías nuevas. Quedarse sólo con el nombre de archivo y resolver contra un directorio base fijo.",
  "String safe = org.apache.commons.io.FilenameUtils.getName(entrada);\n"
  "Path p = BASE_DIR.resolve(safe).normalize();\n"
  "if (!p.startsWith(BASE_DIR)) throw new IllegalArgumentException();"),
 "html.security.plaintext-http-link": G(
  "Enlace / recurso http:// en una plantilla HTML",
  "Un <code>href</code>/<code>src</code> <code>http://</code> en una plantilla (p. ej. la de correo).",
  "Contenido mixto y manipulable en tránsito; en un correo, permite redirigir al ciudadano a un sitio falso.",
  "Sí, sin librerías nuevas. Cambiar a <code>https://</code> o a URL relativa de protocolo.",
  "<a href=\"https://...\">   <!-- no http:// -->"),
 "generic.nginx.security.request-host-used": G(
  "nginx del repo confía en el Host de la petición",
  "El <code>nginx.conf</code> versionado usa <code>$host</code> / <code>$http_host</code> del cliente para "
  "construir URLs o decisiones.",
  "Un atacante que manipule la cabecera <code>Host</code> puede envenenar enlaces, caché o redirecciones.",
  "Sí, sin librerías nuevas. Fijar <code>server_name</code> explícito y usarlo en vez del Host del cliente.",
  "server_name solicitud.edomex.gob.mx;\n# usar un valor fijo, no $host, para redirects/enlaces absolutos"),
 "dockerfile.security.missing-user": G(
  "Dockerfile sin usuario no-root",
  "La imagen no baja de privilegios: el proceso corre como <code>root</code> dentro del contenedor.",
  "Si se compromete el proceso, el atacante es root en el contenedor — facilita escapar o pivotar.",
  "Sí, sin librerías nuevas. Añadir un usuario y <code>USER</code> al Dockerfile.",
  "RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app\nUSER appuser"),
 "DOCKER-MISSING-NON-ROOT-USER": G(
  "Dockerfile sin directiva USER",
  "Igual que arriba: la imagen no define un usuario no privilegiado.",
  "El contenedor corre como root.",
  "Sí, sin librerías nuevas. Añadir <code>USER</code> no-root.",
  "RUN useradd -m -u 10001 appuser\nUSER appuser"),
 "SONAR-docker-S6471": G(
  "Dockerfile — usuario / permisos",
  "SonarQube marca un problema de usuario o permisos en el Dockerfile.",
  "El contenedor corre con más privilegios de los necesarios.",
  "Sí, sin librerías nuevas. Definir <code>USER</code> no-root y permisos mínimos.",
  "USER appuser"),
 "FRONTEND-JWT-LOCALSTORAGE": G(
  "JWT de sesión guardado en localStorage",
  "El token de sesión se almacena en <code>localStorage</code> del navegador.",
  "Cualquier script en la página (una XSS, una dependencia comprometida) lo lee y roba la sesión; además no "
  "expira al cerrar la pestaña.",
  "Sí, sin librerías nuevas. Preferir cookie <code>HttpOnly; Secure; SameSite</code> emitida por el backend; "
  "si debe seguir en el cliente, usar <code>sessionStorage</code> y priorizar corregir las XSS.",
  "// el backend fija la cookie, el JS nunca la ve:\nSet-Cookie: session=<jwt>; HttpOnly; Secure; SameSite=Strict; Path=/"),
 "WCAG-1.3.1-FORM-CONTROL-NO-LABEL": G(
  "Campo de formulario sin etiqueta asociada",
  "Un <code>&lt;input&gt;</code> / <code>&lt;select&gt;</code> sin <code>&lt;label for&gt;</code> ni "
  "<code>aria-label</code> (patrón sistémico en el módulo <code>catalogos/*</code>).",
  "Un lector de pantalla no anuncia para qué sirve el campo. Para los sistemas del sector público del Estado "
  "de México es requisito legal (no una preferencia de diseño).",
  "Sí, sin librerías nuevas. Son cambios de marcado: el <code>for</code> del label y el <code>id</code> del "
  "input deben coincidir (ojo: <code>formControlName</code> no crea un <code>id</code>).",
  "<label for=\"curp\">CURP</label>\n<input id=\"curp\" formControlName=\"curp\">"),
 "WCAG-3.1.1-HTML-MISSING-LANG": G(
  "&lt;html&gt; sin atributo lang",
  "La etiqueta <code>&lt;html&gt;</code> no declara el idioma del documento.",
  "El lector de pantalla no sabe con qué pronunciación leer; requisito WCAG 3.1.1.",
  "Sí, sin librerías nuevas. Añadir <code>lang=\"es\"</code>.",
  "<html lang=\"es\">"),
}

STATUS = {  # (label, css, symbol)
 "corregido": ("Corregido", "st-fixed", "✓"),
 "pendiente": ("Pendiente", "st-pend", "●"),
 "nuevo":     ("Nuevo",     "st-new",  "!"),
}
HAND = {
 "51f6d9a": ("El commit «se eliminan métodos huérfanos o sin uso» borró de <code>CatalogoController</code> los "
             "endpoints <code>rolesWithMenus</code> / <code>catRoles</code> / <code>obtenerPermisos</code> / "
             "<code>catMenu</code> — verificado a mano: ya no existen. La falla queda cerrada de raíz."),
}
NEWNOTE = {
 "java.spring.security.injection.tainted-file-path":
   "Es el <b>mismo</b> path traversal de <code>DocumentosController</code>: el refactor de guardado del .odt "
   "movió la línea de 143 a 142, por eso figura como «nuevo». No es una vulnerabilidad adicional; sigue "
   "pendiente de corregir.",
 "SONAR-java-S2612":
   "<b>Introducido</b> por el cambio de «forma en que se guarda el .odt»: el nuevo código fija permisos "
   "demasiado abiertos al escribir la plantilla (<code>PlantillasOdtUtils.java:75-76</code>).",
}
PENDHAND = {
 "SONAR-java-S6437":
   "Confirmado a mano en el HEAD actual: queda la llave AES en el código "
   "(<code>EncryptionUtil.java:10</code> → <code>\"Sidec0S3cur1tyK3\"</code>) y "
   "<code>Gateway/application.yml:6</code> → <code>client-secret: hidegateway</code>. Los "
   "<code>password:</code> de los <code>application-*.yml</code> de ResourceServer/Eureka <b>sí</b> se movieron "
   "a variables de entorno.",
}

SCA_ENG = {"sca-native","sca","trivy","grype","osv"}
SCA_PFX = ("SCA-","CVE-","GHSA-","OSV-")
def is_sca(cve, eng): return (eng or "").lower() in SCA_ENG or (cve or "").upper().startswith(SCA_PFX)
def esc(s): return html.escape(str(s or ""))
SEV = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
def fam_key(cve):
    for k in GUIDE:
        if cve.upper().startswith(k.upper()) or cve.startswith(k): return k
    return cve
def clean(d):
    d = re.sub(r"\*\*(.+?)\*\*", r"\1", d or ""); d = re.sub(r"`([^`]+)`", r"\1", d)
    d = re.sub(r"^\[[^\]]+\]\s*", "", d); d = re.sub(r"\*\*Archivo:.*?\)\s*", "", d, flags=re.S)
    return re.sub(r"\s+", " ", d).strip()

_PKG=re.compile(r"Paquete:\s*\*?\*?\s*([A-Za-z0-9_.\-]+(?::[A-Za-z0-9_.\-]+)?)")
_INST=re.compile(r"instalada:\s*\*?\*?\s*([A-Za-z0-9_.\-]+)")
_SAFE=re.compile(r"segura:\s*\*?\*?\s*([A-Za-z0-9_.\-]+)")
_MANI=re.compile(r"Manifiesto:\s*\*?\*?\s*([A-Za-z0-9_./\-]+)")
def vkey(v):
    o=[]
    for p in re.split(r"[.\-]", re.sub(r"(?i)\.release|\.final","",v or "")):
        o.append((0,int(p)) if p.isdigit() else (1,p))
    return o

def status_pill(st):
    lbl,cls,sym = STATUS[st]
    return f'<span class="pill {cls}">{sym} {lbl}</span>'

def render_A(asset):
    # merge all three lists, tag each row with its status
    rows = ([dict(r, _st="corregido") for r in asset["corregido"]] +
            [dict(r, _st="pendiente") for r in asset["pendiente"]] +
            [dict(r, _st="nuevo")     for r in asset["nuevo"]])
    rows = [r for r in rows if not is_sca(r["cve"], r["engine"])]
    if not rows:
        return '<p class="ok">Nada en esta categoría.</p>'
    groups = {}
    for r in rows:
        groups.setdefault(fam_key(r["cve"]), []).append(r)
    out = []
    order = lambda rs: min(SEV.get(x["sev"],5) for x in rs)
    for key, rs in sorted(groups.items(), key=lambda kv:(order(kv[1]), -len(kv[1]))):
        g = GUIDE.get(key)
        worst = min(rs, key=lambda x:SEV.get(x["sev"],5))["sev"]
        cnt = collections.Counter(r["_st"] for r in rs)
        chips = " ".join(status_pill(s) for s in ("corregido","nuevo","pendiente") if cnt.get(s))
        chips = " ".join(f'{status_pill(s)}<span class="pc">×{cnt[s]}</span>'
                         for s in ("corregido","nuevo","pendiente") if cnt.get(s))
        title = g["t"] if g else clean(rs[0]["cve"])
        card = [f'<article class="finding f-{worst.lower()}">',
                f'<h4>{title}</h4><div class="chips">{chips}</div>']
        if g:
            card.append(f'<p><b>Qué encontramos.</b> {g["enc"]}</p>')
            card.append(f'<p><b>En qué afecta.</b> {g["afecta"]}</p>')
            card.append(f'<p><b>¿Se corrige sin actualizar librerías?</b> {g["resolver"]}</p>')
            card.append(f'<pre><code>{esc(g["code"])}</code></pre>')
        else:
            card.append(f'<p><b>Qué encontramos.</b> {esc(clean(rs[0]["desc"]))[:400]}</p>')
            card.append('<p><b>¿Se corrige sin actualizar librerías?</b> Sí — es un cambio de código o configuración.</p>')
        # per-location list with status
        locs = "".join(
          f'<li>{status_pill(r["_st"])}<code>{esc(r["loc"])}</code>'
          f'<span class="sv sv-{r["sev"].lower()}">{esc(r["sev"])}</span></li>'
          for r in sorted(rs, key=lambda x:(("corregido","nuevo","pendiente").index(x["_st"]), x["loc"])))
        card.append(f'<div class="where"><div class="wl">Dónde está en el código</div><ul>{locs}</ul></div>')
        for hk,note in HAND.items():
            if hk in asset["head"] and any(r["_st"]=="corregido" for r in rs):
                card.append(f'<p class="note note-fix">{note}</p>')
        for k,note in NEWNOTE.items():
            if key.startswith(k) and any(r["_st"]=="nuevo" for r in rs):
                card.append(f'<p class="note note-new">{note}</p>')
        for k,note in PENDHAND.items():
            if key.startswith(k) and any(r["_st"]=="pendiente" for r in rs):
                card.append(f'<p class="note">{note}</p>')
        card.append('</article>')
        out.append("".join(card))
    return "".join(out)

def render_B(asset):
    rows = ([dict(r,_st="corregido") for r in asset["corregido"]] +
            [dict(r,_st="pendiente") for r in asset["pendiente"]] +
            [dict(r,_st="nuevo") for r in asset["nuevo"]])
    rows = [r for r in rows if is_sca(r["cve"], r["engine"])]
    if not rows:
        return '<p class="ok">Sin CVEs de dependencias en esta base de código.</p>'
    pk = {}
    for r in rows:
        d = re.sub(r"\*\*|`","", r["desc"] or "")
        mp = _PKG.search(d)
        if not mp: continue
        g = pk.setdefault(mp.group(1), {"inst":None,"mani":None,"safe":[],"cve":set(),"sev":[],"st":set()})
        mi,ms,mm = _INST.search(d),_SAFE.search(d),_MANI.search(d)
        if mi and not g["inst"]: g["inst"]=mi.group(1)
        if mm and not g["mani"]: g["mani"]=mm.group(1)
        if ms: g["safe"].append(ms.group(1))
        g["cve"].add(re.sub(r"^SCA-?","",r["cve"])); g["sev"].append(r["sev"]); g["st"].add(r["_st"])
    trs=[]
    for name,g in sorted(pk.items(), key=lambda kv:min(SEV.get(s,5) for s in kv[1]["sev"])):
        worst=min(g["sev"], key=lambda s:SEV.get(s,5))
        try: safe=max((s for s in g["safe"] if s), key=vkey) if g["safe"] else "—"
        except Exception: safe=g["safe"][0] if g["safe"] else "—"
        st = "pendiente" if "pendiente" in g["st"] or "nuevo" in g["st"] else "corregido"
        trs.append(f'<tr><td>{status_pill(st)}</td>'
                   f'<td><span class="sv sv-{worst.lower()}">{esc(worst)}</span></td>'
                   f'<td><code>{esc(name)}</code><br><span class="mani">{esc(g["mani"] or "")}</span></td>'
                   f'<td class="ver"><code>{esc(g["inst"] or "?")}</code> → <code>≥{esc(safe)}</code></td>'
                   f'<td class="cves">{esc(", ".join(sorted(g["cve"])))}</td></tr>')
    return (f'<p><b>Qué encontramos.</b> {len(rows)} vulnerabilidades en dependencias, consolidadas en '
            f'<b>{len(pk)} librería(s)</b>. <b>En qué afecta:</b> son CVEs conocidas de librerías desactualizadas '
            f'(ejecución remota, elusión de autenticación, denegación de servicio según el caso). <b>Sólo se '
            f'resuelven subiendo la versión de la librería.</b> Mientras no sea posible: restringir la ruta '
            f'afectada en el reverse-proxy, deshabilitar la función si no se usa, o aislar el servicio en red — '
            f'el servidor de desarrollo aislado ya reduce la exposición real.</p>'
            f'<div class="tw"><table><thead><tr><th>Estado</th><th>Sev.</th><th>Librería / manifiesto</th>'
            f'<th>Instalada → objetivo</th><th>CVE</th></tr></thead><tbody>{"".join(trs)}</tbody></table></div>')

D = json.load(open(SRC))
gen = datetime.datetime.now().strftime("1 de septiembre de 2026")
tc = sum(a["counts"]["cor"] for a in D["assets"])
tp = sum(a["counts"]["pen"] for a in D["assets"])
tn = sum(a["counts"]["nue"] for a in D["assets"])

secs = []
for a in D["assets"]:
    sysn, comp = PRETTY.get(a["path"], (a["path"], ""))
    c = a["counts"]
    hp = a["head"].split(" ")
    head_short, head_msg = esc(hp[0]), esc(" ".join(hp[4:]))
    changed = (c["cor"] or c["nue"])
    vtxt = "Remediación parcial" if changed else "Sin cambios desde el 31-ago"
    vcls = "parcial" if changed else "sin-cambios"
    secs.append(f'''
    <section class="repo">
      <header class="rh">
        <div><h3>{esc(sysn)}</h3><p class="comp">{esc(comp)}</p></div>
        <div class="vbadge vb-{vcls}">{vtxt}</div>
      </header>
      <p class="commit">HEAD <code>{head_short}</code> · <span>{head_msg}</span></p>
      <div class="tallies">
        {status_pill("corregido")}<b>{c["cor"]}</b>
        {status_pill("nuevo")}<b>{c["nue"]}</b>
        {status_pill("pendiente")}<b>{c["pen"]}</b>
      </div>
      <div class="part part-a"><div class="pl">Parte A — Resolubles sin actualizar librerías</div>
        {render_A(a)}
      </div>
      <div class="part part-b"><div class="pl">Parte B — Requieren subir versión de dependencia</div>
        {render_B(a)}
      </div>
    </section>''')

HTML = f'''<title>Avance de remediación SIAT/SIDECO</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400;6..72,500;6..72,600&family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap">
<style>
:root{{
  --ground:#f6f7f9;--surface:#fff;--ink:#1b2733;--ink-soft:#5b6b7b;--ink-faint:#8593a1;
  --brand:#1a3a5c;--brand-soft:#e7edf3;--rule:#e0e5ea;
  --a:#2f7d4e;--a-bg:#eef7f0;--a-rule:#cfe6d6;
  --b:#b26b12;--b-bg:#fdf5ea;--b-rule:#f0dcc0;
  --fixed:#2f7d4e;--pend:#b26b12;--new:#b23b2f;--new-bg:#fceeec;--new-rule:#f0cfca;
  --crit:#b83227;--high:#c9770d;--med:#9a7a1c;--low:#3f7d4f;--info:#2a6f9e;
  --code-bg:#0f1b28;--code-ink:#dbe4ec;
}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{
  --ground:#0d141c;--surface:#141d27;--ink:#e4e9ee;--ink-soft:#9fadba;--ink-faint:#71818f;
  --brand:#6ea3cf;--brand-soft:#1a2836;--rule:#26313d;
  --a:#5fb27e;--a-bg:#14241b;--a-rule:#2b4636;
  --b:#d29a54;--b-bg:#2a2013;--b-rule:#4a3a20;
  --fixed:#5fb27e;--pend:#d29a54;--new:#e0685c;--new-bg:#2a1613;--new-rule:#4a2620;
  --crit:#e0685c;--high:#e0a24f;--med:#cdb262;--low:#77b98c;--info:#68a8d0;
  --code-bg:#0a1119;--code-ink:#cbd6e0;
}}}}
:root[data-theme="dark"]{{
  --ground:#0d141c;--surface:#141d27;--ink:#e4e9ee;--ink-soft:#9fadba;--ink-faint:#71818f;
  --brand:#6ea3cf;--brand-soft:#1a2836;--rule:#26313d;
  --a:#5fb27e;--a-bg:#14241b;--a-rule:#2b4636;
  --b:#d29a54;--b-bg:#2a2013;--b-rule:#4a3a20;
  --fixed:#5fb27e;--pend:#d29a54;--new:#e0685c;--new-bg:#2a1613;--new-rule:#4a2620;
  --crit:#e0685c;--high:#e0a24f;--med:#cdb262;--low:#77b98c;--info:#68a8d0;
  --code-bg:#0a1119;--code-ink:#cbd6e0;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--ground);color:var(--ink);
  font-family:"DM Sans",system-ui,sans-serif;font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased}}
.wrap{{max-width:880px;margin:0 auto;padding:0 22px 90px}}
code{{font-family:"DM Mono",ui-monospace,monospace;font-size:.86em;background:var(--brand-soft);padding:1px 5px;border-radius:4px}}
.masthead{{border-bottom:2px solid var(--brand);padding:44px 0 18px}}
.eyebrow{{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--brand);font-weight:600}}
h1{{font-family:"Newsreader",Georgia,serif;font-weight:500;font-size:32px;line-height:1.15;margin:.3em 0;text-wrap:balance;letter-spacing:-.01em}}
.lede{{color:var(--ink-soft);max-width:64ch;margin:0}}
.runline{{margin-top:12px;font-size:12.5px;color:var(--ink-faint)}}
.kpis{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:24px 0 6px}}
.kpi{{background:var(--surface);border:1px solid var(--rule);border-radius:10px;padding:14px}}
.kpi .n{{font-family:"Newsreader",Georgia,serif;font-size:29px;font-weight:600;line-height:1;font-variant-numeric:tabular-nums}}
.kpi .l{{font-size:11.5px;color:var(--ink-soft);margin-top:6px}}
.kpi.k-f .n{{color:var(--fixed)}} .kpi.k-p .n{{color:var(--pend)}} .kpi.k-n .n{{color:var(--new)}}
.callout{{background:var(--brand-soft);border:1px solid var(--rule);border-left:3px solid var(--brand);border-radius:8px;padding:13px 15px;margin:20px 0;font-size:13px;color:var(--ink-soft)}}
.callout b{{color:var(--ink)}}
.pill{{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;letter-spacing:.04em;
  text-transform:uppercase;padding:2px 8px;border-radius:20px;border:1px solid transparent;white-space:nowrap}}
.st-fixed{{background:var(--a-bg);color:var(--fixed);border-color:var(--a-rule)}}
.st-pend{{background:var(--b-bg);color:var(--pend);border-color:var(--b-rule)}}
.st-new{{background:var(--new-bg);color:var(--new);border-color:var(--new-rule)}}
.pc{{font-family:"DM Mono",monospace;font-size:10px;color:var(--ink-faint);margin:0 6px 0 3px}}
.repo{{margin:42px 0 0;padding-top:24px;border-top:1px solid var(--rule)}}
.rh{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}}
.rh h3{{font-family:"Newsreader",Georgia,serif;font-weight:600;font-size:21px;margin:0}}
.comp{{margin:2px 0 0;color:var(--ink-soft);font-size:12.5px}}
.vbadge{{font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:5px 11px;border-radius:20px;white-space:nowrap}}
.vb-parcial{{background:var(--b-bg);color:var(--b);border:1px solid var(--b-rule)}}
.vb-sin-cambios{{background:var(--brand-soft);color:var(--ink-soft);border:1px solid var(--rule)}}
.commit{{font-size:11.5px;color:var(--ink-faint);margin:8px 0 10px}}
.commit span{{color:var(--ink-soft)}}
.tallies{{display:flex;gap:6px;align-items:center;font-size:13px;margin-bottom:6px}}
.tallies b{{margin-right:12px;font-variant-numeric:tabular-nums}}
.part{{border-radius:12px;padding:6px 16px 16px;margin:14px 0;border:1px solid var(--rule)}}
.part-a{{background:var(--a-bg);border-color:var(--a-rule)}}
.part-b{{background:var(--b-bg);border-color:var(--b-rule)}}
.pl{{font-size:11px;letter-spacing:.13em;text-transform:uppercase;font-weight:700;padding:12px 0 8px}}
.part-a .pl{{color:var(--a)}} .part-b .pl{{color:var(--b)}}
.ok{{color:var(--ink-soft);font-style:italic;font-size:13.5px;margin:6px 0}}
.finding{{background:var(--surface);border:1px solid var(--rule);border-radius:10px;border-left:3px solid var(--ink-faint);padding:14px 16px;margin:12px 0}}
.finding.f-critical{{border-left-color:var(--crit)}} .finding.f-high{{border-left-color:var(--high)}}
.finding.f-medium{{border-left-color:var(--med)}} .finding.f-low{{border-left-color:var(--low)}}
.finding h4{{margin:0 0 6px;font-size:15px;font-weight:700;text-wrap:balance}}
.chips{{margin-bottom:8px;display:flex;flex-wrap:wrap;gap:4px;align-items:center}}
.finding p{{margin:6px 0;font-size:13.5px}}
.finding p b{{font-weight:600;color:var(--ink)}}
.finding p code, .where code, .note code{{background:var(--brand-soft)}}
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
.note-fix{{border-left:3px solid var(--fixed)}} .note-new{{border-left:3px solid var(--new)}}
.tw{{overflow-x:auto;margin:10px 0}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
th{{text-align:left;font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-soft);padding:8px 9px;border-bottom:1px solid var(--rule);white-space:nowrap}}
td{{padding:9px 9px;border-bottom:1px solid var(--rule);vertical-align:top}}
td.ver{{white-space:nowrap;font-variant-numeric:tabular-nums}}
td.cves{{font-family:"DM Mono",monospace;font-size:10px;color:var(--ink-soft);line-height:1.6}}
.mani{{font-size:10px;color:var(--ink-faint)}}
footer{{margin-top:56px;padding-top:18px;border-top:1px solid var(--rule);font-size:11.5px;color:var(--ink-faint);line-height:1.7}}
a{{color:var(--brand)}}
</style>
<div class="wrap">
  <header class="masthead">
    <div class="eyebrow">Centinela-AI · CASMARTS · Confidencial</div>
    <h1>Avance de remediación: qué se corrigió y qué falta, hallazgo por hallazgo</h1>
    <p class="lede">Comparación del código actual de <b>siat-atencion-citas</b> y <b>sideco-solicitud-web</b>
      (rama <code>develop</code>) contra el análisis del 31 de agosto. Cada hallazgo conserva el mismo formato
      —qué encontramos, en qué afecta, si se corrige sin actualizar librerías, dónde está en el código y el
      código de la corrección— y lleva su estado: <span class="pill st-fixed">✓ Corregido</span>
      <span class="pill st-pend">● Pendiente</span> <span class="pill st-new">! Nuevo</span>.</p>
    <div class="runline">Re-análisis {gen} · todos los motores, SonarQube forzado · mismo alcance (sólo código, sin infraestructura)</div>
  </header>
  <div class="kpis">
    <div class="kpi k-f"><div class="n">{tc}</div><div class="l">Corregidos</div></div>
    <div class="kpi k-p"><div class="n">{tp}</div><div class="l">Aún pendientes</div></div>
    <div class="kpi k-n"><div class="n">{tn}</div><div class="l">Nuevos / regresión</div></div>
  </div>
  <div class="callout">
    <b>Resumen.</b> Sólo <b>sideco-solicitud-web/backend</b> recibió remediación: 9 hallazgos cerrados —incluidas
    las 4 fallas HIGH de escalación de privilegios, al eliminar los endpoints de administración de roles/permisos—
    y 3 nuevos (2 reales por el cambio de guardado del .odt; 1 es el mismo path traversal con la línea desplazada).
    Los otros tres repositorios <b>no recibieron commits nuevos</b>: sus hallazgos del 31-ago siguen abiertos.
  </div>
  {"".join(secs)}
  <footer>
    Método: cada motor de Centinela compara la huella de cada hallazgo contra el escaneo previo y marca
    <code>RESUELTO</code> lo que ya no reproduce. Un hallazgo cuya línea se desplazó por una edición puede figurar
    como «corregido + nuevo» del mismo problema — se anota en el hallazgo cuando ocurre. El reporte base del 31-ago
    (PDF con la marca de Centinela) está en
    <code>/opt/centinela-ai/docs/reportes/Reporte_Citas_SolicitudWeb_Centinela_2026-08-31.pdf</code>.
    Clasificación: CONFIDENCIAL — uso interno.
  </footer>
</div>'''
open(OUT, "w").write(HTML)
print("wrote", OUT, len(HTML))
