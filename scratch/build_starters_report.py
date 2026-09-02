# -*- coding: utf-8 -*-
"""
Reporte de seguridad del grupo GitLab `starters` -- mismo formato detallado que los reportes de
SIAT/SIDECO (qué encontramos / en qué afecta / cómo se corrige sin actualizar librerías +
código de la corrección + ubicación exacta archivo:línea), Parte A / Parte B por repo.

starters: solo lee los activos GitLab/starters/*.

Emite:
  * artefacto HTML  -> scratchpad/reporte_starters_2026-09-02.html   (para publicar)
  * PDF house-style -> /app/docs/reportes/Reporte_STARTERS_Centinela_2026-09-02.pdf  (vía main.py)
"""
import json, html, re, collections, datetime, sys, os

SRC = "/tmp/claude-1000/-opt-centinela-ai/d6ed2905-f3a4-419f-a872-39919860cf03/scratchpad/starters_scan_2026-09-02.json"
OUT_HTML = "/tmp/claude-1000/-opt-centinela-ai/d6ed2905-f3a4-419f-a872-39919860cf03/scratchpad/reporte_starters_2026-09-02.html"

def G(t, e, a, r, c): return dict(t=t, enc=e, afecta=a, resolver=r, code=c)

# GUIDE neutralizado (sin referencias a SIDECO/SIAT )
GUIDE = {
 "AUTHZ-INCONSISTENT-FAMILY": G(
  "Escalación de privilegios — endpoint de identidad sin control de rol",
  "Un endpoint que administra identidad (usuarios / roles / permisos / menús) queda cubierto sólo por la "
  "regla final <code>.antMatchers(\"/**\").authenticated()</code> (o equivalente), mientras endpoints "
  "hermanos de la misma aplicación sí exigen rol de administrador (<code>hasRole</code> / "
  "<code>@roleSecurity.isAdmin</code>).",
  "Cualquier cuenta con sesión iniciada llega a funciones administrativas: listar usuarios, editar sus "
  "atributos, asignar roles con privilegios elevados. OWASP A01:2021 / API5:2023.",
  "Sí, sin librerías nuevas. Añadir la regla de rol que falta ANTES del catch-all, o —mejor— una anotación "
  "a nivel de método.",
  "// SecurityConfig — ANTES de .antMatchers(\"/**\").authenticated()\n"
  ".antMatchers(\"/usuarios/**\", \"/roles/**\").access(\"@roleSecurity.isAdmin(authentication)\")\n\n"
  "// o a nivel de método (defensa en profundidad)\n@PreAuthorize(\"hasRole('ADMIN')\")\n"
  "@GetMapping(\"/usuarios\") public ResponseEntity<?> listar() { ... }"),
 "AUTHZ-PERMITALL-WRITE": G(
  "Operación de escritura pública (permitAll)",
  "Un verbo POST/PUT/DELETE queda cubierto por una regla <code>permitAll()</code> en la configuración de "
  "Spring Security.",
  "Cualquiera sin autenticarse puede invocar una operación que crea, modifica o borra datos.",
  "Sí, sin librerías nuevas. Cambiar la decisión de la regla o sacar el endpoint del bloque permitAll; "
  "revisar que el patrón permitAll no sea más amplio de lo necesario.",
  ".antMatchers(HttpMethod.POST, \"/ruta/afectada\").authenticated()   // o .access(\"...isAdmin...\")"),
 "AUTHZ-ONLY-AUTHENTICATED-WRITE": G(
  "Escritura sensible sin verificación de rol",
  "El endpoint muta datos sensibles y sólo exige <code>.authenticated()</code>.",
  "Cualquier usuario con sesión puede invocarlo; falta un chequeo de rol.",
  "Sí, sin librerías nuevas. Añadir rol en la regla de URL o <code>@PreAuthorize</code> en el método.",
  "@PreAuthorize(\"hasRole('ADMIN')\")   // o hasAnyRole('ADMIN','GESTOR') según el negocio"),
 "AUTHZ-IDOR-PARAM-REVIEW": G(
  "Posible IDOR / BOLA — id del sujeto en la ruta",
  "El controlador recibe el identificador del usuario/recurso como parámetro de ruta y sólo exige "
  "<code>.authenticated()</code>. No se ve comprobación de pertenencia.",
  "Un usuario puede leer o modificar datos de otro cambiando el id en la URL.",
  "Sí, sin librerías nuevas. Comprobar en el servicio que el recurso pertenece a quien lo pide.",
  "Long idToken = usuarioService.idDe(SecurityContextHolder.getContext().getAuthentication());\n"
  "if (!idToken.equals(idRuta) && !esAdmin())\n    return new ResponseEntity<>(HttpStatus.FORBIDDEN);"),
 "AUTHZ-CSRF-DISABLED": G(
  "Protección CSRF deshabilitada",
  "<code>.csrf().disable()</code> en la configuración de seguridad.",
  "Si la app autentica con cookie de sesión o form-login, un sitio de terceros puede forzar peticiones en "
  "nombre del usuario. Aceptable sólo si TODO el acceso es por Bearer token en cabecera.",
  "Sí, sin librerías nuevas. Si el API es 100% stateless, forzar STATELESS y documentarlo; si usa sesión, "
  "reactivar CSRF con repositorio de token.",
  "// API stateless:\nhttp.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);\n"
  "// API con sesión:\nhttp.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());"),
 "AUTHZ-CLIENT-SIDE-ONLY": G(
  "Módulo de administración protegido sólo en el navegador",
  "La ruta del módulo admin de la SPA se protege únicamente con un guard de Angular "
  "(<code>canActivate</code>); el backend que consume ese módulo no verifica rol.",
  "Interceptar la respuesta y reescribir <code>403→200</code> renderiza el módulo y sus llamadas funcionan. CWE-602.",
  "Sí, sin librerías nuevas. El guard del front se queda por UX, pero el control real debe estar en el "
  "backend: cada endpoint que consume el módulo admin necesita <code>@PreAuthorize</code> o regla de rol.",
  "// backend — CADA endpoint consumido por el módulo admin:\n@PreAuthorize(\"hasRole('ADMIN')\")\n"
  "// prueba: repetir la petición con token NO-admin y confirmar 403 real"),
 "AUTHZ-CLIENT-SIDE-UI-GATE": G(
  "Función sensible ocultada sólo del lado del cliente",
  "Un <code>*ngIf</code> sobre un chequeo de rol decide la visibilidad de una función sensible.",
  "Editando el DOM o manipulando la respuesta, la función se ve y se usa igual.",
  "Sí, sin librerías nuevas. El <code>*ngIf</code> puede quedarse por UX; el backend debe rechazar la "
  "operación con 403.",
  "// backend: @PreAuthorize en el endpoint correspondiente — no confiar en el *ngIf"),
 "AUTHZ-ADMIN-BUNDLE-EXPOSED": G(
  "Componentes admin entregados a todos los clientes",
  "El módulo admin se compila en el bundle de la SPA y se entrega a todos los usuarios.",
  "Si su única protección es un guard, se puede renderizar manipulando la respuesta.",
  "Sí, sin librerías nuevas. Prioridad: proteger los endpoints en backend; separar el módulo admin en un "
  "bundle lazy es defensa adicional.",
  "// el control de acceso real va en el servidor"),
 "AUTHZ-NAMESPACE-GAP": G(
  "Prefijo de rutas sin cobertura de seguridad",
  "Los <code>antMatchers</code> cubren un prefijo (p. ej. <code>/v1/**</code>) pero hay controladores o "
  "llamadas del front bajo otro (<code>/api/**</code>) que ninguna regla contempla.",
  "Una ruta directa o un rewrite de proxy evita por completo el control de acceso.",
  "Sí, sin librerías nuevas. Unificar el prefijo y añadir un catch-all defensivo.",
  ".antMatchers(\"/v1/**\").authenticated()\n.antMatchers(\"/api/**\").authenticated()   // prefijo faltante\n"
  ".anyRequest().authenticated();"),
 "AUTHZ-NO-RULE": G(
  "Endpoint sin autorización definida",
  "Un endpoint no coincide con ninguna regla de <code>antMatchers</code>/<code>requestMatchers</code> ni "
  "tiene <code>@PreAuthorize</code>/<code>@Secured</code>.",
  "Su autorización es indefinida: puede quedar totalmente abierto o depender del orden de filtros.",
  "Sí, sin librerías nuevas. Añadir una regla explícita o una anotación de método.",
  "@PreAuthorize(\"isAuthenticated()\")   // punto de partida mínimo; ajustar el rol real requerido"),
 "AUTHZ-NO-METHOD-ANNOTATIONS": G(
  "Autorización sólo por lista de URLs (frágil)",
  "Muchos controladores y 0 anotaciones <code>@PreAuthorize</code>/<code>@Secured</code>. Toda la "
  "autorización depende de una lista de URLs mantenida a mano.",
  "Cualquier endpoint nuevo o renombrado queda sin protección hasta que alguien recuerde añadir la regla.",
  "Sí, sin librerías nuevas. Habilitar method security y anotar los controladores sensibles.",
  "@EnableGlobalMethodSecurity(prePostEnabled = true)   // sobre la clase de configuración"),
 "SPRINGBOOT-NATIVE-QUERY-RISK": G(
  "Consulta nativa concatenada (riesgo de SQL injection)",
  "Un <code>@Query(nativeQuery = true)</code> o una consulta construida por concatenación de cadenas.",
  "Si algún fragmento proviene del usuario, permite inyección SQL: leer o alterar toda la base de datos.",
  "Sí, sin librerías nuevas. Usar parámetros nombrados / binding, nunca concatenación de strings.",
  "@Query(value = \"SELECT * FROM tabla WHERE id = :id\", nativeQuery = true)\n"
  "List<T> find(@Param(\"id\") Long id);"),
 "CODE-INJECTION-EVAL": G(
  "Ejecución dinámica de código (eval)",
  "Uso de <code>eval()</code> / <code>Function()</code> / <code>exec</code> sobre datos que pueden venir del usuario.",
  "Permite ejecución de código arbitrario en el servidor o el navegador.",
  "Sí, sin librerías nuevas. Sustituir por un parseo explícito (<code>JSON.parse</code>, un switch, un mapa de funciones).",
  "// en vez de eval(expr): JSON.parse(expr)  o  { clave: () => ... }[clave]()"),
 "CMD-INJECTION-SHELL-TRUE": G(
  "Ejecución de comando con shell=True / concatenación",
  "Un comando de sistema se construye concatenando entrada y se ejecuta con shell.",
  "Con metacaracteres (<code>; | &amp;&amp; $()</code>) el atacante ejecuta comandos arbitrarios en el host.",
  "Sí, sin librerías nuevas. Pasar el comando como lista de argumentos, sin shell.",
  "subprocess.run([\"binario\", arg1, arg2])   # nunca shell=True con entrada concatenada"),
 "SSRF-UNCHECKED-FETCH": G(
  "Server-Side Request Forgery",
  "La aplicación hace una petición HTTP a una URL influida por el usuario sin validar el destino.",
  "El atacante alcanza servicios internos, metadatos de la nube o la red privada desde el servidor.",
  "Sí, sin librerías nuevas. Validar el host destino contra una allowlist antes de la petición.",
  "URI u = URI.create(entrada);\nif (!ALLOWLIST.contains(u.getHost())) throw new IllegalArgumentException();"),
 "HARDCODED-SECRET": G(
  "Secreto embebido en el código",
  "Una credencial, token o llave está escrita literalmente en el repositorio.",
  "Cualquiera con acceso al código —o al historial de git— la tiene.",
  "Sí, sin librerías nuevas. Mover el valor a variable de entorno / Vault y <b>rotar</b> el secreto expuesto.",
  "password: ${DB_PASSWORD}   # inyectado por entorno\n# y rotar la credencial que ya quedó en el historial"),
 "STD-STRIDE-MISSING-AUDIT-LOG": G(
  "Endpoint de escritura sin bitácora de auditoría",
  "Una operación que crea / modifica / borra datos no deja registro de quién y cuándo.",
  "Ante un abuso no hay forma de investigar qué pasó, quién lo hizo ni cuándo.",
  "Sí, sin librerías nuevas. Añadir una línea de auditoría con usuario, acción, recurso y timestamp.",
  "auditLog.info(\"{} {} recurso={} ts={}\", usuario, \"UPDATE\", idRecurso, Instant.now());"),
 "STD-STRIDE-LOG-SENSITIVE-DATA": G(
  "Dato sensible escrito a la bitácora",
  "Una sentencia de log interpola un valor sensible (token, contraseña, dato personal).",
  "El valor queda en archivos de log en claro; cualquiera con acceso a logs lo obtiene.",
  "Sí, sin librerías nuevas. Quitar el valor del log o enmascararlo.",
  "log.debug(\"token emitido para usuario {}\", usuario);   // no el valor del token"),
 "STD-STRIDE-JWT-INSECURE-ALG": G(
  "JWT con algoritmo inseguro",
  "Se acepta o firma un JWT con <code>alg=none</code> o HS256 con secreto débil / compartido.",
  "Un atacante puede forjar tokens y suplantar a cualquier usuario, incluido un administrador.",
  "Sí, sin librerías nuevas. Fijar el algoritmo esperado explícitamente y usar un secreto fuerte (o RS256).",
  "Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);  // rechaza alg=none"),
 "SONAR-java-S6437": G(
  "Secreto / credencial embebida en el código o configuración",
  "SonarQube encontró una credencial, token o llave escrita literalmente en el repositorio "
  "(típicamente <code>application-*.yml</code>, <code>application.properties</code> o una constante Java).",
  "Cualquiera con acceso al código —o al historial de git— tiene la credencial. Si es la llave de cifrado o "
  "firma, compromete todo lo que la app protege.",
  "Sí, sin librerías nuevas. Mover el valor a variable de entorno / Vault y <b>rotar</b> el secreto expuesto "
  "(sigue en el historial de git aunque se borre del archivo).",
  "# application.yml\nspring:\n  datasource:\n    password: ${DB_PASSWORD}\n"
  "// llaves: NO en el código\nbyte[] KEY = System.getenv(\"APP_ENC_KEY\").getBytes();"),
 "SONAR-java-S2076": G(
  "Inyección de comando de SO",
  "Entrada del usuario llega a <code>Runtime.exec</code> / <code>ProcessBuilder</code> sin sanear.",
  "Ejecución de comandos arbitrarios en el servidor.",
  "Sí, sin librerías nuevas. Pasar argumentos como lista, validar contra allowlist, nunca construir una cadena de shell.",
  "new ProcessBuilder(\"/usr/bin/tool\", argValidado).start();"),
 "SONAR-java-S3649": G(
  "Inyección SQL (consulta construida por concatenación)",
  "Una consulta SQL se arma concatenando entrada del usuario.",
  "Inyección SQL: lectura/alteración de toda la base de datos, elusión de autenticación.",
  "Sí, sin librerías nuevas. Usar <code>PreparedStatement</code> con parámetros, o el binding del ORM.",
  "PreparedStatement ps = con.prepareStatement(\"SELECT * FROM t WHERE id = ?\");\nps.setLong(1, id);"),
 "SONAR-java-S5145": G(
  "Log envenenable (CRLF / forjado de bitácora)",
  "Entrada del usuario se escribe a la bitácora sin sanear saltos de línea.",
  "Un atacante inserta líneas de log falsas para ocultar actividad o confundir una investigación.",
  "Sí, sin librerías nuevas. Sanear <code>\\r\\n</code> antes de loguear entrada del usuario.",
  "log.info(\"login user={}\", user.replaceAll(\"[\\\\r\\\\n]\", \"_\"));"),
 "SONAR-java-S2612": G(
  "Permisos de archivo demasiado abiertos",
  "El código crea archivos o directorios con permisos world-readable/writable (equivalente a <code>chmod 777</code>).",
  "Otro proceso o usuario de la máquina puede leer o alterar esos archivos (documentos, cargas, PDFs generados).",
  "Sí, sin librerías nuevas. Fijar permisos restrictivos al crear el archivo.",
  "Files.createFile(p, PosixFilePermissions.asFileAttribute(\n    PosixFilePermissions.fromString(\"rw-------\")));"),
 "SONAR-java-S5542": G(
  "Cifrado con modo/relleno inseguro (AES/ECB)",
  "<code>Cipher.getInstance(\"AES\")</code> sin especificar modo resuelve a <b>AES/ECB</b>.",
  "ECB no oculta patrones: bloques de texto claro iguales producen bloques cifrados iguales.",
  "Sí, sin librerías nuevas (usa el JCE del JDK). Cambiar a un modo autenticado.",
  "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");   // en vez de \"AES\"\n"
  "// RSA: \"RSA/ECB/OAEPWithSHA-256AndMGF1Padding\""),
 "SONAR-java-S5527": G(
  "Verificación de certificado TLS deshabilitada",
  "Un <code>TrustManager</code> / <code>HostnameVerifier</code> que acepta cualquier certificado.",
  "Un atacante en la red intercepta el tráfico TLS sin que la app lo note (man-in-the-middle).",
  "Sí, sin librerías nuevas. Quitar el TrustManager permisivo y usar el almacén de confianza por defecto.",
  "// borrar el TrustManager que hace 'return' vacío en checkServerTrusted\n// usar SSLContext.getDefault()"),
 "SONAR-java-S4423": G(
  "Protocolo TLS obsoleto",
  "Se fuerza <code>TLSv1</code> / <code>TLSv1.1</code> / <code>SSLv3</code>.",
  "Protocolos con debilidades criptográficas conocidas (BEAST, POODLE).",
  "Sí, sin librerías nuevas. Fijar <code>TLSv1.2</code> como mínimo.",
  "SSLContext.getInstance(\"TLSv1.2\");"),
 "SONAR-java-S5693": G(
  "Límite de tamaño de petición excesivo (~2 GB)",
  "El límite de contenido está en ~2 147 483 648 bytes, frente al recomendado ~8 MB.",
  "Facilita agotar memoria o disco del servidor con una sola petición (denegación de servicio).",
  "Sí, sin librerías nuevas. Bajar el límite a lo que realmente necesita el negocio.",
  "spring:\n  servlet:\n    multipart:\n      max-file-size: 8MB\n      max-request-size: 10MB"),
 "SONAR-java-S4036": G(
  "Ejecutable resuelto por la variable PATH",
  "Se invoca un binario por nombre y se resuelve vía el PATH del proceso.",
  "Un PATH manipulado hace que se ejecute otro binario con los privilegios de la app.",
  "Sí, sin librerías nuevas. Usar la ruta absoluta al ejecutable.",
  "new ProcessBuilder(\"/usr/bin/pdftoppm\", ...)   // no solo \"pdftoppm\""),
 "SONAR-java-S2647": G(
  "Autenticación HTTP básica (credenciales en cada petición)",
  "Se usa Basic Auth: usuario y contraseña en base64 en cada petición.",
  "Si el transporte no es TLS estricto, las credenciales viajan casi en claro y se reutilizan.",
  "Sí, sin librerías nuevas. Migrar a token de sesión / OAuth2; si Basic Auth es inevitable, exigir HTTPS.",
  "// preferir Bearer token; Basic Auth solo sobre TLS y para servicio-a-servicio"),
 "SONAR-typescript-S5332": G(
  "Comunicación en texto plano (http://)",
  "Una URL <code>http://</code> embebida en el código del frontend (típicamente el <code>apiUrl</code> del "
  "<code>environment.ts</code>).",
  "Si el tráfico pasa por una red no confiable, es interceptable y modificable (contraseñas, tokens, datos "
  "personales en claro).",
  "Sí, sin librerías nuevas. Cambiar a <code>https://</code> o a ruta relativa (hereda el esquema de la página).",
  "// environment.ts\napiUrl: 'https://<host>/api'   // no 'http://...'"),
 "SONAR-javascript-S2819": G(
  "postMessage / origen sin validar",
  "Se usa <code>window.postMessage</code> con destino <code>\"*\"</code> o sin comprobar <code>event.origin</code> al recibir.",
  "Cualquier ventana o iframe de otro origen puede leer el mensaje o inyectar uno.",
  "Sí, sin librerías nuevas. Fijar el origen destino y validar el origen al recibir.",
  "win.postMessage(data, 'https://mi-dominio');   // no '*'\n"
  "addEventListener('message', e => { if (e.origin !== 'https://mi-dominio') return; ... });"),
 "SONAR-typescript-S2245": G(
  "Aleatoriedad predecible (Math.random)",
  "<code>Math.random()</code> se usa para un valor con implicación de seguridad (token, id).",
  "Sus valores son predecibles: un atacante puede adivinarlos.",
  "Sí, sin librerías nuevas. Usar <code>crypto.getRandomValues</code>.",
  "const b = new Uint8Array(16); crypto.getRandomValues(b);"),
 "SONAR-typescript-S6268": G(
  "Sanitización de HTML deshabilitada (Angular)",
  "Uso de <code>bypassSecurityTrust*</code> o <code>[innerHTML]</code> con contenido no confiable.",
  "XSS: un valor con <code>&lt;script&gt;</code> o handlers se ejecuta en la sesión de la víctima.",
  "Sí, sin librerías nuevas. Quitar el bypass; dejar que Angular sanee, o sanear explícitamente con DomSanitizer.",
  "this.safe = this.sanitizer.sanitize(SecurityContext.HTML, valor);   // no bypassSecurityTrustHtml"),
 "java.spring.security.injection.tainted-file-path": G(
  "Path traversal — ruta de archivo controlada por el usuario",
  "Un parámetro del usuario entra en una ruta de archivo sin sanear.",
  "Con <code>../</code> el atacante lee o escribe archivos fuera del directorio previsto (config, llaves, "
  "documentos de otros expedientes).",
  "Sí, sin librerías nuevas. Quedarse sólo con el nombre de archivo y resolver contra un directorio base fijo.",
  "String safe = org.apache.commons.io.FilenameUtils.getName(entrada);\n"
  "Path p = BASE_DIR.resolve(safe).normalize();\nif (!p.startsWith(BASE_DIR)) throw new IllegalArgumentException();"),
 "java.lang.security.audit.crypto": G(
  "Criptografía / aleatoriedad débil",
  "Uso de un algoritmo obsoleto (MD5 / SHA-1 / DES) o de <code>java.util.Random</code> para valores de seguridad.",
  "Hashes rompibles, cifrado débil, tokens predecibles.",
  "Sí, sin librerías nuevas (JCE del JDK). Cambiar a SHA-256+ y <code>SecureRandom</code>.",
  "MessageDigest.getInstance(\"SHA-256\");\nprivate static final SecureRandom RNG = new SecureRandom();"),
 "java.lang.security.audit.crypto.use-of-default-aes": G(
  "AES sin configuración (modo por defecto = ECB)",
  "<code>Cipher.getInstance(\"AES\")</code> sin especificar modo ni relleno.",
  "El modo por defecto es ECB, que filtra patrones del texto claro.",
  "Sí, sin librerías nuevas. Especificar <code>AES/GCM/NoPadding</code> y un IV aleatorio por operación.",
  "SecureRandom rnd = new SecureRandom(); byte[] iv = new byte[12]; rnd.nextBytes(iv);\n"
  "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
  "c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));"),
 "html.security.plaintext-http-link": G(
  "Enlace / recurso http:// en una plantilla HTML",
  "Un <code>href</code>/<code>src</code> <code>http://</code> en una plantilla (p. ej. la de un correo).",
  "Contenido mixto y manipulable en tránsito; en un correo, permite redirigir al usuario a un sitio falso.",
  "Sí, sin librerías nuevas. Cambiar a <code>https://</code> o a URL relativa de protocolo.",
  "<a href=\"https://...\">   <!-- no http:// -->"),
 "generic.nginx.security.request-host-used": G(
  "nginx del repo confía en el Host de la petición",
  "El <code>nginx.conf</code> versionado usa <code>$host</code> / <code>$http_host</code> del cliente para "
  "construir URLs o tomar decisiones.",
  "Un atacante que manipule la cabecera <code>Host</code> puede envenenar enlaces, caché o redirecciones.",
  "Sí, sin librerías nuevas. Fijar <code>server_name</code> explícito y usarlo en vez del Host del cliente.",
  "server_name mi-dominio.gob.mx;\n# usar un valor fijo, no $host, para redirects/enlaces absolutos"),
 "dockerfile.security.missing-user": G(
  "Dockerfile sin usuario no-root",
  "La imagen no baja de privilegios: el proceso corre como <code>root</code> dentro del contenedor.",
  "Si se compromete el proceso, el atacante es root en el contenedor — facilita escapar o pivotar.",
  "Sí, sin librerías nuevas. Añadir un usuario y <code>USER</code> al Dockerfile.",
  "RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app\nUSER appuser"),
 "DOCKER-MISSING-NON-ROOT-USER": G(
  "Dockerfile sin directiva USER",
  "La imagen no define un usuario no privilegiado.",
  "El contenedor corre como root.",
  "Sí, sin librerías nuevas. Añadir <code>USER</code> no-root.",
  "RUN useradd -m -u 10001 appuser\nUSER appuser"),
 "SONAR-docker-S6471": G(
  "Dockerfile — usuario / permisos",
  "SonarQube marca un problema de usuario o permisos en el Dockerfile.",
  "El contenedor corre con más privilegios de los necesarios.",
  "Sí, sin librerías nuevas. Definir <code>USER</code> no-root y permisos mínimos.",
  "USER appuser"),
 "SONAR-docker-S6470": G(
  "Dockerfile — COPY demasiado amplio",
  "Un <code>COPY . .</code> puede meter <code>.env</code> / <code>.git</code> / credenciales dentro de la imagen.",
  "Secretos y metadatos del repositorio terminan en la imagen distribuida.",
  "Sí, sin librerías nuevas. Restringir el COPY y usar <code>.dockerignore</code>.",
  ".dockerignore:\n.env*\n.git\n**/node_modules"),
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
  "<code>aria-label</code>.",
  "Un lector de pantalla no anuncia para qué sirve el campo. Para los sistemas del sector público del Estado "
  "de México es requisito legal.",
  "Sí, sin librerías nuevas. Son cambios de marcado: el <code>for</code> del label y el <code>id</code> del "
  "input deben coincidir (ojo: <code>formControlName</code> no crea un <code>id</code>).",
  "<label for=\"curp\">CURP</label>\n<input id=\"curp\" formControlName=\"curp\">"),
 "WCAG-3.1.1-HTML-MISSING-LANG": G(
  "&lt;html&gt; sin atributo lang",
  "La etiqueta <code>&lt;html&gt;</code> no declara el idioma del documento.",
  "El lector de pantalla no sabe con qué pronunciación leer; requisito WCAG 3.1.1.",
  "Sí, sin librerías nuevas. Añadir <code>lang=\"es\"</code>.",
  "<html lang=\"es\">"),
 "WCAG-1.1.1-IMG-MISSING-ALT": G(
  "Imagen sin texto alternativo",
  "Un <code>&lt;img&gt;</code> sin atributo <code>alt</code>.",
  "El lector de pantalla no puede describir la imagen; requisito WCAG 1.1.1.",
  "Sí, sin librerías nuevas. Añadir <code>alt</code> descriptivo (o <code>alt=\"\"</code> si es decorativa).",
  "<img src=\"logo.png\" alt=\"Escudo del Gobierno del Estado de México\">"),
 "WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT": G(
  "Enlace o botón sin nombre accesible",
  "Un <code>&lt;a&gt;</code>/<code>&lt;button&gt;</code> vacío, sin texto ni <code>aria-label</code>.",
  "El lector de pantalla lo anuncia como \"enlace\" / \"botón\" sin decir qué hace; requisito WCAG 2.4.4.",
  "Sí, sin librerías nuevas. Añadir texto visible o <code>aria-label</code>.",
  "<button aria-label=\"Cerrar\"><i class=\"icon-x\"></i></button>"),
 "SONAR-java-S4790": G(
  "Hashing con algoritmo débil (MD5 / SHA-1)",
  "SonarQube encontró uso de <code>MessageDigest.getInstance(\"MD5\"/\"SHA-1\")</code> o equivalente.",
  "MD5/SHA-1 tienen colisiones prácticas: no sirven para integridad ni para hash de contraseñas.",
  "Sí, sin librerías nuevas (JCE del JDK). Para integridad usar SHA-256; para contraseñas, bcrypt/Argon2.",
  "MessageDigest.getInstance(\"SHA-256\");\n// contraseñas: new BCryptPasswordEncoder().encode(pwd)"),
 "SONAR-java-S4830": G(
  "Validación de certificado de servidor deshabilitada",
  "Un <code>TrustManager</code> que no valida la cadena de certificados (método <code>checkServerTrusted</code> vacío).",
  "Un atacante en la red intercepta el tráfico TLS haciéndose pasar por el servidor (man-in-the-middle).",
  "Sí, sin librerías nuevas. Quitar el TrustManager permisivo; usar el almacén de confianza por defecto del JDK.",
  "// borrar el X509TrustManager con checkServerTrusted vacío\n// dejar que el runtime valide la cadena"),
 "SONAR-java-S4423": G(
  "Protocolo TLS obsoleto",
  "Se fuerza <code>TLSv1</code> / <code>TLSv1.1</code> / <code>SSLv3</code>.",
  "Protocolos con debilidades conocidas (BEAST, POODLE).",
  "Sí, sin librerías nuevas. Fijar <code>TLSv1.2</code> como mínimo.",
  "SSLContext.getInstance(\"TLSv1.2\");"),
 "SONAR-java-S5443": G(
  "Uso de directorio temporal compartido para datos sensibles",
  "Se escribe a <code>/tmp</code> (o <code>java.io.tmpdir</code>) un archivo con información sensible.",
  "Cualquier usuario local puede leer o sustituir el archivo (condición de carrera / fuga de datos).",
  "Sí, sin librerías nuevas. Usar <code>Files.createTempFile</code> (crea con permisos restrictivos) o un directorio propio con permisos 700.",
  "Path p = Files.createTempFile(\"app-\", \".tmp\");   // 600 por defecto en POSIX"),
 "SONAR-java-S6418": G(
  "Secreto embebido en el código",
  "SonarQube detectó una cadena que parece una credencial, token o llave asignada literalmente en el código.",
  "Cualquiera con acceso al repositorio —o a su historial— tiene el secreto.",
  "Sí, sin librerías nuevas. Mover a variable de entorno / Vault y <b>rotar</b> el secreto expuesto.",
  "String apiKey = System.getenv(\"API_KEY\");   // no una constante en el .java"),
 "SONAR-typescript-S6418": G(
  "Secreto embebido en el código (frontend)",
  "Una cadena que parece token/llave asignada literalmente en el TypeScript.",
  "Todo secreto en el bundle del frontend es público: cualquier usuario lo extrae del navegador.",
  "Sí, sin librerías nuevas. El frontend no debe llevar secretos: mover la operación al backend, o usar un token de vida corta emitido por sesión.",
  "// nada de claves de API en environment.ts — el backend hace la llamada autenticada"),
 "SONAR-python-S2068": G(
  "Credencial embebida en el código (Python)",
  "Una contraseña o token asignado como literal en el código Python.",
  "Cualquiera con acceso al repositorio la tiene.",
  "Sí, sin librerías nuevas. Leer de entorno / secreto y rotar el valor expuesto.",
  "PASSWORD = os.environ[\"DB_PASSWORD\"]   # no un literal"),
 "SONAR-python-S5332": G(
  "Protocolo en texto plano (http:// / ftp:// / telnet)",
  "Se usa una URL o conexión sin cifrar en el código Python.",
  "Credenciales y datos viajan en claro; interceptables y modificables en tránsito.",
  "Sí, sin librerías nuevas. Cambiar a https:// / ftps / ssh.",
  "requests.get('https://host/api')   # no http://"),
 "SONAR-kubernetes-S5332": G(
  "Protocolo en texto plano en manifiesto de Kubernetes",
  "Un manifiesto k8s referencia un endpoint <code>http://</code>.",
  "Tráfico interno del clúster sin cifrar.",
  "Sí, sin librerías nuevas. Usar https:// o mTLS del service mesh.",
  "# usar el Service con TLS, no http://"),
 "SONAR-kubernetes-S6865": G(
  "Token de service account montado automáticamente",
  "El pod no fija <code>automountServiceAccountToken: false</code> y no necesita hablar con el API server.",
  "Si el pod se compromete, el token da acceso a la API de Kubernetes con los permisos de esa service account.",
  "Sí, sin librerías nuevas. Deshabilitar el automontaje si el pod no usa la API.",
  "spec:\n  automountServiceAccountToken: false"),
 "SONAR-kubernetes-S6864": G(
  "Contenedor sin límites de memoria",
  "El manifiesto no define <code>resources.limits.memory</code>.",
  "Un contenedor con fuga de memoria puede tumbar el nodo entero (afecta a todos los pods vecinos).",
  "Sí, sin librerías nuevas. Añadir requests y limits de memoria y CPU.",
  "resources:\n  limits:\n    memory: \"512Mi\"\n    cpu: \"500m\""),
 "ANGULAR-BYPASS-SECURITY-TRUST": G(
  "Sanitización de Angular deshabilitada (bypassSecurityTrust*)",
  "Uso de <code>DomSanitizer.bypassSecurityTrustHtml/Url/Style/...</code> sobre contenido que puede venir del usuario.",
  "XSS: un valor con <code>&lt;script&gt;</code> o un handler <code>onerror=</code> se ejecuta en la sesión de la víctima.",
  "Sí, sin librerías nuevas. Quitar el bypass y dejar que Angular sanee; si necesitas HTML controlado, sanear explícitamente.",
  "this.safe = this.sanitizer.sanitize(SecurityContext.HTML, valor);   // no bypassSecurityTrustHtml(valor)"),
 "SONAR-typescript-S6268": G(
  "Sanitización de HTML deshabilitada (Angular)",
  "Uso de <code>bypassSecurityTrust*</code> o binding <code>[innerHTML]</code> con contenido no confiable.",
  "XSS en la sesión de la víctima.",
  "Sí, sin librerías nuevas. Quitar el bypass; sanear con <code>DomSanitizer.sanitize</code>.",
  "this.safe = this.sanitizer.sanitize(SecurityContext.HTML, valor);"),
 "SONAR-java-S5527": G(
  "Verificación del nombre de host TLS deshabilitada",
  "Un <code>HostnameVerifier</code> que devuelve siempre <code>true</code>.",
  "Un certificado válido para cualquier dominio sirve para interceptar el tráfico (MITM).",
  "Sí, sin librerías nuevas. Quitar el HostnameVerifier permisivo; usar el por defecto.",
  "// borrar el HostnameVerifier que hace 'return true'"),
 "SONAR-java-S6437": G(
  "Secreto / credencial embebida en el código o configuración",
  "SonarQube encontró una credencial, token o llave escrita literalmente en el repositorio "
  "(típicamente <code>application-*.yml</code>, <code>application.properties</code> o una constante Java).",
  "Cualquiera con acceso al código —o al historial de git— tiene la credencial. Si es la llave de cifrado o "
  "firma, compromete todo lo que la app protege.",
  "Sí, sin librerías nuevas. Mover el valor a variable de entorno / Vault y <b>rotar</b> el secreto expuesto.",
  "# application.yml\nspring:\n  datasource:\n    password: ${DB_PASSWORD}\n"
  "// llaves: NO en el código\nbyte[] KEY = System.getenv(\"APP_ENC_KEY\").getBytes();"),
 "java.lang.security.audit.weak-ssl-context": G(
  "SSLContext débil / confianza TLS permisiva",
  "Se crea un <code>SSLContext</code> con protocolo obsoleto o con un <code>TrustManager</code> que acepta "
  "cualquier certificado (<code>loadTrustMaterial(null, (c,a) -&gt; true)</code>).",
  "Un atacante en la red intercepta el tráfico HTTPS de salida sin que la app lo note (man-in-the-middle).",
  "Sí, sin librerías nuevas. Usar <code>TLSv1.2</code>+ y el trust store por defecto del JDK; si el destino "
  "usa una CA interna, importar <b>esa</b> CA, no confiar en todas.",
  "SSLContext ctx = SSLContext.getInstance(\"TLSv1.2\");\nctx.init(null, null, new SecureRandom());  // trust store por defecto"),
 "javascript.express.security.audit.xss": G(
  "XSS reflejado en Express (respuesta sin escapar)",
  "Una entrada del usuario (<code>req.query</code>/<code>req.params</code>/<code>req.body</code>) se escribe "
  "directamente en <code>res.send</code>/<code>res.write</code> o en una plantilla sin escapar.",
  "El atacante inyecta <code>&lt;script&gt;</code> o handlers que se ejecutan en la sesión de la víctima "
  "(robo de token, acciones en su nombre).",
  "Sí, sin librerías nuevas. Escapar la salida (o usar un motor de plantillas que escape por defecto) y "
  "nunca concatenar entrada en HTML.",
  "res.send(escapeHtml(req.query.q));   // no res.send(`<p>${req.query.q}</p>`)"),
 "SONAR-javascript-S5122": G(
  "CORS con origen comodín",
  "<code>Access-Control-Allow-Origin: *</code> (o reflejo del <code>Origin</code> recibido sin lista blanca).",
  "Cualquier sitio puede llamar al API con las credenciales de la víctima si además se permite "
  "<code>Allow-Credentials</code>.",
  "Sí, sin librerías nuevas. Fijar una lista blanca de orígenes permitidos.",
  "cors({ origin: ['https://mi-dominio.gob.mx'], credentials: true })   // no origin: '*'"),
 "SONAR-javascript-S5689": G(
  "Divulgación de información de versión / tecnología",
  "El servidor devuelve cabeceras como <code>X-Powered-By</code> o banners que revelan framework y versión.",
  "Facilita al atacante buscar exploits conocidos para esa versión exacta.",
  "Sí, sin librerías nuevas. Deshabilitar la cabecera.",
  "app.disable('x-powered-by');   // Express"),
}

STOP = {"any","void","list","string","object","int","long","boolean","final","return","public",
        "private","static","class"}

def esc(s): return html.escape(str(s or ""))
SEV = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

def fam_key(cve, engine=""):
    for k in GUIDE:
        if cve.upper().startswith(k.upper()) or cve.startswith(k):
            return k
    if (engine or "") == "accessibility-wcag" or cve.startswith("WCAG"):
        return "WCAG-1.3.1-FORM-CONTROL-NO-LABEL"
    return cve

def clean(d):
    d = re.sub(r"\*\*(.+?)\*\*", r"\1", d or ""); d = re.sub(r"`([^`]+)`", r"\1", d)
    d = re.sub(r"^\[[^\]]+\]\s*", "", d); d = re.sub(r"\*\*Archivo:.*?\)\s*", "", d, flags=re.S)
    d = re.sub(r"\bhttps?://10\.4\.3\.10/[^\s)]+", "el repositorio", d)
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

def render_A(items):
    if not items:
        return '<p class="ok">Nada en esta categoría.</p>'
    groups={}
    for it in items:
        groups.setdefault(fam_key(it["cve_id"], it["scan_engine"]), []).append(it)
    order = lambda rs: min(SEV.get(x["severity"],5) for x in rs)
    out=[]
    for key, rs in sorted(groups.items(), key=lambda kv:(order(kv[1]), -len(kv[1]))):
        g = GUIDE.get(key)
        worst = min(rs, key=lambda x:SEV.get(x["severity"],5))["severity"]
        title = g["t"] if g else clean(rs[0]["cve_id"])
        card = [f'<article class="finding f-{worst.lower()}">',
                f'<h4>{esc(title)} <span class="count">{len(rs)} hallazgo(s)</span></h4>']
        if g:
            card.append(f'<p><b>Qué encontramos.</b> {g["enc"]}</p>')
            card.append(f'<p><b>En qué afecta.</b> {g["afecta"]}</p>')
            card.append(f'<p><b>¿Se corrige sin actualizar librerías?</b> {g["resolver"]}</p>')
            if g["code"]:
                card.append(f'<pre><code>{esc(g["code"])}</code></pre>')
        else:
            card.append(f'<p><b>Qué encontramos.</b> {esc(clean(rs[0]["description"]))[:500]}</p>')
            card.append('<p><b>¿Se corrige sin actualizar librerías?</b> Sí — es un cambio de código o configuración.</p>')
        locs = "".join(
          f'<li><code>{esc(r["location"] or "—")}</code>'
          f'<span class="sv sv-{r["severity"].lower()}">{esc(r["severity"])}</span>'
          f'<span class="cid">{esc(r["cve_id"])}</span></li>'
          for r in sorted(rs, key=lambda x:(SEV.get(x["severity"],5), x["location"] or ""))[:80])
        card.append(f'<div class="where"><div class="wl">Dónde está en el código ({len(rs)})</div><ul>{locs}</ul></div>')
        card.append('</article>')
        out.append("".join(card))
    return "".join(out)

def render_B(items):
    if not items:
        return '<p class="ok">Sin CVEs de dependencias en esta base de código.</p>'
    pk={}
    for it in items:
        d=re.sub(r"\*\*|`","",it["description"] or "")
        mp=_PKG.search(d)
        if not mp: continue
        g=pk.setdefault(mp.group(1),{"inst":None,"mani":None,"safe":[],"cve":set(),"sev":[]})
        mi,ms,mm=_INST.search(d),_SAFE.search(d),_MANI.search(d)
        if mi and not g["inst"]: g["inst"]=mi.group(1)
        if mm and not g["mani"]: g["mani"]=mm.group(1)
        if ms: g["safe"].append(ms.group(1))
        g["cve"].add(re.sub(r"^SCA-?","",it["cve_id"])); g["sev"].append(it["severity"])
    trs=[]
    for name,g in sorted(pk.items(), key=lambda kv:min(SEV.get(s,5) for s in kv[1]["sev"])):
        worst=min(g["sev"], key=lambda s:SEV.get(s,5))
        try: safe=max((s for s in g["safe"] if s), key=vkey) if g["safe"] else "—"
        except Exception: safe=g["safe"][0] if g["safe"] else "—"
        trs.append(f'<tr><td><span class="sv sv-{worst.lower()}">{esc(worst)}</span></td>'
                   f'<td><code>{esc(name)}</code><br><span class="mani">{esc(g["mani"] or "")}</span></td>'
                   f'<td class="ver"><code>{esc(g["inst"] or "?")}</code> &rarr; <code>&ge;{esc(safe)}</code></td>'
                   f'<td class="cves">{esc(", ".join(sorted(g["cve"])))}</td></tr>')
    return (f'<p><b>Qué encontramos.</b> {len(items)} vulnerabilidades en dependencias, consolidadas en '
            f'<b>{len(pk)} librería(s)</b>. <b>En qué afecta:</b> CVEs conocidas de librerías desactualizadas '
            f'(ejecución remota, elusión de autenticación o denegación de servicio según el caso). '
            f'<b>Sólo se resuelven subiendo la versión de la librería.</b> Mientras tanto: restringir la ruta '
            f'afectada en el reverse-proxy, deshabilitar la función si no se usa, o aislar el servicio en red.</p>'
            f'<div class="tw"><table><thead><tr><th>Sev.</th><th>Librería / manifiesto</th>'
            f'<th>Instalada &rarr; objetivo</th><th>CVE</th></tr></thead><tbody>{"".join(trs)}</tbody></table></div>')

def main():
    D = json.load(open(SRC, encoding="utf-8"))
    gen = datetime.datetime.now().strftime("1 de septiembre de 2026")
    assets = D["assets"]
    tot_A = sum(len(a["fixable_without_upgrade"]) for a in assets)
    tot_B = sum(len(a["needs_version_bump"]) for a in assets)
    crit = sum(1 for a in assets for r in a["fixable_without_upgrade"]+a["needs_version_bump"] if r["severity"]=="CRITICAL")
    high = sum(1 for a in assets for r in a["fixable_without_upgrade"]+a["needs_version_bump"] if r["severity"]=="HIGH")

    secs=[]
    for a in assets:
        name = a["path"]
        A, B = a["fixable_without_upgrade"], a["needs_version_bump"]
        hp = (a.get("head") or "").split(" ")
        head_short = esc(hp[0]) if hp and hp[0] else "—"
        head_msg = esc(" ".join(hp[4:])) if len(hp) > 4 else ""
        secs.append(f'''
        <section class="repo">
          <header class="repo-h">
            <div><h3>{esc(name)}</h3></div>
            <div class="repo-meta">rama <code>{esc(a["branch"])}</code>
              <span class="tally"><b>{len(A)}</b> sin actualizar librerías</span>
              <span class="tally"><b>{len(B)}</b> requieren versión</span></div>
          </header>
          <p class="commit">HEAD <code>{head_short}</code> · <span>{head_msg}</span></p>
          <div class="part part-a"><div class="pl">Parte A — Resolubles sin actualizar librerías</div>
            {render_A(A)}
          </div>
          <div class="part part-b"><div class="pl">Parte B — Requieren subir versión de dependencia</div>
            {render_B(B)}
          </div>
        </section>''')

    HTML = f'''<title>Seguridad del grupo STARTERS</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400;6..72,500;6..72,600&family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap">
<style>
:root{{
  --ground:#f6f7f9;--surface:#fff;--ink:#1b2733;--ink-soft:#5b6b7b;--ink-faint:#8593a1;
  --brand:#1a3a5c;--brand-soft:#e7edf3;--rule:#e0e5ea;
  --a:#2f7d4e;--a-bg:#eef7f0;--a-rule:#cfe6d6;
  --b:#b26b12;--b-bg:#fdf5ea;--b-rule:#f0dcc0;
  --crit:#b83227;--high:#c9770d;--med:#9a7a1c;--low:#3f7d4f;--info:#2a6f9e;
  --code-bg:#0f1b28;--code-ink:#dbe4ec;
}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{
  --ground:#0d141c;--surface:#141d27;--ink:#e4e9ee;--ink-soft:#9fadba;--ink-faint:#71818f;
  --brand:#6ea3cf;--brand-soft:#1a2836;--rule:#26313d;
  --a:#5fb27e;--a-bg:#14241b;--a-rule:#2b4636;--b:#d29a54;--b-bg:#2a2013;--b-rule:#4a3a20;
  --crit:#e0685c;--high:#e0a24f;--med:#cdb262;--low:#77b98c;--info:#68a8d0;
  --code-bg:#0a1119;--code-ink:#cbd6e0;
}}}}
:root[data-theme="dark"]{{
  --ground:#0d141c;--surface:#141d27;--ink:#e4e9ee;--ink-soft:#9fadba;--ink-faint:#71818f;
  --brand:#6ea3cf;--brand-soft:#1a2836;--rule:#26313d;
  --a:#5fb27e;--a-bg:#14241b;--a-rule:#2b4636;--b:#d29a54;--b-bg:#2a2013;--b-rule:#4a3a20;
  --crit:#e0685c;--high:#e0a24f;--med:#cdb262;--low:#77b98c;--info:#68a8d0;
  --code-bg:#0a1119;--code-ink:#cbd6e0;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--ground);color:var(--ink);font-family:"DM Sans",system-ui,sans-serif;
  font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased}}
.wrap{{max-width:880px;margin:0 auto;padding:0 22px 90px}}
code{{font-family:"DM Mono",ui-monospace,monospace;font-size:.86em;background:var(--brand-soft);padding:1px 5px;border-radius:4px}}
.masthead{{border-bottom:2px solid var(--brand);padding:44px 0 18px}}
.eyebrow{{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--brand);font-weight:600}}
h1{{font-family:"Newsreader",Georgia,serif;font-weight:500;font-size:32px;line-height:1.15;margin:.3em 0;text-wrap:balance;letter-spacing:-.01em}}
.lede{{color:var(--ink-soft);max-width:64ch;margin:0}}
.runline{{margin-top:12px;font-size:12.5px;color:var(--ink-faint)}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0 6px}}
.kpi{{background:var(--surface);border:1px solid var(--rule);border-radius:10px;padding:14px}}
.kpi .n{{font-family:"Newsreader",Georgia,serif;font-size:29px;font-weight:600;line-height:1;font-variant-numeric:tabular-nums}}
.kpi .l{{font-size:11.5px;color:var(--ink-soft);margin-top:6px;line-height:1.35}}
.kpi.k-a .n{{color:var(--a)}} .kpi.k-b .n{{color:var(--b)}} .kpi.k-c .n{{color:var(--crit)}}
@media(max-width:640px){{.kpis{{grid-template-columns:repeat(2,1fr)}}}}
.callout{{background:var(--brand-soft);border:1px solid var(--rule);border-left:3px solid var(--brand);
  border-radius:8px;padding:13px 15px;margin:20px 0;font-size:13px;color:var(--ink-soft)}}
.callout b{{color:var(--ink)}}
.repo{{margin:42px 0 0;padding-top:24px;border-top:1px solid var(--rule)}}
.repo-h{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}}
.repo-h h3{{font-family:"Newsreader",Georgia,serif;font-weight:600;font-size:21px;margin:0}}
.repo-meta{{text-align:right;font-size:12px;color:var(--ink-faint);line-height:1.9}}
.tally{{display:block}} .tally b{{color:var(--ink);font-variant-numeric:tabular-nums}}
.commit{{font-size:11.5px;color:var(--ink-faint);margin:8px 0 10px}} .commit span{{color:var(--ink-soft)}}
.part{{border-radius:12px;padding:6px 16px 16px;margin:14px 0;border:1px solid var(--rule)}}
.part-a{{background:var(--a-bg);border-color:var(--a-rule)}}
.part-b{{background:var(--b-bg);border-color:var(--b-rule)}}
.pl{{font-size:11px;letter-spacing:.13em;text-transform:uppercase;font-weight:700;padding:12px 0 8px}}
.part-a .pl{{color:var(--a)}} .part-b .pl{{color:var(--b)}}
.ok{{color:var(--ink-soft);font-style:italic;font-size:13.5px;margin:6px 0}}
.finding{{background:var(--surface);border:1px solid var(--rule);border-radius:10px;border-left:3px solid var(--ink-faint);padding:14px 16px;margin:12px 0}}
.finding.f-critical{{border-left-color:var(--crit)}} .finding.f-high{{border-left-color:var(--high)}}
.finding.f-medium{{border-left-color:var(--med)}} .finding.f-low{{border-left-color:var(--low)}}
.finding h4{{margin:0 0 8px;font-size:15px;font-weight:700;display:flex;gap:10px;align-items:baseline;text-wrap:balance}}
.finding h4 .count{{font-family:"DM Mono",monospace;font-size:11px;font-weight:500;color:var(--ink-faint);
  border:1px solid var(--rule);border-radius:20px;padding:1px 8px;white-space:nowrap}}
.finding p{{margin:6px 0;font-size:13.5px}} .finding p b{{font-weight:600;color:var(--ink)}}
.finding p code,.where code{{background:var(--brand-soft)}}
pre{{background:var(--code-bg);color:var(--code-ink);border-radius:8px;padding:12px 14px;overflow-x:auto;font-size:12px;line-height:1.6;margin:10px 0 4px}}
pre code{{background:transparent;color:inherit;padding:0;font-size:12px}}
.where{{margin-top:10px;border-top:1px solid var(--rule);padding-top:8px}}
.wl{{font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-faint);margin-bottom:4px}}
.where ul{{list-style:none;margin:0;padding:0}}
.where li{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:3px 0;font-size:11.5px}}
.where code{{color:var(--ink-soft);font-size:10.5px}}
.cid{{color:var(--ink-faint);font-family:"DM Mono",monospace;font-size:10px}}
.sv{{font-size:9px;font-weight:700;letter-spacing:.05em;padding:1px 5px;border-radius:4px;text-transform:uppercase;color:#fff}}
.sv-critical{{background:var(--crit)}} .sv-high{{background:var(--high)}} .sv-medium{{background:var(--med)}}
.sv-low{{background:var(--low)}} .sv-info{{background:var(--info)}}
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
    <h1>Seguridad del grupo STARTERS: hallazgo por hallazgo, dónde está y cómo se corrige</h1>
    <p class="lede">Análisis completo de los <b>{len(assets)} repositorios</b> del grupo GitLab
      <code>starters</code>. Cada hallazgo indica qué encontramos, en qué afecta, si se corrige sin actualizar
      librerías, el código de la corrección y la ubicación exacta (archivo:línea).</p>
    <div class="runline">Análisis {gen} · SAST · SCA/OSV · STRIDE · Semgrep · SonarQube · WCAG · Control de acceso</div>
  </header>
  <div class="kpis">
    <div class="kpi"><div class="n">{len(assets)}</div><div class="l">Repositorios</div></div>
    <div class="kpi k-a"><div class="n">{tot_A}</div><div class="l">Resolubles SIN actualizar librerías</div></div>
    <div class="kpi k-b"><div class="n">{tot_B}</div><div class="l">Requieren subir versión</div></div>
    <div class="kpi k-c"><div class="n">{crit}</div><div class="l">Críticas ({high} altas)</div></div>
  </div>
  <div class="callout">
    <b>Estos son plantillas — el defecto se propaga.</b> <code>starter-java-authentik</code> concentra
    <b>59 hallazgos de control de acceso</b> (49 de escalación de privilegios sobre sus controladores
    <code>Rol*</code>/<code>Usuario*</code>) y <code>backend-agendador</code> otros 13. Es el <b>mismo
    patrón</b> que el retest de terceros encontró en SIDECO: un endpoint de administración de identidad que
    sólo exige sesión iniciada mientras hay hermanos con rol de administrador. Corregir la plantilla cierra
    el defecto en la raíz; corregir sólo los proyectos derivados deja que el siguiente que se genere vuelva
    a traerlo.
  </div>
  <div class="callout">
    <b>Cómo leer este reporte.</b> Por cada repositorio hay dos partes. La <b>Parte A</b> agrupa las
    vulnerabilidades que se corrigen con un cambio de código o de configuración — cada tarjeta trae el
    fragmento de código de la corrección y la lista de archivos:línea afectados. La <b>Parte B</b> es el
    bloque que exige subir la versión de una dependencia, consolidado por librería. Sólo se incluyen
    hallazgos de categoría vulnerabilidad (se omiten los <i>code smells</i> de SonarQube y las métricas de
    proceso).
  </div>
  {"".join(secs)}
  <footer>
    Generado por Centinela-AI a partir del análisis multi-motor de la rama por defecto (o <code>develop</code>/
    <code>desarrollo</code> cuando existe) de cada repositorio del grupo <code>starters</code>. El PDF con la marca
    de Centinela está en <code>/opt/centinela-ai/docs/reportes/Reporte_STARTERS_Centinela_2026-09-02.pdf</code>.
    Clasificación: CONFIDENCIAL — uso interno.
  </footer>
</div>'''
    open(OUT_HTML, "w", encoding="utf-8").write(HTML)
    print("wrote", OUT_HTML, len(HTML), "bytes")


if __name__ == "__main__":
    main()
