# Catálogo de reglas del escáner y cómo escribir el código para no provocarlas

Cada fila es un identificador de regla estable que el escáner de la organización (Centinela) reporta. No hace falta tener el
escáner para usar este catálogo: escribe el código como dice «Haz esto» y la regla no tendrá qué reportar. La columna «Skill»
indica dónde está el detalle con ejemplos.

Severidad entre paréntesis cuando es fija; «inf.» = informativa (calidad, no vulnerabilidad); «cumpl.» = cumplimiento (accesibilidad).
Un comodín (`SCA-CVE-*`) agrupa reglas cuyo sufijo varía.

---

## 1. Backend Java / Spring Boot

### 1.1 Autorización y control de acceso
| Regla | Riesgo | Haz esto | Skill |
|---|---|---|---|
| `AUTHZ-NO-METHOD-AUTHZ` (ALTA si muta o toca identidad; MEDIA lectura; CRÍTICA si lee datos de personas) | Cualquier usuario autenticado ejecuta la operación | `@PreAuthorize("hasAuthority('RECURSO_ACCION')")` en cada método (o en la clase), permiso dado de alta y prueba del 403 | backend-seguridad |
| `AUTHZ-NO-METHOD-ANNOTATIONS` | Seguridad por método activada y ningún endpoint la usa | Igual que la anterior en todos los controladores | backend-seguridad |
| `AUTHZ-PREAUTHORIZE-COMMENTED-OUT` (ALTA) | Restricción desactivada a mano | Reactivar la anotación; si el endpoint debe ser abierto, declararlo en `SecurityConfig` con su motivo | backend-seguridad |
| `AUTHZ-PUBLIC-SENSITIVE-READ` (ALTA) | `GET` público sobre usuarios, roles o privilegios | Autenticación + permiso del recurso | backend-seguridad |
| `AUTHZ-PERMITALL-WRITE` (ALTA), `AUTHZ-ONLY-AUTHENTICATED-WRITE` (MEDIA) | Escritura pública o solo autenticada | Exigir el permiso de escritura del recurso | backend-seguridad |
| `AUTHZ-INCONSISTENT-FAMILY` (ALTA) | Un endpoint queda más débil que sus hermanos | Una sola regla para toda la familia de rutas | backend-seguridad |
| `AUTHZ-NO-RULE`, `AUTHZ-NAMESPACE-GAP` | Endpoint o prefijo de rutas sin ninguna regla | Regla explícita por prefijo y `anyRequest().denyAll()` o `authenticated()` al final | backend-seguridad |
| `AUTHZ-TEST-ENDPOINT-EXPOSED` (ALTA), `BACKDOOR-SANDBOX-CONTROLLER` (CRÍTICA) | Controlador de prueba, ejemplo o login alterno en `src/main` | Moverlo a `src/test` o limitarlo con `@Profile("dev")`; nunca un login que salte al proveedor de identidad | backend-seguridad |
| `POTENTIAL-IDOR-NO-OWNERSHIP-CHECK`, `AUTHZ-IDOR-PARAM-REVIEW` | `@PathVariable id` a `findById()` sin comprobar de quién es | Validar que el recurso pertenece a quien lo pide (y a su unidad/tenant), con el identificador del usuario tomado del token | backend-seguridad |
| `AUTHZ-DAST-IDOR`, `AUTHZ-DAST-BROKEN-FUNCTION-LEVEL` | Confirmado en ejecución: un rol accede a datos o funciones de otro | Propiedad y rol comprobados en el servidor en cada petición | backend-seguridad |
| `AUTHZ-DAST-DENY-LEAKS-BODY`, `AUTHZ-DAST-INCONSISTENT-STATUS` | La denegación devuelve datos o códigos distintos | 401/403 con cuerpo genérico, siempre el mismo código | backend-soporte-api |
| `AUTHZ-CSRF-DISABLED`, `SPRINGBOOT-CSRF-DISABLED` | CSRF apagado con sesión por cookie | Mantener CSRF; desactivarlo solo en API sin cookie de sesión y documentarlo en el mismo archivo | backend-seguridad |
| `AUTH-ENDPOINT-NO-RATE-LIMIT` | Login sin límite de intentos | Bucket4j/Resilience4j o contador de fallos con bloqueo temporal | backend-seguridad |
| `SESSION-FIXATION-DISABLED` | `sessionFixation().none()` | `migrateSession()` (valor por omisión) | backend-seguridad |
| `ACCOUNT-ENUMERATION-RESPONSE` (MEDIA) | La recuperación de contraseña revela si la cuenta existe | Misma respuesta exista o no la cuenta; el detalle solo al log | reglas-negocio-core-starter |
| `PASSWORD-POLICY-NOT-ENFORCED`, `PASSWORD-MIN-LENGTH-BELOW-STANDARD` | Política de contraseña solo en el frontend o con mínimo bajo | `@Size(min=10)` + `@Pattern` (mayúscula, número, símbolo) en los DTO de alta, cambio y restablecimiento | reglas-negocio-core-starter |

### 1.2 Entrada, contrato y capas
| Regla | Riesgo | Haz esto | Skill |
|---|---|---|---|
| `REQUESTBODY-WITHOUT-VALID` | Entrada sin validar | `@Valid @RequestBody Dto` + Bean Validation en el DTO; `MethodArgumentNotValidException` → 400 | backend-soporte-api |
| `MASS-ASSIGNMENT-ENTITY-BINDING` | El cliente escribe campos internos (rol, estado) | DTO de entrada con solo los campos permitidos; nunca `@RequestBody Entidad` | backend-modulo-crud |
| `ENTITY-RETURNED-FROM-CONTROLLER` | Se exponen columnas internas; fallas con relaciones perezosas | DTO de respuesta con los campos necesarios | backend-modulo-crud |
| `CONTROLLER-INJECTS-REPOSITORY` | Lógica y transacción en el controlador | Controller → Service → Repository | backend-base-spring |
| `TRANSACTIONAL-ON-CONTROLLER` (inf.) | Transacción en la capa equivocada | `@Transactional` en el servicio | backend-base-spring |
| `FIELD-INJECTION-AUTOWIRED` (inf.) | Dependencias ocultas, difícil de probar | Inyección por constructor con campos `final` (`@RequiredArgsConstructor`) | backend-base-spring |
| `API-ENDPOINT-UNDOCUMENTED` (inf.) | Endpoint sin contrato | `@Operation` + `@ApiResponses` con ejemplos en cada endpoint | documentacion-codigo-y-api |
| `VALIDATION-REIMPLEMENTED` (BAJA, inf.) | RFC/CURP/correo validados con una regex propia | Usar el validador común de la base de arranque | reglas-negocio-core-starter |
| `HTML-TEMPLATE-UNESCAPED-SUBSTITUTION` (MEDIA) | XSS en correos o plantillas | Escapar cada valor (`HtmlUtils.htmlEscape`) o Thymeleaf `th:text` | backend-soporte-api |
| `SSTI-TEMPLATE-FROM-INPUT` | Plantilla construida con datos del usuario | Plantillas fijas; los datos solo como variables | backend-soporte-api |

### 1.3 Datos, concurrencia e integridad
| Regla | Riesgo | Haz esto | Skill |
|---|---|---|---|
| `JPA-ENTITY-MISSING-VERSION` | Dos usuarios pierden cambios en silencio | `@Version` en entidades editables; conflicto → 409 | backend-persistencia-jpa |
| `JPA-MULTI-WRITE-NO-TRANSACTIONAL` | Escrituras parciales si algo falla | `@Transactional` en el método de servicio con ≥ 2 escrituras | backend-persistencia-jpa |
| `JPA-EAGER-FETCH`, `JPA-QUERY-IN-LOOP`, `ORM-N-PLUS-ONE-QUERY` | Consultas en cascada, lentitud | `LAZY` + `JOIN FETCH` o proyección donde se necesite; `findAllById`/`IN` por lote | backend-persistencia-jpa |
| `REPOSITORY-FINDALL-UNPAGINATED` | Listados sin límite | `Pageable` con tamaño máximo | backend-endpoint-paginado |
| `JPA-OBJECT-ARRAY-RESULT` (inf.) | Resultados sin tipo | Proyección con interfaz o `record` | backend-persistencia-jpa |
| `SEQUENTIAL-FOLIO-FROM-MAX` (MEDIA) | Folios duplicados por carrera | Secuencia de BD, `SELECT … FOR UPDATE` o `UPDATE … RETURNING`, más `UNIQUE` | backend-integridad-negocio |
| `AUDIT-LOG-MUTATION-ENDPOINT` (MEDIA) | La bitácora se puede editar o borrar | Bitácora de solo consulta y solo inserción | secure-forensic-audit |
| `STD-STRIDE-MISSING-AUDIT-LOG` | Cambios sin rastro | Registrar usuario, acción, recurso y fecha (sin contraseñas ni tokens), de preferencia en un interceptor central | secure-forensic-audit |
| `NUMERIC-CODE-STORED-AS-NUMBER` (inf.) | Se pierden ceros a la izquierda (CP, claves) | Texto con máscara (`^[0-9]{5}$`) | reglas-negocio-core-starter |

### 1.4 Archivos, memoria y procesos
| Regla | Riesgo | Haz esto | Skill |
|---|---|---|---|
| `FILE-UPLOAD-NO-VALIDATION` | Subida de cualquier archivo | Tamaño máximo, lista blanca de extensiones, tipo real del contenido (Tika), nombre generado por el servidor, almacenamiento fuera de la ruta pública | backend-seguridad |
| `SVG-UPLOAD-WITHOUT-SANITIZATION` (MEDIA) | SVG con script | Sanitizar o convertir a PNG antes de guardar | backend-seguridad |
| `OOM-BYTE-ARRAY-STREAMING` | Archivo completo en memoria | `InputStream` / `StreamingResponseBody` | backend-soporte-api |
| `BLOCKING-THREAD-SLEEP`, `CMMI-MSR-HARDCODED-SLEEP` | Hilo bloqueado, sincronización frágil | Programación (`@Scheduled`), asincronía o espera por condición | backend-base-spring |
| `PATH-TRAVERSAL-RISK` | Lectura de archivos fuera del directorio | Normalizar (`Path.resolve().normalize()`), comprobar que quede bajo el directorio base y rechazar `..` | backend-seguridad |

### 1.5 Criptografía, tokens, errores y configuración
| Regla | Riesgo | Haz esto | Skill |
|---|---|---|---|
| `WEAK-CRYPTOGRAPHY`, `CRYPTO-CBC-NO-AUTHENTICATION` | ECB, DES/3DES/RC4, MD5/SHA-1, CBC sin autenticar | `AES/GCM/NoPadding`; SHA-256+; contraseñas con bcrypt/Argon2 | backend-seguridad |
| `INSECURE-RANDOM-FOR-SECRET` | Tokens predecibles | `SecureRandom` (Java), `secrets` (Python), `crypto.getRandomValues` (JS) | backend-seguridad |
| `TIMING-UNSAFE-SECRET-COMPARISON` | Ataque de temporización | `MessageDigest.isEqual` / `hmac.compare_digest` | backend-seguridad |
| `JWT-IN-URL-PARAM`, `FRONTEND-TOKEN-IN-URL` | Token en logs y en el historial del navegador | Solo `Authorization: Bearer`; para `EventSource`, ticket de un uso y vida corta | backend-seguridad |
| `STD-STRIDE-JWT-INSECURE-ALG` | Token falsificable | Validar con algoritmo asimétrico explícito (RS256/EdDSA); nunca `none` | backend-seguridad |
| `INSECURE-COOKIE-FLAGS` | Cookie robable | `Secure`, `HttpOnly`, `SameSite` | backend-seguridad |
| `CORS-WILDCARD-ORIGIN` | Cualquier sitio llama a la API con credenciales | Orígenes explícitos por ambiente | backend-seguridad |
| `STACK-TRACE-EXPOSURE` | Fuga de detalles internos | `@RestControllerAdvice` con respuesta genérica; la traza solo al log | backend-soporte-api |
| `SWALLOWED-ERROR` (inf.), `CMMI-CAR-SWALLOWED-EXCEPTION` | El error se oculta y el sistema dice «sin resultados» | Registrar con traza o propagar; nunca `catch` vacío | clean-code-contract |
| `JVM-GLOBAL-SSL-BYPASS` | Sin verificación TLS | Nunca desactivar la verificación; importar la CA interna al truststore | backend-seguridad |
| `REDIS-JDK-SERIALIZATION`, `INSECURE-DESERIALIZATION` | Ejecución remota al deserializar | Serializador JSON; nada de `ObjectInputStream`/`pickle` con datos externos | backend-seguridad |
| `XXE-INSECURE-PARSER` | Lectura de archivos vía XML | `disallow-doctype-decl`, sin entidades externas (`defusedxml` en Python) | backend-seguridad |
| `XPATH-INJECTION-CONCAT`, `LDAP-INJECTION-CONCAT` | Inyección en consultas XPath/LDAP | Variables XPath; `LdapEncoder.filterEncode` | backend-seguridad |
| `SPRING-DEVTOOLS-REMOTE-ENABLED` | Ejecución remota de código | Sin `spring.devtools.remote.*`; `devtools` fuera del artefacto de producción | backend-proyecto-gradle |
| `SPRING-H2-CONSOLE-ENABLED` | Consola de BD abierta | Deshabilitada en todo ambiente accesible | backend-proyecto-gradle |
| `SPRING-ACTUATOR-SENSITIVE-EXPOSED` | `env`, `heapdump`, `beans` expuestos | Exponer solo `health` e `info` | backend-proyecto-gradle |
| `SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE` | Hibernate altera o borra el esquema al arrancar | `ddl-auto=none` (o `validate`); todo cambio por migración | database-liquibase-postgresql |
| `GRAPHQL-INTROSPECTION-ENABLED` | Mapa completo de la API | Introspección y GraphiQL apagados fuera de desarrollo | backend-seguridad |

---

## 2. Código general (Java, Python, JavaScript)
| Regla | Riesgo | Haz esto | Skill |
|---|---|---|---|
| `SQL-INJECTION-CONCAT`, `SQL-INJECTION-FSTRING`, `SQL-INJECTION-PERCENT` | Inyección SQL | Parámetros enlazados (`?`, `:nombre`, `%s` del driver); nunca `+`, f-strings ni `%` | backend-persistencia-jpa |
| `ORM-RAW-QUERY-INJECTION`, `SPRINGBOOT-NATIVE-QUERY-RISK` | Inyección en consultas nativas | Parámetros nombrados en `@Query(nativeQuery=true)` / `text()` | backend-persistencia-jpa |
| `CMD-INJECTION-OS-SYSTEM`, `CMD-INJECTION-SHELL-TRUE` | Ejecución de comandos | `subprocess.run([...], shell=False)` / `ProcessBuilder` con lista de argumentos validados | clean-code-contract |
| `CODE-INJECTION-EVAL` | Ejecución de código arbitrario | Sin `eval`/`exec`; `json.loads`/`ast.literal_eval` o un diccionario de funciones | clean-code-contract |
| `SSRF-UNCHECKED-FETCH` | El servidor pide URLs que elige un atacante | Validar esquema y host contra una lista permitida; bloquear loopback y rangos privados | backend-seguridad |
| `HARDCODED-SECRET`, `EXPANDED-CLOUD-SECRET` | Credenciales en el código, con cualquier estilo de nombre (`jwtSecret`, `CLIENT_SECRET`, `apiKey`), como valor por omisión de `@Value("${x:valor}")` o como llave de respaldo en un ternario | Variables de entorno o gestor de secretos, sin valor por omisión | reglas-globales-org |
| `DB-UNENCRYPTED-CONN-STRING` | Conexión a BD sin TLS | `sslmode=require`/`ssl=true` y contraseña del entorno | backend-proyecto-gradle |
| `STD-STRIDE-LOG-SENSITIVE-DATA` | Contraseñas, tokens o PII en logs | Registrar identificadores, nunca valores sensibles | clean-code-contract |
| `CMMI-PQA-DEBT-TODO` | Trabajo sin terminar entregado | Sin `TODO`/`FIXME` en la entrega; abrir la tarea | clean-code-contract |
| `STD-ISO25010-LONG-METHOD`, `COGNITIVE-COMPLEXITY-EXCEEDED` (inf.) | Mantenibilidad | Métodos cortos, complejidad ≤ 10, extraer funciones con nombre | clean-code-contract |

---

## 3. Frontend Angular / React / TypeScript

### 3.1 Seguridad
| Regla | Riesgo | Haz esto | Skill |
|---|---|---|---|
| `ANGULAR-BYPASS-SECURITY-TRUST` (ALTA; BAJA sobre un `blob:` propio) | XSS | No usar `bypassSecurityTrust*` con datos de la API; sanitizar con DOMPurify | generacion-componentes-ts |
| `REACT-DANGEROUSLY-SET-INNER-HTML` | XSS | Renderizar texto o sanitizar antes | generacion-componentes-html |
| `FRONTEND-JWT-LOCALSTORAGE`, `FRONTEND-SENSITIVE-STORAGE`, `RUNTIME-TOKEN-IN-STORAGE` | Robo de token o secreto | Cookie `HttpOnly; Secure; SameSite`; si va en el navegador, vida corta y rotación; nunca contraseñas | frontend-auth-oidc |
| `FRONTEND-EXPOSED-DB-CREDENTIAL` (CRÍTICA) | Credencial de BD en el bundle | Ninguna variable pública (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`) con credenciales | frontend-auth-oidc |
| `FRONTEND-OIDC-INSECURE-CONFIG` (MEDIA) | `requireHttps:false` o validación del discovery apagada fuera de local | Ambos en `true` en QA y producción | frontend-auth-oidc |
| `FRONTEND-TOKEN-IN-CONSOLE`, `FRONTEND-STOMP-DEBUG-LOGGING`, `RUNTIME-TOKEN-IN-CONSOLE` | Token visible en la consola | Sin `console.*` de tokens; `debug` de STOMP vacío fuera de desarrollo local | generacion-servicios |
| `FRONTEND-TEST-ROUTE-EXPOSED` | Rutas demo o debug en producción | Condicionarlas al `environment` o quitarlas | primeng21-expert |
| `AUTHZ-CLIENT-SIDE-ONLY`, `AUTHZ-CLIENT-SIDE-UI-GATE`, `AUTHZ-ADMIN-BUNDLE-EXPOSED` | Un guard o un `*ngIf` no es autorización | Mantenerlo por usabilidad y exigir el permiso en el backend | frontend-auth-oidc |
| `CLIENT-SIDE-REDIRECT` | Redirección abierta | Lista blanca de destinos | generacion-servicios |
| `INSECURE-WEBSOCKET` | Canal sin cifrar | `wss://` (salvo localhost) | generacion-servicios |
| `POSTMESSAGE-WILDCARD-ORIGIN`, `POSTMESSAGE-NO-ORIGIN-CHECK` | Mensajes entre ventanas sin control | Origen destino explícito y validar `event.origin` | generacion-componentes-ts |
| `FRONTEND-HARDCODED-API-URL` (inf.) | URL distinta por ambiente escrita en el código | URL desde `environment` + `API_ENDPOINTS` | generacion-servicios |

### 3.2 Arquitectura y comportamiento (Angular)
| Regla | Haz esto | Skill |
|---|---|---|
| `ANGULAR-SUBSCRIBE-NO-CLEANUP` | `takeUntilDestroyed(this.destroyRef)` o `toSignal()` | generacion-componentes-ts |
| `ANGULAR-NESTED-SUBSCRIBE` | Encadenar con `switchMap`/`forkJoin`, nunca `subscribe` dentro de `subscribe` | generacion-componentes-ts |
| `ANGULAR-VALUECHANGES-NO-DEBOUNCE` | `debounceTime(300)`, `distinctUntilChanged()`, `switchMap(...)` | generacion-componentes-ts |
| `ANGULAR-EFFECT-HTTP`, `ANGULAR-EFFECT-SELF-WRITE` | Sin HTTP en `effect()`; derivar con `computed()`/`linkedSignal()` | generacion-componentes-ts |
| `ANGULAR-LAZYLOAD-PLUS-INIT-LOAD`, `ANGULAR-DOUBLE-LOAD-INIT-EFFECT` | Un solo disparador de carga | generacion-componentes-ts |
| `ANGULAR-HTTP-IN-LOOP` | Endpoint por lote o `forkJoin`/`mergeMap(concurrencia)` | generacion-servicios |
| `ANGULAR-SIGNAL-MUTATION-IN-PLACE` | `lista.update(l => [...l, x])`, nunca `lista().push(x)` | generacion-componentes-ts |
| `ANGULAR-SETTIMEOUT-WORKAROUND` | `ChangeDetectorRef`, `afterNextRender` o señales | generacion-componentes-ts |
| `ANGULAR-SUBMIT-NO-BUSY-GUARD` | Deshabilitar el botón y bloquear el reenvío mientras la petición está en curso | generacion-componentes-ts |
| `ANGULAR-TEMPLATE-METHOD-IN-LOOP` | Precalcular con `computed()` o un pipe puro | generacion-componentes-html |
| `TS-EXPLICIT-ANY` | Interfaces o `unknown` | generacion-dtos |
| `DESTRUCTIVE-ACTION-NO-CONFIRM`, `NATIVE-BROWSER-DIALOG` (inf.) | Borrar o revocar pide confirmación con el diálogo estándar de la UI, no `confirm()`/`alert()` | frontend-heuristicas-usabilidad |

### 3.3 Accesibilidad WCAG 2.1 AA (cumpl.)
| Regla | Haz esto | Skill |
|---|---|---|
| `WCAG-1.1.1-IMG-MISSING-ALT` | `alt` en toda imagen (vacío si es decorativa) | generacion-componentes-html |
| `WCAG-1.3.1-FORM-CONTROL-NO-LABEL`, `ACCESSIBILITY-WCAG-MISSING-LABEL` | `<label for>` que coincide con el `id`, `aria-label` o `label` de PrimeNG | generacion-componentes-html |
| `WCAG-1.3.5-INPUT-NO-AUTOCOMPLETE` | `autocomplete` en correo, teléfono, nombre y contraseña | generacion-componentes-html |
| `WCAG-1.2.2-VIDEO-NO-CAPTIONS` | `<track kind="captions">` en videos con audio | generacion-componentes-html |
| `WCAG-1.4.2-AUTOPLAY-MEDIA` | Sin `autoplay` con sonido | generacion-componentes-html |
| `WCAG-1.4.4-VIEWPORT-ZOOM-DISABLED` | Sin `user-scalable=no` ni `maximum-scale` menor que 2 | generacion-componentes-html |
| `WCAG-2.2.2-MARQUEE-BLINK` | Sin `<marquee>` ni `<blink>` | generacion-componentes-html |
| `WCAG-2.4.1-NO-SKIP-LINK` | Enlace «Saltar al contenido» en la plantilla raíz | generacion-componentes-html |
| `WCAG-2.4.2-MISSING-TITLE` | `<title>` con texto en cada documento | generacion-componentes-html |
| `WCAG-2.4.3-POSITIVE-TABINDEX` | Solo `tabindex="0"` o `-1` | generacion-componentes-html |
| `WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT` | Botón o enlace con nombre (texto, `aria-label`, `label`) | generacion-componentes-html |
| `WCAG-2.4.6-EMPTY-HEADING` | Encabezados con texto | generacion-componentes-html |
| `WCAG-2.4.7-FOCUS-OUTLINE-REMOVED` | Nunca `outline: none` en `:focus` sin borde, sombra o fondo alternativo | generacion-estilos |
| `WCAG-2.5.3-LABEL-IN-NAME` | El `aria-label` contiene el texto visible | generacion-componentes-html |
| `WCAG-3.1.1-HTML-MISSING-LANG` | `<html lang="es">` | generacion-componentes-html |
| `WCAG-4.1.1-DUPLICATE-ID` | `id` únicos en la página | generacion-componentes-html |
| `WCAG-4.1.2-IFRAME-NO-TITLE` | `title` en cada `<iframe>` | generacion-componentes-html |
| `WCAG-<criterio>-AXE-*` | Lo mismo, detectado en la página renderizada (contraste, nombres, estructura) | theming-architecture |
| Un `div` o `span` clicable | `<button>` o `role` + `tabindex="0"` + manejo de teclado | generacion-componentes-html |

Contraste (1.4.3, 1.4.11), reflujo y mensajes de estado solo se verifican con la página en un navegador; el orden lógico o las
trampas de teclado exigen revisión humana. No los des por cumplidos solo porque no aparecen como hallazgo.

---

## 4. Base de datos y migraciones SQL
| Regla | Haz esto | Skill |
|---|---|---|
| `SQL-TABLE-WITHOUT-PRIMARY-KEY` (inf.) | Toda tabla con llave primaria (en el `CREATE` o con `ALTER TABLE … ADD CONSTRAINT … PRIMARY KEY`) | database-liquibase-postgresql |
| `SQL-PK-NOT-UUID` (inf.) | `id uuid DEFAULT uuidv7()` en tablas nuevas | postgres-audit |
| `SQL-TIMESTAMP-WITHOUT-TIMEZONE` (inf.) | `timestamptz` | postgres-audit |
| `SQL-JSON-NOT-JSONB` (inf.) | `jsonb` | postgres-audit |
| `SQL-FLOAT-FOR-MONEY` (inf.) | Montos en `numeric(p,s)` | postgres-audit |
| `SQL-TABLE-WITHOUT-AUDIT-COLUMNS` (inf.) | Columnas del Estándar de auditoría y `auditoria.asignar_triggers('<esquema>.<tabla>')` | postgres-audit |
| `DB-AUTH-TRUST` (CRÍTICA), `DB-AUTH-MD5`, `DB-AUTH-CLEARTEXT-PASSWORD` | `scram-sha-256` en `pg_hba.conf` para toda conexión | postgres-audit |
| `DB-NO-TLS-ENCRYPTION`, `DB-TLS-BELOW-BASELINE` | TLS obligatorio (`ssl_min_protocol_version = 'TLSv1.3'`) | postgres-audit |
| `DB-DEFAULT-PORT-EXPOSED`, `DB-BANNER-LEAK` | Puerto solo para la red privada o VPN (firewall); sin versión en el saludo | postgres-audit |

Documenta cada objeto nuevo con `COMMENT ON` en la misma migración (skill `documentacion-codigo-y-api`).

---

## 5. Configuración y secretos
| Regla | Haz esto | Skill |
|---|---|---|
| `CONFIG-SECRET-LITERAL` (ALTA; MEDIA en perfiles dev/local/test) | `password=${DB_PASSWORD}` desde el entorno o el gestor de secretos | reglas-globales-org |
| `CONFIG-JWT-SECRET-LITERAL` (CRÍTICA) | El secreto de firma nunca en el repositorio | backend-seguridad |
| `SECRETS-*` (secretos en el historial de git) | Rotar la credencial; borrarla del árbol no basta | reglas-globales-org |
| `CICD-HARDCODED-SECRET` | Variables de CI enmascaradas y protegidas | backend-proyecto-gradle |
| `DEPENDENCY-UNREACHABLE` | Todo servicio externo configurado existe en el ambiente; si ya no se usa, quitarlo de la configuración | backend-proyecto-gradle |

---

## 6. Dependencias, cadena de suministro y licencias
| Regla | Haz esto | Skill |
|---|---|---|
| `SCA-CVE-*`, `CVE-*` | Versión corregida de la dependencia (una actualización suele cerrar varias CVE); quitar dependencias que no se usan | backend-proyecto-gradle |
| `SUPPLY-CHAIN-NO-LOCKFILE` | Lockfile versionado (`package-lock.json`, `gradle.lockfile`, `poetry.lock`) | backend-proyecto-gradle |
| `SUPPLY-CHAIN-UNPINNED-DEPENDENCY` | Versiones exactas (sin `latest`, rangos Maven ni `requirements` sin `==`) | backend-proyecto-gradle |
| `SCA-MAL-*` | Paquete malicioso conocido: retirarlo (no basta subir de versión), revisar los equipos y runners donde se instaló y rotar sus credenciales | backend-proyecto-gradle |
| `SUPPLY-CHAIN-INSTALL-SCRIPT-RISKY` | Sin descargas ni `eval`/`node -e`/`\| sh` en `preinstall`/`postinstall`; las herramientas se instalan en un paso explícito con versión y SHA-256 | backend-proyecto-gradle |
| `SUPPLY-CHAIN-DEPENDENCY-FROM-URL` | Dependencias desde el registro (interno si es propia); si viene de git, fijar el commit completo; nunca credenciales en la URL | backend-proyecto-gradle |
| `SUPPLY-CHAIN-LOCKFILE-INSECURE-SOURCE` | Registro configurado con `https://`; regenerar el lockfile | backend-proyecto-gradle |
| `SUPPLY-CHAIN-POSSIBLE-TYPOSQUAT` | Copiar el nombre del paquete de su página oficial; revisar autor y descargas antes de agregarlo | backend-proyecto-gradle |
| `SCA-LICENSE-NETWORK-COPYLEFT`, `SCA-LICENSE-STRONG-COPYLEFT`, `SCA-LICENSE-RESTRICTED`, `SCA-LICENSE-UNKNOWN` | Preferir MIT/Apache/BSD; documentar la decisión legal de cualquier otra; sin paquetes sin licencia | cumplimiento-cmmi-iso |

---

## 7. Contenedores, IaC, CI/CD y GitLab
| Regla | Haz esto | Skill |
|---|---|---|
| `DOCKER-MISSING-NON-ROOT-USER`, `DOCKER-ROOT-USER` | `USER` sin privilegios antes de `ENTRYPOINT`/`CMD` | backend-proyecto-gradle |
| `DOCKER-UNPINNED-BASE-IMAGE`, `CICD-UNPINNED-IMAGE` | Imagen con versión o digest fijo | backend-proyecto-gradle |
| `DOCKER-CURL-PIPE-SHELL`, `CICD-CURL-PIPE-SHELL` | Descargar, verificar el hash y ejecutar; nunca `curl … \| sh` | backend-proyecto-gradle |
| `TRIVY-*` | Configuración de Dockerfile/Kubernetes/Terraform según la regla de Trivy citada | backend-proyecto-gradle |
| `K8S-PRIVILEGED-CONTAINER`, `K8S-RUN-AS-ROOT`, `K8S-PRIVILEGE-ESCALATION`, `K8S-WRITABLE-ROOT-FS`, `K8S-HOSTPATH-MOUNT`, `K8S-AUTOMOUNT-TOKEN`, `CSPM-K8S-PRIVILEGED-CONTAINER`, `CSPM-K8S-PRIVILEGED-POD` | `privileged:false`, `runAsNonRoot:true`, `allowPrivilegeEscalation:false`, `readOnlyRootFilesystem:true`, sin `hostPath`, `automountServiceAccountToken:false` | backend-proyecto-gradle |
| `TF-PUBLIC-S3-BUCKET`, `TF-OPEN-SECURITY-GROUP`, `TF-ADMIN-PORT-WORLD-OPEN`, `CSPM-AWS-S3-PUBLIC`, `CSPM-AWS-S3-PUBLIC-READ` | Buckets privados; orígenes de red concretos; SSH/RDP/BD nunca a `0.0.0.0/0` | backend-proyecto-gradle |
| `CSPM-AWS-IAM-WILDCARD`, `CSPM-IAM-OVERPRIVILEGED-WILDCARD` | Políticas con acciones y recursos concretos | backend-proyecto-gradle |
| `CICD-NO-PIPELINE` | Pipeline con compilación, pruebas y análisis | backend-pruebas-unitarias |
| `CICD-GATE-ALLOW-FAILURE` (inf.) | Jobs de pruebas, lint o seguridad sin `allow_failure` | backend-pruebas-unitarias |
| `TEST-SKIPPED-WITHOUT-REASON` (inf.) | Toda prueba omitida dice por qué y hasta cuándo (`@Disabled("motivo")`, `it.skip` con comentario) | test-driven-development |
| `CICD-DOCKER-PRIVILEGED` | Construir con Kaniko o BuildKit sin privilegios | backend-proyecto-gradle |
| `CICD-TLS-VERIFICATION-DISABLED` | Sin `-k`, `verify=False` ni `GIT_SSL_NO_VERIFY` | backend-proyecto-gradle |
| `CICD-REMOTE-INCLUDE-INSECURE` | `include:` remotos solo por HTTPS y a una versión fija | backend-proyecto-gradle |
| `CICD-INCLUDE-UNPINNED` | `include: project:` siempre con `ref:` a un tag o commit | backend-proyecto-gradle |
| `CICD-UNTRUSTED-INPUT-INJECTION` | Mensaje de commit, rama o título de MR solo como `"$VARIABLE"` entre comillas; nunca dentro de `eval` o `sh -c` | backend-proyecto-gradle |
| `CICD-INPUT-INTERPOLATION-IN-SCRIPT` | `$[[ inputs.x \| posix_escape ]]` o la entrada como variable de entorno | backend-proyecto-gradle |
| `CICD-DEPENDENCY-INSTALL-NOT-FROZEN` | `npm ci` / `yarn install --frozen-lockfile` en CI, nunca `npm install` | backend-proyecto-gradle |
| `REPO-BINARY-ARTIFACT` | Nada de `.jar`/`.exe`/`.apk`/llaves en git: artefactos desde un repositorio con versión; las llaves en el gestor de secretos | backend-proyecto-gradle |
| `REPO-BUILD-OUTPUT-COMMITTED` (inf.) | `target/`, `build/`, `.gradle/`, `__pycache__/` en `.gitignore` | backend-proyecto-gradle |
| `GITLAB-PROJECT-DEFAULT-BRANCH-UNPROTECTED`, `GITLAB-PROJECT-BRANCH-FORCE-PUSH`, `GITLAB-PROJECT-BRANCH-DEVELOPER-PUSH` | Rama por defecto protegida, sin force-push, push solo de mantenedores | cumplimiento-cmmi-iso |
| `GITLAB-PROJECT-MR-NO-PIPELINE-GATE` | Fusionar solo con pipeline en verde y revisión de otra persona | cumplimiento-cmmi-iso |
| `GITLAB-PROJECT-CI-VARIABLE-UNMASKED`, `GITLAB-PROJECT-CI-VARIABLE-UNPROTECTED` | Variables sensibles enmascaradas y protegidas | backend-proyecto-gradle |
| `GITLAB-PROJECT-WEBHOOK-INSECURE` | Webhooks por HTTPS, con secreto y verificación TLS | backend-seguridad |
| `GITLAB-PROJECT-PUBLIC-VISIBILITY` | Proyectos internos o privados salvo decisión expresa | reglas-globales-org |

---

## 8. Contrato de la API
| Regla | Haz esto | Skill |
|---|---|---|
| `API-NO-CONTRACT` | Contrato OpenAPI versionado junto al código (springdoc) | documentacion-codigo-y-api |
| `API-ROUTE-NOT-IN-CONTRACT`, `API-SHADOW-ENDPOINT` | Toda ruta del código está en el contrato, o se elimina | documentacion-codigo-y-api |
| `API-CONTRACT-MISMATCH` | Parámetros y respuestas iguales en código y contrato (generar uno desde el otro) | documentacion-codigo-y-api |
| `API-CONTRACT-ROUTE-NOT-IMPLEMENTED` | No documentar rutas que no existen | documentacion-codigo-y-api |

---

## 9. Pruebas en ejecución (sesión real y pruebas funcionales)
| Regla | Haz esto | Skill |
|---|---|---|
| `RUNTIME-PII-IN-RESPONSE` | Cada perfil recibe solo sus datos personales: filtrar en el servidor y responder con DTO mínimos | backend-seguridad |
| `RUNTIME-AUTH-ERRORS` | Renovación del token antes de vencer, un solo reintento, cierre de sesión ordenado | frontend-auth-oidc |
| `RUNTIME-SERVER-ERRORS`, `WSTG-ERRH-01-API-SERVER-ERROR` | Ninguna pantalla de uso normal provoca un 5xx; entradas inválidas → 4xx | backend-soporte-api |
| `SMART-TESTS-ACCESS-CONTROL-FAILURE` | Un rol sin permiso no ve ni ejecuta la función (403 en el backend, opción oculta en la UI) | bdd-frontend-playwright |
| `SMART-TESTS-FORM-INVALID-SUBMITTED` | El formulario no se envía con datos inválidos (validación en cliente y servidor) | generacion-componentes-ts |
| `SMART-TESTS-FORM-NO-FIELD-ERROR` | Cada campo inválido muestra su mensaje junto al campo | frontend-heuristicas-usabilidad |

---

## 10. Despliegue: servidor, proxy, TLS, sistema operativo y dominio
Se corrigen en la configuración del ambiente, no en el código; quien prepara el despliegue debe dejarlo así.

| Regla | Haz esto |
|---|---|
| `WSTG-ATHN-02-CLEARTEXT-LOGIN`, `WSTG-CRYP-03-UNENCRYPTED-CHANNEL`, `WSTG-CONF-07-INCOMPLETE-HSTS`, `TLS-NOT-ENABLED` | Todo por HTTPS; HSTS `max-age` ≥ 1 año con `includeSubDomains` |
| `WSTG-ATHN-06-LOGIN-CACHEABLE` | `Cache-Control: no-store` en páginas con contraseña |
| `WSTG-SESS-02-COOKIE-SAMESITE` | `SameSite` en la cookie de sesión |
| `WSTG-CLNT-07-INSECURE-CORS` | Orígenes explícitos |
| `WSTG-CLNT-04-OPEN-REDIRECT` | Redirecciones solo a rutas propias |
| `WSTG-INPV-17-HOST-HEADER-INJECTION` | Lista de hosts permitidos (`server_name` explícito) |
| `WSTG-CONF-06-DANGEROUS-HTTP-METHOD` | Sin `TRACE`/`CONNECT`; solo los métodos necesarios |
| `WSTG-CONF-04-SENSITIVE-FILES`, `WSTG-CONF-05-DEBUG-ENDPOINTS` | Sin `.git`, `.env`, copias ni consolas de depuración publicadas |
| `WSTG-CONF-08-CROSSDOMAIN-WILDCARD` | `crossdomain.xml` con dominios explícitos o sin él |
| `WSTG-ERRH-01-VERBOSE-BACKEND-ERROR` | Páginas de error genéricas |
| `WSTG-INFO-02-SERVER-BANNER-LEAK`, `WSTG-INFO-08-FRAMEWORK-FINGERPRINT` | Sin versión en `Server` ni `X-Powered-By` |
| `WSTG-INFO-03-METAFILE-LEAK` | `robots.txt` sin rutas sensibles (protegerlas con autenticación) |
| `WSTG-INFO-05-CONTENT-LEAK` | Sin comentarios con credenciales, TODO o IP privadas en el HTML publicado |
| `WSTG-AUTH-02-DEFAULT-CREDENTIALS` | Cambiar credenciales por defecto antes de publicar |
| `TLS-CERT-EXPIRED`, `TLS-CERT-EXPIRING-SOON`, `TLS-CERT-SELF-SIGNED`, `TLS-CERT-WEAK-KEY`, `TLS-CERT-WEAK-SIGNATURE` | Certificado de una CA válida, RSA ≥ 2048 o ECDSA, renovación automática |
| `IMAGE-CERT-EXPIRED`, `IMAGE-CERT-WEAK-KEY`, `IMAGE-CERT-WEAK-SIGNATURE` | No copiar certificados propios dentro de la imagen de contenedor: montarlos como secreto al ejecutar; si van en la imagen, RSA ≥ 2048 o ECDSA, firma SHA-256+ y renovarlos antes de vencer |
| `TLS-LEGACY-PROTOCOL-ENABLED`, `TLS-WEAK-CIPHER-ENABLED`, `TLS-STATIC-RSA-KEX-ENABLED` | TLS 1.2/1.3 con suites ECDHE |
| `OSINT-MISSING-SECURITY-HEADERS`, `OSINT-TLS-MISCONFIGURATION` | Cabeceras de seguridad y TLS correctos en lo que se publica |
| `CIS-1.1`, `CIS-1.2` | SSH sin login de root ni contraseña (solo llaves) |
| `CIS-2.1`, `CIS-2.2` | `/etc/passwd` ≤ 644 y `/etc/shadow` ≤ 640 |
| `CIS-3.1`, `CIS-5.1` | `PASS_MIN_LEN` ≥ 14; sin contraseñas vacías |
| `CIS-4.1`, `CIS-6.1`, `CIS-6.2` | Firewall activo; `ip_forward=0`; `suid_dumpable=0` |
| `CIS-5.2`, `CIS-7.1` | `auditd` y sincronización de hora activos |
| `OS-PATCH-SECURITY-UPDATES-PENDING`, `OS-EOL`, `OS-REBOOT-REQUIRED`, `OS-AUTO-UPDATES-DISABLED`, `OS-PACKAGE-INDEX-STALE` | Parches de seguridad dentro del plazo, SO con soporte, actualizaciones automáticas y sin reinicios pendientes |
| `DNS-SPF-MISSING`, `DNS-SPF-MULTIPLE`, `DNS-SPF-PERMISSIVE`, `DNS-SPF-SOFTFAIL`, `DNS-SPF-TOO-MANY-LOOKUPS` | Un solo registro SPF terminado en `-all`, ≤ 10 consultas |
| `DNS-DMARC-MISSING`, `DNS-DMARC-MONITOR-ONLY`, `DNS-DMARC-PARTIAL` | DMARC con `p=quarantine` o `p=reject` y `pct=100` |
| `DNS-MTASTS-MISSING`, `DNS-CAA-MISSING`, `DNS-DNSSEC-NOT-ENABLED` | MTA-STS, CAA y DNSSEC publicados |

`OSINT-SUBDOMAIN-DISCOVERY`, `OSINT-THREAT-INTEL-ABUSEIPDB` y `OSINT-THREAT-INTEL-OTX` informan exposición e inteligencia de amenazas
sobre lo ya publicado: no se previenen desde el código; se atienden retirando lo que no debe estar expuesto.

---

## 11. Uso de modelos de IA en la aplicación
| Regla | Haz esto | Skill |
|---|---|---|
| `OWASP-LLM01-PROMPT-INJECTION` | Separar instrucciones de datos del usuario, validar la salida y nunca ejecutar lo que devuelve el modelo | reglas-globales-org |
| `OWASP-LLM02-PII-PROMPT-LEAK` | Redactar PII y secretos antes de enviarlos al proveedor | reglas-globales-org |
| `OWASP-LLM06-EXCESSIVE-AGENCY` | Acciones del agente por lista permitida y con aprobación humana si son destructivas | reglas-globales-org |

---

## 12. Motores externos integrados
| Familia | Qué hacer |
|---|---|
| `SONAR-*` (SonarQube, p. ej. `SONAR-java-S2479`) | Corregir según la regla citada; las de tipo `VULNERABILITY`/`SECURITY_HOTSPOT` antes de entregar, los code smells como deuda planeada |
| Reglas de Semgrep (`java.spring...`, `javascript...`) | Corregir según el mensaje de la regla; casi siempre coinciden con una fila de este catálogo |
| `TRIVY-*` | Ver sección 7 |

---

## 13. Marcadores (no son defectos)
Indican que un motor corrió o etiquetan una categoría: `CIS-BENCHMARK-AUDIT`, `OS-PATCH-AUDIT`, `TLS-AUDIT`, `DNS-SECURITY-AUDIT`,
`CMMI-GIT-HISTORY-CHECK`, `SONARQUBE-QUALITY-GATE`, `TRIVY-REPO`, `GITLAB-CONFIG-AUDIT`, `AUTHZ-DAST-NO-CREDS`, `RUNTIME-SESSION-NOT-EXERCISED`,
`STRIDE-SPOOFING`, `STRIDE-REPUDIATION`, `STRIDE-INFO-DISCLOSURE`. Un «0 hallazgos» solo vale donde el motor correspondiente corrió y
cubre ese lenguaje.
