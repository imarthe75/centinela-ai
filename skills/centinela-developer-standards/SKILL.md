---
name: centinela-developer-standards
description: Estándar obligatorio de arquitectura, seguridad y rigor de proceso para desarrolladores y agentes de IA que trabajan en o contra Centinela AI. Contiene el catálogo de reglas que Centinela detecta (SAST nativo, authz-static con cobertura @PreAuthorize, secretos en configuración, WCAG 2.1, WSTG/ASVS perimetral, TLS, parches de SO, CIS Linux, DB Hardening, IaC K8s/Terraform, SCA con OSV+CVSS+alcanzabilidad, configuración de GitLab, Semgrep multi-lenguaje) y cómo corregir cada una, cómo se lee la severidad efectiva y los veredictos de IA, el modelo de cumplimiento honesto (ISO 27001 / CMMI v3.0 de la organización), las reglas anti-simulación (parches con git apply --check, SOAR real, webhooks fail-closed, tests con ROLLBACK) las trampas de código que ya causaron incidentes, y el registro de cobertura por marco (OWASP Top 10 / API / WSTG, WCAG 2.1, ISO 27001 Anexo A, CMMI de la organización) con lo que Centinela mide y lo que NO.
---

# 🛡️ Centinela Developer Standards & AI Agent Skill

Guía técnica obligatoria para todo desarrollo dentro del ecosistema Centinela AI y para cualquier proyecto que Centinela audite (Spring Boot / Angular / Python). Su objetivo: **que el código nazca sin los hallazgos que Centinela detecta**, y que quien opera Centinela (humano o agente) **nunca presente como verificado algo que no lo está**.

> Última revisión: 2026-10-01. Fuente de verdad de las reglas: `auditors/` y `core/` en este repositorio; el catálogo completo vive en `docs/REGLAS_PROPIAS_CENTINELA.md` (Apéndice A lista las reglas añadidas después de su versión 3.0). **Si esta skill y el código discrepan, manda el código** (verifícalo antes de afirmar).

---

## 0. 🧭 Cómo leer lo que Centinela reporta (para no malinterpretar el dashboard ni los reportes)

1. **Severidad efectiva.** La severidad que pone la herramienta (`severity`) describe el *patrón* en abstracto. Centinela guarda aparte el veredicto sobre el caso concreto (`real_severity`, `risk_verdict`) y **nunca sobrescribe la cruda**. Todo consumidor debe usar **`COALESCE(real_severity, severity)`**; leer solo `severity` hace que dashboards, SLA y reportes discrepen entre sí.
   - Veredictos: `CONFIRMED_NO_RISK` (→ INFO), `DOWNGRADED` (nivel real estrictamente menor), `CONDITIONAL` (el riesgo bajo depende de un supuesto no verificado: **no** baja la severidad), `ANALYST_OVERRIDDEN` (un humano rechazó el veredicto; ningún proceso automático lo vuelve a tocar). La IA **nunca puede subir** una severidad.
   - Las propuestas de supresión de la IA quedan inactivas hasta revisión humana en la pantalla **Supresiones IA**. Aprobar suprime solo los hallazgos concretos evaluados (por huella), no toda la regla en el activo.
2. **Vulnerabilidad vs. informativo.** `finding_category` separa `VULNERABILITY` de `INFORMATIONAL` (code smells, deuda ISO 25010/CMMI). No mezclar ambos en un total "de vulnerabilidades".
3. **Procedencia del análisis.** Un texto de remediación puede venir de: IA por hallazgo, **análisis de patrón compartido** ("heredado del hallazgo X, misma regla y activo"), **análisis de patrón redactado por el asistente**, o el motor heurístico determinístico. Los dos de patrón no revisan cada ocurrencia y lo dicen en su primera línea; **un reporte no debe presentarlos como revisados uno por uno**.
4. **SLA.** Crítico 24 h / Alto 7 d / Medio 30 d / Bajo 90 d, calculado con la severidad **efectiva**.
5. **Un hallazgo reabierto** (se resolvió y volvió) conserva esa marca en el texto del análisis; no lo trates como nuevo.

---

## 1. 🔍 Motores de Centinela y cómo superarlos

### 1.1. Servidores Linux — CIS Level 1 (`auditor_cis_benchmarks.py`)
Subconjunto honesto de CIS (no el benchmark completo), solo lectura por SSH. Un host sin conexión se reporta `SIN_CONEXION`, nunca con una calificación inventada.
- **SSH (`CIS-1.1`, `CIS-1.2`):** `PermitRootLogin no`; `PasswordAuthentication no` (solo llaves).
- **Archivos (`CIS-2.1`, `CIS-2.2`):** `/etc/passwd` ≤ 644; `/etc/shadow` ≤ 640.
- **Cuentas (`CIS-3.1`, `CIS-5.1`):** `PASS_MIN_LEN >= 14`; sin contraseñas vacías.
- **Red/kernel (`CIS-4.1`, `CIS-6.1`, `CIS-6.2`):** firewall activo (`ufw`/`firewalld`); `net.ipv4.ip_forward=0`; `fs.suid_dumpable=0`.
- **Auditoría (`CIS-5.2`, `CIS-7.1`):** `auditd` activo; sincronización NTP activa.

### 1.2. Parches y ciclo de vida del SO (`auditor_os_patches.py`)
Reglas `OS-PATCH-SECURITY-UPDATES-PENDING`, `OS-EOL` (SO fuera de soporte), `OS-REBOOT-REQUIRED`, `OS-AUTO-UPDATES-DISABLED`, `OS-PACKAGE-INDEX-STALE`. Aplicar actualizaciones de seguridad dentro del SLA, tener `unattended-upgrades` (o equivalente) activo y no dejar reinicios pendientes. *Rama RPM/CentOS: no verificada en vivo.*

### 1.3. TLS (`auditor_tls.py`)
`TLS-CERT-EXPIRED` / `TLS-CERT-EXPIRING-SOON`, `TLS-CERT-SELF-SIGNED`, `TLS-CERT-WEAK-KEY`, `TLS-CERT-WEAK-SIGNATURE`, `TLS-LEGACY-PROTOCOL-ENABLED` (TLS 1.0/1.1), `TLS-WEAK-CIPHER-ENABLED`, `TLS-STATIC-RSA-KEX-ENABLED` (sin forward secrecy), `TLS-NOT-ENABLED` (servicio solo HTTP). Exigir TLS 1.2+/1.3, suites con ECDHE, llaves RSA ≥ 2048 o ECDSA, certificados de una CA interna válida y renovación automatizada.

### 1.4. Bases de datos (`auditor_db_hardening.py`)
`DB-NO-TLS-ENCRYPTION` (cifrado en tránsito obligatorio), `DB-DEFAULT-PORT-EXPOSED` (puertos 5432/3306/27017/6379/7687: cambiarlos o restringir por firewall a la red privada/VPN), `DB-BANNER-LEAK`. Aplica a PostgreSQL, MySQL, Oracle, MSSQL, MongoDB, Cassandra, Neo4j, Redis/Valkey.

### 1.5. IaC y contenedores (`auditor_iac_k8s.py`, Checkov/Trivy)
- **K8s:** prohibido `privileged: true` y `hostPath` sin justificación; obligatorio `readOnlyRootFilesystem: true`, `automountServiceAccountToken: false`.
- **Terraform:** prohibido `0.0.0.0/0` en puertos administrativos; prohibidos buckets `public-read*`.
- **Dockerfile:** obligatorio `USER` no root (`DOCKER-MISSING-NON-ROOT-USER`), imagen base con versión fija (`DOCKER-UNPINNED-BASE-IMAGE`); `.dockerignore` que excluya `.env*`/`.git` (Sonar `docker-S6470`).

### 1.6. Secretos (`auditor_secrets.py`, `HARDCODED-SECRET`, `CONFIG-*`)
Tolerancia cero a: llaves AWS, llaves privadas, tokens (`ghp_*`, `glpat-*`, `xoxb-*`), cadenas de conexión con contraseña, `password = "…"`. **Nuevo: también en configuración versionada** — `application*.properties|yml` / `bootstrap*`:
- `CONFIG-SECRET-LITERAL` (HIGH; MEDIUM si el archivo es un perfil `-dev/-local/-test`) y `CONFIG-JWT-SECRET-LITERAL` (CRITICAL: con él se **forjan tokens de cualquier usuario**).
- **Estándares de conformidad** (`auditor_standards_rules.py`, INFORMATIONAL): `SWALLOWED-ERROR` (no atrapes un error para ocultarlo: registra con traza o propaga; un `.catch(() => [])` convierte un endpoint roto en «sin resultados»), `DESTRUCTIVE-ACTION-NO-CONFIRM` / `NATIVE-BROWSER-DIALOG` (borrar y revocar piden confirmación con el diálogo estándar de la UI, no `confirm()`), `SQL-TABLE-WITHOUT-PRIMARY-KEY` (toda tabla lleva llave primaria), `CICD-GATE-ALLOW-FAILURE` (un job de pruebas/lint/seguridad no lleva `allow_failure`/`continue-on-error`), `TEST-SKIPPED-WITHOUT-REASON` (toda prueba omitida dice por qué y hasta cuándo).
- **Configuración de esquema** (`auditor_standards_rules.py`, vulnerabilidad): `SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE` — `spring.jpa.hibernate.ddl-auto=update|create|create-drop` deja que Hibernate altere o borre el esquema al arrancar, fuera de Liquibase y sin auditoría (HIGH con `create*`, MEDIUM con `update`, LOW en perfiles `-dev/-local/-test`). Corrección: `ddl-auto=none` (o `validate`) y todo cambio por migración (skill `database-liquibase-postgresql`).
- **Cliente OIDC inseguro** (vulnerabilidad, MEDIUM): `FRONTEND-OIDC-INSECURE-CONFIG` — `requireHttps: false` o `strictDiscoveryDocumentValidation: false` en un `environment` que no es local/dev (o en código sin guarda de modo local). Corrección: ambos en `true` en QA/producción; solo `environment.local.ts`/`environment.dev.ts` pueden relajarlos (skill `frontend-auth-oidc`).
- **Estándar de base de datos org en migraciones `.sql`** (INFORMATIONAL, agrupados por archivo): `SQL-PK-NOT-UUID` (PK `serial`/`bigint`/`IDENTITY` → `id uuid DEFAULT uuidv7()`), `SQL-TIMESTAMP-WITHOUT-TIMEZONE` (`timestamp` → `timestamptz`), `SQL-JSON-NOT-JSONB` (`json` → `jsonb`), `SQL-FLOAT-FOR-MONEY` (montos en `money`/`float`/`double precision` → `numeric(p,s)`), `SQL-TABLE-WITHOUT-AUDIT-COLUMNS` (faltan `ref`, `row_version`, `fecha_*`, `usuario_*`, `activo`, `borrado` del Estándar de auditoría org; agrégalas y ejecuta `SELECT auditoria.asignar_triggers('<esquema>.<tabla>')`). Las tablas con la convención legada `fc*/ds*/bo*` no reciben los dos últimos avisos (el estándar las deja como están). `SQL-TABLE-WITHOUT-PRIMARY-KEY` reconoce la llave añadida después con `ALTER TABLE ... ADD CONSTRAINT ... PRIMARY KEY` y no evalúa tablas de otros motores (`ENGINE =`).
- **Convenciones del Starter** (INFORMATIONAL): `TRANSACTIONAL-ON-CONTROLLER` (la transacción va en el servicio), `FIELD-INJECTION-AUTOWIRED` (inyección por constructor con campos `final`, `@RequiredArgsConstructor`), `JPA-OBJECT-ARRAY-RESULT` (proyección con interfaz o `record`, no `Object[]`), `FRONTEND-HARDCODED-API-URL` (URL desde `environment` + `API_ENDPOINTS`, no escrita en el servicio), `API-ENDPOINT-UNDOCUMENTED` (cada endpoint con `@Operation` + `@ApiResponses` con ejemplos; skill `documentacion-codigo-y-api`).
- `VALIDATION-REIMPLEMENTED` (LOW, INFORMATIONAL): un patrón de RFC o CURP escrito a mano. Las validaciones comunes (RFC, CURP, correo, código postal, teléfono, fechas, montos) se definen **una sola vez** en el catálogo institucional (0B-4) y se usan como validador reutilizable de la base de arranque; no las reescribas por proyecto. Si el archivo es el propio validador del catálogo, el aviso se ignora.
- Correcto: `spring.datasource.password=${DB_PASSWORD}` leído de variable de entorno o Vault. Si ya estuvo en git, **rotar la credencial y purgarla del historial** (el valor sigue en commits viejos). Los valores de desarrollo no deben existir en producción.
- Centinela **nunca escribe el valor del secreto** en un hallazgo, PDF o log; ni tú en un chat, ticket o commit.

### 1.7. Autorización estática (`auditor_authz.py`, `scan_engine: authz-static`)
Es el motor que cubre OWASP A01 / CWE-862 / ASVS V4.1.3. Entiende reglas de URL (`antMatchers`/`requestMatchers`) **y** anotaciones de método.
| Regla | Sev. | Qué es / cómo se corrige |
|---|---|---|
| `AUTHZ-NO-METHOD-AUTHZ` | HIGH (muta o toca identidad) / MEDIUM (lectura) | El proyecto decide por método (`@EnableMethodSecurity` o endpoints hermanos con `@PreAuthorize`) y este endpoint no la tiene (ni en método ni en clase). Añadir `@PreAuthorize("hasAuthority('RECURSO_ACCION')")`, dar de alta el permiso y probar el 403. |
| `AUTHZ-PREAUTHORIZE-COMMENTED-OUT` | HIGH | Hay un `// @PreAuthorize` y ninguno activo: la restricción fue desactivada. Reactivarla o documentar por qué es abierto. |
| `AUTHZ-PUBLIC-SENSITIVE-READ` | HIGH | `GET` público (`permitAll`) sobre usuarios/roles/privilegios. Exigir autenticación + permiso. |
| `AUTHZ-TEST-ENDPOINT-EXPOSED` | HIGH | Controlador de prueba/ejemplo/sandbox en `src/main` sin `@Profile`. Moverlo a `src/test` o limitarlo a `dev`. |
| `AUTHZ-INCONSISTENT-FAMILY` | HIGH | Un endpoint de identidad quedó más débil que sus hermanos blindados (caso proyecto-k `/usr/**`). Unificar la regla. |
| `AUTHZ-ONLY-AUTHENTICATED-WRITE` / `AUTHZ-PERMITALL-WRITE` | MEDIUM / HIGH | Escritura sensible solo autenticada / pública. Exigir rol/permiso. |
| `AUTHZ-CLIENT-SIDE-ONLY` / `-UI-GATE` / `-ADMIN-BUNDLE-EXPOSED` | HIGH / MEDIUM / LOW | La autorización vive solo en un guard o `*ngIf`. Mantenerlo por UX, pero **exigir el rol en el backend**. |
| `AUTHZ-CSRF-DISABLED`, `AUTHZ-NAMESPACE-GAP`, `AUTHZ-NO-RULE`, `AUTHZ-IDOR-PARAM-REVIEW` | MEDIUM/HIGH | CSRF off con sesión/cookies; prefijo de rutas sin regla; endpoint sin regla ni anotación; `{id}` de usuario en ruta (la confirmación real la hace `authz-dast`). |
- **Alcance real:** una anotación en la **clase** cubre todos sus métodos; el detector toma el bloque completo de anotaciones del método (el `@PreAuthorize` puede ir antes o después de `@PostMapping`/`@Operation`). No valida que el permiso exista en el catálogo ni que un endpoint público sea intencional: **requiere revisión humana**.
- **Si un endpoint debe ser público a propósito**, declararlo explícito en el `SecurityConfig` y documentarlo; no dejarlo implícito.
- **Hecho frecuente a evitar:** `@EnableMethodSecurity` activo con **0** `@PreAuthorize` en los controladores = protección encendida y sin usar (se detectó así en proyecto-a).
- Confirmación en vivo: `auditor_authz_dast.py` (replay multi-rol + sonda IDOR) **necesita credenciales multi-rol en Vault** (ADR-0005); sin ellas **no se ejecuta** y se declara (`AUTHZ-DAST-NO-CREDS` es un marcador, no una vulnerabilidad).

### 1.8. WSTG v4.2 / ASVS v4.0 perimetral (`auditor_wstg.py`, `scan_engine: wstg-perimeter`)
15 reglas deterministas con 1–2 peticiones ligeras por vector (**cero fuerza bruta**; la sonda de credenciales por defecto es opt-in con `WSTG_DEFAULT_CRED_PROBE=1`): login en texto claro / canal sin cifrar, Host Header Injection, métodos HTTP peligrosos (CONNECT), open redirect, fingerprint de framework/servidor, error verboso, CORS, dotfiles. Cobertura de reglas = los 8 hallazgos del pentest de Superset; **solo se manifiestan donde el despliegue los tiene** (no es señal de que el detector falle).

### 1.9. SCA — dependencias (`auditor_sca_dependencies.py`)
- Fuente: OSV.dev en vivo (tabla estática solo si OSV no responde). **Severidad real por CVSS**: se calcula el puntaje base desde el vector (`cvss` v2/v3/v4), no se asume MEDIUM.
- **Versión segura correcta:** debe caer dentro del rango `[introduced, fixed)` que contiene tu versión instalada (un mismo CVE puede tener un rango por línea 0.x/1.x).
- **Alcanzabilidad:** si no hay ningún `import`/`require` del paquete, la severidad **efectiva baja un nivel** (`DOWNGRADED`, la cruda no cambia). Es una señal basada en imports, **no** análisis de llamadas; Maven/`pom.xml` siempre cuenta como alcanzable (sin evidencia no se degrada).
- Regla práctica: mantener manifiestos al día (axios, vite, postcss…), versiones declaradas explícitas en Maven y sin dependencias muertas.

### 1.10. SAST nativo y Semgrep (`auditor_master_vulnerabilities.py`, `auditor_semgrep.py`)
Ver §2–§4 para cada regla. Semgrep corre por lenguaje (Java, TS/JS, Python, Go, PHP, Rust, Terraform, Ruby, C#, C, Kotlin, Swift, Scala, Elixir; **no** hay ruleset oficial para C++/HTML/Bash/Dart → esos quedan sin cobertura, no "limpios").

### 1.11. Configuración de GitLab (`auditor_gitlab_config.py`)
`GITLAB-PROJECT-DEFAULT-BRANCH-UNPROTECTED`, `-BRANCH-FORCE-PUSH`, `-BRANCH-DEVELOPER-PUSH`, `-PUBLIC-VISIBILITY`, `-CI-VARIABLE-UNMASKED/-UNPROTECTED`, `-WEBHOOK-INSECURE`, `-MR-NO-PIPELINE-GATE`, `CICD-NO-PIPELINE`, y en `.gitlab-ci.yml`: `curl | sh`, imágenes `:latest`, secretos literales. Proteger la rama por defecto, prohibir force-push, enmascarar/proteger variables CI, webhooks con TLS y token, pipeline obligatorio en MR. *Con el token `monitor` (Developer) hay proyectos cuyos hooks/variables no se pueden leer: se reporta como parcial, nunca como limpio.*

### 1.12. Reglas añadidas el 2026-10-01 (cierre de brechas OWASP / WSTG / WCAG) y cómo evitarlas
| Regla | Qué detecta | Cómo evitarla |
|---|---|---|
| `MASS-ASSIGNMENT-ENTITY-BINDING` | Un controlador recibe una `*Entity` JPA directamente en `@RequestBody`/`@ModelAttribute` (API3, CWE-915) | Usar un DTO con solo los campos permitidos |
| `INSECURE-RANDOM-FOR-SECRET` | `new Random()`/`Math.random()`/`random.*` generando tokens, contraseñas, códigos (CWE-338) | `SecureRandom` (Java) / `secrets` (Python) |
| `CRYPTO-CBC-NO-AUTHENTICATION`, `WEAK-CRYPTOGRAPHY` | AES/CBC con relleno sin autenticación; `Cipher.getInstance("AES")` (= ECB), DES/3DES/RC4, `MessageDigest` MD5/SHA-1 | `AES/GCM/NoPadding`; SHA-256+; contraseñas con bcrypt/Argon2 |
| `INSECURE-WEBSOCKET`, `POSTMESSAGE-WILDCARD-ORIGIN`, `POSTMESSAGE-NO-ORIGIN-CHECK` | `ws://` fuera de localhost; `postMessage(..., "*")`; listener `message` sin validar `event.origin` | `wss://`; origen destino explícito; validar `event.origin` |
| `CLIENT-SIDE-REDIRECT`, `FRONTEND-SENSITIVE-STORAGE` | Redirección a un valor de la URL; contraseña/secreto en `localStorage` | Lista blanca de destinos; no guardar secretos en el navegador |
| `SESSION-FIXATION-DISABLED`, `GRAPHQL-INTROSPECTION-ENABLED` | `sessionFixation().none()`; GraphiQL/introspección activos | `migrateSession()`; desactivar fuera de desarrollo |
| `SSTI-TEMPLATE-FROM-INPUT`, `XPATH-INJECTION-CONCAT`, `LDAP-INJECTION-CONCAT` | Plantilla/XPath/filtro LDAP construidos por concatenación | Plantillas fijas; variables XPath; `LdapEncoder.filterEncode` |
| `SUPPLY-CHAIN-NO-LOCKFILE`, `SUPPLY-CHAIN-UNPINNED-DEPENDENCY`, `DOCKER-CURL-PIPE-SHELL` | `package.json` sin lockfile; versiones `latest`/rangos Maven/`requirements` sin `==`; `RUN curl … \| sh` | Lockfile versionado; versiones exactas; descargar, verificar hash y luego ejecutar |
| `WSTG-INFO-03-METAFILE-LEAK`, `WSTG-CONF-08-CROSSDOMAIN-WILDCARD`, `WSTG-INFO-05-CONTENT-LEAK`, `WSTG-ATHN-06-LOGIN-CACHEABLE` (dinámicas, 1–2 GET) | `robots.txt` que enumera rutas sensibles; `crossdomain.xml` con `*`; comentarios con credenciales/TODO o IP privadas en la página; formulario de contraseña sin `no-store` | No listar rutas sensibles (protegerlas con autenticación); dominios explícitos; limpiar comentarios en el build; `Cache-Control: no-store` |
| **WCAG nuevas** (`WCAG-1.4.4`, `2.4.1`, `2.4.2`, `4.1.2-IFRAME`, `1.3.5`, `2.2.2`, `1.4.2`, `1.2.2`, `4.1.1`, `2.4.6`, `2.5.3`, `2.4.7`) | Zoom bloqueado; sin enlace «saltar al contenido» en la plantilla raíz; sin `<title>`; `<iframe>` sin `title`; datos personales sin `autocomplete`; marquee/blink; audio con autoplay; video sin subtítulos; ids duplicados incondicionales; encabezados vacíos; `aria-label` que no contiene el texto visible; `:focus { outline: none }` sin alternativa | Ver §3.4 |

---

### 1.x Reglas de arquitectura y supply-chain añadidas el 12-oct-2026 (qué hacer cuando Centinela las reporta)
| Regla | Corrección |
|---|---|
| `REQUESTBODY-WITHOUT-VALID` (uno por controlador) | `@Valid @RequestBody Dto` + `MethodArgumentNotValidException` → 400 claro; validar con Bean Validation en el DTO, no a mano en el servicio. |
| `ENTITY-RETURNED-FROM-CONTROLLER` | Devolver un DTO de respuesta con solo los campos necesarios; nunca la entidad JPA (expone columnas internas y rompe con relaciones perezosas). |
| `CONTROLLER-INJECTS-REPOSITORY` | El controlador llama a un `@Service`; el servicio delimita la transacción y accede al repositorio. |
| `JPA-EAGER-FETCH` / `JPA-QUERY-IN-LOOP` / `REPOSITORY-FINDALL-UNPAGINATED` | `LAZY` + `JOIN FETCH`/proyección DTO solo donde se necesite; `findAllById`/`IN` en vez de una consulta por elemento; `Pageable` en vez de `findAll()`. |
| `ANGULAR-SUBSCRIBE-NO-CLEANUP` / `ANGULAR-NESTED-SUBSCRIBE` | `takeUntilDestroyed(this.destroyRef)` o `toSignal()`; encadenar con `switchMap`/`forkJoin`, nunca `subscribe` dentro de `subscribe`. |
| `ANGULAR-VALUECHANGES-NO-DEBOUNCE` | `valueChanges.pipe(debounceTime(300), distinctUntilChanged(), switchMap(...))`. |
| `ANGULAR-EFFECT-HTTP` / `ANGULAR-EFFECT-SELF-WRITE` | No hacer HTTP en `effect()`; derivar con `computed()`/`linkedSignal()` en vez de escribir la señal que se lee. |
| `ANGULAR-LAZYLOAD-PLUS-INIT-LOAD` / `ANGULAR-DOUBLE-LOAD-INIT-EFFECT` | Un solo disparador de carga (quitar el de `ngOnInit` o `[lazyLoadOnInit]="false"`). |
| `ANGULAR-HTTP-IN-LOOP` | Endpoint por lote (o `forkJoin`/`mergeMap(concurrency)`); si hace falta endpoint nuevo, el cambio es también de backend. |
| `ANGULAR-SIGNAL-MUTATION-IN-PLACE` | `lista.update(l => [...l, x])`, nunca `lista().push(x)`. |
| `SCA-LICENSE-*` | Sustituir la dependencia, obtener licencia comercial o documentar la excepción (ruta 0B-3). Si es solo de desarrollo y no se distribuye, el riesgo no aplica. |
| `DNS-SPF-*`, `DNS-DMARC-*`, `DNS-CAA-*` | SPF con `-all` (o `~all` + DMARC en quarantine/reject), DMARC `p=quarantine`→`reject` con `rua`, un solo registro SPF y ≤10 consultas. Un dominio sin correo: `v=spf1 -all`. |
| `API-ROUTE-NOT-IN-CONTRACT` / `API-NO-CONTRACT` | Versionar el OpenAPI junto al código y documentar (o retirar) las rutas fuera de inventario. |
| `SECRETS-*-PHASE3` (historial git) | **Rotar la credencial** (borrar del árbol no basta: sigue en el historial); luego, si se quiere, reescribir el historial. |

## 2. 🏛️ Backend (Spring Boot / FastAPI)

### 2.1. Autorización por método (obligatoria)
- Todo método de controlador que modifique estado, toque identidad/permisos o exponga datos personales **debe** tener `@PreAuthorize("hasAuthority('…')")` (o la clase completa). Ver tabla §1.7.
- **Prohibidos** los controladores de prueba/backdoor en `src/main` (`LocalAuthController`, `TestSandboxController`, `AuthorizationTestController`, `EjemploM2MController`…): `BACKDOOR-SANDBOX-CONTROLLER` (CRITICAL, CWE-288/798) y `AUTHZ-TEST-ENDPOINT-EXPOSED`.
- Endpoints de login/signin: limitar intentos (Bucket4j/Resilience4j/contador de fallos) → `AUTH-ENDPOINT-NO-RATE-LIMIT`.
- IDOR/BOLA: un `@PathVariable id` que va directo a `findById()` sin comprobar propiedad (`POTENTIAL-IDOR-NO-OWNERSHIP-CHECK`) debe validar que el recurso pertenezca a quien lo pide (y `tenant_id` donde aplique).

### 2.2. Concurrencia e integridad
- Entidades editadas por varios usuarios (expedientes, solicitudes, contratos): **`@Version`** (`JPA-ENTITY-MISSING-VERSION`); manejar `ObjectOptimisticLockingFailureException` → 409. Catálogos de solo lectura pueden omitirlo con justificación escrita.
- Métodos con ≥ 2 escrituras: `@Transactional` (`JPA-MULTI-WRITE-NO-TRANSACTIONAL`).
- Folios/ordinales: secuencias DB atómicas, nunca "contar registros".
- Prohibido llamar HTTP externo (OnlyOffice, Authentik, S3) dentro de `@Transactional`: retiene conexiones del pool.

### 2.3. Archivos y memoria
- Subidas (`MultipartFile`): tamaño máximo, lista blanca de extensiones, tipo real del contenido (Tika), nombre generado por el servidor, almacenamiento fuera de la ruta pública (`FILE-UPLOAD-NO-VALIDATION`; confianza baja si la validación vive en otro filtro).
- No cargar archivos en `byte[]` (`OOM-BYTE-ARRAY-STREAMING`): `InputStream`/`StreamingResponseBody`. Plantillas pequeñas y fijas del propio sistema son aceptables y se documentan.
- `Thread.sleep()` en servicios (`BLOCKING-THREAD-SLEEP`): usar scheduling/async.

### 2.4. Criptografía, tokens y errores
- **Tokens:** nunca en la URL (`?token=`; `JWT-IN-URL-PARAM`, `FRONTEND-TOKEN-IN-URL`) — solo `Authorization: Bearer`. Para `EventSource` usar un ticket de un solo uso y vida corta.
- **Comparar secretos/firmas/tokens en tiempo constante** (`MessageDigest.isEqual`), no con `equals` (`TIMING-UNSAFE-SECRET-COMPARISON`, CWE-208).
- **Contraseñas:** política validada **en el servidor** (`@Size(min=12)` + `@Pattern`) en DTOs de alta/cambio/reset (`PASSWORD-POLICY-NOT-ENFORCED`).
- **Redis:** nada de `JdkSerializationRedisSerializer`; usar `StringRedisSerializer`/JSON y cifrar datos sensibles.
- **Cookies:** `Secure` + `HttpOnly` + `SameSite` (`INSECURE-COOKIE-FLAGS`). **CORS:** nunca `*` con credenciales (`CORS-WILDCARD-ORIGIN`). **Errores:** no devolver stack traces (`STACK-TRACE-EXPOSURE`). **TLS:** no desactivar verificación (`JVM-GLOBAL-SSL-BYPASS`). **SQL:** consultas parametrizadas; `nativeQuery` revisado.
- **Configuración peligrosa de Spring** (nivel `application*.properties`/`.yml`): **DevTools remoto** — nunca `spring.devtools.remote.secret` ni `spring.devtools.remote.enabled=true`, y excluir `spring-boot-devtools` del artefacto de producción (`SPRING-DEVTOOLS-REMOTE-ENABLED`; CVE-2026-40972, CWE-208: su secreto se compara en tiempo no constante → ataque de temporización → RCE). **Consola H2** deshabilitada en cualquier entorno accesible (`SPRING-H2-CONSOLE-ENABLED`). **Actuator:** exponer solo `health`/`info`, nunca `*` ni `env`/`configprops`/`heapdump`/`threaddump`/`beans`/`shutdown` (`SPRING-ACTUATOR-SENSITIVE-EXPOSED`).
- **Bitácora:** operaciones que modifican datos deben dejar rastro (usuario, acción, recurso, fecha; sin contraseñas ni tokens) → `STD-STRIDE-MISSING-AUDIT-LOG` (detección textual: puede estar en un interceptor central; confírmalo).

---

## 3. 🎨 Frontend (Angular / React)

### 3.1. XSS y sanitización
- No usar `bypassSecurityTrust*`, `[innerHTML]` ni `dangerouslySetInnerHTML` con datos de la API sin `DOMPurify.sanitize()` (`ANGULAR-BYPASS-SECURITY-TRUST`, HIGH).
- Excepción reconocida: `bypassSecurityTrustResourceUrl` sobre un `blob:` creado con `URL.createObjectURL(...)` (patrón recomendado para mostrar archivos locales) baja a **LOW** y se revisa que el blob no venga de contenido no confiable.

### 3.2. Tokens y almacenamiento
- Preferir cookies `HttpOnly; Secure; SameSite` a `localStorage` (`FRONTEND-JWT-LOCALSTORAGE`). Si se mantiene por arquitectura: vida corta, rotación, CSP.
- Nunca variables públicas `VITE_/NEXT_PUBLIC_/REACT_APP_` con credenciales de BD (`FRONTEND-EXPOSED-DB-CREDENTIAL`, CRITICAL).

### 3.3. Rutas y guards
- Sin rutas de prueba/demo/debug en el router de producción (`FRONTEND-TEST-ROUTE-EXPOSED`); condicionar al `environment`.
- Un guard (`canActivate`) o un `*ngIf` por rol **no es autorización**: el backend debe exigir el permiso (`AUTHZ-CLIENT-SIDE-*`).

### 3.4. Accesibilidad WCAG 2.1 AA (`auditor_accessibility_wcag.py`; requisito legal en proyectos de gobierno)
Reglas estáticas: `WCAG-1.1.1-IMG-MISSING-ALT`, `WCAG-1.3.1-FORM-CONTROL-NO-LABEL` (control sin `<label for>`/`aria-label`; en Angular el `id` debe coincidir con el `for` cuando se usa `formControlName`), `WCAG-2.4.4-EMPTY-INTERACTIVE-ELEMENT` (botón/enlace sin nombre), `WCAG-3.1.1-HTML-MISSING-LANG` (`<html lang="es">`), `tabindex` positivo, `div/span` clicable sin `role`/`tabindex`.
- **Cuentan como nombre accesible:** `label="…"` y `[label]` de PrimeNG, `aria-label(ledby)`, `title`, texto visible, `th:text` de Thymeleaf. `pTooltip` **no** es nombre accesible para todos los lectores.
- Son **cumplimiento**, no explotación: no los presentes como "vulnerabilidades críticas".
- **Criterios nuevos (18 con detector → 19 criterios estáticos cubiertos):** `<meta viewport>` sin `user-scalable=no` ni `maximum-scale` < 2 (1.4.4); `<title>` con texto en todo documento completo (2.4.2); `title` en cada `<iframe>` (4.1.2); `autocomplete` en correo/teléfono/contraseña (1.3.5); sin `<marquee>`/`<blink>` (2.2.2); sin `autoplay` con sonido (1.4.2); `<track kind="captions">` en videos con audio (1.2.2); ids únicos (4.1.1; ignora ramas `*ngIf`/`@if`); encabezados con texto (2.4.6); el `aria-label` debe contener el texto visible (2.5.3); nunca `outline: none` en `:focus` sin `box-shadow`/borde/fondo (2.4.7, solo CSS propio; se ignoran temas y `.min.`); enlace «saltar al contenido» en la plantilla raíz con `<router-outlet>` (2.4.1).
- **Lo que NO se puede verificar leyendo código (declarado, no «limpio»):** contraste de color (1.4.3, 1.4.11), reflujo (1.4.10), espaciado de texto (1.4.12), idioma de partes (3.1.2), mensajes de estado (4.1.3) — exigen un navegador renderizado (7 criterios); y 24 criterios que exigen juicio humano (orden con sentido, trampas de teclado, subtítulos correctos, etc.). WCAG 2.1 A+AA son 50 criterios: Centinela tiene detector para **19**.
- SSE/WebSocket: reconexión con backoff exponencial para no perder notificaciones en silencio.

---

## 4. ⚡ Código, datos y concurrencia en Python (`auditor_ext.py`, SAST nativo)

- **N+1:** prohibidas consultas en bucles; `JOIN`, `joinedload()/selectinload()` o consultas por lote.
- **Conexiones:** siempre con context managers (`with get_db_connection() as conn:`).
- **Excepciones:** prohibido `except Exception: pass`; capturar específicas y registrar traza completa (`logger.error(..., exc_info=True)` / `traceback.print_exc()`). Un fallo no puede devolver "éxito".
- **Workers en segundo plano:** SQL seguro ante nulos (`IS NOT DISTINCT FROM`), verificar con `SELECT` reales que las filas insertadas correspondan a hallazgos reales (sin duplicación ni huérfanos).
- `eval/exec/os.system/subprocess(shell=True)`, `pickle`/`yaml.load`, `hashlib.md5/sha1`, `ECB`, XML sin protección XXE, rutas dinámicas en `open()` (path traversal) y `requests` con host controlado por entrada (SSRF) son hallazgos del SAST nativo. El detector ignora comentarios y cadenas literales; una mención descriptiva no es un hallazgo.

---

## 5. 📐 Gobierno, Metodología interna y Cumplimiento HONESTO (ISO & CMMI v3.0)

### 5.1. ISO/IEC 25010 y 27001
- Calidad: type hints / TypeScript estricto, PEP 8, complejidad ciclomática ≤ 10 (`STD-ISO25010-LONG-METHOD`, `COGNITIVE-COMPLEXITY-EXCEEDED` son **informativos**, no vulnerabilidades).
- Seguridad: TLS, logs sin PII/tokens, cero secretos en código.
- **ISO 27001:** el universo se **deriva de los controles que algún detector puede violar** (registro `core/coverage_matrix.py` + matriz heredada): hoy **30 buckets** = 26 de los 93 controles del Anexo A con al menos una regla + 3 características de ISO 25010 + el bucket histórico A.8.16 de «hallazgo sin clasificar». Los controles físicos, de personas y la mayoría de los organizativos **no están en el denominador** porque ningún escáner los mide. No es una certificación. Nunca se añade un control para mover el porcentaje: solo entra si existe una regla que pueda violarlo (el 2026-10-01 el denominador pasó de 16 etiquetas —11 controles distintos + 3 de ISO 25010, duplicados por etiquetas compuestas— a 30 y el puntaje medio bajó 4,9 puntos: ahora cuentan reglas que antes no contaban contra ningún control).

### 5.2. CMMI V3.0 — las 19 áreas: qué evidencia mide Centinela (DECISIONS/0007)
**Fuente de verdad:** la columna «Evidencia de cumplimiento» del Anexo 10 del manual de metodología. Es un **indicador interno de preparación, no una evaluación CMMI formal** (el propio manual dice que para ello hace falta el modelo completo de ISACA).

**Niveles de evidencia:** L1 *medido* por Centinela (GitLab, repositorio, su BD) · L2 *artefacto verificado* (instancia de un `ART-*` contra su manifiesto; **aún no implementado**) · L3 *atestiguado* por una persona (se muestra aparte, nunca mezclado) · L0 *no evaluado*. Solo L1+L2 puntúan.
**Regla de ausencia:** no encontrar evidencia es `NO_CUMPLE` solo cuando la comprobación es definitiva (un MR fusionado sin revisión, el último pipeline en rojo, ninguna etiqueta de versión). Si solo se buscan **indicios** en el repositorio (docs, ADR, OpenAPI, pruebas de integración), encontrarlos da `CUMPLE` y no encontrarlos da `NO_EVALUADO`, nunca `NO_CUMPLE`.

**Consulta:** `GET /api/cmmi/evidence/{activo}` devuelve siempre las 19 áreas con el estado real de cada ítem. El porcentaje histórico de 5 áreas (CAR/PQA/CM/MC/VV) no cambió; la evidencia nueva se informa aparte.

**Hábitos de equipo que producen evidencia medible hoy (11 de las 19 áreas tienen ya un ítem con colector):**
| Área | Lo que el equipo debe hacer | Cómo lo mide Centinela |
|---|---|---|
| **PR** Revisión por pares | Que **otra persona** revise cada MR en GitLab (comentario, revisor asignado o aprobación) antes de fusionar | De los últimos 20 MR fusionados (180 días), el 100 % debe tener revisión de alguien distinto del autor |
| **VV** | Tener pruebas y un pipeline que las ejecute en verde en la rama por defecto | Archivos de prueba + último pipeline `success` |
| **CM** | Historial real, etiquetas/releases de versión, rama por defecto protegida, migraciones de esquema versionadas (Liquibase/Flyway/Alembic) | Commits de **todas** las ramas, tags/releases, ramas protegidas, changelog |
| **TS / PI / DAR** (indicios) | `docs/` con arquitectura y diseño, contrato OpenAPI (o springdoc), pruebas de integración, ADR en `docs/adr` o `DECISIONS/` | Presencia en el repositorio (solo suma, su ausencia da `NO_EVALUADO`) |
| **PAD / PCM / II / GOV** (organizacionales) | Mantener plantillas, manifiestos y catálogo versionados y válidos | Manifiestos que cargan con código/nombre/área; historial git de `skills/` |
| **PQA** (flujo propio de Centinela) | Revisar las propuestas de la IA en «Supresiones IA» | Ninguna propuesta lleva más de 14 días sin decisión humana |

**Hoy sin colector (`NO_EVALUADA`, dependen de decisiones de la organización):** RDM, EST, PLAN, MC, RSK (necesitan las instancias de los artefactos `ART-*`), OT (registro de capacitación), CAR y MPM (política de activación pendiente). El código `MSR` no existe en el modelo de la organización.
**Dos errores que casi se cometen (verificados contra la fuente):** (1) los clones del escáner son superficiales, así que `git rev-list` ahí no dice nada del historial; (2) `statistics.commit_count` de GitLab cuenta **solo la rama por defecto** (repos con «1 commit» tenían 3–6 en otras ramas). Concluir «sin historial» desde cualquiera de las dos habría sido un falso negativo.
- **Trazabilidad (RDM):** `RF-xxx` de `ART-F1-03` con entrada en `ART-F1-04`. **VV:** no dar un módulo por completo sin pruebas unitarias (`ART-F3-05`) y de integración/caja negra (`ART-F3-06`). **PQA:** todo parche de IA explicado, sin `TODO`/`pass`, certificado por revisión humana (`ART-F3-04`).
- `N/A` real (p. ej. migraciones de esquema en un repositorio sin base de datos) sale del denominador con su motivo; no se rellena.

---

## 6. 🛡️ Estándar Anti-Simulación y Operación Defensiva

### 6.1. Parches reales (`fix_patch`)
- Un parche existe **solo si `git apply --check` pasa** contra el archivo real (`core.patch_validator.validate_patch`). Sin clon o sin contexto suficiente: `fix_patch = ""`, `can_automate = false`, "Requiere remediación manual". **Sin clon local la validación devuelve `repo_unavailable` y descarta el parche**: no es un fallo del parche (ver §8).
- Prohibidos los scripts de backfill (`backfill_*.py`, `rebuild_*.py`, `remediate_all_*.py`) que inyecten diffs no verificados ni hunks repetitivos o variables inventadas. Un análisis **compartido por patrón nunca copia `fix_patch`**.

### 6.2. SOAR real
- Ninguna acción autónoma (`core/soar_engine.py`) devuelve `success` ni añade texto a una lista sin ejecutar una acción técnica real (Ansible, `ufw`/`iptables`, API de WAF). Si no se ejecutó: `not_executed` o `manual_action_required`.
- La política arranca en `dry_run=TRUE` (ADR-0004); pasarla a real es una decisión humana. `host_isolate` nunca es autónomo.
- `revoke_authentik_user_sessions` borra sesiones activas (nunca desactiva la cuenta: sería un DoS por bloqueo) y requiere `AUTHENTIK_API_TOKEN`.

### 6.3. Fail-Closed en webhooks y clonado
- Webhooks de GitLab (`push-webhook`, `mr-webhook`): sin token configurado → 503; con token incorrecto → 401 (`hmac.compare_digest`). Prohibido `ignored`.
- **Varias instancias de GitLab** (`core/gitlab_instances.py`): el payload solo aporta el `project_id`; la instancia se deduce del **host** de su URL y un host desconocido → 403. Nunca inyectar `oauth2:<token>@` en una URL controlada por el cliente; `clone_or_pull`, `GitLabAutoFixer` y `MRReviewer` se niegan a clonar de un host ajeno. Un `project_id` solo es único **por instancia**.

### 6.4. Aislamiento de pruebas
- Ningún test inserta en `vulnerability_log`, `agent_actions`, `infra_inventory` con nombres/IPs ficticios que distorsionen el inventario. Persistencia → **una conexión con `ROLLBACK` obligatorio** (parchear `db_manager.get_db_cursor`) o esquema temporal; limpiar con `addCleanup` (no `tearDown`, que no corre si `setUp` falla). Verificar después que no quedaron filas (`WHERE fingerprint_hash LIKE 'test-%'`).

### 6.5. Métricas honestas
- Prohibido alterar universos/denominadores (ISO, CMMI, WSTG) para "verse realista". Lo no verificable: `NO EVALUADO`/`N/A`. Un auditor probado solo con mocks se declara **"VALIDADO ÚNICAMENTE CON MOCKS EN AISLAMIENTO (0 % EN PRODUCCIÓN)"**: pasar una suite con mocks no es evidencia de producción.

### 6.6. Archivos y secretos
- Ningún `ART-*.docx`, `.zip` o reporte en `frontend/public/`, `ui/`, `dist/`; los entregables viven en `data/` y se sirven por endpoints autenticados. Los reportes con detalle de vulnerabilidades **no** se envían sin revisar su procedencia.
- Una llave pegada en un chat o ticket debe tratarse como expuesta: guardarla en `.env` (fuera de git), no reimprimirla y ofrecer rotarla.

### 6.7. Veracidad del análisis de IA
- Declarar siempre la procedencia (§0.3). Un análisis de patrón no se vende como revisión individual; un texto genérico del motor heurístico no se graba como definitivo cuando todos los proveedores están agotados (el hallazgo queda **pendiente** y se reintenta).
- Un veredicto "sin riesgo real" debe decir en la primera frase *por qué* difiere de la severidad ("Aunque se reporta como X, el riesgo real es Y porque Z"). Los textos se escriben para dos audiencias: analista SOC y gerente sin conocimientos técnicos.

---

## 7. 🧯 Trampas de código que ya causaron incidentes (no repetir)

1. **Regex en f-strings:** `rf'#{1,3}'` se evalúa como la tupla `(1, 3)`; hay que escribir `#{{1,3}}`. Rompió durante meses el parser de respuestas en prosa de la IA (`group(1)` era `None`).
2. **`hash()` de strings es aleatorio por proceso:** nunca como clave de deduplicación; usar `hashlib.sha256`.
3. **`ON CONFLICT (a, b)` exige un índice único real:** `vulnerability_log` solo tiene `id` y un índice parcial único sobre `fingerprint_hash`; sin él, el `INSERT` falla (y un `except` ancho lo tragaba) o `DO NOTHING` no protege. Deduplicar con `log_finding_deduplicated()`.
4. **Cambiar `asset_id` obliga a recalcular `fingerprint_hash`** (`calculate_fingerprint` lo incluye) o el siguiente escaneo duplica o colisiona.
5. **UUID en PostgreSQL:** no existe `MAX()/MIN()` para `uuid`; `= ANY(%s)` con lista de `str` exige `%s::uuid[]`; el `DROP`+`RENAME` al migrar tipos borra los índices secundarios.
6. **Probar el valor "no se encontró nada":** `subprocess.run(...).stdout` no vacío no implica hallazgos (banners); usar `-silent`/JSON y marcar éxito solo al parsear.
7. **`_run_ssh_command()` debe distinguir "falló la conexión" (`None`) de "salida vacía" (`""`)** o se fabrican calificaciones para hosts apagados.
8. **`ThreadPoolExecutor` bloquea la salida limpia** de scripts que importan `centinela.py`: terminar con `os._exit(0)`.
9. **Timeouts de cliente HTTP ≠ límite total:** un servidor que gotea bytes evita el timeout; usar un plazo duro por wall-clock (`_call_with_hard_deadline`).
10. **Valores por defecto con marcadores de redacción** (`***REMOVED-SECRET***`) escritos en el fuente rompieron el tier de NVIDIA sin que nadie lo notara: buscar ese texto antes de cada release.

---

- **Nunca `setfacl -R` / `chmod -R` sobre el repositorio completo**: las ACL cambian los bits de grupo que SSH ve y dejaron las llaves de `keys/` en `0660` → SSH las rechaza → `/api/users` 502 → «Gestión Usuarios» enviaba al dashboard (12-oct-2026). Las llaves son `0600`.
- **El nombre de un activo GitLab lleva `@rama`**: no compares igualdad ni ancles con `$`; usa `core/gitlab_instances.parse_asset_name`. Una regla anclada con `$` dejó de coincidir y 53 decisiones del analista pasaron a «Sin clasificar».
- **Nunca mandes código a un LLM externo sin pasar por `core/prompt_redaction.py`** (ya va en `call_ai_cascade`): el contexto de `application-*.properties` llevaba contraseñas literales.
- **«Instalado» no es «operativo»**: un motor que nunca escribió una fila (p. ej. `secrets` antes de agregarlo a la flota) no está Online. Comprueba `GET /api/engines/status`.

## 8. ⚙️ Operación de Centinela (para agentes y operadores)

- **Cambios de código:** montaje `.:/app` → editar basta, pero `__pycache__` viejo puede ejecutarse: limpiarlo y `docker restart`; verificar lo cargado con `inspect.getsource`.
- **Cambios de `.env`:** requieren **recrear** (`docker compose up -d <servicio>`), no `restart`. **Recrear `centinela-ai` borra `/tmp/centinela_gitlab_scans` (los clones) y mata cualquier escaneo en curso**: sin clones la validación de parches falla (`repo_unavailable`) y el contexto de código se pierde. Volver a clonar antes de confiar en ellos (`scratch/rescan_sast_sca_*.py` lo hace).
- **Proveedores de IA gratuitos:** la cuota diaria se agota en todos a la vez; la cascada (Groq 2 modelos → Gemini 2 modelos → Cloudflare/Mistral/Cerebras/SambaNova con llave → NVIDIA → OpenRouter) pone en pausa al que falla (1 h si es cuota diaria). La cola da prioridad a `AI_PRIORITY_ASSET_PATTERNS`. Las reglas de patrón comparten un análisis por (activo, regla); los informativos no consumen IA.
- **Pruebas:** `docker exec centinela-backend bash -c "cd /app && python3 -m pytest tests -q -p no:cacheprovider"` (pytest solo está en `centinela-backend`). Una suite verde con mocks no prueba producción.
- **Reportes:** `scratch/build_priority_reports.py <carpeta> <ETIQUETA> '<patrón ILIKE>' <prefijo> …` genera PDF por activo (endpoint real `/api/reports/asset/…`) y GENERAL por grupo; no mover a rutas públicas.

---

## 9. 🚧 Cobertura real por marco y lo que Centinela NO cubre (declarar, no ocultar)

**Fuente:** `core/coverage_matrix.py` → `GET /api/coverage` y `docs/COBERTURA_FRAMEWORKS.md` (generado; una prueba falla si el código emite una regla que el registro no clasifica). «Cubierto» = existe un detector, **no** que el activo cumpla; los mapeos son criterio de ingeniería de Centinela, no una taxonomía normativa.
| Marco | Elementos | Con regla propia | Observación |
|---|---:|---:|---|
| OWASP Top 10:2021 | 10 | 10 | Varias categorías descansan en pocas familias de reglas (A04 la más delgada) |
| OWASP API Security Top 10:2023 | 10 | 9 | Sin detector: API6 (flujos de negocio sensibles; no automatizable) |
| OWASP LLM Top 10:2025 | 10 | 3 | Solo LLM01, LLM02, LLM06 |
| OWASP ASVS 4.0 | 14 capítulos | 14 | A nivel de capítulo, no de los 286 requisitos |
| OWASP WSTG v4.2 | 97 pruebas | 50 | Más 2 solo con motores externos; 45 sin detector (muchas exigen juicio o pruebas activas) |
| WCAG 2.1 A+AA | 50 | 19 | Los 19 criterios verificables en código tienen regla; 7 exigen navegador y 24 juicio humano |
| ISO/IEC 27001:2022 Anexo A | 93 | 26 | 37 organizativos, 8 de personas, 14 físicos y el resto tecnológico; los no técnicos no se miden |
| CMMI V3.0 (19 áreas) | 19 | 11 con ≥1 ítem medible | 8 sin colector; ver §5.2 |

**Sin cobertura hoy:** licencias de dependencias; SPF/DKIM/DMARC; pruebas de fuerza bruta/límite de intentos (excluidas por política); **DAST autenticado multi-rol** (faltan credenciales en Vault); datos reales de Active Directory para BloodHound; C++/HTML/Bash/Dart en Semgrep; incoherencia de caché entre réplicas (no verificable estáticamente); reglas de aprobación de MR de GitLab CE; WCAG de render (contraste, reflujo) hasta incorporar un navegador sin cabeza con axe-core; webhooks de la segunda instancia de GitLab. Un «0 hallazgos» solo significa algo donde el motor correspondiente **corrió** y tiene cobertura para ese lenguaje.

---

## 9.1 🧪 Herramientas de testing integradas (ADR-0009, 7 oct 2026)

- **Pruebas:** nunca `pytest` directo; `scripts/run_tests.sh [args]` (Postgres desechable + Alembic). Hay pruebas con binarios reales (nuclei, trufflehog) y de propiedades (Hypothesis). Frontend: eslint + vitest + `vite build` en un contenedor Node limpio.
- **Secretos (TruffleHog v3):** el JSON es `SourceMetadata.Data.Git.{file,line,commit}` y `DetectorName`; nunca copies `Raw`/`SecretParts` a un hallazgo. La verificación activa envía la credencial a su emisor: solo con `SECRETS_VERIFY_LIVE=1`.
- **Nuclei propio:** plantillas versionadas en `templates/nuclei/`, solo GET; valida con `nuclei -t <dir> -validate` y pruébalas contra un servidor local real.
- **Accesibilidad renderizada (`wcag-render`):** el id es `WCAG-<criterio>-AXE-<regla>`; un render vacío (sin texto) NO es una auditoría válida (no persistir ni reconciliar). Solo se cubren criterios para los que axe tiene regla (`AXE_DECIDABLE` en `coverage_matrix.py`).
- **Contenedores hermanos** (ZAP, a11y, schemathesis): límite de memoria/CPU, tiempo máximo y `docker rm -f` en `finally`.
- **Fuzzing de API (`api-fuzz`):** opt-in por objetivo, GET/HEAD, determinista; **nunca** contra la pila propia (ya tumbó el backend una vez). Corrida incompleta = no reconciliar.
- **Trivy:** `trivy image --quiet --format json`; un fallo de trivy NO es "imagen limpia". `scripts/scan_own_images.py` es idempotente.
- **Documentación viva:** `/api/manual` (uso), `/api/glosario` (términos), `/api/manual/developer`. Al cambiar comportamiento visible, actualiza el manual de uso; al añadir un concepto o motor, el glosario.

## 10. 📋 Lista de chequeo antes de entregar

- [ ] **Autorización:** ¿cada endpoint que muta o toca identidad tiene `@PreAuthorize` (método o clase), sin anotaciones comentadas, y los públicos están declarados a propósito?
- [ ] **Sin controladores de prueba/rutas demo** en `src/main` / router de producción.
- [ ] **Secretos:** ¿cero valores literales en código **y** en `application*.properties|yml`; secreto JWT fuera del repo; rotado si estuvo en git?
- [ ] **Cripto/Tokens:** ¿comparación en tiempo constante, nada de `?token=`, cookies `Secure/HttpOnly/SameSite`, CORS sin `*`?
- [ ] **Datos:** ¿entidades editables con `@Version`, varias escrituras con `@Transactional`, subidas validadas, archivos en streaming?
- [ ] **Contraseñas:** ¿política validada en el servidor (`@Size`/`@Pattern`)?
- [ ] **Servidor/DB/TLS/SO:** SSH sin root ni contraseña, DB con TLS y puerto acotado, TLS ≥ 1.2 con certificado válido, parches de seguridad al día.
- [ ] **IaC/Contenedores:** `USER` no root, imagen con versión, K8s con `readOnlyRootFilesystem`, sin `privileged`.
- [ ] **Frontend:** sanitización antes de renderizar HTML, WCAG (labels, `alt`, `lang`, nombres en botones icono), sin tokens en `localStorage` ni rutas de prueba.
- [ ] **GitLab:** rama por defecto protegida, sin force-push, variables CI enmascaradas, pipeline en MR.
- [ ] **Anti-simulación:** `fix_patch` validado con `git apply --check` (o vacío con "Requiere remediación manual"); SOAR con ejecución real; webhooks fail-closed.
- [ ] **Honestidad del análisis:** procedencia declarada (individual / patrón / heurístico); controles no evaluados como `NO EVALUADO`; sin mocks presentados como producción.
- [ ] **Pruebas:** evidencia de `pytest`/SQL reales sin errores; tests de persistencia con `ROLLBACK` y sin residuos en producción.
- [ ] **Archivos protegidos:** ningún `.docx`/`.zip`/reporte en directorios públicos.

---

## 11. 📚 Catálogo complementario: reglas que Centinela emite y cómo no provocarlas

Complementa las secciones 1–9. Cada fila es un `cve_id` real que emite el código; escribe el código de la columna «Haz esto» y Centinela no tendrá qué reportar.

### 11.1. Código (SAST nativo, `sast-native`)
| Regla | Haz esto |
|---|---|
| `SQL-INJECTION-CONCAT` / `SQL-INJECTION-FSTRING` / `SQL-INJECTION-PERCENT` | Nunca construyas SQL con `+`, f-strings o `%`. Usa parámetros enlazados (`%s`/`?`/`:nombre`) y deja que el driver los pase aparte. |
| `ORM-RAW-QUERY-INJECTION` / `SPRINGBOOT-NATIVE-QUERY-RISK` | En `@Query(nativeQuery=true)` o `.raw()`/`text()` usa parámetros nombrados; jamás concatenes entradas. |
| `ORM-N-PLUS-ONE-QUERY` | Carga relaciones con `JOIN FETCH`/`selectinload`/`prefetch`; no consultes dentro de un bucle. |
| `CMD-INJECTION-OS-SYSTEM` / `CMD-INJECTION-SHELL-TRUE` | `subprocess.run([...], shell=False)` con lista de argumentos; nada de `os.system`. Valida los argumentos contra una lista permitida. |
| `CODE-INJECTION-EVAL` | No uses `eval`/`exec`. Para datos usa `json.loads`/`ast.literal_eval`; para lógica, un diccionario de funciones. |
| `INSECURE-DESERIALIZATION` / `REDIS-JDK-SERIALIZATION` | Nada de `pickle`/`ObjectInputStream`/serialización JDK de fuentes no confiables; usa JSON con esquema. En Redis configura serializador JSON. |
| `XXE-INSECURE-PARSER` | Desactiva DTD y entidades externas (`disallow-doctype-decl`, `defusedxml`). |
| `PATH-TRAVERSAL-RISK` | Resuelve la ruta (`Path.resolve()`), comprueba que quede bajo el directorio base y rechaza `..`; no uses nombres de archivo del usuario sin normalizar. |
| `SSRF-UNCHECKED-FETCH` | Antes de pedir una URL dada por el usuario valida esquema y host contra una lista permitida y bloquea rangos privados/loopback. Una URL con host fijo y solo el path variable no cuenta. |
| `SPRINGBOOT-CSRF-DISABLED` | No llames `csrf().disable()` salvo API sin sesión por cookie; si lo haces, documenta por qué en el mismo archivo. |
| `REACT-DANGEROUSLY-SET-INNER-HTML` | Renderiza texto, o sanitiza con DOMPurify antes de inyectar HTML. |
| `DB-UNENCRYPTED-CONN-STRING` | La cadena de conexión lleva TLS (`sslmode=require`/`ssl=true`) y la contraseña viene del entorno/Vault. |
| `EXPANDED-CLOUD-SECRET` | Ninguna llave de nube en el código: variables de entorno o gestor de secretos. |
| `DOCKER-ROOT-USER` | `USER` no root en el Dockerfile (ver §1.5). |
| `ACCESSIBILITY-WCAG-MISSING-LABEL` | Todo control de formulario con `<label for>`, `aria-label` o el `label` de PrimeNG (§3.4). |
| `FRONTEND-STOMP-DEBUG-LOGGING` | No configures `debug: (s) => console.log(s)` en un cliente STOMP/WebSocket: las tramas llevan el token de sesión. Deja `debug` vacío o actívalo solo en desarrollo local con una bandera que no llegue a QA/producción. |
| `FRONTEND-TOKEN-IN-CONSOLE` | No escribas tokens, contraseñas ni secretos en `console.*` (ni el token decodificado). Registra un indicador («token presente: sí/no»). Elimina los `console.debug` de autenticación antes de entregar. |

### 11.2. Arquitectura Angular/TypeScript (`auditor_arch_rules.py`)
| Regla | Haz esto |
|---|---|
| `ANGULAR-SETTIMEOUT-WORKAROUND` | No uses `setTimeout` para esperar a Angular; usa `ChangeDetectorRef`, `afterNextRender` o signals. |
| `ANGULAR-SUBMIT-NO-BUSY-GUARD` | Deshabilita el botón y bloquea el reenvío mientras la petición está en curso. |
| `ANGULAR-TEMPLATE-METHOD-IN-LOOP` | No llames métodos desde `*ngFor`/`@for`; precalcula con `computed()` o un pipe puro. |
| `TS-EXPLICIT-ANY` | Tipa con interfaces o `unknown`; evita `any`. |

### 11.3. Autorización (`auditor_authz.py`, `auditor_authz_dast.py`)
| Regla | Haz esto |
|---|---|
| `AUTHZ-NO-METHOD-ANNOTATIONS` | Si el proyecto decide por método, cada endpoint lleva `@PreAuthorize` (§2.1). |
| `AUTHZ-ADMIN-BUNDLE-EXPOSED` | El bundle de administración no se sirve a todos: sepáralo o protégelo en el servidor, no solo en la UI. |
| `AUTHZ-CLIENT-SIDE-UI-GATE` | Ocultar un botón no es control de acceso: valida el permiso también en el backend. |
| `AUTHZ-DAST-IDOR` / `AUTHZ-DAST-BROKEN-FUNCTION-LEVEL` | El servidor comprueba propiedad y rol en cada petición, con el identificador tomado del token y no del cuerpo. |
| `AUTHZ-DAST-DENY-LEAKS-BODY` / `AUTHZ-DAST-INCONSISTENT-STATUS` | Una denegación devuelve 401/403 con cuerpo genérico y siempre el mismo código. |

### 11.4. Estándares y calidad
| Regla | Haz esto |
|---|---|
| `STD-STRIDE-JWT-INSECURE-ALG` | Verifica JWT solo con algoritmos asimétricos explícitos (RS256/EdDSA) y nunca `none`/HS256 con llave pública. |
| `STD-STRIDE-LOG-SENSITIVE-DATA` | No interpoles contraseñas, tokens ni PII en logs; registra identificadores, no valores. |
| `CMMI-CAR-SWALLOWED-EXCEPTION` | Nada de `except: pass`; registra la traza o relanza. |
| `CMMI-MSR-HARDCODED-SLEEP` | No uses `sleep` fijo para sincronizar; espera una condición o evento. |
| `CMMI-PQA-DEBT-TODO` | No dejes `TODO`/`FIXME` en la entrega; ábrelo como tarea. |

### 11.5. Infraestructura como código y CI
| Regla | Haz esto |
|---|---|
| `K8S-PRIVILEGED-CONTAINER`, `K8S-RUN-AS-ROOT`, `K8S-PRIVILEGE-ESCALATION`, `K8S-WRITABLE-ROOT-FS`, `K8S-HOSTPATH-MOUNT`, `K8S-AUTOMOUNT-TOKEN` | `securityContext`: `privileged:false`, `runAsNonRoot:true`, `allowPrivilegeEscalation:false`, `readOnlyRootFilesystem:true`; sin `hostPath`; `automountServiceAccountToken:false` si no se usa la API. |
| `TF-PUBLIC-S3-BUCKET`, `TF-OPEN-SECURITY-GROUP`, `TF-ADMIN-PORT-WORLD-OPEN` | Buckets privados con bloqueo de acceso público; reglas de red con orígenes concretos; SSH/RDP/DB nunca a `0.0.0.0/0`. |
| `CSPM-AWS-IAM-WILDCARD`, `CSPM-IAM-OVERPRIVILEGED-WILDCARD` | Políticas IAM con acciones y recursos concretos, sin `*`. |
| `CICD-CURL-PIPE-SHELL` | Descarga, verifica el hash y ejecuta; nunca `curl … \| sh`. |
| `CICD-UNPINNED-IMAGE` | Imagen con versión o digest fijo, no `latest`. |
| `CICD-HARDCODED-SECRET` | Secretos como variables de CI enmascaradas y protegidas. |
| `CICD-DOCKER-PRIVILEGED` | Evita `privileged: true`; usa Kaniko/BuildKit sin privilegios. |
| `CICD-TLS-VERIFICATION-DISABLED` | No desactives la verificación TLS (`-k`, `verify=False`, `GIT_SSL_NO_VERIFY`). |
| `CICD-REMOTE-INCLUDE-INSECURE` | Los `include:` remotos solo por HTTPS y a una versión fija. |
| `GITLAB-PROJECT-BRANCH-FORCE-PUSH` / `GITLAB-PROJECT-BRANCH-DEVELOPER-PUSH` | Rama por defecto protegida, sin force-push y con push solo de mantenedores. |
| `GITLAB-PROJECT-CI-VARIABLE-UNMASKED` / `GITLAB-PROJECT-CI-VARIABLE-UNPROTECTED` | Marca las variables sensibles como enmascaradas y protegidas. |
| `GITLAB-PROJECT-MR-NO-PIPELINE-GATE` | Exige pipeline verde para fusionar. |
| `GITLAB-PROJECT-WEBHOOK-INSECURE` | Webhooks con HTTPS, secreto y verificación TLS. |
| `GITLAB-PROJECT-PUBLIC-VISIBILITY` | Proyectos internos o privados, salvo decisión expresa. |

### 11.6. Configuración perimetral que Centinela prueba en vivo (`wstg-perimeter`)
Configura el servidor/proxy así y las pruebas no encuentran nada:
- **Transporte:** todo por HTTPS, HSTS completo (`max-age` ≥ 1 año, `includeSubDomains`), sin formulario de login por HTTP (`WSTG-ATHN-02-CLEARTEXT-LOGIN`, `WSTG-CRYP-03-UNENCRYPTED-CHANNEL`, `WSTG-CONF-07-INCOMPLETE-HSTS`).
- **Cabeceras:** `X-Frame-Options`/`frame-ancestors` único y estricto (`WSTG-CLNT-09`), sin `Server`/`X-Powered-By` con versión (`WSTG-INFO-02`, `WSTG-INFO-08`).
- **Cookies:** `Secure`, `HttpOnly`, `SameSite` (`WSTG-SESS-02`).
- **CORS:** orígenes explícitos, nunca `*` con credenciales (`WSTG-CLNT-07`).
- **Host y redirecciones:** valida `Host`/`X-Forwarded-Host` contra una lista y las redirecciones contra rutas propias (`WSTG-INPV-17`, `WSTG-CLNT-04`).
- **Métodos:** solo los necesarios; `TRACE`/`CONNECT` desactivados (`WSTG-CONF-06`).
- **Errores y archivos:** errores genéricos sin traza (`WSTG-ERRH-01`); sin `.git`, `.env`, copias ni endpoints de depuración (`WSTG-CONF-04`, `WSTG-CONF-05`).
- **Credenciales por defecto:** cámbialas antes de publicar (`WSTG-AUTH-02`).

### 11.7. Licencias y gobierno de IA
| Regla | Haz esto |
|---|---|
| `SCA-LICENSE-NETWORK-COPYLEFT` (AGPL) / `SCA-LICENSE-STRONG-COPYLEFT` (GPL) / `SCA-LICENSE-RESTRICTED` / `SCA-LICENSE-UNKNOWN` | Elige dependencias con licencia permisiva (MIT/Apache/BSD) o documenta la decisión legal; no dejes paquetes sin licencia. |
| `OWASP-LLM01-PROMPT-INJECTION` | Separa instrucciones de datos del usuario, valida la salida y nunca ejecutes lo que devuelve el modelo. |
| `OWASP-LLM02-PII-PROMPT-LEAK` | No envíes PII ni secretos en prompts; redáctalos antes (en Centinela, `core/prompt_redaction.py`). |
| `OWASP-LLM06-EXCESSIVE-AGENCY` | Las acciones del agente pasan por una lista permitida y por aprobación humana cuando son destructivas. |

---

## 12. 🔄 Cambios de plataforma que afectan a quien desarrolla (actualizado 14-oct-2026)
- **Sin nombres de organización en el código.** Vault, contenedores, llave SSH, IdP, URL pública y marca se leen de variables de entorno mediante `core/org_config.py` (`VAULT_NAMESPACE`, `WAZUH_MANAGER_CONTAINER`, `AUTHENTIK_URL`, `CENTINELA_PUBLIC_URL`, `REPORT_ORG_NAME`…). No escribas un nombre de empresa, host o dominio en el código, documentación o pruebas: `tests/test_no_org_names.py` y el gate de la release pública lo rechazan.
- **Tickets sin credenciales literales.** `core/ticketing.py` solo lee `REDMINE_*` o `GITEA_*` del entorno; sin configurar, el endpoint responde 503. Prohibido dejar usuario o contraseña por defecto.
- **Medusa retirado.** La configuración insegura de Dockerfile/Kubernetes/Terraform la cubre `trivy-config` (`TRIVY-<ID>`); no cites a Medusa en documentación.
- **Política de datos hacia proveedores de IA** (`core/ai_data_policy.py`): cada proveedor tiene una clase máxima (`PUBLIC`/`INTERNAL`/`CLIENT_CODE`); un prompt con código del cliente no llega a un proveedor restringido. **Guardia de inyección** (`core/prompt_guard.py`): texto con instrucciones al modelo dentro del código analizado impide que ese análisis baje la severidad.
- **Reglas informativas de estándares** (`auditor_standards_rules.py`): `SWALLOWED-ERROR`, `DESTRUCTIVE-ACTION-NO-CONFIRM`, `NATIVE-BROWSER-DIALOG`, `SQL-TABLE-WITHOUT-PRIMARY-KEY`, `CICD-GATE-ALLOW-FAILURE`, `TEST-SKIPPED-WITHOUT-REASON`, las del estándar de base de datos (`SQL-PK-NOT-UUID`, `SQL-TIMESTAMP-WITHOUT-TIMEZONE`, `SQL-JSON-NOT-JSONB`, `SQL-FLOAT-FOR-MONEY`, `SQL-TABLE-WITHOUT-AUDIT-COLUMNS`), las convenciones del Starter (`TRANSACTIONAL-ON-CONTROLLER`, `FIELD-INJECTION-AUTOWIRED`, `JPA-OBJECT-ARRAY-RESULT`, `FRONTEND-HARDCODED-API-URL`), más `VALIDATION-REIMPLEMENTED`. Se evitan así: registrar o relanzar toda excepción, confirmar acciones destructivas con un diálogo propio, toda tabla con clave primaria, compuertas de CI que fallan de verdad y pruebas omitidas con motivo; para RFC/CURP usa la librería de validación compartida, no regex propios.
- **Linaje del Starter** (`auditors/starter_lineage.py`): un hallazgo en un archivo idéntico a la plantilla se corrige **una vez en el Starter**, no en cada proyecto. Quita del proyecto los archivos de demostración de la plantilla (`product.service.ts`, `crud.ts`, `uikit/*`).
- **Preflight** (`GET /api/preflight`, `GET /api/checklist-evidence/{activo}`): comprueban si este despliegue puede ejecutar cada motor y qué evidencia existe; «sin hallazgos» no es «limpio» si el motor no corrió.
- **El activo GitLab lleva la rama** (`GitLab[N]/<ruta>@<rama>`); no construyas nombres de activo a mano (`core/gitlab_instances.py`).
- **Pruebas:** solo con `scripts/run_tests.sh` (base desechable). Una prueba destructiva nunca hereda su destino del entorno de la aplicación.
- **Publicación:** la release pública se construye con `scripts/build_public_release.py` (gates de IPs, secretos, nombres de organización y de clientes); nada se publica sin que pasen.

### 12.1. Contrato de generación: antes de escribir código con IA
1. Identifica el stack (Spring, Angular/React, FastAPI, SQL, Docker/CI) y aplica de memoria las secciones 2–4 y 11 correspondientes.
2. Escribe la prueba primero con un caso que debe fallar y otro que debe pasar (como en cada regla de Centinela).
3. Al terminar, **ejecuta el escáner sobre tus cambios** (ver el plan ADR-0013, fase 1: `scripts/scan_working_tree.py`) y corrige hasta cero hallazgos nuevos; si no puedes ejecutarlo, declara «no verificado por Centinela».
4. Entrega en el formato de la sección 10 con el log real de las pruebas.

`GITLAB-CONFIG-AUDIT` es el marcador de que la auditoría de GitLab corrió (no es un defecto). `PROWLER-CHECK` son hallazgos de Prowler sobre cuentas de nube: se corrigen en la configuración de la cuenta, no en el código.

### 11.8. Identificadores completos de lo que Centinela prueba en despliegues y contratos
**WSTG perimetral** (lo que se corrige en el servidor/proxy, ver 11.6): `WSTG-AUTH-02-DEFAULT-CREDENTIALS` (cambia credenciales por defecto), `WSTG-CLNT-04-OPEN-REDIRECT` (valida destinos de redirección), `WSTG-CLNT-07-INSECURE-CORS` (orígenes explícitos), `WSTG-CLNT-09-DUPLICATE-OR-WEAK-FRAME-OPTIONS` (una sola política de marcos), `WSTG-CONF-04-SENSITIVE-FILES` (sin `.git`/`.env`/copias), `WSTG-CONF-05-DEBUG-ENDPOINTS` (sin consolas de depuración), `WSTG-CONF-06-DANGEROUS-HTTP-METHOD` (sin `TRACE`/`CONNECT`), `WSTG-ERRH-01-VERBOSE-BACKEND-ERROR` y `WSTG-ERRH-01-API-SERVER-ERROR` (errores genéricos, nunca 5xx ante entradas válidas ni trazas), `WSTG-INFO-02-SERVER-BANNER-LEAK` (sin versión en `Server`), `WSTG-INFO-08-FRAMEWORK-FINGERPRINT` (sin `X-Powered-By`), `WSTG-INPV-17-HOST-HEADER-INJECTION` (lista de hosts permitidos), `WSTG-SESS-02-COOKIE-SAMESITE` (`SameSite` en cookies de sesión).

**Contrato y superficie de la API:**
| Regla | Haz esto |
|---|---|
| `API-CONTRACT-MISMATCH` | La especificación OpenAPI y el código describen los mismos parámetros y respuestas; genera una desde la otra. |
| `API-CONTRACT-ROUTE-NOT-IMPLEMENTED` | No documentes rutas que el código no implementa. |
| `API-SHADOW-ENDPOINT` | Toda ruta que existe en el código está documentada en OpenAPI, o se elimina. |

**Nube y Kubernetes en cuentas vivas (CSPM):** `CSPM-AWS-S3-PUBLIC` y `CSPM-AWS-S3-PUBLIC-READ` (buckets sin acceso público ni ACL `public-read`), `CSPM-K8S-PRIVILEGED-CONTAINER` y `CSPM-K8S-PRIVILEGED-POD` (`privileged:false`).

**DNS y correo del dominio** (se corrige en la zona DNS, no en el código):
| Regla | Haz esto |
|---|---|
| `DNS-SPF-MISSING`, `DNS-SPF-MULTIPLE`, `DNS-SPF-PERMISSIVE`, `DNS-SPF-SOFTFAIL`, `DNS-SPF-TOO-MANY-LOOKUPS` | Un único registro SPF, que termine en `-all`, con 10 consultas DNS como máximo. |
| `DNS-DMARC-MISSING`, `DNS-DMARC-MONITOR-ONLY`, `DNS-DMARC-PARTIAL` | DMARC publicado con `p=quarantine` o `p=reject` y `pct=100`. |
| `DNS-MTASTS-MISSING` | Publica MTA-STS para forzar TLS en el correo entrante. |
| `DNS-CAA-MISSING` | Registro CAA que limite qué autoridades emiten certificados. |
| `DNS-DNSSEC-NOT-ENABLED` | Activa DNSSEC en la zona. |

**Marcadores, no defectos** (indican que un motor corrió o etiquetan una categoría): `CIS-BENCHMARK-AUDIT`, `OS-PATCH-AUDIT`, `TLS-AUDIT`, `DNS-SECURITY-AUDIT`, `CMMI-GIT-HISTORY-CHECK`, `SONARQUBE-QUALITY-GATE`, `TRIVY-REPO`, `ZAP-ZAP-UNKNOWN`, `ISO25010-MAINTAINABILITY`, `STRIDE-SPOOFING`, `STRIDE-REPUDIATION`, `STRIDE-INFO-DISCLOSURE`.


### 11.9. Lo que Centinela observa con una sesión real de QA (motor `runtime-session`) y en la configuración
Con credenciales de prueba por perfil guardadas en Vault (botón «Perfiles» del inventario), Centinela inicia sesión en un navegador y revisa lo que un usuario vería en las herramientas de desarrollo. Se evita así:
| Regla | Haz esto |
|---|---|
| `RUNTIME-TOKEN-IN-CONSOLE` | Ningún `console.*` ni depuración de STOMP/WebSocket imprime el token (ver `FRONTEND-STOMP-DEBUG-LOGGING` y `FRONTEND-TOKEN-IN-CONSOLE`). |
| `RUNTIME-PII-IN-RESPONSE` | Un perfil recibe solo los datos personales que le corresponden: filtra por unidad/rol/propietario en el servidor y devuelve DTO con los campos mínimos (nada de CURP o RFC ajenos). |
| `RUNTIME-AUTH-ERRORS` | El refresco del token debe ser estable: la renovación ocurre antes de que venza, con un solo reintento y cierre de sesión ordenado; no repitas llamadas que devuelven 401/403. |
| `RUNTIME-SERVER-ERRORS` | Ninguna pantalla de uso normal debe provocar un 5xx. |
| `RUNTIME-TOKEN-IN-STORAGE` | Prefiere cookies `HttpOnly; Secure; SameSite`; si el token va en `localStorage`, vida corta y rotación. |
| `RUNTIME-SESSION-NOT-EXERCISED` | Marcador: el inicio de sesión de prueba falló y no se auditó nada tras él; revisa URL, campos y credencial. |
| `DEPENDENCY-UNREACHABLE` | Todo servicio externo escrito en la configuración (editor de documentos, firma, base de datos, correo) debe estar en pie en el ambiente donde se prueba; si ya no se usa, quítalo de la configuración. |
Además, `AUTHZ-NO-METHOD-AUTHZ` sube a **CRÍTICO** cuando un endpoint de lectura que devuelve datos de personas (usuarios, servidores públicos, CURP, RFC, correo) carece de autorización por método: añade `@PreAuthorize` con el permiso de ese recurso y valida la unidad/propietario del dato.
