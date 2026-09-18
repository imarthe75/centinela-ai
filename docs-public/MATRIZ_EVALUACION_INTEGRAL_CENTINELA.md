# 🏛️ Matriz de Evaluación Integral de Centinela AI: Infraestructura y Código Fuente

Esta matriz constituye la referencia técnica exhaustiva de todas las reglas, vectores de ataque, estándares internacionales y comprobaciones automatizadas que la plataforma **Centinela AI** evalúa en tiempo continuo.

---

# PARTE I: EVALUACIÓN DE INFRAESTRUCTURA Y RUNTIME

## 1. Hardening de Servidores Linux (CIS Benchmarks Level 1)
Evaluado por el motor `auditors/auditor_cis_benchmarks.py` mediante inspección remota vía SSH restringido o agente Wazuh EDR:

| ID de Control | Vector de Evaluación | Parámetro Obligatorio | Riesgo Mitigado / Norma |
| :--- | :--- | :--- | :--- |
| **`CIS-1.1`** | Acceso Root por SSH | `PermitRootLogin no` en `/etc/ssh/sshd_config` | Acceso administrativo directo no auditable (`CWE-250`) |
| **`CIS-1.2`** | Autenticación SSH por Contraseña | `PasswordAuthentication no` (solo llaves ED25519/RSA-4096) | Ataques de fuerza bruta y credential stuffing |
| **`CIS-2.1`** | Permisos de `/etc/passwd` | Máximo permisos `644` (`rw-r--r--`), dueño `root:root` | Modificación no autorizada de cuentas locales (`CWE-732`) |
| **`CIS-2.2`** | Permisos de `/etc/shadow` | Máximo permisos `600` (`rw-------`) o `640`, grupo `shadow` | Extracción de hashes de contraseñas de sistema |
| **`CIS-3.1`** | Política de Longitud de Contraseña | `PASS_MIN_LEN 14` en `/etc/login.defs` | Contraseñas débiles descifrables por diccionario |
| **`CIS-4.1`** | Enrutamiento de Red (IP Forwarding) | `net.ipv4.ip_forward = 0` en `sysctl.conf` | Servidor utilizado como pivote o router no autorizado |
| **`CIS-5.1`** | Cuentas sin Contraseña | Sin campos de hash vacíos en `/etc/shadow` | Acceso a shell sin credenciales |
| **`CIS-5.2`** | Demonio de Auditoría | Servicio `auditd` instalado, activo y configurado | Falta de registro de llamadas críticas del sistema (ISO 27001 A.8.15) |
| **`CIS-6.1`** | Desactivación de Core Dumps | `fs.suid_dumpable = 0` y `* hard core 0` en `limits.conf` | Extracción de memoria con secretos tras un crash |
| **`CIS-6.2`** | Cortafuegos de Host | `ufw` o `firewalld` activo con política default deny | Exposición accidental de puertos no gestionados |
| **`CIS-7.1`** | Sincronización de Reloj | Servicio NTP activo (`chrony`, `systemd-timesyncd`) | Desfase temporal que invalida la correlación forense |

---

## 2. Hardening de Bases de Datos (Relacionales, NoSQL y Cachés)
Evaluado por el motor `auditors/auditor_db_hardening.py` contra instancias PostgreSQL, MySQL, MariaDB, Oracle, MSSQL, Redis, Valkey y MongoDB:

| Código de Hallazgo | Severidad | Tecnología | Regla / Evaluación Técnica |
| :--- | :--- | :--- | :--- |
| **`DB-NO-TLS-ENCRYPTION`** | **CRITICAL** | Todas | El servidor acepta conexiones de clientes sin exigir cifrado SSL/TLS en tránsito (`ssl=on`). Permite intercepción en red (*Man-in-the-Middle*). |
| **`DB-DEFAULT-PORT-EXPOSED`** | **MEDIUM** | Todas | Puertos estándares (`5432`, `3306`, `6379`, `27017`) expuestos hacia redes no confiables (`0.0.0.0/0`) sin filtrado perimetral. |
| **`DB-WEAK-AUTH-SCHEME`** | **HIGH** | PostgreSQL / MySQL | Uso de algoritmos obsoletos de hashing (`md5` o `mysql_native_password`) en lugar de `scram-sha-256` o `caching_sha2_password`. |
| **`REDIS-NO-AUTH`** | **CRITICAL** | Redis / Valkey | Instancia en memoria sin directiva `requirepass` activa. Permite lectura y vaciado de caché por cualquier cliente con alcance de red. |
| **`REDIS-DANGEROUS-COMMANDS`** | **HIGH** | Redis / Valkey | Comandos administrativos no renombrados ni deshabilitados (`FLUSHALL`, `FLUSHDB`, `CONFIG`, `KEYS`). |
| **`DB-SUPERUSER-CONNECTION`** | **HIGH** | PostgreSQL | Aplicaciones conectadas utilizando el usuario administrativo `postgres` en lugar de un rol de mínimo privilegio específico para el servicio. |

---

## 3. Infraestructura como Código (IaC) y Contenedores
Evaluado por `auditors/auditor_iac_k8s.py`, Checkov y Trivy sobre manifiestos Kubernetes (`.yaml`), Terraform (`.tf`) y `Dockerfile`:

| Código de Regla | Ámbito | Evaluación Técnica |
| :--- | :--- | :--- |
| **`DOCKER-ROOT-USER`** / **`DOCKER-MISSING-NON-ROOT-USER`** | Dockerfile | El contenedor no declara directiva `USER` o ejecuta explícitamente como `USER root` / `USER 0`. Permite escape de contenedor con privilegios root. |
| **`K8S-PRIVILEGED-CONTAINER`** | Kubernetes | Contenedor con `securityContext.privileged: true`. Otorga acceso directo a los dispositivos y kernel del host (`CWE-250`). |
| **`K8S-HOSTPATH-MOUNT`** | Kubernetes | Montaje de volúmenes `hostPath` (`/var/run/docker.sock`, `/etc`, `/`). Permite sobrescritura del sistema anfitrión. |
| **`K8S-WRITABLE-ROOT-FS`** | Kubernetes | Falta de `readOnlyRootFilesystem: true`. Permite a atacantes descargar y ejecutar payloads maliciosos en runtime. |
| **`K8S-AUTOMOUNT-SA-TOKEN`** | Kubernetes | Tokens de cuenta de servicio montados por defecto (`automountServiceAccountToken: true`) facilitando el compromiso del API Server. |
| **`TF-OPEN-SECURITY-GROUP`** | Terraform | Reglas de ingress con `cidr_blocks = ["0.0.0.0/0"]` en puertos administrativos (SSH 22, RDP 3389, DB 5432). |
| **`TF-PUBLIC-S3-BUCKET`** | Terraform | Buckets de almacenamiento con ACL pública (`public-read`, `public-read-write`) o sin bloque de acceso público (`aws_s3_account_public_access_block`). |

---

## 4. Detección de Amenazas en Runtime (EDR, NDR, eBPF & ITDR)

### 4.1. Runtime Host & Containers (Falco eBPF)
* **`Spawned Shell in Container`**: Apertura interactiva de `/bin/sh`, `/bin/bash` dentro de un contenedor en producción.
* **`Read sensitive file untrusted`**: Procesos no autorizados intentando leer `/etc/shadow`, `/root/.ssh` o certificados TLS.
* **`Drop and execute new binary`**: Escritura y ejecución de ejecutables en directorios temporales (`/tmp`, `/dev/shm`).

### 4.2. Detección de Red (Zeek NDR)
* **Análisis Continuo `conn.log`**: Inspección de cada flujo IP de origen/destino contrastado en tiempo real con Feodo Tracker y feeds de CTI para detectar beaconing hacia servidores Command & Control (C2).
* **`notice.log`**: Escaneos de puertos (*Port Scanning*), inundación SYN y anomalías de protocolos TLS/HTTP.

### 4.3. Detección en Endpoint (Wazuh EDR)
* **Integridad de Archivos (FIM / Syscheck)**: Modificación no autorizada de binarios del sistema en `/usr/bin`, `/usr/sbin`.
* **Escalación de Privilegios**: Ejecución no autorizada de `sudo` o explotación de vulnerabilidades de kernel.
* **Fuerza Bruta**: Fallos reiterados de autenticación SSH, PAM o RDP.

### 4.4. Detección de Amenazas de Identidad (Authentik ITDR)
* **`ITDR-PASSWORD-SPRAY`**: Múltiples intentos de inicio de sesión con una misma contraseña contra diversas cuentas.
* **`ITDR-IMPOSSIBLE-TRAVEL`**: Inicios de sesión exitosos desde coordenadas geográficas distantes en intervalos de tiempo físicamente imposibles.
* **`ITDR-BRUTE-FORCE`**: Intentos repetidos sobre una cuenta específica que exceden el umbral de bloqueo.

---

# PARTE II: EVALUACIÓN DE CÓDIGO FUENTE (SAST, SCA, DAST)

## 1. Análisis Estático de Seguridad de Código (SAST Nativo)
Evaluado por `auditors/auditor_master_vulnerabilities.py` y Semgrep:

| Categoría CWE | Regla Centinela | Descripción Técnica de Detección |
| :--- | :--- | :--- |
| **`CWE-89` (SQL Injection)** | `SQL-INJECTION-CONCAT` | Concatenación de cadenas o formateo f-string dentro de llamadas de consulta SQL (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) en lugar de parámetros bind. |
| **`CWE-78` (Command Injection)** | `CMD-INJECTION-SHELL-TRUE` / `COMMAND-INJECTION` | Invocación de `subprocess.Popen/run/call(..., shell=True)`, `os.system()`, `Runtime.getRuntime().exec()` o `exec()` con variables dinámicas. |
| **`CWE-502` (Insecure Deserialization)** | `INSECURE-DESERIALIZATION-PYTHON` / `INSECURE-DESERIALIZATION-YAML` | Uso de `pickle.loads()`, `marshal.loads()`, `yaml.load()` (sin `SafeLoader`) o deserializadores no tipados de Node.js/Java. |
| **`CWE-22` (Path Traversal)** | `PATH-TRAVERSAL-PYTHON` / `PATH-TRAVERSAL-JAVA` / `PATH-TRAVERSAL-NODE` | Apertura de archivos concatenando entradas de usuario (`open(user_path)`, `new File(path)`) sin validación de `os.path.realpath` y directorio base. |
| **`CWE-798` (Hardcoded Secrets)** | `SECRETS-EXTENDED-*` (AWS, GCP, Vault, GitHub, GitLab, Slack, Stripe, Private Keys) | Entropía y patrones regex de tokens de API, credenciales en código, llaves RSA privadas y tokens administrativos. |
| **`CWE-327` (Weak Cryptography)** | `WEAK-CRYPTO-*` | Algoritmos obsoletos o rotos: MD5 (`hashlib.md5`), SHA-1 (`hashlib.sha1`), DES (`Cipher.getInstance("DES")`), RC4 y modo ECB en AES. |
| **`CWE-611` (XXE - XML External Entity)** | `XXE-XML-PARSER-*` | Parsers XML (`lxml`, `etree`, `DocumentBuilderFactory`) configurados con resolución de entidades externas activa sin `resolve_entities=False`. |
| **`CWE-352` / `CWE-693` (Misconfigurations)** | `CSRF-PROTECTION-DISABLED` / `HELMET-CSP-DISABLED` | Desactivación explícita de protecciones en frameworks (`http.csrf().disable()` en Spring Security, desactivación de CSP en Express Helmet). |
| **`CWE-532` (Sensitive Data Logging)** | `INSECURE-LOGGING-PASSWORD` | Emisión de variables que contienen `password`, `token`, `secret` o `api_key` hacia logs o consola estándar. |

---

## 2. Análisis de Composición de Software (SCA)
Evaluado por `auditors/auditor_sca_dependencies.py`:
* **Ecosistemas Analizados**:
  * Python: `requirements.txt`, `Pipfile`, `pyproject.toml`.
  * Node.js: `package.json`, `package-lock.json`.
  * Java: `pom.xml`, `build.gradle`.
  * Go: `go.mod`.
  * PHP: `composer.json`.
* **Métricas Correlacionadas**:
  * Base de datos OSV (Open Source Vulnerabilities) y National Vulnerability Database (NVD).
  * Puntuación **CVSS v3.1** (Base, Temporal y Ambiental).
  * Probabilidad de Explotación en Vivo (**EPSS** - *Exploit Prediction Scoring System*).
  * Catálogo **CISA KEV** (*Known Exploited Vulnerabilities*) que confirma explotación activa en el mundo real.

---

## 3. Autorización Dinámica DAST (BOLA / IDOR / BFLA)
Evaluado por `auditors/auditor_authz_dast.py`:
* **`AUTHZ-DAST-BROKEN-FUNCTION-LEVEL` (`CRITICAL`)**: Un token con rol estándar (`ROLE_USER` o `conciliador`) obtiene respuesta `200 OK` con datos sensibles en endpoints catalogados como de uso exclusivo administrativo (`/admin/*`, `/usuarios`, `/roles`).
* **`AUTHZ-DAST-IDOR` (`HIGH`)**: Alteración de identificadores en rutas dinámicas (`/api/expedientes/{id}`) donde un usuario puede consultar registros que pertenecen a otro usuario sin que el backend verifique la relación de propiedad.
* **`AUTHZ-DAST-DENY-LEAKS-BODY` (`MEDIUM`)**: Endpoints que responden `401 Unauthorized` o `403 Forbidden` pero devuelven en el cuerpo JSON información del sistema, trazas de excepción o datos de configuración.

---

## 4. Accesibilidad Web (WCAG 2.1 Nivel AA)
Evaluado por `auditors/auditor_accessibility_wcag.py` sobre templates HTML, JSX, TSX y vistas web:
* **`WCAG-IMAGE-ALT-MISSING`**: Etiquetas `<img>` carentes del atributo descriptivo `alt`.
* **`WCAG-FORM-LABEL-MISSING`**: Campos de entrada (`<input>`, `<select>`, `<textarea>`) sin etiquetas asociadas (`<label for="...">`) o `aria-label`.
* **`WCAG-LINK-DISCERNIBLE-TEXT`**: Enlaces vacíos o que solo contienen iconos sin texto accesible para lectores de pantalla.
* **`WCAG-DOCUMENT-LANG-MISSING`**: Elemento `<html>` sin declaración de idioma (`lang="es"`).

---

## 5. Calidad de Código, Concurrencia y Arquitectura (ISO 25010 & CMMI v3.0)

* **Antipatrón ORM N+1 (`ORM-N-PLUS-ONE-QUERY`)**:
  Detección de bucles (`for`/`while`) que ejecutan consultas SQL o llamadas `.get()` / `.filter()` por cada iteración sobre colecciones en lugar de utilizar `select_related`, `prefetch_related` o `JOINs` agregados.
* **Complejidad Ciclomática y Cognitiva**:
  Límite estricto de $\le 10$ por función para garantizar testeabilidad, bajo acoplamiento y legibilidad.
* **Control de Concurrencia Optimista**:
  Entidades de negocio en JPA o bases relacionales deben incluir campos `@Version` para prevenir sobreescrituras perdidas (*Lost Updates*) en accesos concurrentes.
* **Retención de Conexiones DB**:
  Prohibición de mantener transacciones de base de datos abiertas durante I/O bloqueante (llamadas HTTP externas a microservicios o proveedores de IA).
* **Evaluación de Áreas de Práctica CMMI v3.0**:
  * **CAR** (*Causal Analysis and Resolution*): Registro histórico y remediación de causas raíz.
  * **PQA** (*Process and Quality Assurance*): Cumplimiento de Quality Gates en pipelines CI/CD.
  * **CM** (*Configuration Management*): Trazabilidad estricta de cambios mediante ramas `centinela-fix` y Merge Requests firmados.
  * **MC** (*Measurement and Analysis*): Métricas MTTD (Mean Time to Detect) y MTTC (Mean Time to Contain).
  * **VV** (*Verification and Validation*): Validación automatizada de código mediante suites de pruebas antes del paso a producción.
