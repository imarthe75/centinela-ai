# 🛡️ Guía Maestra de Auditoría y Evaluación Profunda: Centinela AI Omni-XDR

Este documento detalla exhaustivamente **todo lo que evalúa Centinela AI**, tanto en la infraestructura física/virtual/cloud como en el código fuente de las aplicaciones del ecosistema (**SETAG**, **SIDECO**, **SIAT**, **Kardex**, **Starters**).

---

## 🏛️ 1. EVALUACIÓN DE INFRAESTRUCTURA Y SISTEMA OPERATIVO

### 1.1. Escáner CIS Linux Benchmarks (`auditors/auditor_cis_benchmarks.py`)
Inspecciona servidores Linux (Ubuntu, Debian, RHEL, CentOS) mediante comandos de solo lectura sobre SSH:

- **SSH Hardening (`CIS-1.1`, `CIS-1.2`):**
  - Acceso `root` deshabilitado (`PermitRootLogin no` en `/etc/ssh/sshd_config`).
  - Autenticación por contraseña deshabilitada (`PasswordAuthentication no`, uso exclusivo de llaves SSH).
- **Permisos de Archivos del Sistema (`CIS-2.1`, `CIS-2.2`):**
  - `/etc/passwd`: Máximo `644` (`rw-r--r--`). Prohibida la escritura para otros usuarios.
  - `/etc/shadow`: Máximo `600` (`rw-------`) o `640` (`rw-r-----`). Prohibida la lectura a terceros.
- **Políticas de Cuentas y Contraseñas (`CIS-3.1`, `CIS-5.1`):**
  - Longitud mínima de contraseña >= 14 (`PASS_MIN_LEN 14` en `/etc/login.defs`).
  - Cero cuentas locales con contraseñas vacías en `/etc/shadow`.
- **Hardening de Red y Kernel (`CIS-4.1`, `CIS-6.1`, `CIS-6.2`):**
  - Estado del firewall activo (`ufw` o `firewalld` en estado `active`).
  - IP Forwarding deshabilitado (`sysctl -n net.ipv4.ip_forward` debe ser `0`).
  - Core Dumps restringidos (`sysctl -n fs.suid_dumpable` debe ser `0`).
- **Auditoría y Sincronización Horaria (`CIS-5.2`, `CIS-7.1`):**
  - Demonio `auditd` activo.
  - Sincronización NTP activa (`chrony`, `ntp` o `systemd-timesyncd`).

---

### 1.2. Escáner de Hardening de Bases de Datos (`auditors/auditor_db_hardening.py`)
Inspecciona instancias relacionales (PostgreSQL, MySQL, Oracle, MSSQL), NoSQL (MongoDB, Neo4j) y cachés (Redis, Valkey):

- **Cifrado SSL/TLS en Tránsito (`DB-NO-TLS-ENCRYPTION`):** Exigencia de cifrado SSL para todas las conexiones entrantes de clientes.
- **Aislamiento de Puertos (`DB-DEFAULT-PORT-EXPOSED`):** Verificación de restricción de puertos predeterminados (`5432`, `3306`, `27017`, `6379`, `7687`) a nivel de Security Group o Firewall local (permitiendo únicamente IPs privadas/VPN).

---

### 1.3. Escáner de Infraestructura como Código e Imágenes Docker (`auditors/auditor_iac_k8s.py` & Dockerfile)

- **Kubernetes Hardening (`.yaml` / `.yml`):**
  - `K8S-PRIVILEGED-CONTAINER`: Prohibición de `privileged: true` (evita escape del contenedor al host).
  - `K8S-HOSTPATH-MOUNT`: Prohibición de volúmenes `hostPath` directos al sistema de archivos del servidor.
  - `K8S-WRITABLE-ROOT-FS`: Exigencia de `readOnlyRootFilesystem: true`.
  - `K8S-AUTOMOUNT-TOKEN`: Verificación de `automountServiceAccountToken: false`.
  - `K8S-PRIVILEGE-ESCALATION`: Prohibición de `allowPrivilegeEscalation: true`.
  - `K8S-RUN-AS-ROOT`: Exigencia de `runAsNonRoot: true` y restricción de `runAsUser: 0`.
- **Terraform Hardening (`.tf`):**
  - `TF-OPEN-SECURITY-GROUP`: Detección de `0.0.0.0/0` en reglas de ingress de Security Groups.
  - `TF-PUBLIC-S3-BUCKET`: Detección de buckets S3 con ACL `public-read` o `public-read-write`.
  - `TF-ADMIN-PORT-WORLD-OPEN`: Bloqueo de exposición mundial de puertos administrativos (SSH 22, RDP 3389, DB 5432/3306).
- **Dockerfile Hardening:**
  - `DOCKER-ROOT-USER`: Prohibición de ejecución implícita o explícita como usuario `root` (`USER 0`).
  - `DOCKER-MISSING-NON-ROOT-USER`: Exigencia de directiva `USER appuser` o `USER nonroot`.
  - `DOCKER-UNPINNED-BASE-IMAGE`: Detección de imágenes base con etiqueta inestable `:latest`.

---

### 1.4. Telemetría de Runtime e eBPF (`falcosidekick` & Wazuh EDR)
- **Falco Kernel Events:** Detección en tiempo real de lectura de archivos sensibles (`/etc/shadow`), ejecución de shells dentro de contenedores y binarios no autorizados.
- **Wazuh EDR:** Detección de escalación de privilegios `sudo`, logins anómalos e intentos de modificación de binarios en `/usr/bin`.

---

## 💻 2. EVALUACIÓN DE CÓDIGO FUENTE Y LÓGICA DE NEGOCIO

### 2.1. Escáner SAST Nativo (`auditors/auditor_master_vulnerabilities.py`)
Soporta análisis AST y sintáctico en Python, Java, JavaScript, TypeScript, HTML, XML, Properties y Shell scripts:

- **Inyecciones de Código y Comandos (`CWE-89`, `CWE-78`, `CWE-94`):**
  - SQL Injection via f-strings (`SQL-INJECTION-FSTRING`), formateo `%` sin tupla (`SQL-INJECTION-PERCENT`) o concatenación (`SQL-INJECTION-CONCAT`).
  - ORM Raw Query Injection (`ORM-RAW-QUERY-INJECTION`) en SQLAlchemy, Django ORM y Sequelize.
  - Command Injection en `subprocess(..., shell=True)` y `os.system()`.
  - Dynamic Code Execution via `eval()`.
- **Deserialización Insegura & XXE (`CWE-502`, `CWE-611`):**
  - `INSECURE-DESERIALIZATION`: `pickle.loads()`, `marshal.loads()`, `yaml.load()` desprotegido.
  - `XXE-INSECURE-PARSER`: Parsers XML `DocumentBuilderFactory` / `ElementTree` sin protección DTD.
- **Seguridad en Web & Servidores (`SSRF`, `CSRF`, `Path Traversal`, `CWE-327`):**
  - `SSRF-UNCHECKED-FETCH`: Peticiones HTTP a hosts interpolados dinámicamente.
  - `PATH-TRAVERSAL-RISK`: Apertura de archivos usando rutas dinámicas sin canonicalización.
  - `SPRINGBOOT-CSRF-DISABLED`: Desactivación explícita de CSRF en Spring Security.
  - `WEAK-CRYPTOGRAPHY`: Uso de `MD5`, `SHA-1` o modo `AES/ECB`.
- **Calidad de Código y Complejidad:**
  - `COGNITIVE-COMPLEXITY-EXCEEDED`: Funciones Python con complejidad cognitiva > 15.
  - `ORM-N-PLUS-ONE-QUERY`: Detección multilínea de consultas SQL ejecutadas dentro de bucles `for`.

---

### 2.2. Escáner de Secretos y Credenciales (`auditors/auditor_secrets.py`)
Inspección basada en expresiones regulares y análisis de entropía de Shannon:

- **Tolerancia Cero a Llaves y Credenciales:**
  - AWS Access Keys (`AKIA...`), AWS Secret Keys.
  - Llaves Privadas RSA (`-----BEGIN RSA PRIVATE KEY-----`) y OpenSSH.
  - Tokens PAT de GitHub (`ghp_`), GitLab (`glpat-`) y HashiCorp Vault (`hvs.`).
  - Credenciales de cuentas de servicio GCP (`"type": "service_account"`).
  - Cadenas de conexión DB con contraseñas explícitas (`mongodb+srv://user:pass@...`, `postgres://user:pass@...`).

---

### 2.3. Blindaje RBAC, Broken Access Control & BOLA (`auditors/auditor_authz.py` & `auditor_authz_dast.py`)

- **Análisis Estático (SAST):**
  - Cobertura 100% `@PreAuthorize` en métodos de controladores Spring Boot y endpoints FastAPI.
  - Detección de controladores Sandbox/Test desplegados en producción (`LocalAuthController`, `TestSandboxController`).
  - Detección de deshabilitación global de SSL en la JVM (`TrustAllManager`, `NullHostnameVerifier`).
  - Detección de transmisión de JWT en parámetros de URL (`?token=...`).
  - Detección de serialización predeterminada Redis vulnerable (`JdkSerializationRedisSerializer`).
  - Detección de arreglos `byte[]` en memoria para lectura de archivos grandes (`OOM-BYTE-ARRAY-STREAMING`).
- **Pruebas Activas Multi-Rol (DAST):**
  - `AUTHZ-DAST-BROKEN-FUNCTION-LEVEL`: Un rol no administrador recibe respuesta HTTP `2xx` en rutas exclusivas de administración.
  - `AUTHZ-DAST-IDOR` / `BOLA`: Variación de parámetros `{id}` de ruta entre cuentas para verificar acceso cruzado a datos.
  - `AUTHZ-DAST-DENY-LEAKS-BODY`: Respuestas `401`/`403` que filtran payloads sustanciales en el cuerpo de la respuesta.

---

### 2.4. Escáner SCA de Dependencias (`auditors/auditor_sca_dependencies.py`)
Inspección de archivos de manifiesto (`pom.xml`, `package.json`, `requirements.txt`, `go.mod`, `composer.json`):

- **Filtro de Alcance (*Reachability*):** Distinción entre librerías declaradas y paquetes efectivamente importados en el código.
- **Resolución de Versiones Heredadas:** Extracción automática de versiones heredadas desde `<parent>` en Maven `pom.xml`.

---

### 2.5. Accesibilidad Web y Frontend (`auditors/auditor_accessibility_wcag.py`)
Evaluación de plantillas HTML, componentes Angular/React y vistas JSF/JSP:

- **XSS en DOM:** Detección de `dangerouslySetInnerHTML` (React), `[innerHTML]` (Angular) y sanitización explícita bypassed (`bypassSecurityTrustHtml`).
- **Almacenamiento Inseguro:** Uso de `localStorage.setItem('token')` expuesto a extracción XSS.
- **WCAG 2.1 AA:** Elementos interactivos (`<button>`, `<a>`, `<input>`) sin atributos `aria-label` o `<label for="...">`.

---

## 📊 3. RESUMEN DE MOTORES Y COBERTURA INTEGRAL

| Ámbito | Motor de Auditoría | Archivos / Componentes Evaluados | Norma / Estándar de Referencia |
| :--- | :--- | :--- | :--- |
| **Infraestructura** | `auditor_cis_benchmarks.py` | `/etc/passwd`, `/etc/shadow`, SSH, UFW, Sysctl, Auditd | CIS Level 1 Linux Benchmark |
| **Bases de Datos** | `auditor_db_hardening.py` | PostgreSQL, MySQL, Redis, Valkey, MongoDB, Neo4j | CIS DB Benchmarks / OWASP |
| **IaC & Contenedores** | `auditor_iac_k8s.py` | `Dockerfile`, Kubernetes `.yaml`, Terraform `.tf` | CIS Kubernetes / Checkov |
| **Código SAST** | `auditor_master_vulnerabilities.py` | `.py`, `.js`, `.ts`, `.java`, `.html`, `.xml` | OWASP Top 10 / CWE Top 25 |
| **Secretos** | `auditor_secrets.py` | Código fuente, manifiestos `.env`, `.yml`, `.json` | ISO 27001 / OWASP Secrets |
| **Autorización RBAC/BOLA** | `auditor_authz.py` / `auditor_authz_dast.py` | Controladores Spring Boot, FastAPI, JWT, Vault | OWASP API Top 10 (API1 / API5) |
| **Dependencias SCA** | `auditor_sca_dependencies.py` | `pom.xml`, `package.json`, `requirements.txt` | CVE / EPSS / CISA KEV |
| **Accesibilidad** | `auditor_accessibility_wcag.py` | Componentes Angular, React, Vistas HTML | WCAG 2.1 AA |
