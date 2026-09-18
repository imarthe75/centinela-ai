---
name: centinela-developer-standards
description: Estándar obligatorio de arquitectura, seguridad y rigor de proceso para desarrolladores y agentes de IA. Garantiza 0 vulnerabilidades y 0 hallazgos en auditorías profundas de Centinela AI (SAST, DAST, CIS Benchmarks Linux, DB Hardening, IaC K8s/Terraform, Secrets, ISO 27001/25010, CMMI v3.0, OWASP Top 10, SonarQube, ZAP, N+1 queries, BOLA, hallazgos de auditoría de módulos Front/Back y reglas AGENTS.md).
---

# 🛡️ Centinela Developer Standards & AI Agent Skill (Deep Scanner & Module Audit Compliance)

Este documento establece la guía técnica y arquitectura obligatoria para todo desarrollo dentro del ecosistema Centinela AI. Su cumplimiento estricto garantiza el paso limpio (0 hallazgos y 0 vulnerabilidades) ante las auditorías automatizadas de **Centinela AI** (motores SAST, DAST, CIS Linux Benchmarks, DB Hardening, IaC, Secrets Scanner), **SonarQube**, **OWASP ZAP**, **Semgrep**, **Checkov**, **Trivy**, **Wazuh**, auditorías independientes de módulos frontend/backend y normas **ISO / CMMI**.

---

## 1. 🔍 Análisis Profundo de los Escáneres Centinela y Cómo Superarlos

### 1.1. Escáner de Servidores y Sistema Operativo (`auditor_cis_benchmarks.py`)
Centinela evalúa la postura de hardening en servidores Linux (Ubuntu, Debian, RHEL) mediante la suite de comprobaciones CIS Level 1:
- **SSH Hardening (`CIS-1.1`, `CIS-1.2`):**
  - `PermitRootLogin no` obligatorio en `/etc/ssh/sshd_config`. Prohibido autenticar como root directamente por SSH.
  - `PasswordAuthentication no` obligatorio. Autenticación **exclusiva por llaves SSH**.
- **Permisos de Archivos Críticos (`CIS-2.1`, `CIS-2.2`):**
  - `/etc/passwd`: Máximo permisos `644` (`rw-r--r--`). Prohibido permisos de escritura a otros.
  - `/etc/shadow`: Máximo permisos `600` (`rw-------`) o `640` (`rw-r-----`). Prohibida la lectura a otros.
- **Políticas de Contraseñas y Cuentas (`CIS-3.1`, `CIS-5.1`):**
  - Longitud mínima de contraseña >= 14 (`PASS_MIN_LEN 14` en `/etc/login.defs`).
  - Prohibidas cuentas locales con contraseñas vacías en `/etc/shadow`.
- **Seguridad de Red y Kernel (`CIS-4.1`, `CIS-6.1`, `CIS-6.2`):**
  - Firewall activo obligatoriamente (`ufw` o `firewalld` en estado `active`).
  - IP Forwarding deshabilitado (`sysctl -w net.ipv4.ip_forward=0`).
  - Core Dumps restringidos (`sysctl -w fs.suid_dumpable=0`).
- **Auditoría y Sincronización (`CIS-5.2`, `CIS-7.1`):**
  - Demonio de auditoría de sistema `auditd` instalado y activo.
  - Sincronización NTP activa (`chrony`, `ntp` o `systemd-timesyncd`).

---

### 1.2. Escáner de Hardening de Bases de Datos (`auditor_db_hardening.py`)
Centinela inspecciona instancias de bases de datos relacionales (PostgreSQL, MySQL, Oracle, MSSQL), NoSQL (MongoDB, Cassandra, Neo4j) y cachés en memoria (Redis, Valkey):
- **Cifrado SSL/TLS en Tránsito (`DB-NO-TLS-ENCRYPTION`):**
  - **Obligatorio:** Todas las bases de datos deben exigir cifrado SSL/TLS para conexiones de clientes y aplicaciones.
- **Aislamiento de Puertos (`DB-DEFAULT-PORT-EXPOSED`):**
  - **Recomendación:** Cambiar puertos predeterminados (`5432`, `3306`, `27017`, `6379`, `7687`) o restringir el tráfico estrictamente a nivel de Security Group / Firewall local (permitiendo únicamente IPs de la red privada/VPN).

---

### 1.3. Escáner de Infraestructura como Código y Contenedores (`auditor_iac_k8s.py` & Checkov/Trivy)
Evaluación automatizada de archivos `.tf` (Terraform), `.yaml` / `.yml` (Kubernetes) y `Dockerfile`:
- **Kubernetes Hardening (`K8S-PRIVILEGED-CONTAINER`, `K8S-HOSTPATH-MOUNT`, `K8S-WRITABLE-ROOT-FS`):**
  - **Prohibido:** `privileged: true` (acceso root al host).
  - **Prohibido:** Volúmenes de tipo `hostPath` sin justificación ni restricción.
  - **Obligatorio:** `readOnlyRootFilesystem: true` en el `securityContext` del contenedor.
  - **Obligatorio:** `automountServiceAccountToken: false` a menos que sea estrictamente necesario.
- **Terraform Hardening (`TF-OPEN-SECURITY-GROUP`, `TF-PUBLIC-S3-BUCKET`):**
  - **Prohibido:** Reglas de ingress con `cidr_blocks = ["0.0.0.0/0"]` en puertos administrativos (SSH, RDP, DB).
  - **Prohibido:** Buckets S3 con `acl = "public-read"` o `public-read-write`.
- **Dockerfile Hardening:**
  - **Obligatorio:** Directiva `USER nonroot` o un usuario de sistema dedicado (evitar ejecución por defecto como root).

---

### 1.4. Escáner de Secretos y Credenciales (`auditor_secrets.py`)
Inspección regex y de entropía sobre código fuente, manifiestos y configuraciones:
- **Patrones de Tolerancia Cero:**
  - AWS Access Keys (`AKIA...`), AWS Secret Keys.
  - Llaves Privadas RSA (`-----BEGIN RSA PRIVATE KEY-----`) y OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`).
  - Tokens de API (`api_token`, `ghp_*` de GitHub, `xoxb-*` de Slack).
  - Cadenas de conexión DB con contraseñas explícitas (`mongodb+srv://user:pass@...`, `mysql://user:pass@...`).
  - Asignaciones de variables `password = "..."` o `API_KEY = "..."`.
- **Manejo:** Todos los secretos deben consumirse desde variables de entorno (`os.getenv()`, `process.env`) o Secret Managers.

---

## 2. 🏛️ Estándares Específicos de Módulos Backend (Basado en Auditorías de Módulos)

### 2.1. Blindaje RBAC y Cobertura `@PreAuthorize`
- **Regla:** El 100% de los métodos de controladores Spring Boot / FastAPI DEBEN contar con anotaciones explícitas de autorización (`@PreAuthorize("hasAuthority('...')")` o dependencias de seguridad).
- **Prohibición de Backdoors & Controllers Sandbox:** Queda estrictamente prohibido desplegar controladores de prueba (`LocalAuthController`, `TestSandboxController`) en entornos productivos o staging (`CWE-288` / `CWE-798`).

### 2.2. Concurrencia Optimista y Bloqueos de Secuencias
- **Prevención de Race Conditions en Folios:** Prohibido calcular folios u ordinales contando registros en tiempo real sin transacciones aisladas o secuencias DB atómicas.
- **Entidades Auditables (`@Version`):** Toda entidad JPA que represente expedientes, contratos o estados de negocio DEBE incluir una propiedad `@Version` para evitar el antipatrón de actualizaciones perdidas ("Lost Updates").

### 2.3. Streaming de Archivos y Gestión de Conexiones
- **Evitar OOM en Archivos Grandes:** Prohibido cargar archivos o plantillas OnlyOffice/Bóveda en arreglos de memoria `byte[]`. Obligatorio procesar mediante `InputStream` y `StreamingResponseBody`.
- **No Retención de Conexiones DB durante I/O:** Queda prohibido realizar llamadas HTTP externas (OnlyOffice, Authentik, S3) dentro de un bloque `@Transactional` que retenga conexiones del pool HikariCP.

### 2.4. Seguridad en Caché y Transmisión de Tokens
- **Cierre de Transmisión JWT en URL:** Prohibido enviar tokens JWT en parámetros de URL (`?token=...`). Enviar exclusivamente en la cabecera `Authorization: Bearer <token>`.
- **Cifrado en Redis:** Evitar la serialización predeterminada vulnerable (`JdkSerializationRedisSerializer`). Usar `StringRedisSerializer` o `GenericJackson2JsonRedisSerializer` y cifrar datos sensibles antes de almacenar en caché.

---

## 3. 🎨 Estándares Específicos de Módulos Frontend (Angular / React)

### 3.1. Protección Contra XSS y Sanitización Insegura
- Prohibido el uso de `bypassSecurityTrustHtml`, `bypassSecurityTrustScript` o `innerHTML` directo con datos provenientes de la API sin previo paso por `DOMPurify.sanitize()`.

### 3.2. Gestión de Almacenamiento y Tokens
- Prohibido almacenar tokens sensibles en `localStorage` cuando sea posible utilizar Cookies `HttpOnly` con flag `SameSite=Strict` y `Secure`.

### 3.3. Sincronización de Eventos (SSE / WebSockets)
- Todo cliente EventSource / WebSocket debe implementar mecanismos de re-conexión automática con exponencial backoff y persistencia local para evitar pérdida silenciosa de notificaciones.

### 3.4. Accesibilidad Web (WCAG 2.1 AA)
- Todos los elementos interactivos (`<button>`, `<a>`, `<input>`, `<select>`) deben incluir atributos `aria-label` o `<label for="...">`.

---

## 4. ⚡ Heurísticas de Código y Arquitectura de Datos (`auditor_ext.py`)

### 4.1. Prevención Absoluta de Consultas N+1
- Prohibido ejecutar consultas a la base de datos dentro de bucles `for` / `while`.
- **Solución:** Utilizar `JOIN`, eager loading (`selectinload()` / `joinedload()` en SQLAlchemy) o consultas por lote (`in_([])`).

### 4.2. Manejo de Conexiones y Context Managers
- Toda conexión o cursor debe abrirse con administradores de contexto:
  ```python
  with get_db_connection() as conn:
      with conn.cursor() as cur:
          cur.execute("SELECT ... WHERE id = %s", (user_id,))
  ```

### 4.3. Control Estricto de Excepciones y Workers
- **Prohibición:** Prohibido usar `try...except Exception: pass` o retornos silenciosos.
- **Obligatorio:** Capturar excepciones específicas e incluir la traza completa con `logger.error("...", exc_info=True)`.
- En queries SQL para workers en segundo plano, utilizar operadores seguros ante nulos (`IS NOT DISTINCT FROM`).

---

## 5. 📐 Gobierno y Proceso de Desarrollo (ISO & CMMI v3.0)

### 5.1. ISO/IEC 25010 & 27001
- **Calidad del Producto:** 100% de anotaciones de tipo (Type Hints / TypeScript Strict), PEP 8, complejidad ciclomática <= 10.
- **Seguridad de la Información:** Cifrado en tránsito (TLS 1.3/HTTPS), sanitización de logs (mascarar PII y tokens), cero secretos hardcodeados.

### 5.2. CMMI v3.0 & AGENTS.md (Veracidad y No Simulación)
- **Principio de No Simulación:** Prohibidos stubs, mocks, datos hardcodeados, comentarios `TODO` o funciones vacías.
- **Criterio de Aceptación 100%:** Ninguna tarea se da por completada sin evidencia de pruebas ejecutadas (`pytest`, comprobaciones SQL, logs de terminal reales).

---

## 6. 📋 Lista de Chequeo de Auditoría Completa (Checklist)

- [ ] **Servidor/Linux:** ¿SSH root deshabilitado, autenticación por llave activa y permisos de `/etc/shadow` en 600/640?
- [ ] **Bases de Datos:** ¿Cifrado SSL/TLS activado y acceso a puertos acotado por firewall?
- [ ] **IaC / Contenedores:** ¿Dockerfile contiene `USER nonroot` y manifiestos K8s usan `readOnlyRootFilesystem: true`?
- [ ] **Secretos:** ¿Cero contraseñas, tokens o llaves privadas en código o archivos de configuración?
- [ ] **APIs / DAST / RBAC:** ¿Cada controlador backend posee `@PreAuthorize` y comprobación BOLA por `tenant_id`?
- [ ] **Rendimiento / I/O:** ¿Archivos procesados mediante streaming (`InputStream`) sin cargar `byte[]` enteros a RAM?
- [ ] **Concurrencia:** ¿Las entidades auditables contienen `@Version` y los folios se generan con secuencias DB?
- [ ] **Frontend:** ¿Sanitización con DOMPurify antes de renderizar HTML dinámico y cero tokens en URL `?token=`?
- [ ] **Proceso / Pruebas:** ¿Se adjunta evidencia de tests reales (`pytest`/SQL) ejecutados sin errores ni mocks?
