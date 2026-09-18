# 🛡️ Reglas de Gobierno y Estándares de Desarrollo Centinela AI

Este documento actúa como la regla activa de gobierno para la prevención de vulnerabilidades y cumplimiento de auditorías profundas en Centinela AI.

## 1. Reglas Fundamentales de Auditoría y Blindaje
- **CIS Linux Hardening:** SSH root deshabilitado (`PermitRootLogin no`), `PasswordAuthentication no`, `/etc/passwd` permissions 644, `/etc/shadow` permissions 600/640, `PASS_MIN_LEN 14`, firewall activo, sysctl `net.ipv4.ip_forward=0`, `fs.suid_dumpable=0`, demonio `auditd` y sincronización NTP activos.
- **DB Hardening:** Conexiones DB cifradas vía SSL/TLS obligatorias y aislamiento de puertos por Security Groups/Firewall.
- **IaC & Contenedores:** `privileged: true` y `hostPath` prohibidos en K8s; `readOnlyRootFilesystem: true` obligatorio. `0.0.0.0/0` ingress y buckets S3 públicos prohibidos en Terraform. `USER nonroot` en Dockerfiles.
- **Gestión de Secretos:** Tolerancia cero a contraseñas, llaves RSA, tokens o API keys hardcodeadas en código o configuraciones.
- **Backend & RBAC:** Cobertura 100% `@PreAuthorize` en endpoints controlador; prohibición absoluta de controladores Sandbox/Test en staging o prod. Prevención de race conditions con secuencias DB y `@Version` para entidades JPA. Streaming de archivos con `InputStream` / `StreamingResponseBody`. No retención de conexiones DB durante I/O HTTP. Prohibición de tokens JWT en parámetros de URL.
- **Frontend & Accesibilidad:** Desinfectar HTML dinámico con `DOMPurify.sanitize()`. Atributos WCAG 2.1 AA (`aria-label`, `<label for>`) obligatorios en elementos interactivos.
- **Heurísticas de Datos:** Prohibidas las consultas SQL N+1 en bucles. Manejo explícito de conexiones con administradores de contexto `with get_db_connection()`. Prohibido el silenciamiento de excepciones `try...except Exception: pass`.

## 2. Cumplimiento ISO 27001/25010 & CMMI v3.0
- Ninguna entrega ni desarrollo se da por completado sin evidencia directa de ejecución de pruebas (`pytest`, scripts SQL o comprobaciones funcionales).
