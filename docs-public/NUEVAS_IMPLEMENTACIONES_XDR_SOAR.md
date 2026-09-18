# 🛡️ Documentación Técnica de Nuevas Implementaciones: Centinela AI Omni-XDR & SOAR 2.0

Este documento detalla la arquitectura, especificaciones funcionales, endpoints y resultados de validación de los 8 motores y componentes avanzados incorporados a la plataforma Centinela AI.

---

## 1. Cierre del Bucle de Remediación GitLab (Webhook Inbound & Auto-Close)

### Descripción Arquitectónica
Anteriormente, el módulo de auto-remediación (`remediation/gitlab_autofix.py`) creaba ramas automáticas (`centinela-fix/<cve>-<vuln_id>`) y abría Merge Requests (MR) en GitLab, pero cuando los desarrolladores aprobaban y fusionaban el MR, el hallazgo permanecía indefinidamente en estado `NEW` o `IN_PROGRESS` dentro de la base de datos de Centinela.

### Solución Implementada
1. **Manejador de Eventos Merged (`remediation/gitlab_autofix.py::handle_mr_merged`)**:
   - Escucha los webhooks de GitLab con `action in ("merge", "merged")` o `state == "merged"`.
   - Extrae de forma determinista el identificador del hallazgo (`vuln_id`) a partir de la rama fuente (`centinela-fix/.*-(\d+)$`) o del cuerpo/título del MR.
   - Actualiza automáticamente la tabla `public.vulnerability_log`:
     ```sql
     UPDATE public.vulnerability_log
     SET status = 'RESOLVED'
     WHERE id = %s AND status != 'RESOLVED';
     ```
   - Actualiza el historial de remediación `public.remediation_history` a `status = 'COMPLETED'`, marcando `executed_bool = TRUE` y `executed_at = NOW()`.
   - Registra una acción de auditoría inmutable en `public.agent_actions` (`ACTION_GITLAB_AUTOFIX_MR`) con evidencia del enlace web del MR.
2. **Endpoint Webhook (`main.py::gitlab_mr_webhook`)**:
   - Ruta: `POST /api/gitlab/mr-webhook`
   - Valida el token secreto `X-Gitlab-Token` configurado en `GITLAB_WEBHOOK_TOKEN`.
   - Si la acción es `merge` o el estado es `merged`, invoca inmediatamente `handle_mr_merged` y retorna el conteo de hallazgos cerrados.

---

## 2. Auto-Remediación Asistida por IA (On-Demand AI Auto-Patching)

### Descripción Arquitectónica
Para hallazgos de código que van más allá de parches mecánicos (como Dockerfile non-root o bump de versiones en SCA), se requiere comprensión profunda del código fuente para generar parches sintácticamente válidos.

### Solución Implementada
1. **Generador de Parches IA (`remediation/gitlab_autofix.py::generate_ai_patch`)**:
   - Extrae el contexto real del archivo vulnerable dentro del repositorio clonado (35 líneas antes y después del número de línea reportado).
   - Construye un prompt especializado hacia el cascade de IA (`centinela.call_ai_cascade`), soportando proveedores Groq y Google Gemini.
   - Exige la devolución de un bloque en formato **Unified Diff** (`diff --git a/... b/...`).
   - **Validación rigurosa**: Antes de realizar cualquier commit, ejecuta `git apply --check --whitespace=fix` sobre el repositorio clonado en `/tmp`. Si el parche falla sintácticamente, se descarta y no se contamina el repositorio.
   - Si la verificación es exitosa, aplica el parche con `git apply`, sube la rama `centinela-fix/...` y persiste el diff en la columna `vulnerability_log.fix_patch`.

---

## 3. Integración con Wazuh EDR y Telemetría ClickHouse UEBA

### Descripción Arquitectónica
Conexión directa entre la telemetría de endpoints y servidores supervisados por los agentes Wazuh EDR con el motor de incidentes y almacenamiento analítico columnar en ClickHouse.

### Solución Implementada
1. **Endpoint Ingestor EDR (`main.py::wazuh_edr_webhook`)**:
   - Ruta: `POST /api/edr/wazuh/webhook`
   - Autenticación mediante `WAZUH_WEBHOOK_TOKEN` o `ITDR_WEBHOOK_TOKEN`.
   - Mapeo dinámico de severidades de Wazuh (Reglas nivel $\ge 12 \rightarrow$ `CRITICAL`, $\ge 8 \rightarrow$ `HIGH`, $\ge 5 \rightarrow$ `MEDIUM`, $\ge 3 \rightarrow$ `LOW`).
   - Resolución automática del activo en `public.infra_inventory` mediante `agent.id`, `agent.ip` o `agent.name`.
   - Inserción en `public.runtime_alerts` y emisión asíncrona de telemetría de alta frecuencia a ClickHouse (`centinela_telemetry.telemetry_events`).
2. **Clasificación de Tácticas MITRE ATT&CK (`core/incident_engine.py`)**:
   - Reglas con prefijo `WAZUH-` marcadas como incidentes candidatos independientes.
   - Extracción de indicadores específicos de Wazuh: `srcip`, `dstip`, `srcuser`, `dstuser`.
   - Clasificación táctica automatizada:
     - Eventos de sudo y ejecución de comandos como root $\rightarrow$ **Privilege Escalation**.
     - Fallos de autenticación PAM y SSH $\rightarrow$ **Initial Access** / **Credential Access**.

---

## 4. Matriz de Correlación Omnidireccional: SAST Repositorio vs Runtime Host

### Descripción Arquitectónica
Relación directa entre las vulnerabilidades detectadas en el análisis estático de código fuente y las alertas de runtime disparadas en los hosts o contenedores donde se despliega dicho código.

### Solución Implementada
1. **Endpoint de Correlación Híbrida (`main.py::get_sast_runtime_correlations`)**:
   - Ruta: `GET /api/correlations/sast-runtime`
   - Consulta y agrega:
     - **Incidentes Híbridos**: Agrupaciones de `public.incidents` que contienen simultáneamente eventos provenientes de `vulnerability` (código) y `runtime_alert` (host/EDR).
     - **Activos en Riesgo Cruzado**: Servidores y repositorios con concurrencia de vulnerabilidades de código abiertas y alertas de host activas.
     - **Telemetría Reciente**: Feed de ejecuciones anómalas en tiempo real.
2. **Interfaz de Usuario Frontend (`frontend/src/components/Dashboard.jsx`)**:
   - Nueva vista interactiva: **"Correlación XDR"** accesible desde la barra lateral de navegación con icono de capas.
   - Tarjetas de KPIs ejecutivos, tabla de incidentes híbridos con cadena de ataque MITRE ATT&CK, y tabla de concurrencia de activos.

---

## 5. Motor de Autorización Dinámica DAST (BOLA / IDOR / BFLA)

### Descripción Arquitectónica
Capacidad de realizar pruebas dinámicas autenticadas multi-rol contra endpoints REST descubiertos por OpenAPI o análisis estático, probando escalación de privilegios horizontal y vertical.

### Solución Implementada
1. **Esquema de Base de Datos (`core/schema.py`)**:
   - Declaración de la tabla `public.asset_auth_configs`:
     ```sql
     CREATE TABLE IF NOT EXISTS public.asset_auth_configs (
         id SERIAL PRIMARY KEY,
         asset_id INTEGER REFERENCES public.infra_inventory(id) ON DELETE CASCADE,
         asset_name TEXT UNIQUE NOT NULL,
         base_url TEXT,
         config JSONB NOT NULL,
         created_at TIMESTAMP NOT NULL DEFAULT NOW(),
         updated_at TIMESTAMP NOT NULL DEFAULT NOW()
     );
     ```
2. **Carga Multifuente de Credenciales (`auditors/auditor_authz_dast.py::_load_config`)**:
   - Nivel 1: Archivo JSON local en `/app/data/authz`.
   - Nivel 2: Secretos en HashiCorp Vault (`secret/setag/authz/{asset_name}`).
   - Nivel 3: Base de datos PostgreSQL (`public.asset_auth_configs`).
   - Nivel 4: Variables de entorno de respaldo (`AUTHZ_ADMIN_TOKEN`, `AUTHZ_USER_TOKEN`, `AUTHZ_BASE_URL`).
3. **Endpoints de Gestión REST (`main.py`)**:
   - `GET /api/authz/configs`
   - `GET /api/authz/configs/{asset_name}`
   - `POST /api/authz/configs`

---

## 6. Plantilla CI/CD Reutilizable de Quality Gate para GitLab

### Descripción Arquitectónica
Estandarización del Quality Gate de seguridad y madurez para que cualquier repositorio del ecosistema (grupo Kardex, Starters o microservicios) pueda integrar Centinela en su pipeline de integración continua.

### Solución Implementada
1. **Plantilla Reutilizable (`templates/centinela-quality-gate.gitlab-ci.yml`)**:
   - Etapa `centinela:mr-security-gate`: Evalúa las líneas agregadas en cada Merge Request invocando `/api/gitlab/mr-review`. Si se detectan vulnerabilidades $\ge$ `HIGH`, bloquea la fusión del pipeline.
   - Etapa `centinela:cmmi-iso-quality-gate`: Evalúa la madurez CMMI v3.0 e ISO 27001 en la rama principal, descargando el reporte oficial PDF y generando artefactos JSON para GitLab.
2. **Endpoint Proveedor de Plantilla (`main.py::get_gitlab_ci_template`)**:
   - Ruta: `GET /api/templates/gitlab-ci`
   - Permite que los proyectos remotos incluyan el pipeline con una sola directiva:
     ```yaml
     include:
       - remote: 'http://10.4.3.10:8000/api/templates/gitlab-ci'
     ```

---

## 7. Reportes Ejecutivos Consolidados de Grupo por WeasyPrint (PDF/HTML)

### Descripción Arquitectónica
Generación de informes ejecutivos consolidados que agrupan todos los repositorios y activos de una unidad o subsistema específico (ej. Grupo Kardex).

### Solución Implementada
1. **Endpoint de Reportes de Grupo (`main.py::download_group_executive_report`)**:
   - Ruta: `GET /api/reports/group/{group_name:path}`
   - Filtra y agrega todos los activos pertenecientes a `GitLab/{group_name}/%`.
   - Evalúa el cumplimiento CMMI v3.0 y nivel de madurez promedio por activo.
   - Agrega métricas de vulnerabilidades por severidad (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
   - Renderiza un documento profesional estilizado con branding SETAG/Centinela mediante WeasyPrint (con fallback transparente a HTML responsive si WeasyPrint no está disponible).

---

## 8. Paridad Multi-Arquitectura en Dockerfile.backend

### Descripción Arquitectónica
Garantizar que la imagen del backend ejecute idénticamente en arquitecturas x86_64 (`amd64`) y ARM64 (`arm64`), incluyendo todos los binarios de auditoría estática y dinámica.

### Solución Implementada
- Actualizado a base `python:3.11-slim` con `ARG TARGETARCH=amd64`.
- Instalación de binarios multi-arch con auto-detección: Trivy, Nuclei v3.3.0 (`linux_${TARGETARCH}`), Syft, Grype, ffuf (`linux_${TARGETARCH}`), TruffleHog.
- Instalación de librerías nativas Cairo/Pango para generación de reportes PDF de alta fidelidad con WeasyPrint.
- Paquetes Python integrados: `checkov`, `semgrep`, `medusa-security`.
- Ejecución segura bajo usuario no-root (`appuser`, UID 1000).

---

## 9. Resumen de Pruebas y Evidencia de Ejecución

La totalidad de los nuevos motores y extensiones cuenta con cobertura de pruebas automatizadas:
* **Suite Principal de Integración (`tests/test_xdr_soar_integrations.py`)**: 10 tests aprobados al 100%.
* **Suite de SAST Ampliado (`tests/test_sast_master_vulnerabilities.py`)**: 11 tests aprobados al 100%.
* **Suite de Shift-Left MR Review (`tests/test_mr_review.py`)**: 9 tests aprobados al 100%.
* **Ejecución Consolidada en Contenedor**: **30 tests aprobados en 20.19 segundos**.
