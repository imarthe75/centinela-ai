# 🛠️ Documentación Técnica: Centinela-AI (XDR Engine)

## 1. Alcance Técnico
Centinela-AI es un motor **XDR (Extended Detection and Response)** enfocado en la defensa profunda. A diferencia de las herramientas de Pentesting, su arquitectura está optimizada para la detección pasiva, correlación de logs y remediación reactiva. El sistema carece de módulos de explotación de vulnerabilidades.

> **Última actualización:** 2026-06-09 — Integración ZAP DAST, Secrets Scanning, SpiderFoot OSINT

## 2. Arquitectura del Sistema
Centinela-AI es un sistema de orquestación de seguridad (SOAR) basado en microservicios, diseñado para el ecosistema CASMARTS.

### Componentes Core:
- **Backend (FastAPI):** Orquestador central de APIs, gestión de base de datos, streaming de alertas vía WebSockets y triaje de IA.
- **Ansible Playbook Engine:** Despliegue automatizado del agente Wazuh y aplicación de recetas de parcheo de seguridad en hosts Linux/Windows.
- **Wazuh Agent Manager:** Integración con la API de Wazuh para interactuar directamente con agentes (restart, active scan, log extraction).
- **Ticketing Connector:** Integración bidireccional con Gitea y Redmine para registrar y documentar remediaciones XDR.
- **WeasyPrint Engine:** Motor de generación de reportes ejecutivos en PDF con renderizado de HTML+CSS (actualizado 2026-06-02).
- **Frontend (React + Vite):** Dashboard de mando y control con visualización de datos en tiempo real.
- **Database (PostgreSQL):** Persistencia de inventario (`infra_inventory`) y alertas de runtime (`runtime_alerts`).

## 2. Stack de Inteligencia Artificial (Dual-Provider)
El sistema utiliza una arquitectura de redundancia para garantizar la disponibilidad del análisis:
- **Primario:** Google Gemini 1.5 Flash (vía SDK nativo `google-genai`).
- **Respaldo (Fallback):** Groq Llama 3.3 (vía SDK `groq`).
- **Lógica de Conmutación:** Si el motor primario devuelve un error de cuota (429) o conectividad, el sistema escala automáticamente al respaldo en <1s.

## 3. Integración de Remediación (SOAR)
### Estrategia de Agente Híbrido:
1. **Docker SDK:** Para contenedores en la misma red o host. La remediación es directa.
2. **Wazuh & Ansible:** Para activos externos (Linux/Windows). Se utiliza Ansible para provisionar el agente en activos nuevos y Wazuh para enviar comandos de remediación en caliente.

## 4. Manual de Despliegue
### Requisitos Previos:
- Docker & Docker Compose.
- Variables de entorno en `.env`: `GOOGLE_API_KEY`, `GROQ_API_KEY`, `DB_PASSWORD`, `Wazuh_API_Key`, `GITEA_TOKEN`, `REDMINE_API_KEY`.

### Comandos de Instalación:
```bash
docker compose up -d --build
```

## 5. Módulos de Escaneo (Stack Completo 2026)

| Módulo | Archivo | Tipo | Cuándo se ejecuta | Detecta |
|--------|---------|------|-------------------|---------|
| **Nuclei** | auditor_ext.py | SAST/Template | Cada ciclo (10 min) | CVEs conocidos, misconfigs |
| **ZAP DAST** | auditor_zap.py | DAST activo | URLs/AppServers (on-demand o ciclo) | CSRF, auth bypass, logic flaws |
| **Medusa** | auditor_medusa.py | AI-SAST | Repositorios (cada ciclo) | Patrones de código vulnerables |
| **Secrets** | auditor_secrets.py | Secrets | Repositorios (cada ciclo, PHASE 1) | API keys, passwords hardcoded |
| **SpiderFoot** | auditor_spiderfoot.py | OSINT | URLs (cada ciclo extendido) | Subdomains, TLS issues, headers |
| **Trivy** | auditor_ext.py | SCA/Container | Repos + containers | CVEs en dependencias |
| **Checkov** | auditor_ext.py | IaC | Repositorios | Misconfigs de infraestructura |
| **Nmap** | auditor_ext.py | Network | IPs/AppServers | Puertos abiertos |
| **SQLMap** | auditor_ext.py | DAST-DB | Databases | SQL injection |
| **Wazuh** | centinela.py | Runtime | Continuo (push) | FIM, privilege escalation |

## 6. Endpoints Críticos (API Swagger)

### Inventario y Descubrimiento
- `POST /api/inventory`: Registro de activos con auto-geolocalización.
- `POST /api/inventory/{asset_name}/vault-secret`: Almacenar credenciales en Vault.

### Escaneo On-Demand (NUEVO 2026-06-09)
- `POST /api/scan/dast/{asset_id}`: Lanza escaneo ZAP DAST (perfil: light/balanced/aggressive/api).
- `POST /api/scan/secrets/{asset_id}`: Lanza secrets scanner (fase 1/2/3).
- `POST /api/scan/osint/{asset_id}`: Lanza SpiderFoot OSINT (subdomain, CT, TLS, threat intel).
- `GET /api/scan/coverage`: Breakdown de vulnerabilidades por motor de escaneo.

### Monitoreo y Alertas
- `GET /api/ws/alerts` (WebSocket): Canal bidireccional de alertas críticas en tiempo real.
- `GET /api/alerts/runtime`: Alertas de runtime (Wazuh/Falco).
- `POST /api/investigate/runtime`: Análisis IA de una alerta específica.
- `GET /api/health`: Estado de salud con módulos de escaneo detectados.

### Remediación SOAR
- `GET /api/remediation`: Historial de vulnerabilidades + remediaciones.
- `POST /api/remediation/approve/{vuln_id}`: Aprobar ejecución de script.
- `POST /api/remediation/{vuln_id}/ticket`: Crear ticket en Redmine/Gitea.
- `POST /api/wazuh/agent/{agent_id}/action`: Control de agente Wazuh en caliente.

### Reportes
- `GET /api/reports/executive`: Reporte ejecutivo PDF (WeasyPrint).
- `GET /api/reports/asset/{asset_name}`: Reporte de activo PDF.
- `GET /api/reports/vulnerability/{vuln_id}`: Detalle de vulnerabilidad PDF.
- `GET /api/stats/soar-roi`: Métricas SOAR vs Manual.

## 6. Cambios Recientes

### 2026-06-02: Actualización Motor de Reportes PDF

**Migración:** Carbone.io → WeasyPrint

| Aspecto | Carbone | WeasyPrint |
|---------|---------|-----------|
| **Tipo** | Templates de documentos (DOCX, XLSX) | HTML+CSS → PDF |
| **Dependencia** | Servicio externo (HTTP) | Librería Python |
| **Rendimiento** | HTTP round-trip (~1-2s) | In-process (<100ms) |
| **Estilo** | Template-based | CSS nativo |
| **Fallback** | No disponible | Embedded font support |

**Endpoints Actualizados:**
- `GET /api/reports/executive` ✅
- `GET /api/reports/asset/{asset_name}` ✅
- `GET /api/reports/vulnerability/{vuln_id}` ✅

**Cambios en código:**
- `main.py` línea 856: Nueva función `render_pdf_with_weasyprint()`
- `requirements.txt`: Agregado `WeasyPrint`
- `Dockerfile.backend`: Dependencias Cairo/Pango

**Beneficios:**
- PDFs válidos sin corrupción
- Eliminada dependencia externa
- Renderizado más rápido
- Estilos CSS completos preservados

---
© 2026 CASMARTS Technical Team.

