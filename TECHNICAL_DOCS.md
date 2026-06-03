# 🛠️ Documentación Técnica: Centinela-AI (XDR Engine)

## 1. Alcance Técnico
Centinela-AI es un motor **XDR (Extended Detection and Response)** enfocado en la defensa profunda. A diferencia de las herramientas de Pentesting, su arquitectura está optimizada para la detección pasiva, correlación de logs y remediación reactiva. El sistema carece de módulos de explotación de vulnerabilidades.

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

## 5. Endpoints Críticos (API Swagger)
- `POST /api/investigate/runtime`: Recibe una alerta y devuelve un reporte estructurado de IA.
- `GET /api/inventory`: Lista de activos monitoreados y su estado.
- `POST /api/assets/register`: Registro de nuevos tipos de infraestructura.
- `GET /api/ws/alerts` (WebSocket): Canal bidireccional de alertas críticas en tiempo real.
- `POST /api/wazuh/agent/{agent_id}/action`: Ejecución de comandos en caliente (restart, scan, logs).
- `POST /api/soar/ticket`: Creación de un ticket de remediación en Gitea o Redmine.
- `GET /api/reports/executive`: Reporte ejecutivo (WeasyPrint).
- `GET /api/reports/asset/{asset_name}`: Reporte de seguridad de activo (WeasyPrint).
- `GET /api/reports/vulnerability/{vuln_id}`: Detalle de vulnerabilidad en PDF (WeasyPrint).
- `GET /api/stats/soar-roi`: Métricas financieras y comparativas de tiempo de respuesta (SOAR vs Manual).

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

