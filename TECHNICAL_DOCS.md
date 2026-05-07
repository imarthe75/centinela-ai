# 🛠️ Documentación Técnica: Centinela-AI (XDR Engine)

## 1. Alcance Técnico
Centinela-AI es un motor **XDR (Extended Detection and Response)** enfocado en la defensa profunda. A diferencia de las herramientas de Pentesting, su arquitectura está optimizada para la detección pasiva, correlación de logs y remediación reactiva. El sistema carece de módulos de explotación de vulnerabilidades.

## 2. Arquitectura del Sistema
Centinela-AI es un sistema de orquestación de seguridad (SOAR) basado en microservicios, diseñado para el ecosistema CASMARTS.

### Componentes Core:
- **Backend (FastAPI):** Orquestador central de APIs, gestión de base de datos y triaje de IA.
- **Sentinel (Python Agent):** Agente de ejecución de remediaciones con acceso a `docker.sock`.
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
2. **Wazuh Integration:** Para activos externos. Centinela detecta la presencia del agente Wazuh para disparar comandos remotos.
3. **SSH Fallback:** Como alternativa, se puede usar acceso por llave pública.

## 4. Manual de Despliegue
### Requisitos Previos:
- Docker & Docker Compose.
- Variables de entorno en `.env`: `GOOGLE_API_KEY`, `GROQ_API_KEY`, `DB_PASSWORD`.

### Comandos de Instalación:
```bash
docker compose up -d --build
```

## 5. Endpoints Críticos (API)
- `POST /api/investigate/runtime`: Recibe una alerta y devuelve un reporte estructurado de IA.
- `GET /api/inventory`: Lista de activos monitoreados.
- `POST /api/assets/register`: Registro de nuevos tipos de infraestructura.

---
© 2026 CASMARTS Technical Team.
