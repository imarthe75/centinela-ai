# 🗺️ Centinela-AI: MAP.md (Arquitectura de Seguridad)

> **Nota de veracidad (2026-08-11):** corregido junto con `CONTEXT.md` — describía servicios
> (`casmarts-core-netdata`, `casmarts-core-pghero`) y un flujo (Valkey, Vertex AI, OpenSign,
> SeaweedFS) que no existen en este despliegue real. Ver `docker-compose.yml` y `CLAUDE.md`
> como fuente de verdad.

## 🏗️ Estructura de Servicios Reales (`docker-compose.yml`)
- `centinela-ai` (`centinela.py`): orquestador — discovery, dispatch de auditores, loops de IA/CTI/CIS/BloodHound.
- `centinela-backend` (`main.py`, FastAPI/uvicorn): API REST que consume el frontend.
- `centinela-sentinel` (`sentinel.py`): ejecuta remediaciones aprobadas vía Ansible.
- `centinela-frontend` (Vite/React): dashboard.
- `centinela-neo4j`, `centinela-zeek`: grafo BloodHound y sensor NDR.
- `wazuh-manager` (contenedor `casmarts-core-wazuh-manager`): EDR manager.
- **Fuera de este `docker-compose.yml`** (en otros servidores): PostgreSQL `centinela_db`
  (10.4.3.23), HashiCorp Vault + Authentik (10.4.3.208).

## 🗄️ Flujo de Datos Real
1. **Detección:** Auditores nativos + herramientas externas (nuclei, trivy, ZAP, Medusa,
   TruffleHog, SpiderFoot, nmap, sqlmap, etc.) → `log_finding_deduplicated()`
   (`core/deduplication_engine.py`) → `vulnerability_log` (Postgres).
2. **Análisis:** `centinela.correlate_vulnerability()` → cascada de IA (Groq → Gemini → NVIDIA →
   OpenRouter) → fallback heurístico determinístico si las 4 fallan → `vulnerability_log`
   (`status='CORRELATED'`, `fix_patch`/`executive_summary`/`business_impact`).
2. **Remediación:** `remediation_history` → aprobación humana en el SOAR UI → `sentinel.py`
   ejecuta Ansible/SSH (o `git apply` + Merge Request para hallazgos de GitLab-Repo) → marca
   `RESOLVED`/`FAILED`.
4. **Reportes:** `/api/reports/executive` genera el PDF bajo demanda, en memoria — no hay
   archivo/repositorio externo.

## 📂 Mapeo de Directorios Reales (Host)
- `/opt/centinela-ai/` es la raíz del repo, montada como `.:/app` en los 3 contenedores Python.
- `/opt/centinela-ai/remediation/playbooks/`: playbooks Ansible reales.
- `/opt/centinela-ai/keys/`: llaves SSH (montadas en `/app/keys/*.key` dentro del contenedor).
- `/opt/centinela-ai/.agent/STATE.md`: bitácora real de hitos y decisiones de este proyecto.
