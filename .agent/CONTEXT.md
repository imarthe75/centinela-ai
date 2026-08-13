# 🌌 Centinela-AI: CONTEXT.md (Propósito Técnico)

> **Nota de veracidad (2026-08-11):** este archivo describía un stack genérico heredado de la
> plantilla `resident-agent-framework` (Valkey, pgvector, SeaweedFS, DB `casmarts_security`) que
> **nunca existió en este despliegue real**. Corregido tras una auditoría profunda que verificó
> el stack real contra `docker-compose.yml` y la base de datos en vivo. Ver `CLAUDE.md` para el
> detalle completo de la arquitectura y su historial de incidentes/fixes.

## 🏢 Arquitectura Real
Centinela-AI es el motor de correlación y SOAR de seguridad de CASMARTS: escaneo continuo
multi-motor (SAST/SCA/DAST/OSINT/Secrets/IaC/CMMI/DB-Hardening/CIS/CTI), correlación por IA en
cascada (Groq → Gemini → NVIDIA → OpenRouter, con fallback heurístico determinístico), y
remediación aprobada por humano ejecutada vía Ansible/SSH.

## 🧩 Integraciones Reales
- **Wazuh** (`casmarts-core-wazuh-manager`, 10.4.3.34): telemetría EDR de agentes remotos vía
  puertos 1514/1515/55000, ingerida directamente por `centinela.py`.
- **Zeek** (`centinela-zeek`): NDR pasivo, logs de conexión (`conn.log`) correlacionados contra
  el feed CTI en `process_zeek_conn_log()`.
- **Valkey SÍ existe y está en uso real** (corrección 2026-08-11, encontrada por error propio en
  la primera versión de esta nota): contenedor `casmart-valkey` (imagen `valkey/valkey:8`) en
  `10.4.3.23`, fuera de este `docker-compose.yml` — es infraestructura compartida de
  `core-casmarts`, no algo desplegado por este repo. `centinela.py` lo usa como cola real de
  alertas de Falco/Zeek (`consume_falco_alerts()`/`consume_zeek_...()`, `get_valkey_connection()`
  vía `VALKEY_HOST`). **No** se usa como caché semántica ni como canal `centinela:alerts` de la
  plantilla genérica original — ese uso nunca existió. Incidente real encontrado y corregido el
  mismo día: el directorio host `/opt/casmart/valkey/data` pertenecía a UID 1000, pero el proceso
  `valkey-server` corre como UID 999 (usuario no-root de la imagen oficial) — Valkey llevaba
  desde el 13 de julio sin poder guardar su snapshot RDB (`rdb_last_bgsave_status: err`),
  bloqueando escrituras y con ello la ingesta de alertas Falco/Zeek en tiempo real durante
  semanas. Corregido con `chown -R 999:999` en el host; verificado en vivo con un `BGSAVE` manual
  (`rdb_last_bgsave_status` pasó a `ok`) y confirmando que los errores `MISCONF` dejaron de
  aparecer en los logs de `centinela-ai`.
- **Neo4j** (`centinela-neo4j`): grafo de rutas de ataque estilo BloodHound (dormido hasta que
  exista un dominio AD real que importar).
- **PostgreSQL `centinela_db`** (10.4.3.23, usuario `centinela_user`): única fuente de verdad,
  compartida entre `centinela-ai`/`centinela-backend`/`centinela-sentinel`. **PKs son
  `serial`/`integer`, no `uuid`** — no aplica la regla de PKs UUID de `AGENT.md` en este
  proyecto concreto.
- **HashiCorp Vault** (10.4.3.208): credenciales de Ansible (SSH/password) por activo, bajo
  `casmarts/ansible/*`. No almacena hallazgos ni cachés — solo secretos.
- **Reportes**: PDF generado bajo demanda vía `/api/reports/executive` (backend, en memoria),
  no hay repositorio SeaweedFS ni firma OpenSign en este proyecto.
- **pgvector no existe en este despliegue** — no hay memoria vectorial de "lecciones aprendidas";
  la memoria de largo plazo real de este proyecto es este mismo directorio `.agent/` (Markdown
  plano) más `CLAUDE.md`.
