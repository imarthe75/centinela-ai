# 🔒 RITO DE CIERRE — Centinela-AI (2026-08-27)

**Operador:** Claude Code (Sonnet 5)
**Origen:** evaluar CodeRabbit (revisión de código con IA) y el SOC agéntico "The Rock" (KIO)
e incorporar mejoras. Items entregados: **1 (parcial), 2, 3, 4, 5**. Items **6** documentado
para decisión.
**Referencias:** `DECISIONS/0002` (entregado), `0003` (diseño item 2, implementado),
`0004` (item 6, decisión pendiente). Bitácora: `CLAUDE.md` → "Session 2026-08-27".

---

## ✅ ESTADO GLOBAL: OPERACIONAL

```
✅ centinela-ai        Up (reiniciado, __pycache__ limpio)
✅ centinela-backend   Up (127.0.0.1:8302)
✅ centinela-sentinel  Up
✅ centinela-frontend  Up
✅ neo4j / zeek / falco / falcosidekick / sonarqube / clickhouse / wazuh-manager  Up
```

`/api/health` → **Healthy**, 20/20 servicios Online.
Suite de pruebas: **121 passed**, 4 subtests (era 85 al inicio de la sesión).

---

## 📦 ENTREGADO

| Item | Módulo | Estado | Evidencia en vivo |
|---|---|---|---|
| 3 · Supresiones FP/riesgo aceptado | `finding_suppressions`, `core/deduplication_engine.find_active_suppression()`, `/api/suppressions*` | ✅ 100% | pytest 4/4 DB real + round-trip SOAR (row→SUPPRESSED, ledger) |
| 4 · Ledger de acciones autónomas | `agent_actions`, `core/agent_ledger.py`, `/api/agent-actions` | ✅ 100% | pytest 4/4 + filas reales en producción (`ai_correlation` 39, `threat_intel_enrichment` 28, `zap_container_reap` 1) |
| 5 · Contexto blast-radius en prompts | `core/code_context.py` | ✅ 100% | pytest 7/7 + 20 hallazgos reales (símbolos/callers correctos) + end-to-end en `correlate_vulnerability()` |
| 2 · Correlación de incidentes | `incidents`/`incident_events`, `core/incident_engine.py`, `run_incident_correlation_loop()`, `/api/incidents*` | ✅ 100% | pytest 12/12 + end-to-end contra el loop real: 4 alertas → 1 incidente, idempotente, note/status/MTTC probados, limpiado |
| 1 · Revisión de MR + commit status | `auditors/mr_review.py`, `/api/gitlab/mr-webhook`, `/api/gitlab/mr-review/*` | ⚠️ PARCIAL | camino read-only verificado contra MR real (`!57`); SAST+Dockerfile+secretos+**SCA**+**Semgrep** sobre el diff; pytest 8/8 |

**Nuevo en el repo:** `core/schema.py` (primer esquema versionado, `ensure_core_schema()` en
arranque de `centinela.py` y `main.py`).

---

## 🚧 DEUDA / PENDIENTES (Truthful Disclosures)

1. **Item 1 — escritura a GitLab NO ejercida en vivo.** `post_inline` / `upsert_summary_note`
   / `set_status` solo con tests unitarios. Postear en un MR real necesita un proyecto de
   prueba desechable o autorización explícita. **Congelado por decisión del usuario.**
2. **Item 1 — config lado GitLab pendiente:** webhook (`/api/gitlab/mr-webhook` +
   `GITLAB_WEBHOOK_TOKEN`) y exigir el status check `centinela/security` en los proyectos.
3. **Item 6 — respuesta autónoma:** NO implementado. `DECISIONS/0004` con propuesta,
   salvaguardas y 5 preguntas abiertas para el usuario. Automatizar contención contradice una
   regla vigente adoptada tras incidentes reales → requiere decisión explícita del dueño.
4. **`agent_actions`:** ~19 filas `threat_intel_enrichment` de la primera versión (una por
   iteración) — exactas, solo verbosas; la versión final registra al vaciar backlog o ante KEV.
5. **Semgrep en `scan_changed_files`:** cableado y sin error, pero devolvió 0 en la prueba
   rápida (los rulesets `p/*` requieren registro/red y el archivo de prueba era mínimo). SCA
   sí verificado con 21 CVEs reales de OSV.dev.

---

## 🔁 CÓMO SEGUIR

- **Item 1 completo:** configurar el webhook en GitLab + exigir el check; luego probar
  `POST /api/gitlab/mr-review/{project}/{iid}` contra un MR desechable y confirmar los 3
  writes (`discussions`, `notes`, `statuses`).
- **Item 6:** responder las 5 preguntas de `DECISIONS/0004` §4; si se aprueba, empezar por
  `proxy_ip_block` en `dry_run` ≥ 2 semanas.
- **Incidentes:** el motor está inerte hasta que lleguen señales no-ruido en la ventana de 6h.
  Panel frontend de incidentes = fase 2 (backend + API ya listos).

---

**Fecha:** 2026-08-27
**Rito de inicio de referencia:** `.agent/RITO_INICIO_2026_06_09.md`
