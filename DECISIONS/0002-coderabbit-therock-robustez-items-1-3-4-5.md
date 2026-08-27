# ADR-0002: Robustez inspirada en CodeRabbit + "The Rock" — items 1, 3, 4, 5 (+ 2)

**Fecha:** 2026-08-27
**Estado:** Items 3, 4, 5 y **2** implementados y verificados en vivo. Item 1 PARCIAL (ver §6):
la lógica de escaneo del diff — incluido Semgrep + SCA — está implementada y probada; las 3
llamadas de *escritura* a GitLab y la config del webhook quedan pendientes por decisión del
usuario. Item 6 documentado aparte (`0004`).
**Origen:** el usuario pidió evaluar CodeRabbit (revisión de código con IA) y el SOC agéntico
"The Rock" de KIO, y arrancar con mejoras concretas.

## Item 2 — Motor de correlación de incidentes

**Qué:** `core/incident_engine.py` agrupa señales que ya existen en `runtime_alerts` /
`vulnerability_log` (CTI/IoC, BloodHound, KEV) en incidentes con línea de tiempo, cadena
ATT&CK y reloj MTTD/MTTC. `run_incident_correlation_loop()` en `centinela.py` (hilo daemon,
120s). Agrupación determinista union-find por activo + ventana temporal + indicador compartido
(IP/usuario); sin LLM (resumen ejecutivo IA opcional sobre la narrativa ya construida).
Denylist `NOISE_RULES` para el ~93% de `runtime_alerts` que es ruido propio de los escáneres.
Tablas `incidents` + `incident_events`. Endpoints `GET /api/incidents`,
`GET /api/incidents/{id}`, `POST /api/incidents/{id}/note`, `POST /api/incidents/{id}/status`.
Diseño completo en `DECISIONS/0003`. **Verificado en vivo end-to-end** contra el loop real:
4 alertas de fuerza bruta → 1 incidente (event_count 4, CRITICAL, kill_chain Credential
Access, containment real), idempotente, note/status/MTTC probados, todo limpiado.
`tests/test_incident_correlation.py` 12/12.

---

## Item 3 — Memoria de falsos positivos / riesgo aceptado (`finding_suppressions`)

**Qué:** tabla `public.finding_suppressions` + `core.deduplication_engine.find_active_suppression()`,
consultada dentro de `log_finding_deduplicated()` justo tras calcular el `fingerprint`. Si un
hallazgo coincide con una supresión activa y no expirada, la fila existente se aparca en
`status='SUPPRESSED'` (o no se inserta si es nueva), y se incrementa `match_count` /
`last_matched_at` en la supresión para no perder de vista que el escáner lo sigue detectando.

Una supresión se define por cualquier combinación de `asset_id` / `cve_id` / `url_path_pattern`
(LIKE) / `fingerprint_hash`, con `scope` (`FALSE_POSITIVE` | `ACCEPTED_RISK` | `WONT_FIX`),
`created_by`, `expires_at` opcional. La API exige ≥1 predicado (una supresión toda-NULL
silenciaría toda la plataforma).

**Endpoints:** `GET/POST /api/suppressions`, `DELETE /api/suppressions/{id}`,
`POST /api/remediation/{vuln_id}/suppress` (atajo desde el SOAR: fija la supresión al
`fingerprint_hash` del hallazgo — mutea solo ese hallazgo, no todos los de su `cve_id`).

**Exclusión coherente:** `SUPPRESSED` se trata como estado terminal donde el código ya
excluía `RESOLVED` — `/api/remediation` (cola SOAR) y los contadores `critical`/`high`/
`breakdown` de `/api/stats`. `reconcile_resolved_findings()` no lo toca (solo actúa sobre
`OPEN/NEW/CORRELATED/REOPENED`). El loop de correlación IA ya lo ignora por su filtro de estado.

**Motivación:** `CLAUDE.md` documenta ~8 clases de falso positivo de detectores arregladas
globalmente en código. Esto es lo complementario: memoria **por-repo** que no requiere
redeploy y que aprende de la decisión del analista, como hace CodeRabbit con el feedback del
revisor.

---

## Item 4 — Ledger unificado de acciones autónomas (`agent_actions`)

**Qué:** tabla `public.agent_actions` + `core/agent_ledger.py::record_action()` — único punto
de escritura, **nunca lanza excepción** (un fallo del ledger no puede romper el trabajo real
que registra; se loguea con traceback completo, regla #6). Acepta un cursor externo para
unir la escritura a la transacción del cambio de estado que describe.

**Call sites cableados:**
| Acción | Origen | `action_type` |
|---|---|---|
| Correlación IA OK / fallida | `centinela.py::main_loop` | `ai_correlation` / `ai_correlation_failed` |
| MR de auto-fix abierto | `remediation/gitlab_autofix.py` | `gitlab_autofix_mr` |
| Reap de contenedores ZAP huérfanos | `auditors/auditor_zap.py` | `zap_container_reap` |
| Enriquecimiento EPSS/CISA KEV | `centinela.py` (acumulado en idle + inmediato si hay KEV) | `threat_intel_enrichment` |
| Supresión creada / hallazgo suprimido | `main.py` | `suppression_created` / `finding_suppressed` |
| Revisión de MR (item 1) | `auditors/mr_review.py` | `mr_review` |

**Endpoint:** `GET /api/agent-actions?limit=&action_type=&outcome=&since_hours=` (lista +
resumen agregado). Base para un panel "qué ha hecho la IA" y para medir MTTR más adelante.

**Motivación:** "The Rock" promociona "30 000+ acciones autónomas" como métrica de
rendición de cuentas; Centinela no tenía un registro único y consultable de su propia
actividad (estaba disperso entre `remediation_history` y líneas de log).

---

## Item 5 — Contexto de blast-radius en los prompts de remediación (`core/code_context.py`)

**Qué:** `gather_repo_context(asset_name, url_path)` — para un hallazgo de `GitLab-Repo`
(o del activo self-audit, mapeado a `/app`), lee el **bloque de la función que contiene** la
línea señalada desde el clon que el escáner de flota ya dejó en disco
(`/tmp/centinela_gitlab_scans/<namespace>`), extrae el símbolo relevante y ejecuta
`git grep -w` para listar sus otras referencias. Se inyecta como sección `CONTEXTO DE CÓDIGO`
+ `BLAST RADIUS` en el prompt de `correlate_vulnerability()`.

**Salvaguardas:** best-effort y **solo lectura** — cualquier fallo (repo no clonado,
`url_path` no parseable, `git` ausente) devuelve un bloque vacío sin lanzar excepción.
Rechaza `url_path` absoluto o con `..` (evita que `os.path.join` lea fuera del repo).
Si el símbolo es demasiado genérico (`>40` hits de `git grep`, o un tipo primitivo tipo
`boolean` — lista de stopwords multi-lenguaje) se muestra el bloque de código pero **no** la
lista de referencias, para no meter ruido engañoso.

**Motivación:** la ventaja de CodeRabbit es el contexto (función envolvente + puntos de
llamada afectados). Antes, el prompt solo tenía la línea suelta + la descripción corta del
escáner y ya pedía un diff aplicable con `git apply`.

---

## Item 1 — Revisión de Merge Request + estado de commit bloqueante (`auditors/mr_review.py`)

**Qué:** webhook GitLab `object_kind=merge_request` → `POST /api/gitlab/mr-webhook`
(valida `X-Gitlab-Token` contra `GITLAB_WEBHOOK_TOKEN`) → tarea en background:

1. `GET .../merge_requests/:iid/changes` — archivos cambiados + `diff_refs`.
2. `parse_added_lines()` — parsea los hunks del diff unificado → conjunto de líneas **nuevas**
   por archivo.
3. Clona con `--filter=blob:none --no-checkout` y hace checkout de `refs/merge-requests/:iid/head`.
4. `scan_changed_files()` — detectores nativos **sin escritura a DB** sobre solo los archivos
   cambiados: `scan_sast_code` (regex SAST), `scan_iac_dockerfile`, y patrones de secretos
   (`SecretsScanner.SECRET_PATTERNS`) línea a línea.
5. `findings_on_changed_lines()` — filtra a hallazgos que caen sobre una línea que el MR
   añadió (±2 de fuzz).
6. Comentarios en línea (`.../discussions` con `position`), idempotentes vía marcador
   `<!-- key:path:line:cve -->`; nota-resumen (upsert); y `POST .../statuses/:sha` con
   `context=centinela/security`, `state=failed` si hay hallazgo ≥ severidad bloqueante
   (`MR_REVIEW_BLOCKING_SEVERITY`, default `HIGH`), si no `success`.
7. Fila en `agent_actions` (`mr_review`).

**Endpoint manual / re-run:** `POST /api/gitlab/mr-review/{project_id}/{mr_iid}`.

**Config GitLab necesaria (lado servidor, no código):** Webhook → URL
`http://<centinela-backend>/api/gitlab/mr-webhook`, Secret token = `GITLAB_WEBHOOK_TOKEN`,
trigger "Merge request events". Para que **bloquee** de verdad: Project → Settings → Merge
requests → exigir el status check `centinela/security` (o "Pipelines must succeed").

**Motivación:** shift-left. Hoy la flota se escanea en bucle y se abren MRs de fix *después*
de que la vuln ya está en `main`. Esto la detecta y comenta **antes** del merge.

---

## Esquema y despliegue

`core/schema.py::ensure_core_schema()` (todo `CREATE ... IF NOT EXISTS`) se aplica en el
arranque de `centinela.py::main_loop()` y `main.py::startup_event()`. Es el primer objeto de
esquema de este repo que vive **en código** en vez de en un script suelto de `scratch/` — ver
el docstring del módulo. Script de aplicación inmediata: `scratch/apply_core_schema_2026-08-27.py`.

---

## §6 — Estado PARCIAL de item 1 y deuda

- **Verificado en vivo (solo lectura) contra un MR real** (`rpp-2.0/ms-rpp-administracion !57`):
  `get_mr` / `get_mr_changes` / `parse_added_lines` / clon con checkout de
  `refs/merge-requests/57/head` (HEAD resultante == `head_sha` exacto) / `scan_changed_files` /
  `findings_on_changed_lines` / `decide_state`. Todo el camino que **no** escribe en GitLab.
- **NO ejercido en vivo:** las 3 llamadas de escritura a GitLab (`post_inline`,
  `upsert_summary_note`, `set_status`). Publicar comentarios y un status en el MR de otro
  equipo es una acción saliente que requiere o un proyecto de prueba desechable o autorización
  explícita. Cubiertas por tests unitarios de la lógica pura, no de la I/O.
- **Pendiente lado GitLab:** configurar el webhook y exigir el status check en los proyectos
  objetivo (cambio de configuración de GitLab, no de código).
- ~~**Deuda menor:** `scan_changed_files` no corre Semgrep ni SCA.~~ **Resuelto 2026-08-27:**
  ahora corre además los `audit_*` de `auditor_sca_dependencies` sobre manifiestos cambiados
  (hallazgo anclado a la línea real de la dependencia) y una invocación Semgrep acotada a los
  archivos fuente cambiados. Verificado en vivo (21 CVEs OSV.dev sobre pins viejos).
- **Ruido histórico:** ~19 filas `threat_intel_enrichment` en `agent_actions` de la primera
  versión (pre-refactor) que registraba cada iteración; inocuas, la versión final solo
  registra al vaciar el backlog o al haber un hit KEV.
