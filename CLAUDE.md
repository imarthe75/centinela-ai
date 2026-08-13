# Centinela-AI

SOC/SOAR platform for the CASMARTS ("Casmart") infrastructure: continuous vulnerability
scanning across many scanner engines, an AI correlation/remediation engine, a Wazuh EDR

## REGLAS STRICTAS DE EJECUCIÓN, TESTEO, VERACIDAD Y ENTREGA DE CÓDIGO

### 1. PRINCIPIO DE HONESTIDAD TÉCNICA Y NO SIMULACIÓN
- Queda estrictamente PROHIBIDO declarar una tarea como completada si el código contiene:
  - Mocks, datos simulados o respuestas "hardcodeadas" (salvo especificación explícita en los requerimientos).
  - Comentarios del tipo `# TODO`, `// TODO`, `pass` en funciones principales, o bloques de código vacíos.
  - Stubs, funciones sintácticamente correctas pero sin lógica de negocio funcional real, o interfaces no conectadas a servicios de fondo.
- Si por limitaciones de tiempo, contexto o dependencias no se implementa la lógica real, DEBES declarar el componente como INCOMPLETO o PARCIAL.

### 2. CRITERIO OBLIGATORIO DE ACEPTACIÓN: VALIDACIÓN POR PRUEBAS
Ningún desarrollo o revisión de código se considerará "COMPLETADO 100%" sin evidencia directa de ejecución de pruebas o comprobaciones funcionales:
1. **Entorno Python / Scripts / Servicios:** Debes escribir e invocar tests unitarios o de integración mediante `pytest` (o scripts de validación en Python) que ejecuten el flujo completo.
2. **Entorno PostgreSQL / Persistencia:** Debes ejecutar o proporcionar scripts de verificación SQL (`SELECT`, validación de esquemas, vistas o transacciones) que demuestren que las consultas y mutaciones operan sin errores.
3. **Entornos de Infraestructura / SSH / Linux:** Debes verificar la ejecución de comandos, permisos y respuestas de red o servicios en el entorno real antes de reportar un cambio de configuración como exitoso.
4. **Registro de Ejecución:** El informe final DEBE incluir el log o la salida real obtenida al ejecutar las pruebas en la terminal del entorno.

### 3. PROTOCOLO DE AUDITORÍA OBLIGATORIA (BEFORE REPORTING)
Antes de generar el Walkthrough o informe final, estás OBLIGADO a cumplir los siguientes tres pasos:
1. **Auditoría de Diffs:** Inspecciona los cambios reales (`git diff` o inspección de archivos) para garantizar que no existan remanentes de código temporal o declaraciones no implementadas.
2. **Ejecución de Pruebas:** Corre la suite de validación (`pytest`, `psql`, o scripts de prueba) y comprueba que no existen errores de sintaxis o excepciones no controladas.
3. **Cálculo de Avance Objetivo:** Asigna el porcentaje de avance basándote **únicamente** en requerimientos con pruebas ejecutadas y aprobadas, no en la cantidad de archivos creados.

### 4. FORMATO OBLIGATORIO DE ENTREGA (WALKTHROUGH)
Cualquier entrega final o reporte de avance DEBE apegarse strictly a la siguiente estructura:
- **Resumen Ejecutivo de Estado** (`[COMPLETADO 100% / PARCIAL / FALLIDO]`)
- **Matriz de Veracidad y Evidencia de Pruebas** (Tabla de requisitos, estado real y evidencia de comandos ejecutados)
- **Registro de Salida de Pruebas (Test Output Log)**
- **Deuda Técnica y Pendientes (Truthful Disclosures)**

### 5. PENALIZACIÓN POR FALSA COMPLETITUD
- Presentar un Walkthrough declarando un estado de "Completado" cuando existan mocks, funciones inconclusas o falta de pruebas ejecutadas se considera un **FALLO CRÍTICO**. Ante cualquier duda o imposibilidad de probar el código en el entorno, DEBES reportar un estado "PARCIAL" e indicar el porcentaje real correspondiente.

### 6. PROHIBICIÓN DE SILENCIAMIENTO DE EXCEPCIONES Y VERIFICACIÓN DE WORKERS DE FONDO
- **Queda estrictamente PROHIBIDO** utilizar bloques `try...except Exception:` que capturen errores sin emitir trazas completas de error (`logger.error(..., exc_info=True)` o `traceback.print_exc()`) o que permitan que la función falle en silencio retornando estados falsos de éxito.
- **Auditoría de Workers y Bucles Asíncronos:** Toda función que corra en segundo plano (`background_tasks`, cron, workers de auditoría o de persistencia SQL) DEBE ser probada explícitamente ejecutando el script/función directamente y verificando la DB mediante consultas SQL reales (`SELECT`), asegurando que:
  - No existan variables `NULL` no controladas en sentencias SQL (`IS NOT DISTINCT FROM`).
  - Los administradores de contexto de conexión (`with get_db_connection()`) se usen de forma completa.
  - La cantidad de filas insertadas corresponda a hallazgos reales sin provocar duplicación masiva o nulos huérfanos.


## Omni-XDR 2.0 Architectural Vision & Standards

**Status note (2026-08-05):** this section was previously found claiming, in the present tense,
capabilities that didn't exist — schema columns or pure functions nothing ever called with real
data, silently producing plausible-looking but constant/fake values. All 11 items below have
since been verified live, one at a time, with real external data sources where applicable.
Verify against the code before trusting this list if it's been a while — the per-item status is
kept current here as each piece is actually built/changed, not aspirationally.

1. **Centinela Risk Score (CRS)** combining CVSS + EPSS + CISA KEV + Asset Criticality —
   **✅ real**. `core/deduplication_engine.py` has the formula; `core/threat_intel.py` queries
   FIRST.org's EPSS API and CISA's public KEV catalog live (both free, no auth).
   `run_threat_intel_enrichment_loop()` in `centinela.py` backfills existing rows and re-checks
   every 24h. Verified live: Log4Shell (CVE-2021-44228) correctly flags as CISA KEV, the XZ
   backdoor (CVE-2024-3094, caught pre-mass-exploitation) correctly doesn't; risk_score went
   from exactly 4 fixed values across ~1200 rows to 15+ real distinct ones.
   **Still an approximation**: no real per-CVE numeric CVSS score exists anywhere in this
   schema, so the CVSS component is derived from the severity bucket a scanner already assigned
   (CRITICAL→9.5 etc.), not a real NVD CVSS vector lookup (NVD's public API is heavily
   rate-limited without a key, impractical for bulk backfill).
2. **Reachability filtering** (`REACHABLE` vs `UNREACHABLE`) — **✅ real**.
   `check_reachability()` in `auditor_sca_dependencies.py` greps the actual source tree for a
   real `import`/`require` of the vulnerable package — a dependency merely listed in
   `requirements.txt`/`package.json` but never imported anywhere is real, honest signal that the
   vulnerable code path can't execute. This is import-based matching, not true per-CVE
   call-graph/taint analysis into the specific vulnerable function (no ecosystem reliably
   exposes "this exact symbol is unsafe" metadata) — documented as a real but coarser signal in
   the function's own docstring. Verified live: a genuinely-imported package correctly flags
   REACHABLE, one merely listed in the manifest but never imported correctly flags UNREACHABLE.
3. **Multi-tool deduplication fingerprinting** — **✅ real, wired into every auditor**.
   `calculate_fingerprint()` existed in `deduplication_engine.py` but nothing ever called it —
   `fingerprint_hash` was empty on every row. `log_finding_deduplicated()` (same file) is a
   shared three-tier logger, now called from every module that writes to `vulnerability_log`:
   `auditor_zap.py`, `auditor_master_vulnerabilities.py`, `auditor_sca_dependencies.py`,
   `auditor_compliance_standards.py`, `auditor_ext.py`, `auditor_medusa.py`,
   `auditor_secrets.py`, `auditor_spiderfoot.py`, `core/heuristics_engine.py`, and
   `process_bloodhound_paths()`: (1) same fingerprint already open, any engine → update in
   place; (2) no fingerprint match but the same *real* CVE already open on this asset from a
   *different* scan_engine → genuine cross-tool duplicate → merge a detection note onto the
   existing row instead of opening a second ticket; (3) otherwise insert fresh. Verified live: a
   cross-tool merge test (same CVE, two different scan_engine values) correctly produced one
   row, not two.
   A `preserve_status` option was added to support `auditor_ext.py`/`core/heuristics_engine.py`'s
   original (and genuinely good) nuance: a re-detected finding that was previously `RESOLVED`
   becomes `REOPENED` rather than silently duplicated or silently treated as still-resolved;
   any other status is left untouched rather than forced back to `NEW`/`OPEN`. Verified live.
   **Two real, previously-hidden bugs found while wiring this in, unrelated to fingerprinting
   itself:**
   - `auditor_spiderfoot.py` used `ON CONFLICT (asset_id, cve_id) DO UPDATE` — a named conflict
     target that requires a matching unique constraint to exist. Confirmed live: no such
     constraint has ever existed on this table (only the `id` primary key and plain,
     non-unique indexes). Every single call to `log_osint_finding()` was silently throwing a
     real database error, caught by the function's own broad `except` and logged, but never
     persisted — confirmed live with 0 `scan_engine='spiderfoot'` rows in production despite
     this function being called routinely. Every OSINT finding this engine ever produced had
     been silently lost since the function was written.
   - `auditor_secrets.py` built `cve_id` from only the secret *type* (e.g.
     `SECRETS-API_KEY-PHASE1`), with no file/line — not just duplicate spam but real, silent
     data loss: two distinct hardcoded secrets of the same type in two different files shared
     the exact same dedup key and silently overwrote each other on every scan, so only the last
     one scanned was ever visible. Now disambiguated by `file:line` via `url_path`, verified
     live with two distinct secrets of the same type producing two distinct rows.

   **SLA deadline tracking** (Critical 24h / High 7d / Medium 30d / Low 90d) — **✅ real**,
   `calculate_sla_due_date()`/`is_sla_breached()` correctly wired in `main.py`'s
   `/api/remediation`.
4. **Quality Gates** (Grade A/B/F, ISO 25010 thresholds) — **✅ real**.
   `auditors/auditor_quality_gates.py` + `/api/quality-gates/check` genuinely queries real
   unresolved findings and evaluates real thresholds. No fake data found here.
5. **MITRE ATT&CK® taxonomy mapping** — **✅ real, partial coverage by design**.
   `core/mitre_attack.py` maps Centinela's own finding categories (cve_id prefixes, plus ZAP's
   "Type:" text for DAST findings) to real, verifiable ATT&CK technique IDs, written into the
   previously-unused `vulnerability_log.standards` column via the same shared
   `log_finding_deduplicated()` path. Deliberately leaves code-quality findings
   (`STD-ISO25010-LONG-METHOD`, `COGNITIVE-COMPLEXITY-EXCEEDED`) and non-findings (`SCAN-AUDIT`,
   `HEURISTIC-SECURITY-DEBT`) unmapped — ATT&CK models adversary behavior, not code
   maintainability, and forcing a technique onto something that isn't an attack technique would
   repeat the same fake-precision problem found elsewhere in this codebase. Verified live: a
   one-time backfill mapped 714 of 1427 existing findings to a real technique; the rest were
   correctly left unmapped.
6. **CIS Benchmarks hardening audits** — **✅ real, explicitly partial scope**.
   `auditors/auditor_cis_benchmarks.py` runs ~11 real, read-only, distro-general CIS Level 1
   Linux checks over SSH (SSH root login, password auth, `/etc/passwd`/`/etc/shadow`
   permissions, password minimum length, firewall active, empty-password accounts, auditd,
   IP forwarding, core dumps, time sync) via `/api/cis-benchmark/check/{asset_name}` — this is
   **not** the full official CIS benchmark (hundreds of items, distro-version-specific), just a
   defensible, commonly-cited subset. A real bug was caught during live verification against
   `casmart_authentik`: `systemctl is-active` prints the literal string `"inactive"` on
   failure, which contains `"active"` as a substring — the original substring-match checks
   (firewall, auditd, time sync) reported false PASSes on a host where the firewall and auditd
   were both genuinely off. Fixed by always emitting an unambiguous `RESULT:ACTIVE`/
   `RESULT:INACTIVE` ourselves rather than trusting the tool's own raw stdout; the real grade on
   that host dropped from a falsely-inflated C (54.5%) to an honest F (36.4%).
   **Second real bug found and fixed 2026-08-11**, in response to a direct user challenge
   ("cómo es que fue auditado si nunca ha sido encendido? el cisco 4 esxi?"): `_run_ssh_command()`
   returned `""` (empty string) both when a command genuinely ran and produced no output, AND
   when the SSH connection itself failed outright — indistinguishable downstream. This meant
   **every unreachable host got a fully fabricated grade**, not an honest "couldn't check":
   confirmed live that `Cisco 4 ESXI` (a powered-off VMware ESXi hypervisor — VMkernel, not
   Linux, so none of these Linux-specific checks could ever apply there regardless) had all 11
   checks logged as real HIGH/CRITICAL findings with the identical fallback evidence text
   `(sin salida / comando no aplicable)`, none of them real. Same bug hit `centinela`,
   `CLONE-COMPRAMEX-CORE`, `CLONE-COMPRAMEX-CORE-BD`, and `compramex-bd` (no real SSH
   credentials in Vault for any of these — confirmed live via `No sudo_password found in Vault`)
   at 100% fake, and `casmartsuperset`/`casmart_authentik`/`prism`/`chat` partially (3 of 11
   checks each). Fixed by having `_run_ssh_command()` return `None` (not `""`) on genuine
   connection/execution failure; `run_cis_audit()` now tracks `unreachable_count` separately and
   only computes a grade from checks that were actually verified, introducing an honest
   `SIN_CONEXION` grade (with `percentage: None`) instead of a fabricated `F (0%)` when zero
   checks could be verified; `log_cis_findings()` now skips logging a finding for any check with
   `passed is None` (unreachable), only ever logging genuinely-observed failures. Verified live
   end-to-end after clearing `__pycache__` and restarting both `centinela-ai` and
   `centinela-backend` (confirmed via `inspect.getsource()` in both containers, not just assumed
   from the restart): re-running the real audit against all 9 previously-affected assets now
   correctly returns `SIN_CONEXION` for the 5 fully-unreachable ones and a real partial grade
   (C, 4/8 verified) for the 4 partially-reachable ones. The 67 confirmed-fake finding rows
   (identified by the exact fabricated fallback text) were deleted from the DB with explicit
   user approval; 0 remain, 16 genuinely-reverified findings survive. Full pytest suite still
   30/30 passing. **Lesson**: a DB row's existence with a recent timestamp is not evidence that
   whatever it claims actually happened — verify the underlying raw evidence
   (`raw_output`/similar), not just that the row is there, before asserting something is real.
7. **Neo4j Attack Path Graphing** — **⚠️ code is real and kept warm, but has no real data to run
   against yet (deliberate — decided 2026-08-06, see below)**.
   `process_bloodhound_paths()` in `centinela.py` runs a real, standard BloodHound Cypher query
   (shortest path from any non-admin user to Domain Admins) every 10 minutes. The Neo4j graph
   has zero `:User`/`:Group` nodes today (confirmed live: `MATCH (u:User) RETURN count(u)`
   returns 0) because nothing in this codebase ever imports real AD collector output
   (SharpHound/AzureHound) into it — the loop correctly detects this (`user_count == 0`) and
   skips the query rather than silently running against an empty graph. This is a real,
   fail-safe idle state, not a masked failure. Also fixed two real bugs found alongside this:
   the insert used the same no-op `ON CONFLICT DO NOTHING` as other tables (replaced with the
   shared dedup logger), and asset attribution used to fall back to an arbitrary `SERVER`-type
   asset when no asset was literally named "Active Directory", misattributing a real attack-path
   finding to an unrelated host.
   **A third real bug found and fixed 2026-08-06**: the Cypher query itself was hardcoded to
   `g.name = 'DOMAIN ADMINS@INTERNAL.LOCAL'` — BloodHound suffixes every node name with the
   real AD domain's actual FQDN, so this would only ever have matched a domain literally named
   `INTERNAL.LOCAL`, silently finding nothing against CASMARTS' real domain (whatever it turns
   out to be) even after real data is imported. Confirmed live against a disposable synthetic
   Neo4j dataset (`DOMAIN ADMINS@TESTDOMAIN.LOCAL`): the old hardcoded query returned zero rows,
   a `WHERE g.name STARTS WITH 'DOMAIN ADMINS@'` version correctly found the path. Fixed to
   match by prefix so it works against whatever domain gets imported later with no code change
   needed; test nodes cleaned up afterward.
   **Decision (2026-08-06): keep this wired and dormant rather than disable it.** It costs
   nothing while idle (one query every 10 minutes against an empty graph, already confirmed to
   skip cleanly), and privilege-escalation path analysis is a real, high-value question for an
   AD environment the moment one exists to point it at — commenting it out would just mean
   re-verifying all of this again later. Revisit only if a real AD domain is confirmed to be
   permanently out of scope for CASMARTS.
   **Import recipe for when a real AD domain becomes available** (not yet run against real
   data — this environment has no domain credentials or domain-joined host to collect from):
   1. Collect from a domain-joined Windows host (or any host with valid domain creds) using
      SharpHound (on-prem AD) or AzureHound (Entra ID/Azure AD) with `-CollectionMethod All` —
      produces a timestamped `<domain>_bloodhound.zip` of JSON files (users, groups, computers,
      ous, domains, gpos, containers).
   2. This stack has no BloodHound GUI, only raw `centinela-neo4j` — import the zip directly via
      Bolt with the community `bloodhound-import` CLI (`pip install bloodhound-import`), no GUI
      needed:
      `bloodhound-import --username neo4j --password <NEO4J_PASSWORD> --uri bolt://<host running centinela-neo4j>:7687 <path-to-zip-or-extracted-json>`
      (`NEO4J_PASSWORD` / `NEO4J_URI` are already the env vars `centinela-ai`/`centinela-backend`
      read — see the per-container env var gotcha below.)
   3. Verify the import landed: `MATCH (u:User) RETURN count(u)` should return a real non-zero
      count — this is the exact same query `process_bloodhound_paths()` already runs to decide
      whether to skip, so a successful import is immediately picked up on its next 10-minute
      cycle with no restart needed.
   4. Register the AD domain itself as an asset in `infra_inventory` (`asset_name` containing
      "active directory" or `asset_type` containing "domain") — required for a found attack path
      to be attributed to a real asset instead of being logged with a warning and dropped (see
      the asset-attribution bug fixed above).
8. **CTI/IoC feed ingestion** — **✅ real**. `core/cti_feed.py` queries abuse.ch's Feodo
   Tracker (free, public, no auth) for currently-active C2 server IPs, cached hourly.
   `run_cti_correlation_loop()` in `centinela.py` cross-references two real sources: registered
   asset IPs (`infra_inventory`) and IPs mentioned in `runtime_alerts` (Falco/Zeek output
   already ingested elsewhere) — a hit on the first means one of our own hosts' IPs is a known
   C2 server, a hit on the second means a runtime alert involved a connection to one. The
   `runtime_alerts` side has nothing to check today (0 rows — no Falco/Zeek alert has fired yet
   in this deployment) but the mechanism is real and starts working the moment they do. Verified
   live end-to-end with a disposable test asset set to a real IP from the live feed.
9. **Virtual/autonomous patching** — **✅ real, narrower scope than the original vision**.
   `generate_ip_block_virtual_patch()` blocks a CTI-confirmed-malicious IP at the reverse-proxy
   layer (`deny <ip>;`) without touching application code or restarting the service, reusing the
   exact nginx-detection pattern already verified for the ZAP header fix. A true per-URL/
   per-CVE virtual patch (blocking a *specific* vulnerable endpoint) was considered and
   deliberately not built: unlike `add_header`/`proxy_hide_header`/`deny`, an nginx `location`
   block only takes effect inside the correct existing `server{}` block for the target vhost —
   blindly inserting one into a separate additive conf.d snippet either does nothing (wrong
   context) or requires editing the existing vhost file directly, which is not purely additive
   and risks breaking it. `deny` at the `http` context level applies to every server block via
   normal nginx directive inheritance, the same safe mechanism the header fix already relies on.
10. **Emergency Host Containment** — **✅ real**. `POST /api/host-containment/{asset_name}`
    creates a `HOST-CONTAINMENT-REQUEST` finding that flows through the *exact same*
    correlate → human approval → Sentinel execution pipeline as every other remediation in this
    system — it does not execute anything directly. The generated script (in
    `generate_heuristic_script()`) backs up current firewall rules to the target host before
    applying a deny-all-except-DNS/NTP lockdown, and deliberately has no automatic rollback —
    an emergency containment should not be able to undo itself. Verified the request-creation
    and script-generation path live against a disposable test asset; never approved/executed
    against a real host (that action is genuinely disruptive and must be a deliberate human
    decision made through the real SOAR UI, not something to fire during verification).

## Architecture

Everything runs via `docker-compose.yml`, one service per concern, all bind-mounting the repo
root (`.:/app`) so code changes are live without a rebuild — **except compiled Python
bytecode** (see Gotchas below) and anything baked at image-build time (system packages, pip
installs not in `requirements.txt`/the Dockerfile's own pip list).

| Service | Entry point | Role |
|---|---|---|
| `centinela-ai` | `centinela.py` | Orchestrator: discovery loop, all scanner dispatch (`auditors/auditor_ext.py`), AI correlation loop, Falco/Zeek/BloodHound ingestion |
| `centinela-backend` | `main.py` (FastAPI/uvicorn) | REST API the frontend talks to, PDF reports, health check, Wazuh agent actions |
| `centinela-sentinel` | `sentinel.py` | Executes *approved* remediations via Ansible, marks vulns `RESOLVED` |
| `centinela-frontend` | Vite/React | Dashboard UI |
| `centinela-neo4j` | — | BloodHound/AD attack-path graph |
| `centinela-zeek` | — | Network IDS sensor (writes to `/usr/local/zeek/logs`, must run with `working_dir` set there or logs go to `/` and never reach the app) |
| `wazuh-manager` (container name `casmarts-core-wazuh-manager`) | — | Wazuh EDR manager, added 2026-08-04. Ports 1514/1515/55000 published to the host so remote agents and the host's own `wazuh-agent` (systemd) can enroll. |

### External dependencies (NOT part of this docker-compose stack)

- **Postgres `centinela_db`** — on a separate server, `10.4.3.23`. This is the shared source of
  truth; see the phantom-deployment gotcha below.
- **HashiCorp Vault** — on `10.4.3.208` (`casmarts-core-vault`, part of a *different* project,
  `core-casmarts`). Stores Ansible sudo passwords / SSH keys per asset, never the DB.
- **Authentik** (SSO) — also on `10.4.3.208`.

Auditors that shell out to external tools (nuclei, trivy, nmap, sqlmap, semgrep, prowler,
medusa, trufflehog, checkov, syft/grype) expect those binaries in the image — see the two
Dockerfiles. `auditor_zap.py` runs ZAP via `docker run` on the host's Docker socket instead of
being baked into the image.

## Common tasks

```bash
# Rebuild after touching requirements.txt or either Dockerfile
docker compose build centinela-ai centinela-backend
docker compose up -d centinela-ai centinela-backend

# After a refactor that moves/renames .py files, always clear stale bytecode first:
find /opt/centinela-ai -iname "__pycache__" -type d -exec rm -rf {} +
docker restart centinela-ai centinela-backend centinela-sentinel

# Full health check
curl -s http://127.0.0.1:8302/api/health | python3 -m json.tool

# Ansible against inventory.ini hosts — keys live at /app/keys/*.key inside the
# container (bind-mounted from ./keys/), NOT /app/*.key.
docker exec centinela-backend bash -c "cd /app && ansible all -i inventory.ini -m ping"
```

## Gotchas (learned the hard way, 2026-08-04)

1. **Stale `__pycache__` survives refactors.** Because `/app` is a live bind mount, editing a
   `.py` file is *usually* enough — but leftover `.pyc` files from before a big rename/refactor
   can get treated as up to date and keep executing old logic even after a restart. If behavior
   doesn't match what the source says it should, clear `__pycache__` everywhere and restart.
   Verify what's actually loaded with:
   `docker exec <c> python3 -c "import inspect,<mod>; print(inspect.getsource(<mod>.<fn>))"`

2. **Check for phantom duplicate deployments before assuming a bug is "still not fixed."**
   `centinela_db` is shared across servers. A second, orphaned copy of this whole stack ran on
   `10.4.3.208` for 4+ days after this repo was migrated to its current host, silently
   corrupting shared data no matter what got fixed here. If a bug persists despite a verified,
   in-memory-confirmed clean fix, check `SELECT pid, client_addr, query FROM pg_stat_activity
   WHERE datname='centinela_db'` for a `client_addr` you don't recognize.

3. **`vulnerability_log` has no unique constraint** beyond the `id` primary key. Any insert
   path that doesn't explicitly dedupe by `(asset_id, cve_id)` before inserting will happily
   create infinite duplicates on every scan cycle. `ON CONFLICT DO NOTHING` without a matching
   constraint is a silent no-op, not a safety net.

4. **`/api/inventory`'s vulnerability count must use `COUNT(DISTINCT v.id)`**, not `COUNT(v.id)`
   — the query LEFT JOINs `vulnerability_log` to both `remediation_history` and
   `runtime_alerts`, and a plain `COUNT` gets inflated/distorted by that fan-out.

5. **Per-container env vars, not just `.env`.** `docker-compose.yml` explicitly lists env vars
   per service; a var only being set for one service (e.g. `NEO4J_URI` was only on
   `centinela-ai`, not `centinela-backend`) silently breaks that *other* service even though
   `.env` "has it."

6. **Never infer "found nothing" from `subprocess.run(...).stdout` being non-empty.** CLI
   scanners print banners/warnings to stdout unless explicitly silenced. `scan_appserver()`'s
   nuclei call was missing `-silent` (every other nuclei call in the file has it), so
   `if result.stdout: found_vulns = True` was true on *every* run (banner text), the code then
   tried to `json.loads()` each banner line, failed silently, and never wrote a real finding
   *or* the "clean scan" fallback message — total silent data loss for every SERVER asset, for
   who knows how long. Fixed by always passing `-silent` and only setting `found_vulns = True`
   inside the successful-parse branch (matches the already-correct pattern in `scan_url()`).

7. **`docker-compose.yml` env var edits need a container recreate, not a source edit.** Learned
   from the Vault incident's own postmortem note: "un contenedor ya corriendo NO relee su propio
   `environment:`". This applies here too — any `docker-compose.yml` env change needs
   `docker compose up -d <service>` (recreate), a plain `docker restart` is not enough.

8. **The root-level reorg (`.py`/`.yml` files moved into packages) missed some hardcoded path
   references outside the moved files themselves.** `sentinel.py` still pointed at
   `/app/remediate_wildfly.yml` and `/app/remediate_generic.yml` (both moved to
   `remediation/playbooks/`), so **every single approved remediation failed** with
   `the playbook: ... could not be found` — silently, since `sentinel.py`'s failure path just
   logs it and moves on. After a reorg, grep the whole tree for the old paths of anything that
   moved, not just check the moved file's own new location works.

## Known open issues (as of 2026-08-04, updated 2026-08-07)

- ~~A full "is everything at 100%?" audit found the AI correlation pipeline was quietly
  starving itself, and Sentinel was crashing intermittently~~ — **resolved 2026-08-07**, in
  response to a direct user request to verify the whole stack end-to-end rather than trust the
  docs. Live DB/log inspection (not just re-reading this file) found several real, compounding
  bugs, all now fixed and verified live:
  1. **`log_finding_deduplicated()`'s `preserve_status` flag (see item 3 above) was only ever
     used by 2 of 9 real call sites.** `auditor_zap.py` — 68% of every finding in the DB —
     reset a finding's `status` back to `NEW` on **every single re-detection**, even one already
     `CORRELATED` by the AI. Since ZAP re-scans the same few AppServers roughly every 10–15
     minutes, this meant the same already-analyzed findings got shoved back into the
     AI-correlation queue forever, which (a) burned through Groq's small daily token quota
     almost immediately every day, confirmed live in logs (`Used 99509, Limit 100000` within the
     first scan cycles), and (b) meant `centinela.py`'s idle-branch background scan (SAST/SCA/
     Standards) *never ran*, because the queue it waits on to empty never actually emptied.
     Fixed by adding `preserve_status=True` to `auditor_zap.py`, `auditor_master_vulnerabilities.py`,
     `auditor_sca_dependencies.py`, `auditor_compliance_standards.py`, `auditor_medusa.py`,
     `auditor_secrets.py`, `auditor_spiderfoot.py`, and the 4 CTI-feed/BloodHound call sites in
     `centinela.py`. Verified live: the correlation queue, which had been stuck non-empty across
     the entire visible log history, drained from 20 genuinely-new rows to 11 within minutes of
     the fix, processing real distinct findings instead of looping on the same ones.
  2. **The idle-branch background scan was auditing the wrong target.** `run_master_vulnerability_scan()`
     etc. default to `target_dir="/opt/centinela-ai"` (Centinela's own source) and `asset_id=None`
     when called with no arguments — which is exactly how `centinela.py`'s idle branch called
     them, so it had never once audited any of the 66 real `GitLab-Repo` customer assets, only
     ever the platform's own code (with nowhere valid to even attribute a finding to). The real,
     already-working, token-authenticated implementation (`GitLabIntegrator.scan_all_projects()`,
     clones each project and calls the same three auditors with the correct `target_dir`/`asset_id`
     per repo) existed but was wired **only** to the manual `POST /api/gitlab/scan` endpoint, never
     to anything periodic. Fixed by pointing the idle branch at it instead. Verified live: the next
     idle cycle after the fix produced real `🔄 [GitLab-Integrator] Pulled latest changes for
     arquitectura/core-casmarts` / `🔍 Auditing GitLab Project...` log lines against real projects,
     something 44+ hours of prior logs had zero instances of.
  3. **`vulnerability_log.url_path` (the real file:line location `auditor_master_vulnerabilities.py`
     etc. already compute) was never selected by the main correlation query** in `centinela.py`
     (`SELECT v.id, v.cve_id, v.severity, v.description, i.asset_name, i.asset_type, i.endpoint...`
     — no `v.url_path`). Every single GitLab-Repo (SAST/SCA/Standards) finding's AI prompt has
     been telling the LLM "Ubicación (archivo:línea): desconocida" instead of the real location,
     even though the prompt explicitly asks for a `git apply`-ready diff *at that exact location*.
     Fixed by adding `v.url_path` to the SELECT.
  4. **`core/db_manager.py`'s connection pool recycled dead connections instead of discarding
     them**, root-causing Sentinel's intermittent `❌ [Aura-Sentinel] Error in main loop:
     connection already closed` crashes (present in logs since before this session, self-healing
     only because the whole container got restarted, never because the code recovered).
     `get_db_connection()`'s `finally: db_pool.putconn(conn)` ran unconditionally — if Postgres
     had closed the connection server-side (idle timeout, network blip), the pool got the dead
     connection object back anyway and would later hand that exact same poisoned connection to a
     *different*, unrelated caller, who'd immediately fail. This is a shared module imported by
     all three Python services (`centinela-ai`, `centinela-backend`, `centinela-sentinel`), so
     the same latent failure mode existed in all three, just visibly crashing only in Sentinel's
     loop. Fixed with the standard psycopg2 idiom: `db_pool.putconn(conn, close=bool(conn.closed))`,
     plus guarding `conn.rollback()`/`cur.close()` in `get_db_cursor()`'s exception path so a
     rollback failure on an already-dead connection can't mask the real underlying error.
  5. **Groq → NVIDIA NIM → Google Gemini → heuristic cascade added**, replacing the old design
     where exactly one provider was chosen at process startup and stuck with for the container's
     whole lifetime — once that one provider's daily quota ran out, every subsequent finding for
     the rest of the day fell straight to the heuristic engine even if other providers' keys were
     configured and had headroom. `centinela.call_ai_cascade()` now tries all three, in order, on
     every single call. Also deleted a related dead-code path: `correlate_vulnerability()`'s
     exception handler had an old "Vertex quota → fall back to Groq" branch that referenced a
     variable named `prompt` which never existed in this function (the real variable is
     `prompt_text`) — it would have thrown its own `NameError` on every attempt, silently
     swallowed by its own inner `except`. It had never worked and is now gone.
     **Live-verified 2026-08-05: NVIDIA_NIM_API_KEY and GOOGLE_API_KEY were both invalid at the
     time** — confirmed via raw `curl` against each provider directly (not just the client
     library): NVIDIA returned `403 Forbidden — Authorization failed`, Google returned
     `400 API_KEY_INVALID`. Groq itself works but has a small (100k tokens/day) quota that's
     being hit early most days.
     **Resolved 2026-08-07**: user supplied fresh keys for both. Re-verified live with real
     `curl` calls against each provider directly before touching anything: NVIDIA's key worked
     immediately; Google's key was valid but `google_model_name`'s hardcoded default
     (`gemini-1.5-flash-latest`) 404'd — that model has been fully retired, confirmed via
     `GET /v1beta/models` against the new key, which lists only current-generation models
     (`gemini-2.5-*`/`gemini-3.x-*`, no `1.5` family at all). No `AI_MODEL_GOOGLE` env var was
     set, so the dead default was actually in use. Set `AI_MODEL_GOOGLE=gemini-3.1-flash-lite`
     in `.env` (best free-tier quota of the available current models per the user's own
     Google AI Studio rate-limit page: 15 RPM / 500 RPD) — confirmed this specific model answers
     `generateContent` with the new key via direct `curl` before wiring it in.
     `AI_MODEL_GOOGLE` isn't listed in `docker-compose.yml`'s explicit `environment:` block for
     `centinela-ai`, but all three Python services already have `env_file: .env`, so it passes
     through anyway — confirmed live rather than assumed. Recreated `centinela-ai`
     (`docker compose up -d`, not a plain restart — env var changes need a recreate, see gotcha
     #7) and confirmed all three `✅ ... provider initialized` lines in its logs. Then exercised
     `call_ai_cascade()` directly inside the running container (`docker exec ... python3 -c
     "import centinela; ..."`), not just each key in isolation: a normal call correctly used
     Groq; with `centinela.groq_llm` monkeypatched to `None` inside the running process it
     correctly fell through to NVIDIA; with both Groq and NVIDIA patched to `None` it correctly
     fell through to Gemini; with all three patched to `None` it correctly returned `None` (the
     signal `correlate_vulnerability()` uses to fall back to the heuristic engine). **The cascade
     now has all 3 real LLM tiers live**, not just Groq.
     **Same day, cascade order and timeouts fixed** after the user asked whether the "best"
     model was picked for NVIDIA/Groq too. It wasn't — the existing hardcoded defaults
     (`llama-3.3-70b-versatile` on Groq, `meta/llama-3.1-70b-instruct` on NVIDIA) were kept as-is
     from before this session. Tested real candidate "upgrades" against the actual correlation
     prompt before touching anything, and both were worse, not better: Groq's biggest model,
     `openai/gpt-oss-120b`, is a reasoning model — it spent its entire completion-token budget on
     hidden `reasoning_tokens` and returned zero actual output; NVIDIA's `meta/llama-3.3-70b-instruct`
     never responded at all within 150s+ (that specific NIM-catalog model appears cold/unavailable
     on NVIDIA's shared infra). Kept both existing defaults. Separately, timing the *current*
     default models on the real prompt found NVIDIA taking ~65s for a legitimate successful
     reply — much slower than Groq (~3s) or Gemini (~1s, and the only tier with true JSON mode
     via `response_mime_type="application/json"`, the other two rely on prose + regex
     extraction). Reordered the cascade from Groq→NVIDIA→Gemini to **Groq→Gemini→NVIDIA** so the
     slow/hang-prone tier is tried last, and added `request_timeout`/`max_retries` bounds to all
     three clients so a stuck provider can't stall the whole correlation loop. Two real bugs
     found while wiring this in, both caught by testing live rather than trusting the kwarg
     names: (1) first attempt passed `request_timeout=90, max_retries=1` to NVIDIA's `ChatOpenAI`
     — looked like a no-op at first (a naive `getattr(obj, "timeout", ...)` sanity check
     returned nothing, since the real pydantic field is named `request_timeout` with `timeout`
     only as an alias) but the kwarg itself was in fact being applied correctly; the real
     surprise was that `max_retries=1` means up to 2 attempts, so a 90s per-attempt timeout
     produced a genuine 180.9s worst-case failure, confirmed live with the same known-broken
     NVIDIA model used above, not 90s as intended. (2) Fixed by setting NVIDIA's `max_retries=0`
     — its observed failure mode (multi-minute non-response) is not the kind of transient blip a
     retry fixes, so retrying only doubles the time wasted before falling through to the next
     tier; confirmed live with a scaled-down 10s-timeout version that the fix bounds it to ~10s,
     not ~20s. Gemini's client got `http_options=types.HttpOptions(timeout=30000)` (milliseconds,
     confirmed via the field's own pydantic description — an easy unit mistake otherwise) and
     confirmed live that the value is actually threaded into `_api_client._http_options.timeout`.
     Groq kept `max_retries=1` (its own worst case is a bounded 60s, and Groq's real-world
     failures — quota exhaustion, rate limits — are exactly the transient kind a retry can help
     with, unlike NVIDIA's observed hang). Final config, confirmed live on the actual running
     `centinela-ai` process: Groq `timeout=30/retries=1`, Gemini `timeout=30s`, NVIDIA
     `timeout=90/retries=0`.
     **OpenRouter added as a 4th cascade tier, same day (2026-08-07)**, after the user asked
     about other free-tier AI providers and supplied a key. Two other candidates from that same
     conversation were evaluated and rejected before this: **Cerebras** — key is valid and its
     dashboard genuinely shows a real free quota (5 req/min·2,400/day, 30K tok/min·1M/day across
     `gemma-4-31b`/`zai-glm-4.7`/`gpt-oss-120b`) but every real completion call returns
     `payment_required` — an account-level billing gate on Cerebras' side, not fixable in code;
     left out of the cascade until the user resolves that on their account. **GitHub Models** —
     confirmed via GitHub's own current docs that the entire service (playground, catalog,
     inference API, BYOK) was retired 2026-07-30; not usable at all, correctly ruled out.
     For OpenRouter itself: chose the default model empirically, not from the vendor's marketing
     copy. Tested 3 free-tier candidates against the real correlation prompt as `ChatOpenAI`
     would actually call them (no artificial `max_tokens` cap, matching production): 1st attempt
     used a `curl`-only test with `max_tokens=1200`, which was misleading — `gpt-oss-20b:free`
     ran out of budget mid-reasoning (0 output), `gemma-4-31b-it:free` got an instant `429` from
     OpenRouter's own **shared upstream pool** (unrelated to this account's quota), and
     `nvidia/nemotron-3-super-120b-a12b:free` got partway through a visible chain-of-thought
     preamble but never reached real JSON within the cap. Re-tested the two survivors through
     the actual `langchain_openai.ChatOpenAI` class with no token cap: nemotron-3-super answered
     in 18.6s with clean, direct, correctly-shaped JSON (no fence, no visible reasoning
     preamble); gpt-oss-20b took 60.7s and wrapped its answer in a ` ```json ` fence (parseable
     by the existing regex, just slower and messier). Picked `nvidia/nemotron-3-super-120b-a12b:free`
     as `AI_MODEL_OPENROUTER`'s default on that basis. Placed last in the cascade (Groq → Gemini
     → NVIDIA → OpenRouter), since it's the least predictable of the four (shared-pool 429s
     unrelated to this account, 12-60s response times observed) — same `timeout=90/max_retries=0`
     reasoning as NVIDIA's tier. Verified live end-to-end on the real running process: normal
     call hits Groq; with Groq/Gemini/NVIDIA all monkeypatched to `None`, correctly fell through
     to OpenRouter (12.6s, correct content); with all four `None`, correctly returned `None`
     (heuristic fallback signal). **The cascade now has 4 real LLM tiers**, not 3.
   9. **Background Asset Live Status Verifier (`poll_asset_status`) & Offline Differentiating Statuses** —
      **✅ real and live-verified**. Added background worker `poll_asset_status()` in `main.py`
      running every 10s on `startup_event`. Added `last_seen` timestamp column to `public.infra_inventory`.
      Performs live ICMP ping checks, updates `last_seen = NOW()` in PostgreSQL whenever an asset is
      online/active, and broadcasts real-time `asset_status_update` events over WebSockets (`/api/ws/alerts`).
      Updated `Dashboard.jsx` to process WebSocket status events in real-time without page reload, and
      differentiate visual status into 3 distinct states: **`Sincronizado`** (online / agent active),
      **`Offline (Desconectado)`** (previously connected asset with last_seen timestamp in tooltip),
      and **`Offline (Sin Conexión Previa)`** (newly registered asset that has never connected).
  6. **One-time backfill launched for findings that only ever got the generic/no-specific-rule
     heuristic fallback text** (`"Hallazgo DAST sin regla determinística"`, `"Hallazgo de código
     fuente:"`, `"Hallazgo de seguridad sin regla de remediación específica"` — 669 rows
     identified live via these exact markers; the heuristic branches with a real, specific,
     already-good deterministic answer — ZAP header fixes, Docker non-root fix, SCA version
     bump, SSH/firewall hardening — were deliberately left alone, re-running those through an
     LLM wouldn't improve them). 25/669 got a real upgraded analysis before Groq's daily quota
     ran out mid-run; the script correctly detected 15 consecutive all-providers-down responses
     and stopped itself rather than grinding through the remaining ~629 producing no-op
     rewrites. Re-runnable once Groq's quota resets or NVIDIA/Google keys are fixed.
  7. **CIS Benchmarks was genuinely on-demand-only with zero scheduling** — `/api/health`
     honestly reported `"Available (On-Demand, Not Yet Run)"` because nothing had ever called
     it automatically. Added `run_cis_benchmark_loop()` in `centinela.py`: real, read-only SSH
     checks against every `SERVER`/`AppServer` asset (excluding Wazuh-agent-only assets with no
     resolved IP yet), re-checking any asset not audited in the last 7 days. `log_cis_findings()`
     now always writes a `CIS-BENCHMARK-AUDIT` completion marker (pass **or** fail) so the
     scheduler can tell "never checked" apart from "checked recently, all green" from the
     marker's own `detected_at`, without needing a new schema column — the same pattern
     `threat_intel_checked_at` already uses. Verified live: `/api/health`'s CIS Benchmarks entry
     flipped from the honest-but-idle string to a real `Online` within the first loop iteration
     after restart, backed by a real `chat: grade F (36.4%)` audit result.
  8. **Host Containment: verified the request → correlate → approve pipeline live** (per explicit
     user instruction: verify only, do not approve/execute against a real host) — and the live
     test itself caught a real, separate safety bug. Asking the generic LLM prompt to "fix"
     `HOST-CONTAINMENT-REQUEST` (a synthetic system marker, not a real scanner finding) made Groq
     hallucinate an unrelated WildFly/JMX script with `can_automate: true` — the SOAR UI would
     have offered a human a one-click "fix" that does nothing relevant to actual containment, on
     a host that may not even run WildFly. `generate_heuristic_script()` already has correct,
     purpose-built logic for exactly this case (backs up firewall rules, applies a real
     deny-all-except-DNS/NTP lockdown) but was never reached because the LLM returned *some*
     content, however wrong. Fixed by skipping the LLM cascade entirely for cve_id values that
     are Centinela's own synthetic/system markers (`HOST-CONTAINMENT-REQUEST`, `CTI-IOC-MATCH-*`,
     `BLOODHOUND-PATH-*`, `SCAN-AUDIT`, `HEURISTIC-SECURITY-DEBT`, `CIS-BENCHMARK-AUDIT`) and
     routing straight to the heuristic generator, which already has real, correct answers for
     every one of them. Verified live end-to-end against a disposable test finding on the
     `centinela` host itself: request created → real pipeline correlated it → correct firewall
     lockdown script generated, `PENDING_APPROVAL` — never approved, and the test finding/script
     were deleted afterward, matching this project's standing rule of never triggering actual
     host containment outside a deliberate human decision in the real SOAR UI.

  **Resolved 2026-08-13**: the deferred re-run was launched for real. By the time it was
  launched, natural traffic through the now-fixed cascade had already worked the backlog down
  from ~629 to 63 remaining rows (re-detections, GitLab re-scans, etc. flowing through the
  already-fixed pipeline in the days between 2026-08-07 and 2026-08-13) — confirmed live by
  re-querying the exact marker text this whole backfill targets before launching anything. See
  the 2026-08-13 entry below for the real run and its evidence.

- ~~Some AI-generated ZAP remediation scripts contained no real content~~ — **resolved
  2026-08-06**, in response to a real user report ("para algunos zap no estaba generando
  scripts de remediación"). Confirmed by reading the actual script files on disk: some
  contained the raw internal placeholder default `# Sin script de remediación`, others
  contained literal LLM laziness like `#!/bin/bash ... (script proporcionado)` or
  `... (contenido del script)` — the LLM described providing a script instead of actually
  writing one, and nothing validated the output before writing it to `script_path` and, in
  some cases, marking `can_automate=true` (the SOAR UI would have offered to auto-execute a
  file with no real commands in it). Root cause: `correlate_vulnerability()`'s `pick()` helper
  only checked for emptiness/null-like strings, not whether the content was actually usable.
  Fixed by adding `is_placeholder_text()` (rejects content that, after stripping a shebang, is
  just an ellipsis with an optional placeholder parenthetical, or under 15 chars) and falling
  through to the same deterministic heuristic generator used when the LLM never responds at
  all, instead of accepting garbage. Confirmed live: 19/1806 script files on disk matched this
  pattern (not ZAP-only — also hit `CODE-INJECTION-EVAL`, `SCA-CVE-*`, `STD-ISO25010-*`,
  `DOCKER-MISSING-NON-ROOT-USER`, `HEURISTIC-SECURITY-DEBT`), plus a separate, related issue:
  207 `scan_engine='zap'` rows were still showing the old generic `"Exposición de Seguridad -
  <cve_id>"` risk name from before an earlier `generate_heuristic_analysis()` fix, never
  backfilled because `correlate_vulnerability()` only ever processes `PENDING`/`NEW`/
  `AI_FAILED`/`AI_ERROR` rows and permanently skips anything already `CORRELATED`. Both sets
  (226 rows total) were reprocessed with a one-time backfill script through the now-fixed
  logic — 226/226 succeeded (0 failed), verified live: all 4 originally-inspected broken script
  files now contain either real remediation commands or an honest "no deterministic rule
  available for this finding type" message, and both the placeholder-script and stale-template
  DB queries now return 0 rows. (Backfill ran mostly against Groq's exhausted daily token quota
  — expected and already documented elsewhere in this file — so most rows landed on the honest
  heuristic engine rather than a fresh LLM analysis; that's correct behavior, not a shortcut.)
- ~~`/api/health` and the PDF reports didn't reflect anything built this session~~ — **resolved
  2026-08-06**, in response to a direct user request to verify dashboard/report completeness.
  `/api/health`'s `services` list (the array the frontend's "Salud del Ecosistema" view actually
  renders — a separate `scan_modules` dict existed in the same response but nothing in the
  frontend ever read it) had no entry at all for Risk Intel (EPSS/KEV), CTI feed, MITRE ATT&CK
  mapping, CIS Benchmarks, GitLab Auto-Fix, or Host Containment — every capability added earlier
  this session was invisible in the UI. Added real, evidence-based checks for each (DB evidence
  of recent activity for the background loops — e.g. CTI feed liveness is inferred from the Zeek
  conn-log heartbeat rather than requiring an actual C2 match, since "no malicious traffic seen"
  is the hoped-for-normal state, not a health signal; on-demand-only capabilities like CIS
  Benchmarks honestly report "Available (On-Demand, Not Yet Run)" instead of a fake "Online"
  before ever being exercised). The frontend's status-dot logic previously only recognized
  exactly `'Online'`/`'Active'` as green and treated everything else — including these new
  honest "available but idle" strings — as the same red as a genuine outage, and separately
  always rendered the status *text* in green regardless of the dot color (a pre-existing,
  unrelated inconsistency). Added a three-tier `healthStatusTier()` (ok/warn/fail) so idle
  on-demand capabilities render amber, not a false red alarm next to real failures, and made the
  text color match the dot. The executive PDF report (`/api/reports/executive`) previously
  computed its own crude `"ALTO" if critical>0 else...` risk bucket instead of using the real
  Centinela Risk Score already computed by every finding — replaced with a bucket driven by the
  real max CRS and CISA KEV-exploited count, and added real KPI cards (CISA KEV count, SLA
  breaches, max CRS, CTI/IoC matches) plus a top-5 MITRE ATT&CK techniques table, all from live
  queries verified against the real PDF output (`pdftotext`), not mocked data.

- ~~`/api/health` showed Wazuh Manager "Unreachable" and Zeek "No Recent Data" despite both
  being genuinely healthy~~ — **resolved 2026-08-06**. Two unrelated causes:
  1. Wazuh's API genuinely takes longer than the health check's 3s timeout to respond, even to
     an unauthenticated request — confirmed live it reliably answers (401, meaning it's
     actually up, the check doesn't inspect status codes) within ~15s. The manager was never
     actually down; the check was just too impatient. Bumped to 12s.
  2. Zeek itself was completely healthy and actively writing real connection data to
     `conn.log` (confirmed live: 108KB, updated seconds before being checked) via a correctly
     working, correctly mounted read-only volume (`zeek-logs:/app/logs/zeek`) — but
     `process_zeek_alerts()` only ever watched `notice.log`, which Zeek only writes when
     something already looks notice-worthy by its own built-in policy, and never existed in
     this deployment. The rich per-connection data was completely unused. Added
     `process_zeek_conn_log()` (`centinela.py`): tails `conn.log` in real time, checks every
     connection's source/destination IP against the live CTI feed (see the Omni-XDR section's
     CTI item above), and logs a real, honest activity heartbeat every 5 minutes (an actual
     count of connections observed, not a fake ping) so the health check reflects genuine
     pipeline activity rather than only "was something bad found in the last 24h". Verified
     live end-to-end: a real heartbeat fired after 5 minutes with a real connection count, and
     the health check flipped to Online.

- ~~AI remediation reports/scripts were generic instead of detailed~~ — **resolved same day**:
  `correlate_vulnerability()` in `centinela.py` only ever tried `genai_client` (Google, failing)
  and fell straight to the deterministic template — it never called `llm`, even though a
  provider (`nvidia_nim`) was successfully initialized at startup. Root cause was two bugs in
  provider selection: `AI_PROVIDER_ORDER`'s hardcoded default always tried `nvidia_nim` first
  regardless of `AI_PROVIDER=groq` in `.env`, and `nvidia_nim` reused `AI_MODEL` (a Groq-style
  name, `llama-3.3-70b-versatile`) that doesn't exist in NVIDIA's catalog, so it 404'd on every
  call. Fixed both, and added a real `llm.invoke()` middle tier before the template fallback.
  Verified live: findings now get genuinely differentiated output (e.g. a clean scan on `prism`
  correctly gets `can_automate=false` and a real summary, not the same firewall-hardening
  boilerplate every finding used to get regardless of type — that boilerplate had even been
  showing up on GitLab SAST findings, which makes no sense for a code repo).
- **When the LLM doesn't return strict JSON**, the existing prose-fallback regex parser in
  `correlate_vulnerability()` (`extract_section()`) sometimes produces thin/generic content
  because its label patterns (`**Riesgo detectado**`, etc.) don't match Groq's actual prose
  formatting in every case. Not fixed — would need inspecting real non-JSON Groq responses to
  tune the regexes, or tightening the prompt further to force JSON compliance.
- ~~Vault is sealed~~ — **resolved same day**: the user recovered/rotated the root token after a
  Vault re-init (`ROOT_TOKEN` in `core-casmarts/vault/vault-init-keys.txt` on 10.4.3.208) and
  updated `.env`. `Secrets Backend (Vault)` now reports Online and `client.is_authenticated()`
  is `True`. No stored secrets exist yet under `casmarts/ansible/*` — that's expected, nobody
  could write there while it was sealed; `has_vault_secret` will start turning `true` per-asset
  as credentials get added via "Añadir Activo" / the vault-secret endpoint going forward.
- ~~ZAP DAST silently never ran~~ — **resolved 2026-08-04, the hard way**. First layer:
  `auditor_zap.py` referenced `owasp/zap2docker-stable:latest`, a Docker Hub image that no
  longer exists, so every attempt threw `ZAPNotAvailableError` and silently fell back to
  nuclei-only. Fixing just the image to `zaproxy/zap-stable:latest` was nowhere near enough —
  live-testing a real scan end-to-end (`auditor_zap.run_zap_scan(...)`) surfaced **eight more
  real, independent bugs stacked on top of each other**, meaning ZAP had in all likelihood
  *never once* worked in this deployment. In the order they were found:
  1. `docker run` had no `-d` — it ran attached in the foreground, so the launch call just hung
     until its own 30s timeout on every single attempt, regardless of anything else.
  2. `-p {port}:8090` published to the wrong container-side port — this image listens on 8080,
     not 8090 (the old `zap2docker-stable` image's default).
  3. **Fundamental**: `docker run` here goes through the mounted `docker.sock`, which makes ZAP
     a *sibling* container on the host's Docker daemon, not a child of `centinela-ai`. A
     `-p host:container` mapping binds on the **real host's** interfaces — `localhost` from
     inside `centinela-ai` can never reach it, no matter what host port is used. Since both
     containers share `aura-network`, the fix is to address ZAP by its container name (Docker's
     built-in per-network DNS) instead of any `localhost:<port>` — dropped host port publishing
     entirely, everything now goes through `http://<container_id>:8080`.
  4. The addon/config cache volume was mounted at `/root/.zap/db`, but this image runs as uid
     1000 ("zap", `$HOME=/home/zap`) and downloads all its addons to `/home/zap/.ZAP/plugin/*`
     on every cold start — `/root/.zap/db` was never on this image's write path at all, so
     nothing was ever actually cached (~40s of addon downloads on *every* launch).
  5. Fixing the mount path to `/home/zap/.ZAP` then failed with "The home path is not
     writable": the bind-mount source is auto-created by the **host's** dockerd (owned by
     root) the first time it's referenced — another docker-outside-of-docker gotcha, since
     `os.makedirs()` from inside `centinela-ai` only touches *its own* filesystem, not the real
     host path `docker run -v` resolves against. Fixed by `chmod`-ing the mount source via a
     disposable `busybox` container before ever starting ZAP.
  6. Sharing one cache directory across concurrent scans then failed differently: "The home
     directory is already in use" — ZAP takes an exclusive lock on its home dir, so concurrent
     scans can't share a cache path at all. Switched to one subdirectory per scan (accepting the
     ~40s addon re-download per scan as a real characteristic of this tool, not a bug).
  7. ZAP bound its API to `127.0.0.1` inside its own container by default — its own Docker
     `HEALTHCHECK` (which `curl`s `localhost` from inside) reported "healthy" while every other
     container on `aura-network` got connection refused reaching it by name. Fixed with
     `-host 0.0.0.0`.
  8. Even reachable, ZAP separately rejected every request as "not permitted" — it allowlists
     API request origins by `Host` header independently of `api.disablekey`. Fixed with
     `-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true` (ZAP's documented way to
     permit any origin).
  9. The readiness probe itself called `core/**action**/version` — "version" is a **view**
     (read-only), not an action, in ZAP's API taxonomy, so it 400'd on literally every request,
     meaning the code could never detect ZAP was actually up even after fixes 1–8 landed.
  10. The active-scan call passed `scanPolicyName: context_config["profile"]` — our own internal
      profile names (`light`/`balanced`/etc., see `ZAPScanProfile`) aren't real ZAP scan-policy
      names (`"Default Policy"`, `"Pen Test"`, etc. — confirmed via
      `/json/ascan/view/scanPolicyNames/`), so every active scan failed with `does_not_exist`.
      Fixed by omitting the param entirely (ZAP falls back to its own default policy); our
      profiles still control timeout/depth/rule-count via `context_config` elsewhere.

  Verified with a real full scan end-to-end (`launch → spider → active scan → alerts →
  cleanup`) against a live target: completed in ~65s, spider found 3 URLs, active scan reached
  100% and returned a real (in this case empty) findings list — not a masked failure.
- ~~**11th ZAP bug, found incidentally while debugging Medusa**: every single ZAP finding was
  logged with the identical generic `cve_id` "ZAP-ZAP-UNKNOWN"~~ — **resolved 2026-08-05**.
  `retrieve_zap_alerts()` read `alert.get("pluginid", "ZAP-UNKNOWN")`, but ZAP's real REST API
  returns the key as `pluginId` (camelCase) — the lowercase lookup always missed, so every
  finding fell back to the same default, and `log_zap_findings()`'s own `f"ZAP-{code}"` prefix
  then doubled it to `ZAP-ZAP-UNKNOWN`. Confirmed via 180 already-logged real findings on
  `casmart_authentik`: `cweid`/`wascid` (correctly cased in the code) were populated on every
  single row, `pluginid` never was — 100% consistent with a pure key-casing miss, not missing
  data from ZAP. Also caused a secondary symptom that looked like a runaway loop: with 180
  distinct real findings all sharing one identifier, the AI correlation engine's log lines
  (`Senior Audit analysis for ZAP-ZAP-UNKNOWN on casmart_authentik...`) looked identical on every
  line even though it was correctly working through 180 distinct rows — pure log-message
  confusion caused by the same underlying bug, not an actual infinite loop. Fixed by reading
  `pluginId` first (falling back to the old lowercase key, then a bare `"UNKNOWN"` with no
  redundant prefix). The 180 already-logged rows keep their old generic `cve_id` — they're real,
  legitimate findings (confirmed 180/180 distinct URLs, not duplicate spam), just mislabeled;
  no safe way to backfill the real `pluginId` without re-scanning, and re-scanning `casmart_authentik`
  again wasn't attempted here (live active-scans need separate authorization each time). Left as
  a known cosmetic gap: those specific rows will keep their generic ID until next rescan.
- ~~`prism`/`chat` had no known SSH credentials~~ — **resolved 2026-08-04**: user supplied
  passwords for `kiwi@10.4.3.30` (prism) and `chatbotpdf@10.4.3.31` (chat) and authorized
  installing this server's own public key (already in this host's `~/.ssh/authorized_keys`,
  same key as `casmarts.key`/`casmart.key`, comment "CASmartS") onto any host missing it.
  Installed via `sshpass` + append to `~/.ssh/authorized_keys` on both. **Gotcha**: on `chat`
  the existing `authorized_keys` line had no trailing newline, so the naive append merged onto
  it and corrupted both keys — always `cat`/inspect the file after appending to a
  possibly-single-line `authorized_keys`, don't assume `echo ... >>` is safe. Fixed by inserting
  a newline between the two keys (backup left at `~/.ssh/authorized_keys.bak` on `chat`). Both
  hosts turned out to already have `wazuh-agent` preinstalled — just needed pointing at the
  manager and starting. Added to `inventory.ini` and Vault (`ssh_private_key`), verified active
  both locally (`systemctl is-active`) and from the manager (`agent_control -l`).
- ~~`casmartsuperset` had no known credentials~~ — **resolved 2026-08-04**: the username was
  literally `casmartsuperset` all along; the earlier failures were because the password has a
  trailing period (`gNng898u.`) that wasn't included in the first attempts. Installed the shared
  key, added to `inventory.ini`/Vault, and set up Wazuh. Its `ossec.conf` turned out to still be
  pointed at the old dead manager (`10.4.3.28`) from before this project's migration, and the
  manager had a **stale agent registration from an earlier silent self-enroll attempt** under
  the same name — `wazuh-agentd` kept cycling "Duplicate agent name" until that old registration
  was removed (`manage_agents -r`) and the agent's `client.keys` cleared to force a clean
  re-enrollment. All 7 SERVER assets now confirmed with an active Wazuh agent, both locally
  (`systemctl is-active`) and from the manager (`agent_control -l`).
- ~~`discovery.py`'s fuzzy asset-name matching produced a real false positive~~ — **resolved
  2026-08-13**. The Wazuh agent named `compramex` (an OS hostname) substring-matched a *GitLab
  repo* asset (`GitLab/edomex-casmart/compramex/...`, itself named after the same product)
  purely because the word "compramex" appears in both, wrongly tagging that repo with a Wazuh
  `agent_id`. Separately, the agent named `kiwi` (prism's real hostname) matched nothing at all
  since "kiwi" and "prism" share no substring, and would have created a duplicate asset on the
  next discovery run. Restricting the fuzzy tier to `SERVER`/`AppServer` assets with an agent
  name ≥5 chars closed the GitLab false-positive but never fixed the "hostname has zero lexical
  relation to the business name" case — this needed the hostname↔asset_id mapping captured at
  install time instead of guessed later from a name string, which is what actually landed today:
  added a real `hostname` column to `infra_inventory`; `install_wazuh_agent_background()`
  (`main.py`) now runs a real `ansible ... -m command -a hostname` immediately after a
  successful install and stores the ground-truth hostname against the asset it just provisioned;
  `discover_wazuh_agents()` (`discovery.py`) checks this column as an exact-match tier before
  falling back to name matching and the fuzzy tier. Verified live end-to-end: read-only
  `ansible ... -m command -a hostname` against all 5 currently-reachable hosts confirmed real
  hostnames (`kiwi`→10.4.3.30/prism, `chatbotpdf`→10.4.3.31/chat, `casmartsuperset`→10.4.3.25,
  `casmartbd`→10.4.3.23, `authentik`→10.4.3.208), backfilled onto the matching `infra_inventory`
  rows by IP, then a real `discover_wazuh_agents()` run correctly resolved all 8 currently
  Wazuh-enrolled agents (including `kiwi`/`chatbotpdf`, the exact zero-lexical-overlap case that
  was broken) to their correct existing assets via the new hostname tier, with zero new
  duplicate rows created (`infra_inventory` row count unchanged before/after: 81).
  **Also found and fixed while verifying this, unrelated to the hostname gap itself**:
  `discover_wazuh_agents()`/`discover_core_assets()` were real, correct, working functions that
  were never actually called anywhere in the running system — no periodic loop, no startup
  hook, nothing; they only ever ran when a human manually `docker exec`'d them (which is
  presumably how every prior asset-discovery entry in this file's history actually happened).
  Any agent enrolled via the zero-trust curl-one-liner install path (`main.py`'s
  `/api/inventory` response includes a self-enrolling one-liner with no Python-side asset link
  at install time) would sit enrolled in Wazuh but never get linked to `infra_inventory` until
  someone remembered to run discovery by hand. Added `run_wazuh_discovery_loop()` in
  `centinela.py` (real 10-minute interval, calls the exact same `discover_wazuh_agents()` that
  was just verified live above) and wired it into the same startup thread list as the other
  periodic loops (CIS Benchmarks, CTI correlation, threat-intel enrichment).
- ~~GitLab project scanning has no token~~ — **resolved 2026-08-04**: user supplied several
  GitLab PATs; tested each against `GET /api/v4/user` and `/api/v4/personal_access_tokens/self`
  to find valid ones. First pass used `sonar_pat` (user `monitor`, `api`/`read_repository`
  scope) — 46/63 projects scanned, 74 vulnerabilities found. The other 17 turned out **not** to
  be empty repos: `git clone` on any of them returned a real `403 You are not allowed to
  download code from this project` — the `monitor` service account has no repository access to
  the entire `arquitectura/` GitLab group (it can list those projects via the API but not clone
  them). Confirmed `israelm`'s own personal token *can* clone them, switched `GITLAB_TOKEN` to
  that one, re-ran the scan: **59/59 projects scanned, 431 real vulnerabilities found**. Using a
  named admin's personal token for an automated integration isn't ideal long-term — cleaner fix
  would be granting the `monitor` service account Developer access to the `arquitectura/` group
  in GitLab and switching back, but that's a GitLab-side permission change, not a code fix.
  ~~**Residual gap (Developer role on `monitor`)**~~ — **resolved 2026-08-13**: a GitLab admin
  granted `monitor` the `Developer` role directly on the `arquitectura/` group (confirmed via a
  real screenshot of GitLab's own Group Members page — `Monitor @monitor` now shows role
  `Developer`, direct member via `Administrator`). Verified live, not just from the screenshot:
  `GITLAB_TOKEN` in `.env` already resolves to `monitor` (`GET /api/v4/user` → `username:
  "monitor"`) — a real, comprehensive clone test of all 18 `arquitectura/` projects
  (`git clone` per repo, not just the API listing) returned **18/18 success, 0 failures**, the
  exact group that used to 403 every single clone attempt for this account. Cross-checked
  against `infra_inventory`: all 18 already carry a real `last_audit` timestamp from earlier
  today, confirming the existing periodic `GitLabIntegrator.scan_all_projects()` loop had
  already been scanning every one of them successfully with no code or config change needed —
  the permission grant alone was the fix. `docs-public/manual-tecnico.html`'s matching
  "Pendiente conocido" note removed.
- ~~`sentinel.py`'s remediation execution was password-only~~ — **resolved 2026-08-04**: added
  `get_ssh_private_key()` (reads the `ssh_private_key` field `store_vault_secret()` already
  wrote to `casmarts/ansible/{asset_name}`, which nothing previously read back). The generic
  Ansible path now writes it to a 0600 temp file and passes `ansible_ssh_private_key_file` when
  present, falling back to the password vars otherwise. Verified live: stored
  `casmart_authentik`'s real key in Vault via the actual `/api/inventory/{name}/vault-secret`
  endpoint, approved a real pending finding, and watched Sentinel authenticate with the key and
  mark it `COMPLETED`/`RESOLVED` — confirmed Authentik itself (`https://auth.casmart.internal`)
  stayed healthy (HTTP 302) afterward.
- ~~Failed remediations on Wazuh-enrolled assets were silently marked `COMPLETED`~~ — **resolved
  2026-08-04**: removed the `if status == "FAILED" and agent_id ...: status = "COMPLETED"`
  fallback in `process_remediations()` that faked a Wazuh Active Response call which never
  actually happened. Failures now stay `FAILED` (`executed_bool=False`,
  `vulnerability_log.status` stays whatever it was, never force-set to `RESOLVED`). Re-approving
  via the UI (`approval_token='APPROVED'`) makes Sentinel pick it up and retry — no separate
  "retry" mechanism was added since that already does the job. Verified live on
  `CLONE-COMPRAMEX-CORE` (no stored credentials): now correctly reports `FAILED`, not
  `COMPLETED`.
- ~~Several inventory assets point at unreachable IPs~~ — **resolved 2026-08-04**: `sf_sigeti_superset`
  (10.4.3.17), `casmart_ia` (10.4.3.28), `CLONE-COMPRAMEX-DIGITAL` (10.4.3.200),
  `CLONE-COMPRAMEX-DIGITAL-BD` (10.4.3.201), `CLONE-PMCP-BD` (10.4.3.205), `CLONE-SICOPA-BD`
  (10.4.3.207) were confirmed dead by both ICMP and TCP and removed from `infra_inventory`
  (with their findings/remediation rows) at the user's request — those IPs no longer exist.
  `10.4.3.51` (pmcp) was also removed from `inventory.ini`'s `[casmarts_nodes]` group for the
  same reason.
- ~~`auditor_medusa.py`'s CLI flags were unverified~~ — **resolved 2026-08-05**: ran
  `medusa scan --help` for real against the correctly-pinned version (see version-drift note
  below). `--no-ai-safe` does exist in `medusa-security` 2026.7.0 but is unrelated to prompts —
  it toggles payload obfuscation. `--no-install` doesn't exist in this version at all (it was
  seen during earlier ad-hoc testing against a different, unpinned resolve). Neither the old
  `echo "yes" | medusa scan ... --no-ai-safe` pattern nor a `--no-install` flag was ever the
  right fix. The actual fix needed **no special flag at all**: with no TTY attached (always true
  under `subprocess.run`), medusa auto-detects it can't prompt and prints "Non-interactive mode:
  continuing without optional tools." on its own. Command is now just
  `medusa scan "{repo_path}" --format json -o "{output_dir}"`. Also bumped the internal
  `subprocess.run(..., timeout=...)` from 300s to 900s — Medusa shells out to `trivy fs
  --scanners vuln,secret,misconfig` as a sub-process on top of its own ~45 analyzers, and a cold
  Trivy CVE-database download alone can eat the old 300s budget. Verified with a real scan
  against a cloned repo (`arquitectura/resident-agent-framework`) after clearing stale
  `__pycache__` in `centinela-backend` — a first verification attempt silently kept running the
  old 300s-timeout bytecode even after the source was edited (see stale-bytecode gotcha #1) and
  timed out at exactly 300.2s; clearing `__pycache__` and rerunning confirmed the live code
  actually reflects the fix. Even with the timeout raised and a clean environment, the scan
  still failed every time with the command as given — root-caused to **three more independent
  bugs**, found by testing the real end-to-end path instead of trusting the CLI help text:
  1. Medusa's own default multi-worker pool (`-w` auto-detects >1 workers) reliably crashed with
     a `BrokenPipeError` inside `multiprocessing.Pool` while sending a result back to the
     parent — reproduced consistently both under heavy host load (see below) and on an idle
     host, so it's a real bug in this version's worker-pool IPC, not resource starvation. Fixed
     by forcing `-w 1` (single worker, no pool) — same repo then scanned cleanly in ~9s.
  2. Medusa 2026.7.0 always writes a second, unrelated `scan_history.json` (a JSON *list*, not a
     report) alongside the real report, and the real report's filename is timestamped
     (`medusa-scan-YYYYMMDD-HHMMSS.json`), not the fixed `medusa-report.json`/`report.json` the
     original code assumed. Picking "the first `*.json` file in the directory listing" is
     non-deterministic and grabbed `scan_history.json` on a real run, crashing with `'list'
     object has no attribute 'get'` when the code tried `data.get("findings", [])`. Fixed by
     explicitly excluding `scan_history.json` from the candidate list.
  3. `cve_id` was built with Python's built-in `hash()` on `file_path + str(line)` —
     **`hash()` on strings is randomized per process** (`PYTHONHASHSEED`, unset here) by design,
     confirmed live: the same string produced two different hash values across two separate
     `python3` invocations in the same container. That means the exact same finding got a
     *different* `cve_id` every time `centinela-backend` restarted, silently defeating
     `log_vulnerability()`'s dedupe-by-`(asset_id, cve_id)` check and re-inserting every
     previously-seen Medusa finding as "new" on every restart — the same duplicate-flooding
     failure mode as the original PROWLER-AUDIT bug, just via non-deterministic ID generation
     instead of a missing dedupe check. Fixed with `hashlib.sha256(...).hexdigest()[:8]`
     (deterministic across runs), and also stripped a redundant `MEDUSA-` prefix from
     `rule_id` before building `cve_id` (Medusa's own rule IDs are already `MEDUSA-`-prefixed,
     e.g. `MEDUSA-GENAI-SCAN-134`, which was doubling up to `MEDUSA-MEDUSA-GENAI-SCAN-134-...` —
     the same cosmetic bug class as the ZAP `pluginId` fix below). Verified: rerunning the same
     scan twice produced 21/21 `🔄 Updated` (not `📝 Logged`) on the second pass, confirming the
     hash is now stable and dedupe actually works.

  While debugging the `BrokenPipeError` under load, also found and cleaned up **three leftover
  `zap-scan-*` test containers** from the ZAP verification above that were never actually torn
  down (one had been running for 40+ minutes) — real resource waste, and a contributing factor
  to the host's load average hitting 76 (8 CPUs) during testing. **Separately found real version
  drift**: `centinela-ai`'s image had
  `medusa-security 2026.7.0`, `centinela-backend`'s had `2025.8.5.4` (11 months older, different
  incompatible flags) even though both Dockerfiles installed it "unpinned" around the same
  time — pip resolved differently per build. Pinned `medusa-security==2026.7.0` in both
  `requirements.txt` and the main `Dockerfile`'s pip list so this can't silently drift again;
  rebuilt both images.
- **AI remediation scripts were cosmetic across most of the finding taxonomy** — **resolved
  2026-08-05**, in response to real user-reported examples (a `DOCKER-MISSING-NON-ROOT-USER`
  "fix" that only printed a warning and created an unrelated local Linux user, never touching
  the actual Dockerfile). Root cause was architectural: **all** `sast-native`/`sca-native`/
  `standards-audit` findings (~517 rows — `CODE-INJECTION-EVAL`, `HARDCODED-SECRET`,
  `DOCKER-MISSING-NON-ROOT-USER`, `SCA-CVE-*`, `STD-*`, `COGNITIVE-*`, `CMD`/`SQL`/`SSRF-*`) live
  on `asset_type = 'GitLab-Repo'` assets — there is no live host to SSH into and "harden"; the
  real fix is a code change in the repo itself. `sentinel.py`'s only execution path was Ansible
  SSH (`asset_ip` for these rows is actually the repo's `web_url`, not an IP — every approval
  would have failed at the Ansible connection step, or worse, silently done nothing relevant if
  it somehow connected to a *different* host that happened to share the IP octets). Fixed in
  several parts:
  1. `remediation/gitlab_autofix.py` was **already wired to a real endpoint**
     (`POST /api/gitlab/autofix/{vuln_id}` in `main.py`, just never called from the frontend)
     but was non-functional end-to-end: referenced `re` without importing it, never cloned or
     edited anything, and called GitLab's MR API with a `source_branch` that was never pushed
     (which GitLab has always rejected — you cannot open an MR from a branch that doesn't
     exist). Rewritten with real `git clone` → apply fix → `git commit`/`push` to a new
     `centinela-fix/*` branch → open Merge Request (never a direct push to the default branch).
     Also fixed `project_id` defaulting to a hardcoded `1` regardless of which repo the
     vulnerability actually belonged to — now resolved from the vuln's own asset via GitLab's
     path-based project lookup.
  2. Added two **deterministic** patchers (no LLM needed, mechanical and safe):
     `DOCKER-MISSING-NON-ROOT-USER`/`DOCKER-ROOT-USER` (adds/fixes a real `USER` directive in
     the Dockerfile) and `SCA-CVE-*` (bumps the vulnerable package to the known-fixed version in
     `requirements.txt`/`package.json`, using the `fixed_version` `auditor_sca_dependencies.py`
     already computes from its `KNOWN_VULNERABLE_PACKAGES` table but never surfaced anywhere).
     Verified live on a disposable throwaway GitLab project created and destroyed for this
     purpose (never touched a real scanned repo): both produced a real, correctly-scoped MR with
     exactly the expected one-line diff.
  3. For findings that need real code understanding (`CODE-INJECTION-EVAL`, `HARDCODED-SECRET`,
     `CMD`/`SQL`/`SSRF-*`), `correlate_vulnerability()` now asks the LLM for a `fix_patch`
     (unified diff, using the file/line/snippet now available — see the file-path fix below) —
     stored in `vulnerability_log.fix_patch` (an existing, previously entirely unused column) —
     instead of a nonsensical bash "remediation_script". `gitlab_autofix.py` applies it with
     `git apply` through the same clone/branch/push/MR pipeline as the deterministic patchers.
     Verified the full JSON-parsing → `fix_patch` extraction → `git apply` → MR chain live with
     a realistic mocked LLM response (Groq's daily token quota was still exhausted at test time,
     see the AI-provider entry above, so the real end-to-end LLM call itself couldn't be
     exercised today) — a real `git diff`-generated patch applied and opened a correct MR.
  4. `can_automate` was previously **hardcoded to `True`** in the heuristic fallback path and
     **hardcoded to `False`** (discarding whatever the LLM actually said) in the main JSON-parse
     path — neither reflected reality. Added `heuristic_can_automate()` (mirrors
     `generate_heuristic_script()`'s own branches) and made the JSON path respect the LLM's own
     `can_automate` while still requiring real output (a patch or a script) to ever be `True`.
  5. `STD-ISO25010-LONG-METHOD`/`COGNITIVE-COMPLEXITY-EXCEEDED` (code-quality findings, 267 rows
     combined) and non-vulnerability status messages (`SCAN-AUDIT` — "no vulnerabilities found"/
     "scan skipped"; `HEURISTIC-SECURITY-DEBT` — an aggregate meta-finding) now get an honest
     "no automated fix, here's why" message instead of a fake success script. `SCAN-AUDIT` was
     previously keyword-matched into the **firewall-lockdown branch** (`ufw default deny
     incoming` + allow only 22/80/443) — meaning approving a finding that literally says "no
     vulnerabilities found" would have applied a deny-all firewall policy to a perfectly healthy
     host for no reason. Fixed.
  6. **Separately found and fixed, incidentally, while building this**: `auditor_master_vulnerabilities.py`/
     `auditor_sca_dependencies.py`/`auditor_compliance_standards.py` (the `sast-native`/
     `sca-native`/`standards-audit` engines) captured `file`/`line` on every finding but never
     actually persisted them anywhere — the `INSERT` only carried `cve_id`/`severity`/
     `description`, so no remediation (human or AI) could ever know which file to fix. Now
     stored in `url_path` as `relative/path:LINE` (reusing the same generic "where this finding
     lives" column `auditor_zap.py` already uses for URLs) and prefixed into `description`. Same
     three files also had the exact `ON CONFLICT DO NOTHING`-with-no-real-constraint bug as the
     Medusa/PROWLER-AUDIT cases above (see gotcha #3) — every re-scan of the GitLab org
     re-inserted every finding as brand new. Fixed with the same explicit
     SELECT-then-UPDATE/INSERT dedupe pattern already working in `auditor_zap.py`.
  7. **Also found, while investigating why `CODE-INJECTION-EVAL` "fixes" made no sense**: the
     detection regex `r'eval\s*\('` had no word boundary and (with `re.IGNORECASE`) matched the
     substring "Eval(" inside *any* longer identifier — e.g. `this.onErrorEval(err)` was flagged
     as a dangerous `eval()` call. Confirmed against real production data: **136 of 140** logged
     `CODE-INJECTION-EVAL` findings were exactly this false positive, not an actual `eval()`
     call. Fixed with `r'\beval\s*\('`.
  8. Real ZAP DAST findings (641 rows, on real reachable `SERVER` assets — genuinely
     automatable, unlike the GitLab-Repo cases above) got a real nginx security-header
     remediation generator (`generate_zap_header_fix()` in `centinela.py`) covering the standard
     header findings actually present in production (`X-Content-Type-Options`,
     `Strict-Transport-Security`, `X-Frame-Options`, CSP, `X-Powered-By`/`Server` leaks,
     Cache-Control, Permissions-Policy, Referrer-Policy). Detects nginx at the system level
     first, then falls back to detecting a **containerized** nginx reverse-proxy (confirmed live
     on `casmart_authentik`: no system nginx, but a `nginx:alpine` gateway container fronting
     it) — and within that, detects whether `/etc/nginx/conf.d` is writable inside the container
     or only via its host-side bind-mount source (confirmed live: `casmart_authentik`'s gateway
     mounts `conf.d` **read-only** in-container from
     `/opt/ecosistema-casmarts/core-casmarts/gateway/conf.d` on the host — a deliberate, common
     hardening pattern). Writes an idempotent, additive-only snippet file (never touches
     existing vhost configs), validates with `nginx -t` before reloading, and verifies the
     header is actually present in a live response afterward. **Not live-tested end-to-end**:
     the final apply-and-reload step is a live write to `casmarts-core-gateway`, which is shared
     infrastructure fronting several other apps (`admin.conf`/`apps.conf`/`auth.conf`/
     `axioma.conf`/`core.conf`/`lexivault.conf`/`oidc.conf`/`projects.conf`) outside this repo's
     own footprint — blocked by the permission classifier as a live shared-infra write; the
     script's *logic* was validated against the real host structure via read-only inspection
     (real bind-mount path, real container name, real absence of system nginx), but the actual
     apply-and-verify run needs to happen via a real approval in the SOAR UI.

## Session 2026-08-13: post-reboot recovery + full gap sweep

The host had rebooted (`uptime` showed 11 minutes at session start) and the whole stack was
down — no restart policy had brought it back automatically. Brought everything back up
(`docker compose up -d`, cleared `__pycache__`, restarted the three Python services), confirmed
`/api/health` fully green, then worked through every open item still listed in this file plus a
fresh gap sweep, in response to a direct instruction to keep going until bugs/gaps/debt were
covered, not just the one deferred backfill. All of the below is verified live against the real
`centinela_db` and the real running containers — not inferred from reading the code.

1. **Generic-heuristic backfill (the deferred item from 2026-08-07) — launched for real.**
   Re-checking the exact marker text this backfill targets found only 63 rows left (not the
   ~629 originally estimated — natural traffic through the already-fixed cascade over the
   intervening days had already worked most of the backlog down). Wrote
   `scratch/backfill_generic_heuristic_2026-08-13.py`, which re-runs `correlate_vulnerability()`
   for each of the 63 rows through the real 4-provider cascade and writes the result back.
   First attempt hit a self-inflicted bug: the `LIKE` patterns for the DAST/repo generic markers
   were missing a leading `%` (the real stored text is `**Riesgo Detectado:** Hallazgo DAST sin
   regla determinística...`, not starting at position 0), so the first run matched 0 rows —
   caught immediately by cross-checking against a direct DB query, fixed, reran. Verified live
   mid-run: Groq's small daily quota was already exhausted (expected, documented elsewhere in
   this file), and the cascade correctly fell through to Gemini/NVIDIA/OpenRouter every time,
   landing real, specific, non-generic content (e.g. a `ZAP-10109` finding on `casmart_authentik`
   correctly upgraded to "Modern Web Application (Client-Side Rendering) Discovery" instead of
   the generic "sin regla determinística" text). No non-JSON prose response was observed in the
   portion completed live (Gemini's native JSON mode absorbed most of the fallback traffic), so
   the separately-tracked `extract_section()` regex-tuning item below is still blocked on real
   data, not addressed this session.

2. **`discovery.py`'s hostname↔asset_id gap — resolved.** See the updated entry earlier in this
   file (search "hostname column") for the full write-up: added a real `hostname` column,
   captured at Wazuh-install time via a real `ansible ... -m command -a hostname`, checked by
   `discover_wazuh_agents()` as an exact-match tier before the fuzzy substring fallback. Verified
   live against all 5 currently-reachable hosts with zero new duplicate `infra_inventory` rows.

3. **`discover_wazuh_agents()`/`discover_core_assets()` were never actually scheduled anywhere**
   — real, correct, working code that only ever ran via manual `docker exec`. Added
   `run_wazuh_discovery_loop()` (10-minute interval) to `centinela.py`'s startup thread list.

4. **Four on-demand audit endpoints defaulted to a host-side path that doesn't exist inside any
   container.** `target_dir` defaulted to `"/opt/centinela-ai"` in `/api/audit/full-spectrum`,
   `/api/audit/llm-governance`, `/api/audit/iac-k8s`, and the underlying `run_master_vulnerability_scan()`/
   `run_sca_audit()`/`run_compliance_standards_audit()`/`run_iac_scan()`/`run_cmmi_audit()`/
   `audit_cloud_iac_and_cspm()`/`run_llm_governance_audit()`/`run_shadow_api_audit()` function
   signatures themselves (8 functions total) — the real bind mount in every one of the three
   Python containers is `/app` (per this file's own Architecture section), confirmed live
   (`ls /opt/centinela-ai` inside `centinela-backend` → "No such file or directory"). `os.walk()`
   on a nonexistent path silently returns nothing, no exception — so every one of these
   endpoints had always silently returned "0 findings" on its own default, with no error, for as
   long as they've existed. Fixed all defaults to `/app`. Confirmed live before/after:
   `/api/audit/full-spectrum` went from `{"sast":0,"sca":0,"standards":0,"cspm":0}` to
   `{"sast":121,"sca":77,"standards":71,"cspm":1,"total":270}` on the exact same call with no
   other change. `/api/audit/shadow-api` went from 0 to 3 real findings.
5. **`/api/audit/iac-k8s` has been throwing an `ImportError` on every single call since it was
   written.** It imported `run_iac_k8s_audit` from `auditors.auditor_iac_k8s` — that name has
   never existed there (only `run_iac_scan` does). Confirmed live: `curl` against the endpoint
   before the fix returned `{"detail":"cannot import name 'run_iac_k8s_audit' from
   ...auditor_iac_k8s"}`, a plain 500 on every call. Fixed the import; endpoint now returns
   `{"status":"success","count":0,...}` (0 is real — this repo currently has no k8s/Terraform
   manifests matching the detector's patterns, not a masked failure).
6. **`/api/audit/full-spectrum` and the shadow-API/LLM-governance/IaC endpoints never attributed
   findings to a real `asset_id`** — every finding these produced had `asset_id = NULL`, which
   silently excludes a row from the main AI-correlation query's `JOIN infra_inventory` and from
   every asset-scoped dashboard view. Confirmed live: 181 real orphaned rows had piled up this
   way over the preceding week (real `url_path` values like `package.json:1`, `Dockerfile:1`
   proving they came from genuine self-audit scans, not garbage). Same root cause this file
   already documents for the old idle-branch loop, just via these separate on-demand endpoints,
   which were never given the same fix. Added `resolve_self_audit_asset_id()` in `main.py`
   (mirrors `gitlab_integration.py`'s own per-repo asset-resolution pattern) — creates/reuses a
   real `"Centinela-AI (Self-Audit)"` `GitLab-Repo` asset and threads its `asset_id` through every
   one of these endpoints. Backfilled the 181 pre-existing orphaned rows onto this new asset
   (`UPDATE vulnerability_log SET asset_id = ... WHERE asset_id IS NULL`); confirmed 0 orphaned
   rows remain.
7. **A real bug I introduced myself while doing the orphan backfill in item 6, caught before it
   shipped as a false "fix."** The blanket `UPDATE ... SET asset_id = 47631 WHERE asset_id IS
   NULL` changed `asset_id` on those 181 rows without recomputing `fingerprint_hash`, which is
   computed *from* `asset_id` (`calculate_fingerprint()` in `core/deduplication_engine.py`) and
   is exactly what `log_finding_deduplicated()`'s Tier-1/Tier-3 dedup logic keys on. This left
   181 rows whose `fingerprint_hash` still encoded their *old* `asset_id=None`, silently
   mismatched against their own current `asset_id` — a landmine where any future write for the
   same finding with `asset_id=None` would collide into one of these now-mis-owned rows instead
   of creating its own, and a future *correct* re-scan (real `asset_id=47631`) would compute a
   *different* fingerprint and never find these rows via Tier 1, creating a fresh duplicate
   instead. Caught by the test suite: `test_run_sonarqube_audit_persists_real_row` started
   failing (`run_sonarqube_audit(tmpdir, asset_id=None, ...)` printed success but no marker row
   ever appeared) — root-caused to exactly this mechanism, confirmed by direct reproduction
   (`log_finding_deduplicated(cur, None, 'SONARQUBE-QUALITY-GATE', ...)` returned
   `('updated', 22336)` where row 22336 actually belonged to `asset_id=47631`, i.e. it was
   matched purely by the database's own `ON CONFLICT (fingerprint_hash)` constraint, bypassing
   Tier 1's `asset_id`-aware `SELECT` entirely). Fixed properly, not just patched around the
   test: recomputed the correct fingerprint for all 440 rows on the self-audit asset; where the
   recomputed value collided with an already-existing fresh row (89 cases — the full-spectrum
   re-scan in item 6 had already independently rediscovered the same real findings with the
   correct `asset_id`, making the old row pure duplicate debris), deleted the stale row (and its
   `remediation_history` entry) in favor of the fresh one; where it didn't collide (92 cases),
   corrected the `fingerprint_hash` in place. Verified: full suite went from 1 failure to
   62/62 passing.
8. **`discovery/discovery_osint.py` was fabricating data and presenting it as real passive
   OSINT.** Found while checking the `ON CONFLICT (asset_id, cve_id) DO UPDATE` in this file
   against `vulnerability_log`'s real constraints (confirmed live via `pg_indexes`:
   `vulnerability_log` has no such composite constraint, only its `id` primary key and a partial
   unique index on `fingerprint_hash` alone) — the same failure class already fixed once for
   `auditor_spiderfoot.py` (silent DB error on every insert, caught by a broad `except`), missed
   in this file at the time. But investigating it surfaced something worse than a persistence
   bug: `geolocate_ip_passive()`'s fallback for a failed public geolocation lookup was a fixed,
   hardcoded `{"Mexico", "Querétaro", "CASMARTS Headquarters"}` returned for *any* IP regardless
   of where it actually is, and `shodan_query_passive()` — confirmed live, `SHODAN_API_KEY` is
   unset in this deployment, so this was the *only* branch this function has ever taken — silently
   returned a fixed, entirely invented port/service list (`[80,443,5432,6379,8200]` /
   `["Nginx","PostgreSQL","Valkey","HashiCorp Vault"]` for anything on a private range) with the
   docstring literally admitting "Simulates passive Shodan scan retrieval." Both fed directly
   into a `vulnerability_log` row whose text claimed these were "Detectados pasivamente" — a
   direct violation of this project's own zero-fabrication rule (section 1 at the top of this
   file), not merely a cosmetic issue. Confirmed live that zero `OSINT-ENRICH` rows exist in the
   DB today (`SELECT count(*) ... WHERE cve_id='OSINT-ENRICH'` → 0), meaning the ON CONFLICT bug
   had accidentally contained the damage — the fabricated data was generated on every cycle but
   never actually persisted, purely by accident of the other bug. Fixing the persistence bug
   *without* also fixing the fabrication would have started writing fake findings to the real
   dashboard for the first time. Fixed both together: both functions now return a `"real": bool`
   flag and an honest "unavailable" result instead of a guess on failure/no-key; the caller
   skips writing an enrichment entry entirely when neither source produced real data, and uses
   the shared `log_finding_deduplicated()` logger (fixing the persistence bug) for the case where
   real data *is* available. Verified live: reran `run_osint_discovery()` end-to-end against the
   real DB — no fabricated data, no exception, still correctly 0 `OSINT-ENRICH` rows (the one
   matching asset in current inventory, `compramex-bd`, has no resolvable IP, so it's correctly
   skipped, not fabricated around). **Not verified against a real Shodan API key or a live
   IP/URL-type asset with a resolvable endpoint** — no such asset currently exists in inventory;
   the success path reuses the same `log_finding_deduplicated()` call already proven correct by
   ~10 other call sites, but this specific function's success path itself is logic-verified, not
   live-exercised end-to-end.
9. **A duplicate, dead route definition for `GET /api/wazuh/agent/{agent_id}/info`** — two
   separate functions, both named `get_wazuh_agent_info`, registered on the identical path.
   FastAPI/Starlette match routes in registration order, so the second definition was 100%
   unreachable dead code, confirmed by FastAPI's own `Duplicate Operation ID` warning at
   startup. Checked which one the frontend actually depends on
   (`Dashboard.jsx` reads `agentInfo.os_name/hostname/kernel/arch/wazuh_version/last_keepalive/
   syscheck_time`) — that shape matches only the *first*, richer definition (OS-name
   normalization, `-j` JSON output), confirming the frontend was never actually broken by this,
   just carrying dead, confusing duplicate code. Removed the second (raw-text, `{agent_id, raw,
   parsed}`-shaped) definition. Confirmed live: the `Duplicate Operation ID` warning is gone from
   `centinela-backend`'s startup log.
10. **Full pytest suite run twice**: first run found the one real failure described in item 7
    (`test_run_sonarqube_audit_persists_real_row`); second run, after the fingerprint fix,
    passed 62/62 (see the Registro de Salida de Pruebas in the closing Walkthrough for this
    session for the exact captured output).

All of the above (except the still-completing backfill in item 1) is fully deployed and
restarted live — `centinela-ai`/`centinela-backend` were restarted with a cleared `__pycache__`
after every batch of source changes, per the stale-bytecode gotcha, and `/api/health` was
re-confirmed green after each restart. The backfill itself finished in a later pass the same
day: 63/63 originally-targeted rows resolved (0 failed), plus 6 more that appeared from ordinary
live scanning while the backfill ran (not survivors of the original set) also cleared in a final
cleanup pass — 0 stale generic-marker rows remain.

**11. A real ~30+ minute hang against OpenRouter, hit live during the backfill, root-caused and
fixed the same day.** One backfill row's cascade call to OpenRouter never returned — `ss -tnp`
showed the TCP connection still `ESTAB`, no timeout ever fired, despite `request_timeout=90`
configured on that `ChatOpenAI` client (confirmed via direct attribute inspection: the real
underlying `openai.OpenAI` client genuinely had `.timeout == 90.0` and `.max_retries == 0` at
the moment of the hang, so this wasn't a config mistake). Isolated the mechanism with two real,
local tests rather than guessing:
  - A TCP listener that accepts a connection and never sends a single byte back → the client's
    own timeout fired correctly, at exactly the configured value. This ruled out "the timeout
    mechanism itself is broken."
  - A TCP listener that accepts a connection and then sends one byte (`:`) every 3 seconds
    forever, never completing an HTTP response → the client's timeout **never fired**, because
    httpx's read-timeout is measured as *idle time since the last byte*, not *total time for the
    whole request* — a periodic keep-alive trickle resets that clock indefinitely. This is a
    plausible, known real behavior for a shared-pool free-tier gateway (OpenRouter's own
    documented characteristics: variable latency, backed-up shared models) and matches the
    observed symptom exactly (connection alive, no error, no data completing).
  A per-request `timeout=` kwarg on an HTTP client protects against *no response at all*, not
  against *a response that trickles forever without completing* — those are different failure
  modes, and only the first one was covered before this fix. Added `_call_with_hard_deadline()`
  in `centinela.py`: every one of the four provider calls in `call_ai_cascade()` now runs inside
  a `ThreadPoolExecutor` and is bounded by `future.result(timeout=...)`, a true wall-clock
  deadline that fires regardless of whether bytes are trickling in (hard caps set a bit above
  each provider's own already-configured client-level timeout: Groq 70s, Gemini 40s, NVIDIA
  100s, OpenRouter 100s). The abandoned worker thread is left running in the background (Python
  cannot force-kill a thread) until the underlying call eventually errors or closes on its own —
  a bounded, acceptable cost against never again blocking the whole correlation loop.
  **Verified live end-to-end**, not just by code inspection: rebuilt the exact keep-alive-trickle
  listener, pointed a real `ChatOpenAI` client at it with a *longer* client-level timeout (60s)
  than the hard deadline (10s) specifically to prove the hard deadline — not the client's own
  timeout — is what fires; confirmed `TimeoutError` raised at exactly 10.0s. Then restarted
  `centinela-ai`/`centinela-backend`/`centinela-sentinel`, ran a real `call_ai_cascade()` call
  end-to-end (landed on Groq, correct JSON content back), and reran the full pytest suite: still
  62/62 passing.
  **Real, disclosed side effect found while building this, fixed where it actually matters**:
  `ThreadPoolExecutor` registers a process-wide `atexit` hook that blocks a *clean* Python
  process exit until every submitted thread finishes — including abandoned, still-hung ones. For
  the long-running `centinela.py` **service** this doesn't matter (it's killed via SIGTERM/
  SIGKILL from Docker, which bypasses `atexit` entirely, not a normal `sys.exit()`), but it would
  make a one-off **script** that imports `centinela.py` (like the backfill script above) hang at
  process exit — after already finishing its real work and writing its summary — until any
  abandoned thread from a hard-deadline timeout eventually resolves on its own. Added `os._exit(0)`
  at the end of `scratch/backfill_generic_heuristic_2026-08-13.py`'s `__main__` block, which skips
  that wait entirely (safe here: every DB write already committed per-row inside `main()` before
  this point, nothing is lost by not waiting on a stray network thread). Future one-off scripts
  that import `centinela.py` and call into the AI cascade should do the same.

- ~~PDF regeneration for the executive presentation~~ — **resolved same day**, revisited after
  being flagged as blocked. `Presentacion_Centinela_AI.pptx` was updated with real, live-verified
  figures via `python-pptx`; the paired `.pdf` export was stale relative to it and this
  environment had neither `libreoffice` nor `soffice`. Installed `libreoffice-impress`
  (`--no-install-recommends`, ~136MB) as root directly in the running `centinela-backend`
  container — deliberately **not** added to `Dockerfile`/`requirements.txt`, so it doesn't
  survive an image rebuild; a genuinely one-off tool for a one-off document-export task, not a
  permanent addition to a security platform's attack surface. Converted headless
  (`soffice --headless --convert-to pdf`), verified the real output with `pypdf` (12 pages, real
  extracted text from the stats slide matching the updated figures — 82/8,799/1,285/17/46 — not
  the old 11-Aug numbers), copied it into place, then **purged libreoffice-impress and its
  unique dependencies immediately after** (freed 136MB) rather than leave the extra footprint
  running. Confirmed live: `centinela-backend` still imports and serves normally after the
  purge, `/api/health` still `Healthy`.

**Still open, investigated thoroughly and confirmed genuinely blocked, not avoided**:
- **`extract_section()`'s prose-fallback regex tuning.** Went beyond passively hoping a real
  non-JSON sample would show up: deliberately forced `call_ai_cascade()` to skip Groq/Gemini
  (both JSON-compliant) and answer only via NVIDIA/OpenRouter (the two providers with no native
  JSON mode, the ones actually capable of triggering the prose-fallback path) against a real
  production-shaped prompt. Result, with real evidence for each:
  - **NVIDIA NIM**: 3 separate live attempts, all `Request timed out` (bounded at the new 100s
    hard deadline each time — see the hard-deadline fix above). Consistent with this same
    model's documented characteristic elsewhere in this file (`meta/llama-3.1-70b-instruct`,
    "cold/unavailable on NVIDIA's shared infra").
  - **OpenRouter**: `429 Rate limit exceeded: free-models-per-day` — confirmed via the response's
    own `X-RateLimit-Remaining: 0` header that this account's free-tier daily quota (50
    requests/day) is genuinely exhausted for today, resetting at `X-RateLimit-Reset` = **2026-08-14
    00:00 UTC** (decoded from the raw epoch-ms value in the error, not guessed). Real,
    quota-driven, self-resolving tomorrow — not a bug.
  Across the full backfill (164 real LLM calls this session: 63 original + 6 that appeared
  mid-run + 101 more from ongoing live scanning + this targeted verification), zero non-JSON
  prose responses were observed, because the only two providers capable of producing one are
  both unavailable in this environment today for reasons now concretely identified and dated,
  not merely "didn't happen to occur." The regex's correctness remains genuinely unverifiable
  without a real sample — fabricating one would violate this file's own rule against acting on
  invented data. **Next real opportunity to close this**: any time after 2026-08-14 00:00 UTC,
  force OpenRouter alone (`groq_llm`/`gemini_client`/`nvidia_llm` monkeypatched to `None`,
  exactly as done here) against a real prompt and inspect the raw `content` before the
  `json.loads()` call in `correlate_vulnerability()`.
- **A real, incidental discovery while investigating this**: OpenRouter's free-tier exhaustion
  causes the live correlation loop to fall through to the heuristic engine more often than
  expected today whenever it coincides with Groq's own small daily quota being temporarily
  exhausted at the same moment (both cycle independently over the day) — confirmed live in
  `centinela-ai`'s own logs, several real `⚙️ Using Native Heuristics AI Engine` fallbacks for
  GitLab-Repo SAST findings with no dedicated heuristic branch (`SONAR-*`, `CODE-INJECTION-EVAL`,
  `CMD-INJECTION-SHELL-TRUE`), which land on the same generic catch-all text this whole session's
  backfill was clearing. This is **expected, honest degraded-mode behavior** — the heuristic
  engine is the correct designed fallback when every real provider is genuinely down, and it
  produces an honest "no rule available" message, not a fabricated one — not a bug to fix, just
  a real, current resource constraint.

  Ran one further backfill pass on the newly-accumulated rows same-day rather than let them sit
  (101 targeted: 44 genuinely upgraded, 57 landed back on the honest heuristic text — many of
  those specifically *because* all 4 providers were briefly down at once during the run, not
  because a real LLM reasoned there was nothing better to say, a distinction this backfill
  script's own log message doesn't currently draw). Checked the DB again immediately after:
  **121 generic-marker rows remained — more than the 101 just targeted.** Root cause, not a
  regression: this session's own fixes (the 18 newly-Developer-accessible `arquitectura/`
  repos getting scanned for the very first time today, plus the `/api/audit/full-spectrum`
  self-audit fix) genuinely increased real scanning volume happening *during* the backfill,
  and a meaningful share of that new volume is landing during the same OpenRouter-exhausted/
  NVIDIA-timing-out window documented above. **Deliberately stopped chasing this further today**
  rather than run more passes against a wall of two exhausted/unreliable providers — every
  further attempt would mostly burn Groq's own recovering daily quota (needed by the live
  production correlation loop for real-time work happening in parallel) for a shrinking chance
  of success, not close a real gap. The honest, current, disclosed state: 121 rows carry the
  generic fallback text as of this session's end, a real and current number, not zero. A
  follow-up pass will have meaningfully better throughput any time after Groq's quota next
  resets and, especially, after OpenRouter's free-tier resets at 2026-08-14 00:00 UTC — reuse
  `scratch/backfill_generic_heuristic_2026-08-13.py` as-is, it re-queries fresh from the DB
  every run.

**12. A real, previously-undocumented duplicate-findings bug, found in response to a direct user
challenge ("¿son únicas? ¿se borraron las erróneas o duplicadas?") — not from routine review.**
Grouping `vulnerability_log` by `(asset_id, cve_id, url_path)` for anything not `RESOLVED` found
**138 groups with exactly 2 rows each** (276 rows, 138 of them true duplicates) — same real
finding, same asset, same exact URL, logged twice. Root-caused with certainty, not guessed:
`calculate_fingerprint()`'s formula itself has never changed (checked its full git history), but
**138 older rows had a `fingerprint_hash` computed from `description` instead of `url_path`** —
confirmed by directly recomputing `calculate_fingerprint(asset_id, cve_id, description)` against
a real pair and getting an exact match to the stale stored value, while
`calculate_fingerprint(asset_id, cve_id, url_path)` (what today's code actually passes) does not
match. Verified this explains **all 138 groups, not just a sample** (wrote a script that checked
every group, not a handful). Practical effect: any of these older, still-open findings could
never fingerprint-match a fresh re-scan using the current, correct `url_path`-based formula, so
every re-detection silently created a second row instead of updating the first — most visible on
ZAP (repeat DAST scans against the same live SERVER assets), but the grouping query wasn't
scoped to any one `scan_engine`.
  Fixed as a real merge, not a blind delete: checked every one of the 138 pairs for a real,
  non-default `remediation_history.approval_token` first (a human decision must never be
  silently discarded) — confirmed live, **zero** pairs had one, both sides were still the
  untouched `PENDING_APPROVAL` default, safe to merge automatically. For each pair, kept whichever
  row was `CORRELATED` with real (non-generic) AI content, preferring the more recent detection
  on ties; corrected that survivor's `fingerprint_hash` to the value a fresh scan would actually
  compute (closing the gap for future re-scans too, not just today); deleted the other row and
  its `remediation_history` entry. Verified live: 0 duplicate groups remain, `vulnerability_log`
  dropped from 9,092 to 8,954 rows (exactly -138).
  **Also found and cleaned up in the same integrity pass**: 13 orphaned `remediation_history`
  rows pointing at `vuln_id`s that no longer exist (predating this session, unrelated to today's
  merge — all `PENDING_APPROVAL`, no real decision lost). Deleted.
  **Separately verified, same conversation, that the dashboard itself is not hardcoded**: read
  `/api/stats` and `/api/inventory` in full — both are real parameterized SQL against
  `vulnerability_log`/`infra_inventory` with no literal fake values, and both already carry
  real dedup/exclusion logic for synthetic markers (`SCAN-AUDIT`, `HEURISTIC-SECURITY-DEBT`,
  etc. — see gotcha #4). Grepped the frontend for suspiciously large hardcoded numbers in
  component state — none found. Cross-checked `/api/stats`'s live HTTP response against a
  direct SQL query run independently: `total` and `critical` matched exactly (8,954 / 1,326),
  confirming the endpoint is genuinely live-querying, not cached or fabricated.
