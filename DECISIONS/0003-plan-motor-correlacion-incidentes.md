# Plan de implementación 0003: Motor de correlación de incidentes (item 2)

**Fecha:** 2026-08-27
**Estado:** ✅ IMPLEMENTADO y verificado en vivo (2026-08-27, misma sesión). Este documento se
conserva como el diseño; ver `DECISIONS/0002` §"Item 2" y `CLAUDE.md` (Session 2026-08-27,
punto 7) para la evidencia de ejecución. Desviaciones respecto al plan original: (a) se añadió
denylist de reglas-ruido (`NOISE_RULES`) tras confirmar en vivo que `runtime_alerts` es ~93%
ruido propio de los escáneres; (b) se añadió `analyst_notes` a la tabla `incidents`;
(c) `attach_or_create_incidents` hace además *attach* a incidentes abiertos existentes, no solo
crea nuevos.
**Origen:** evaluación de "The Rock" (SOC agéntico de KIO) + CodeRabbit.

---

## 1. Problema

Centinela hoy correlaciona **vulnerabilidades una a una** (`centinela.py::correlate_vulnerability`),
cada `vulnerability_log` es un ticket independiente. No existe la noción de **incidente**: un
conjunto de señales de runtime relacionadas (mismo activo, ventana temporal, misma cadena de
ataque) agrupadas en un solo caso con línea de tiempo, técnicas ATT&CK y contención recomendada.

"The Rock" describe exactamente esto como capacidad central: *"clasificación y agrupación
automatizada de eventos"* + *"generación de evidencia para investigaciones"* + métrica de
**dwell time** (el atacante se mueve en ~29 min de media). Centinela tiene las fuentes de señal
(`runtime_alerts` de Falco/Zeek/Wazuh, `vulnerability_log`, feed CTI, hits BloodHound) pero
nada las une.

### Estado real de las fuentes (verificado en vivo 2026-08-27)

| Fuente | Tabla / mecanismo | Volumen actual |
|---|---|---|
| Falco | `runtime_alerts` vía `process_falco_alerts()` (Valkey list `falco`) | histórico ~0 (pipeline real, sin detecciones aún) |
| Zeek notice | `runtime_alerts` vía `process_zeek_alerts()` (`notice.log`) | ~0 (Zeek no escribe notice.log en este despliegue) |
| Zeek conn | `process_zeek_conn_log()` — solo cruza IPs contra CTI, **no** persiste conexiones | heartbeat cada 5 min |
| Wazuh | `poll_new_alerts()` en `main.py` | activo |
| CTI/IoC | `run_cti_correlation_loop()` — inserta `CTI-IOC-MATCH-*` en `vulnerability_log` | 0 matches |
| BloodHound | `process_bloodhound_paths()` — inserta `BLOODHOUND-PATH-*` | 0 (grafo vacío, sin datos AD) |

> **Consecuencia de diseño:** el motor debe ser *fail-safe ante ausencia de datos* (como
> `process_bloodhound_paths()` ya lo es) — arrancar, no encontrar nada que correlacionar, y
> quedarse inerte sin generar incidentes falsos. Igual que el resto de loops de este proyecto.

---

## 2. Alcance de esta fase (MVP honesto)

**SÍ:**
- Nueva tabla `incidents` + `incident_events` (unión N:M a las señales que ya existen).
- Un `run_incident_correlation_loop()` en `centinela.py` (mismo patrón que los demás loops:
  hilo daemon, intervalo fijo, `db_manager.get_db_cursor()`).
- Reglas de agrupación **deterministas** (sin LLM) por: `asset_id` + ventana temporal
  deslizante + solapamiento de indicadores (IP, usuario, hash, puerto, `cve_id`).
- Mapeo de cada evento a su táctica ATT&CK reutilizando `core/mitre_attack.map_finding()`
  (ya existe y es el único mapeador centralizado) + las tácticas de `cat_incident_categories`
  (tabla ya poblada con `A01…A06` → `Initial Access`/`Execution`/…).
- Narrativa de línea de tiempo generada **determinísticamente** (plantilla ordenada por
  timestamp), y **opcionalmente** un resumen ejecutivo del incidente vía `call_ai_cascade()`
  (mismo cascade de 4 proveedores + fallback heurístico ya endurecido).
- Reloj **MTTD/MTTC** por incidente (`first_event_at`, `detected_at`, `contained_at`).
- Endpoints REST: `GET /api/incidents`, `GET /api/incidents/{id}`, `POST /api/incidents/{id}/note`,
  `POST /api/incidents/{id}/status`.
- Registro en el ledger `agent_actions` (item 4, ya implementado): `action_type='incident_correlation'`.
- Tests `tests/test_incident_correlation.py` contra la DB real (patrón `get_db_cursor` +
  `tearDown`), incluyendo el caso "sin señales → 0 incidentes".

**NO (fuera de fase, documentado como deuda):**
- UEBA / baseline de comportamiento sobre Zeek conn.log (item aparte).
- Respuesta autónoma (item 6 — ver `0004`).
- Persistir cada conexión Zeek (cambio de volumen grande; hoy `conn.log` no se guarda).
- Correlación entre incidentes (campañas).

---

## 3. Esquema propuesto (a añadir en `core/schema.py::CORE_SCHEMA_STATEMENTS`)

```sql
CREATE TABLE IF NOT EXISTS public.incidents (
    id            BIGSERIAL PRIMARY KEY,
    asset_id      INTEGER REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
    title         TEXT NOT NULL,
    category_code TEXT,                        -- FK lógica a cat_incident_categories.code
    severity      TEXT NOT NULL DEFAULT 'MEDIUM',
    status        TEXT NOT NULL DEFAULT 'OPEN',-- OPEN | INVESTIGATING | CONTAINED | CLOSED | FALSE_POSITIVE
    kill_chain    TEXT[],                      -- tácticas ATT&CK observadas, en orden
    indicators    JSONB,                       -- {ips:[], users:[], hashes:[], ports:[], cves:[]}
    narrative     TEXT,                        -- línea de tiempo determinista
    ai_summary    TEXT,                        -- resumen ejecutivo opcional (call_ai_cascade)
    recommended_containment TEXT,              -- texto; NUNCA se auto-ejecuta (ver 0004)
    first_event_at TIMESTAMP,
    detected_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    contained_at  TIMESTAMP,
    closed_at     TIMESTAMP,
    event_count   INTEGER NOT NULL DEFAULT 0,
    fingerprint   TEXT UNIQUE                  -- asset + bucket temporal + indicadores núcleo
);

CREATE TABLE IF NOT EXISTS public.incident_events (
    incident_id  BIGINT NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
    source       TEXT NOT NULL,               -- 'runtime_alert' | 'vulnerability' | 'cti' | 'bloodhound'
    source_id    BIGINT NOT NULL,             -- id en la tabla de origen
    occurred_at  TIMESTAMP NOT NULL,
    tactic       TEXT,
    summary      TEXT,
    PRIMARY KEY (incident_id, source, source_id)
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.incidents (status, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_events_src ON public.incident_events (source, source_id);
```

Sin migración externa: se aplica en el arranque igual que `finding_suppressions`/`agent_actions`.

---

## 4. Algoritmo de correlación (determinista, sin LLM)

`run_incident_correlation_loop()` cada N segundos (propuesta: 120 s):

1. **Recolectar señales frescas** de la última ventana (p. ej. 6 h) que aún no estén en
   `incident_events`:
   - `runtime_alerts` (todas)
   - `vulnerability_log` con `cve_id LIKE 'CTI-IOC-MATCH%'` o `'BLOODHOUND-PATH%'` o
     `is_cisa_kev = TRUE` con `detected_at` reciente (una vuln KEV recién detectada en un
     activo con alertas de runtime SÍ es señal de incidente).
2. **Extraer indicadores** de cada señal: IPs (de `output_fields`/`alert_text` con regex ya
   usada en `process_zeek_conn_log`), usuario, hash, puerto, `cve_id`.
3. **Agrupar** — dos señales van al mismo incidente si:
   - mismo `asset_id` (o `asset_id IS NULL` en ambas y comparten ≥1 IP), **y**
   - `|Δt| ≤ CORRELATION_WINDOW` (propuesta: 60 min, configurable por env), **y**
   - comparten ≥1 indicador **o** una es `Initial Access`/`Execution` y la otra es una
     táctica posterior en la misma cadena (orden de `cat_incident_categories`).
   Implementación: *union-find* sobre las señales de la ventana (sin dependencias nuevas).
4. **Materializar** cada grupo con ≥2 señales (o 1 señal si es KEV+runtime, o `BLOODHOUND-PATH`)
   como un incidente:
   - `fingerprint = sha256(asset_id : floor(first_event_at / bucket) : sorted(core_indicators))`
     → `ON CONFLICT (fingerprint) DO UPDATE` (mismo patrón anti-duplicado que
     `log_finding_deduplicated`).
   - `kill_chain` = tácticas únicas ordenadas por el orden canónico.
   - `severity` = máx severidad de las señales, +1 nivel si `kill_chain` cubre ≥3 etapas.
   - `narrative` = plantilla: `"HH:MM · [fuente] resumen"` por línea, ordenado.
   - `recommended_containment` = texto derivado por reglas (IP → "bloquear en proxy vía
     `generate_ip_block_virtual_patch`"; credencial → "rotar y revisar sesiones Authentik";
     proceso → "aislar host vía `POST /api/host-containment`"). **Solo texto.**
5. **Reconciliar cierre:** un incidente `OPEN` sin señales nuevas en `AUTO_CLOSE_IDLE`
   (propuesta: 72 h) y sin `vulnerability_log` abierto asociado → `status='CLOSED'`,
   `closed_at=NOW()` (mismo espíritu que `reconcile_resolved_findings`).
6. Registrar en `agent_actions`: 1 fila por pasada con incidentes creados/actualizados
   (acumulado en idle como se hizo con `threat_intel_enrichment`, para no generar ruido).

### Resumen IA opcional (paso 4b)
Solo si el incidente es `HIGH`/`CRITICAL` y `call_ai_cascade()` responde: pedir un párrafo
ejecutivo a partir de la `narrative` ya construida. Si no responde → `ai_summary` queda NULL y
la `narrative` determinista es la fuente de verdad. **Nunca** se pide a la IA que invente
eventos ni indicadores (regla #1 del proyecto).

---

## 5. Parámetros configurables (env, con defaults)

| Env | Default | Qué controla |
|---|---|---|
| `INCIDENT_CORRELATION_INTERVAL_S` | `120` | frecuencia del loop |
| `INCIDENT_CORRELATION_WINDOW_MIN` | `60` | ventana de agrupación temporal |
| `INCIDENT_LOOKBACK_HOURS` | `6` | cuánto atrás mira cada pasada por señales sin asignar |
| `INCIDENT_AUTO_CLOSE_IDLE_HOURS` | `72` | inactividad para autocierre |
| `INCIDENT_AI_SUMMARY` | `1` | permitir resumen ejecutivo IA (0 = solo narrativa determinista) |

---

## 6. Cambios de código (archivos concretos)

| Archivo | Cambio |
|---|---|
| `core/schema.py` | +2 tablas en `CORE_SCHEMA_STATEMENTS` |
| `core/incident_engine.py` | **nuevo** — `extract_indicators()`, `group_signals()` (union-find), `build_narrative()`, `upsert_incident()`, `reconcile_closed_incidents()`. Puro/testeable. |
| `centinela.py` | `run_incident_correlation_loop()` + hilo en `main_loop()` (junto a `run_cti_correlation_loop` etc.) |
| `main.py` | 4 endpoints REST + registro OpenAPI |
| `core/agent_ledger.py` | +constante `ACTION_INCIDENT_CORRELATION` |
| `tests/test_incident_correlation.py` | **nuevo** — union-find, fingerprint estable, "sin señales → 0", autocierre, endpoint |
| `frontend/src/components/` | (fase posterior) panel "Incidentes" + timeline |
| `CLAUDE.md` | entrada de sesión + item nuevo en la sección Omni-XDR |

---

## 7. Criterios de aceptación (para declarar el item 2 COMPLETO, regla #2 del proyecto)

1. `pytest tests/test_incident_correlation.py` pasa, incluyendo el caso vacío.
2. Con señales sintéticas insertadas en `runtime_alerts` (2+ alertas mismo activo/ventana con
   IP común) → se materializa **exactamente 1** incidente, con `kill_chain` real y `narrative`
   ordenada; re-ejecutar el loop **no** crea un segundo (fingerprint estable, verificado con
   `SELECT`).
3. Sin señales reales en la DB → el loop corre y `SELECT count(*) FROM incidents` sigue en 0.
4. `GET /api/incidents` y `GET /api/incidents/{id}` devuelven datos reales de la DB (no mock).
5. El reloj MTTD/MTTC se calcula de timestamps reales; autocierre verificado moviendo
   `detected_at` hacia atrás en una fila de prueba.
6. Log real de la ejecución incluido en el walkthrough final.
7. `agent_actions` recibe fila(s) `incident_correlation` reales.

---

## 8. Riesgos / decisiones abiertas para el usuario

- **Ventana de 60 min y umbral "≥2 señales":** arbitrarios de partida. Ajustables sin cambio
  de esquema. ¿Prefieres empezar más conservador (≥3 señales) para evitar incidentes ruidosos
  mientras `runtime_alerts` se llena?
- **`recommended_containment` es solo texto** — la ejecución sigue siendo decisión humana por
  el pipeline SOAR existente. Cualquier automatización de esto entra en el item 6 (`0004`).
- **Panel frontend** queda como fase 2 separada; el MVP es backend + API + tests.
- **UEBA sobre Zeek** (baseline de conexiones) es un item hermano, no bloqueante para este.
