# ADR-0004: Respuesta autónoma por niveles (item 6) — DECISIÓN PENDIENTE

**Fecha:** 2026-08-27
**Estado:** PROPUESTA — **no implementar sin autorización explícita del usuario.**
**Origen:** evaluación de "The Rock" (SOC agéntico de KIO), que promociona *"medidas de bloqueo
y contención automatizadas"*. El usuario pidió expresamente **documentar esto para decidir
después**, no construirlo.

---

## 1. Contexto y tensión

"The Rock" ejecuta contención de forma autónoma (bloqueo de IP, aislamiento de host) sin
intervención humana en los casos de alta confianza. Centinela **ya tiene toda la plomería**:

- `generate_ip_block_virtual_patch()` — `deny <ip>;` en el proxy, aditivo, sin reiniciar servicio.
- `POST /api/host-containment/{asset_name}` — genera un `HOST-CONTAINMENT-REQUEST` que fluye por
  el pipeline `correlate → aprobación humana → ejecución Sentinel`.
- `sentinel.py` — ejecutor Ansible de remediaciones **aprobadas**.

…pero **por diseño, todo pasa hoy por aprobación humana**. La regla del proyecto es tajante y
está repetida en `CLAUDE.md`:

> *"never approved/executed against a real host (that action is genuinely disruptive and must
> be a deliberate human decision made through the real SOAR UI, not something to fire during
> verification)"*
> *"an emergency containment should not be able to undo itself"*

Automatizar la contención **contradice directamente** esa regla. Por eso este item se
documenta y se congela: la decisión es del dueño del sistema, no del agente.

---

## 2. Propuesta concreta (si se aprobara)

Una **capa de política** sobre el pipeline existente — no plomería nueva de ejecución.

### 2.1 Tabla `autoresponse_policy`

```sql
CREATE TABLE public.autoresponse_policy (
    id             SERIAL PRIMARY KEY,
    action_kind    TEXT NOT NULL,      -- 'proxy_ip_block' | 'host_isolate'
    max_severity_auto TEXT,            -- hasta qué severidad se permite auto (NULL = nunca)
    asset_scope    TEXT NOT NULL DEFAULT 'NON_CRITICAL', -- 'NON_CRITICAL' | 'NONE' | 'TAGGED:<tag>'
    require_cti_confirmed BOOLEAN NOT NULL DEFAULT TRUE,  -- solo si hay hit CTI real
    daily_cap      INTEGER NOT NULL DEFAULT 3,            -- tope de acciones auto / 24 h
    dry_run        BOOLEAN NOT NULL DEFAULT TRUE,         -- arranca en observación
    active         BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by     TEXT, updated_at TIMESTAMP DEFAULT NOW()
);
```

### 2.2 Reglas de elegibilidad (TODAS deben cumplirse para auto-ejecutar)

1. `action_kind` con `active = TRUE` y `dry_run = FALSE` en `autoresponse_policy`.
2. Confianza alta y objetiva:
   - IP: **hit confirmado en el feed CTI** (`core/cti_feed.py`, Feodo Tracker) — no heurística.
   - Host: alerta Falco/Wazuh de severidad `CRITICAL` **+** incidente correlacionado (item 2)
     con ≥2 fuentes independientes.
3. **Blast radius bajo:**
   - `proxy_ip_block`: siempre bajo (aditivo, reversible con `DELETE` de la línea `deny`).
   - `host_isolate`: solo activos con `criticality IN ('LOW','MEDIUM')` y **nunca**
     infra compartida (`casmarts-core-*`, gateway, DB).
4. No superar `daily_cap` en 24 h (circuit breaker).
5. Ventana horaria opcional (p. ej. solo fuera de horario laboral para `host_isolate`).

Si **algo** falla → se crea el `*-REQUEST` como hoy y espera aprobación humana. El default es
"pedir permiso"; la automatización es la excepción explícitamente configurada.

### 2.3 Salvaguardas obligatorias

- **Modo `dry_run` por defecto:** durante ≥2 semanas la política solo *registra en
  `agent_actions`* qué habría hecho (`outcome='skipped'`, `detail.would_have=...`). El usuario
  revisa ese log antes de poner `dry_run=FALSE`.
- **Notificación inmediata** (PushNotification / webhook Slack) en cada auto-acción, con enlace
  para revertir en 1 clic.
- **Reversión con TTL para `proxy_ip_block`:** el `deny` auto-insertado lleva un comentario
  `# centinela-auto expires=<ts>`; un barrido lo retira a las 24 h salvo que un humano lo
  promueva a permanente. (El bloqueo manual/aprobado NO expira.)
- **`host_isolate` NUNCA se auto-revierte** (coherente con la regla actual: una contención de
  emergencia no debe deshacerse sola). Revertir es decisión humana.
- **Kill switch:** `autoresponse_policy.active = FALSE` global desactiva todo al instante.
- Todo pasa por el ledger `agent_actions` (item 4) con `actor='centinela-autoresponse'`.

---

## 3. Qué NO se propone automatizar (nunca, en ninguna fase)

- Cambios en infra compartida (`casmarts-core-gateway`, Vault, Authentik, `centinela_db`).
- Remediaciones de código (MRs) — siempre revisión humana del merge.
- Borrado de datos, rotación de credenciales, cambios de firewall más allá de un `deny <ip>`
  aditivo.
- Cualquier acción sobre activos `criticality = 'CRITICAL'` o `'HIGH'`.

---

## 4. Preguntas para el usuario (para decidir después)

1. ¿Se quiere **algún** grado de auto-respuesta, o la contención debe seguir siendo
   100% humana? (El resto de items — 1/2/3/4/5 — no dependen de esto.)
2. Si sí: ¿empezar **solo** con `proxy_ip_block` sobre IPs confirmadas por CTI (el caso de
   menor riesgo y totalmente reversible), y dejar `host_isolate` siempre manual?
3. ¿Cuánto tiempo en `dry_run` antes de habilitar ejecución real?
4. ¿Qué canal de notificación inmediata se usa (Slack / correo / webhook Authentik)?
5. ¿Tope diario aceptable de acciones automáticas?

---

## 5. Recomendación del autor de este documento

**No activar `host_isolate` automático.** El riesgo de aislar por error un host que resulta
ser legítimo (falso positivo de Falco/Wazuh, que este proyecto ha encontrado repetidamente en
otros detectores) supera el beneficio de ahorrar minutos, y contradice una regla de seguridad
que el proyecto ya adoptó tras incidentes reales.

**Sí es defendible**, tras un periodo `dry_run` revisado, activar `proxy_ip_block` automático
**exclusivamente** para IPs con hit CTI confirmado y TTL de 24 h: es aditivo, reversible,
acotado por `daily_cap`, y el feed CTI (Feodo Tracker) es una fuente objetiva y de baja tasa
de falsos positivos. Aun así, es una decisión del dueño del sistema — de ahí este ADR.
