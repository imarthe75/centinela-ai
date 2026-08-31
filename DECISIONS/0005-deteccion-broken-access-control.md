# ADR-0005: Detección de Broken Access Control / BOLA / autorización solo-cliente

**Fecha:** 2026-08-31
**Estado:** IMPLEMENTADO (capa estática A/B/E-SAST) + IMPLEMENTADO con degradación honesta
(capa dinámica C/D/E-DAST — se ejecuta de verdad cuando hay credenciales multi-rol; si no,
deja un marcador informativo y no inventa nada).
**Origen:** retest de SIDECO (agosto 2026, reportado por Francisco Gaona). La cuenta `TcsCSA2`
(sin rol de administrador) recibía **HTTP 200** en `GET /wsbev1//api/usr/getUsuarios/1` y, al
reescribir en un proxy una respuesta `403 → 200`, la SPA renderizaba el módulo de
administración de usuarios y permitía **editar usuarios y asignar roles con privilegios
elevados**. El análisis de terceros solo entregó "encontramos esto", sin contexto ni forma de
reproducir. Pregunta del usuario: *¿Centinela está preparado para detectar esto? Si no, ¿hay
forma de incorporar este tipo de análisis?* Instrucción final: *resuelve todo lo posible en
los 5 puntos… que Centinela tenga esta capacidad.*

---

## 1. Diagnóstico: por qué Centinela NO lo detectaba (antes de esta sesión)

`OWASP A01:2021 Broken Access Control` es, por diseño de OWASP, la categoría **más difícil de
detectar con herramientas** porque la regla correcta ("¿quién puede hacer esto?") vive en la
intención del negocio, no en un patrón de código. Los motores que ya existían miran otra cosa:

| Motor | Qué mira | Por qué se le escapa el caso SIDECO |
|---|---|---|
| `auditor_master_vulnerabilities` (SAST nativo) | regex de inyección/secretos/XSS/Docker | no modela autorización de endpoints |
| `auditor_compliance_standards` (STRIDE) | JWT alg, logs sensibles, ruta sin auditoría | "sin auditoría" ≠ "sin control de rol" |
| `auditor_semgrep` | reglas `p/owasp-top-ten`, `p/java`, … | las reglas de A01 de Semgrep OSS son genéricas y no cruzan config Spring ↔ controladores |
| `auditor_zap` (DAST) | spider + active scan **no autenticado** | nunca inicia sesión, jamás compara rol A vs rol B |
| `auditor_api` (ffuf) | descubre endpoints | no diferencia por rol |

Las tres causas raíz del caso SIDECO eran todas visibles en el código, pero **ninguna
herramienta las estaba leyendo**:

- **A.** `ResourceServerConfig` blinda `/v1/catalogos/roles*` con `@roleSecurity.isAdmin(...)`
  pero **no tiene regla para `/v1/usr/**`** → cae en `.antMatchers("/v1/**").authenticated()`.
- **B.** El módulo Angular de administración se protege **solo** con
  `canActivate: [AutorizacionGuard]` (guard de front-end); el backend que consume no revisa rol
  → reescribir `403 → 200` en un proxy lo derrota por completo (CWE-602).
- **C.** **0 de 36** controladores llevan `@PreAuthorize`/`@Secured` a nivel de método.

---

## 2. Lo que se construyó

### 2.1 Capa estática — `auditors/auditor_authz.py` (`scan_engine = 'authz-static'`)

Análisis puramente estático (sin red). Parsea las `SecurityConfig` de Spring
(`antMatchers`/`requestMatchers`/`mvcMatchers` → patrón Ant → regex, con la decisión terminal:
`admin` / `role` / `authenticated` / `permitAll` / `denyAll` / `custom` / `anonymous`),
extrae los endpoints de los `@RestController` (`@GetMapping`… + `@RequestMapping` de clase),
hace *first-match* como lo hace Spring, y contrasta.

Hallazgos que emite:

| cve_id | Severidad | Qué detecta |
|---|---|---|
| `AUTHZ-NO-RULE` | HIGH | endpoint sin regla de URL **y** sin anotación de método → autorización indefinida |
| `AUTHZ-PERMITALL-WRITE` | HIGH | `POST/PUT/DELETE/PATCH` cubierto por una regla `permitAll()` |
| `AUTHZ-INCONSISTENT-FAMILY` | HIGH | **el caso SIDECO**: un endpoint que administra identidad (usuarios/roles/permisos/acceso) queda con `authenticated`/sin regla mientras hay hermanos blindados con rol admin en la misma app |
| `AUTHZ-ONLY-AUTHENTICATED-WRITE` | MEDIUM | escritura sensible gateada solo por `.authenticated()`, sin rol |
| `AUTHZ-NAMESPACE-GAP` | MEDIUM | los `antMatchers` cubren `/v1/**` pero hay controladores o llamadas del front bajo `/api/**` que ninguna regla contempla (habilita el bypass por rewrite de proxy) |
| `AUTHZ-CSRF-DISABLED` | MEDIUM | `.csrf().disable()` con auth por cookie/sesión en juego |
| `AUTHZ-NO-METHOD-ANNOTATIONS` | LOW | ≥5 controladores y 0 `@PreAuthorize` → toda la autorización depende de una lista de URLs a mano |
| `AUTHZ-CLIENT-SIDE-ONLY` | HIGH | ruta de módulo admin protegida **solo** por guard de front-end y sin refuerzo de rol en backend (CWE-602) — **causa B** |
| `AUTHZ-CLIENT-SIDE-UI-GATE` | MEDIUM | función sensible mostrada/ocultada con `*ngIf` sobre chequeo de rol en cliente |
| `AUTHZ-ADMIN-BUNDLE-EXPOSED` | LOW | componentes de módulo admin compilados en el bundle SPA, ocultos solo en cliente |
| `AUTHZ-IDOR-PARAM-REVIEW` | MEDIUM | controlador que recibe el id del sujeto como path-param con solo `.authenticated()` → revisar pertenencia del recurso (la confirmación real la hace la sonda DAST) |

**Resultado verificado en vivo** (2026-08-31, ejecutado con `asset_id` real, persistido):

| Activo | Hallazgos | Detalle relevante |
|---|---|---|
| `Local/siat/backend-sideco-develop` (47734) | 21 | **7× `AUTHZ-INCONSISTENT-FAMILY` HIGH** sobre `UsuarioController.java` (líneas 105 `getUsuarios`, 127 `guardarUsuarios`, 148 `revisarRolRuta`, 261) y `CatalogoController.java` (712, 1362, 1741 — catálogos de roles/permisos) — **exactamente el hallazgo del pentest** |
| `Local/siat/frontend-sideco-develop` (47735) | 2 | `AUTHZ-CLIENT-SIDE-ONLY` HIGH en `catalogos-admin-routing.module.ts:12`; `AUTHZ-ADMIN-BUNDLE-EXPOSED` en `layoutcompleto-routing.module.ts:158` — **causa B** |
| `Local/siat/siat-develop-2026` (47736) | 5 | 2× `AUTHZ-PERMITALL-WRITE` HIGH, 2× CSRF, 1× namespace-gap |
| Código propio de Centinela (`main.py` + `frontend/` + `core/` + `auditors/`) | **0** | sin falsos positivos |

Cableado: `auditors/gitlab_integration.py::scan_all_projects()` (loop de flota, un `try/except`
como los demás motores) y `scratch/rescan_local_siat_2026-08-28.py`. Cada corrida con
`asset_id` reconcilia sus propios hallazgos obsoletos vía `reconcile_resolved_findings`.

### 2.2 Capa dinámica — `auditors/auditor_authz_dast.py` (`scan_engine = 'authz-dast'`)

La **confirmación en tiempo de ejecución**: inicia sesión con varias cuentas de distinto
privilegio y reproduce las mismas peticiones con cada una — lo que hace un pentester a mano.

Hallazgos:

| cve_id | Severidad | Qué confirma |
|---|---|---|
| `AUTHZ-DAST-BROKEN-FUNCTION-LEVEL` | CRITICAL | un rol no-admin obtuvo `2xx` en un endpoint solo-admin (OWASP API5) |
| `AUTHZ-DAST-IDOR` | HIGH | como rol A, cambiar el id en la ruta devolvió `2xx` con datos distintos (OWASP API1 / BOLA) |
| `AUTHZ-DAST-DENY-LEAKS-BODY` | MEDIUM | un `401/403` **aún trae el payload JSON** → habilita el bypass reescribiendo solo la línea de estado (la técnica exacta del retest SIDECO) |
| `AUTHZ-DAST-INCONSISTENT-STATUS` | MEDIUM | un rol recibió `2xx` con cuerpo de datos donde ningún modelo de acceso lo autoriza explícitamente |
| `AUTHZ-DAST-NO-CREDS` | INFO (marcador) | el motor corrió pero no había config multi-rol → **no ejecutado**, sin inventar nada |

Cableado: `auditors/auditor_ext.py` para activos `URL` / `AppServer` / `SERVER` / `API-Gateway`
(helper `_run_authz_dast`). GET por defecto; solo replica verbos mutantes si la config lo
habilita explícitamente (`allow_mutating_probes: true`).

**Degradación honesta** (mismo contrato que `auditor_cis_benchmarks` cuando no hay credenciales
SSH en Vault): sin config → escribe el marcador `AUTHZ-DAST-NO-CREDS` y termina. Nunca fabrica
un resultado.

---

## 3. Decisiones tomadas

### 3.1 Almacenamiento de credenciales multi-rol → **Vault**, con fallback a archivo local

- **Ruta:** `secret/casmarts/authz/{asset_name}` (KV v2, con fallback a v1), o
  `$CENTINELA_AUTHZ_CONFIG_DIR/{asset_name}.json` (default `/app/data/authz/`) para entornos sin
  Vault. Ninguna credencial entra al repo ni a la base de datos.
- **Motivo:** es exactamente el patrón que ya usa este proyecto para credenciales SSH de Ansible
  (`casmarts/ansible/{asset_name}`). No se introduce un mecanismo nuevo.

Contrato de config (documentado en el docstring de `auditor_authz_dast.py`):

```json
{
  "base_url": "https://sideco.edomex.gob.mx/wsbev1",
  "roles": [
    {"name": "admin",       "kind": "admin", "token": "eyJ..."},
    {"name": "conciliador", "kind": "user",  "login": {
        "url": "https://.../oauth/token", "method": "POST",
        "form": {"grant_type":"password","username":"TcsCSA2","password":"…","client_id":"…"},
        "token_json_path": "access_token"}}
  ],
  "endpoints": ["/api/usr/getUsuarios/1", "/api/catalogos/roles"],
  "openapi_url": "https://.../v2/api-docs",
  "access_model": {
     "admin_only":    ["*/usr/*", "*/catalogos/roles*", "*/permisos*"],
     "authenticated": ["*/**"],
     "public":        ["*/mail/*"]
  },
  "allow_mutating_probes": false,
  "idor_probe": true
}
```

### 3.2 Fuente del "modelo de acceso" (qué endpoint es solo-admin) → **cascada de 3 niveles**

1. **`access_model` explícito en la config** del activo (lo más fiable — lo define quien conoce
   el negocio).
2. **OpenAPI/Swagger** del propio servicio (`openapi_url`), leyendo `x-required-role` si está.
3. **Heurística integrada** (`_DEFAULT_ADMIN_ONLY`: `*/usr/*`, `*/usuarios*`, `*/catalogos/roles*`,
   `*/permisos*`, `*/catMenu*`, `*/admin/*`, `*/asignarRol*`, `*/resetPassword*`…) **+
   correlación con la capa estática**: si `auditor_authz` ya marcó ese endpoint como
   `AUTHZ-INCONSISTENT-FAMILY`, la sonda lo trata como solo-admin y confirma en vivo.

El nivel 3 es el que funciona **sin ninguna configuración previa** más allá de las credenciales,
que es lo que hace la capacidad utilizable de inmediato.

### 3.3 Alcance de las sondas → **solo lectura por defecto**

`GET` únicamente salvo `allow_mutating_probes: true` explícito. La sonda IDOR varía un id
numérico de ruta y hace `GET` a `id±1, id±2, 1, 2`; compara los primeros 500 bytes del cuerpo
para no marcar como IDOR una respuesta idéntica (p. ej. una página de error común). Pausa de
50 ms entre peticiones. Tope de `_MAX_ENDPOINTS = 400`.

### 3.4 Ruido del marcador `AUTHZ-DAST-NO-CREDS`

Se clasifica como `INFORMATIONAL` (añadido a `_INFORMATIONAL_CVE_EXACT` en
`core/deduplication_engine.py`), igual que `CIS-BENCHMARK-AUDIT`. `preserve_status=True` +
`log_finding_deduplicated` → **una sola fila por activo**, actualizada en sitio, no una por
ciclo de escaneo.

---

## 4. Lo que queda pendiente (requiere acción de una persona, no de código)

1. **Aprovisionar credenciales multi-rol** de SIDECO / SIAT en
   `secret/casmarts/authz/{asset_name}` para que la capa DAST se ejecute de verdad contra los
   frontends desplegados (`54782` SIAT Cita Online, `54783` SIDECO Solicitud Web). Hoy esos
   activos reciben el marcador `AUTHZ-DAST-NO-CREDS` (honesto: "listo, pero no ejecutado por
   falta de credenciales").
2. **Confirmar el `access_model`** de cada servicio con el equipo de desarrollo, o publicar un
   OpenAPI con `x-required-role`. Mientras tanto opera la heurística del nivel 3.
3. **Remediación real en SIDECO** (fuera del alcance de Centinela): añadir regla
   `/v1/usr/**` con `@roleSecurity.isAdmin` en `ResourceServerConfig`, o `@PreAuthorize` a nivel
   de método en `UsuarioController`; y mover el control del módulo admin del guard de Angular al
   backend. Los 7 hallazgos `AUTHZ-INCONSISTENT-FAMILY` HIGH ya están en el dashboard con la
   ubicación exacta (`archivo:línea`).

---

## 5. Pruebas

`tests/test_auditor_authz.py` — fixtures temporales de Spring + Angular:
- un `SecurityConfig` que blinda `/v1/catalogos/roles*` y **olvida** `/v1/usr/**` + un
  `UsuarioController` sin anotaciones → **debe** disparar `AUTHZ-INCONSISTENT-FAMILY`.
- un `SecurityConfig` con `@PreAuthorize` en todos los controladores de identidad → **no** debe
  disparar.
- un routing Angular con `canActivate: [AuthGuard]` sobre `catalogos-admin` y backend sin rol →
  `AUTHZ-CLIENT-SIDE-ONLY`.
- regresión: el árbol de `auditors/` + `core/` de Centinela → **0 hallazgos**.

Suite completa esperada: 122 → 12x passing tras añadir este archivo.
