# Estado del Proyecto - Centinela CAI

## 📅 Fecha: 11 de Agosto, 2026 (tarde, continuación) — Falco desplegado y verificado end-to-end
El usuario pidió activar Falco de verdad (estaba comentado en `docker-compose.yml` desde siempre,
ver la nota "Falco nunca se desplegó" más abajo en este archivo). Con confirmación explícita del
usuario dado que requiere `privileged: true` y montajes amplios del host, se desplegó
`falcosecurity/falco:latest` (auto-selecciona el driver eBPF moderno en kernel ≥5.8, sin paso de
carga manual — este host corre 6.8.0) + `falcosidekick`.

**Depuración real, no trivial, para llegar a un pipeline verificado**:
1. El comando original (comentado en `docker-compose.yml`, heredado sin probar) usaba
   `-o http_output.enabled=true -o http_output.url=...` — Falco cargó la config sin error, pero
   0 eventos llegaban a Falcosidekick pese a que las reglas sí disparaban (confirmado en el
   stdout de Falco, con detecciones reales y tags MITRE ATT&CK reales).
2. Se probó reemplazar por `falcosidekick.enabled=true` (sugerido por un comentario del propio
   `falco.yaml` sobre el Helm chart oficial) — tampoco funcionó; ese comentario resultó aplicar
   solo al método de despliegue vía Helm, no a un contenedor suelto.
3. Se probó montar el override como archivo en `config.d/` — Falco confirmó cargarlo con
   `schema validation: ok`, pero seguía sin funcionar: el archivo principal `falco.yaml` se carga
   *después* de `config.d/` y su propio `http_output.enabled: false` por defecto ganaba.
4. Se reemplazó `/etc/falco/falco.yaml` completo (copia del archivo real del contenedor con solo
   `http_output.enabled`/`json_output` cambiados) — confirmado cargado correctamente
   (`cat` dentro del contenedor mostró los valores correctos) pero **seguía sin llegar nada**.
5. Se probó `program_output` con `curl` como workaround (patrón documentado en el propio
   `falco.yaml` para casos así) — tampoco.
6. **Causa raíz real, encontrada al inspeccionar Valkey directamente en vez de asumir por los
   logs**: Falcosidekick **sí estaba entregando los eventos correctamente desde el primer
   intento** (paso 1) — pero a la llave `falco`, no `centinela:falco` como se esperaba. La
   variable de entorno `REDIS_STORAGEKEY=centinela:falco` de `falcosidekick` (documentada como
   configurable) **no se respeta en la versión desplegada** — 32 eventos reales, incluyendo mis
   propias pruebas desde `2026-08-11T13:47:51` (la primerísima prueba), llevaban acumulados en
   Valkey todo este tiempo sin que nada los consumiera, porque `centinela.py` escuchaba en el
   nombre de llave equivocado. El pipeline llevaba funcionando perfectamente desde el primer
   intento; el bug real estaba en el lado consumidor, no en Falco/Falcosidekick.
7. Corregido: `centinela.py`'s `process_falco_alerts()` ahora escucha en `"falco"` (la llave
   real observada), revertidos los intentos 2-5 a la configuración nativa simple (solo
   `http_output.enabled`/`json_output` vía reemplazo de `falco.yaml`), limpiados los 32 eventos
   de prueba acumulados, y **verificado end-to-end con una prueba limpia**: contenedor Alpine
   desechable → `cat /etc/shadow` → detección real de Falco (tag MITRE T1555) →
   `🚨 [Centinela-AI] Falco Alert: Read sensitive file untrusted` en los logs de `centinela-ai` →
   fila real en `runtime_alerts` (ids 915-916). **Primera vez en la historia de este deployment
   que una alerta de Falco llega a la base de datos.**

**Lección**: cuando algo "no llega a ningún lado" pese a que cada eslabón individual parece
responder bien, inspeccionar el almacén de destino directamente (`KEYS *`) antes de asumir dónde
está el problema — cinco intentos de arreglar Falco/Falcosidekick fueron innecesarios porque el
verdadero bug estaba en una sola línea del lado consumidor, escuchando la llave equivocada.

## 📅 Fecha: 11 de Agosto, 2026 (tarde) — CMMI real conectado al dashboard + 2 incidentes de producción
El usuario pidió que el cumplimiento CMMI (y en menor medida ISO) por activo se reflejara con
datos reales en el dashboard general y en el panel de detalle de cada activo, con un botón de
descarga de reporte PDF. Al implementarlo se encontraron y corrigieron **dos bugs reales,
independientes, que tumbaron el backend en producción durante las pruebas** — documentados aquí
en detalle porque ambos son graves y podrían repetirse si se vuelve a tocar código cercano.

1. **`GET /api/inventory/{asset_name}/details` lanzaba `NameError: name 'details' is not defined`
   para prácticamente cualquier activo en línea/alcanzable.** La variable `details` nunca se
   inicializaba — cada rama de tipo de activo (`if any(k in atype for k in (...))`, 17
   categorías) solo hacía `details["clave"] = valor` (asignación de ítem) sobre un nombre que no
   existía todavía. La única ruta que alguna vez funcionó fue el `return` temprano para activos
   offline/nunca-encendidos, que construye su propio diccionario literal. Esto explica por qué el
   frontend, aunque ya tenía código para leer `info?.compliance?.cmmi_score`, siempre caía al
   cálculo estimado en el cliente — el dato real nunca llegaba, el endpoint fallaba con 500 en
   silencio para el operador. Corregido inicializando `details` con los campos base justo después
   del chequeo de `is_unpowered`. Verificado en vivo contra 4 activos de tipos distintos
   (GitLab-Repo, SERVER×3) — los 4 ahora devuelven 200 con datos reales.
2. **Un solo cambio de estilos CSS compartido por *todos* los reportes PDF podía congelar el
   backend entero para todos los usuarios, de forma silenciosa e impredecible.**
   `CIVIKA_PDF_STYLES` (usado por `/api/reports/executive`, `/api/reports/asset/{name}`,
   `/api/reports/coverage`, `/api/reports/vulnerability/{id}`, y los nuevos `/api/reports/cmmi*`)
   tenía un `@import url('https://fonts.googleapis.com/...')`. WeasyPrint intenta descargar ese
   CSS externo al renderizar el PDF, **sin timeout alguno** — si esa conexión HTTPS saliente se
   queda a medias (confirmado en vivo con `ss -tnp` dentro del contenedor: conexiones `ESTAB`
   hacia IPs reales de Google/Cloudflare/AWS que nunca avanzaban), el hilo único de `uvicorn`
   (un solo worker, llamadas síncronas de psycopg2/requests sin offload a threadpool) se congela
   por completo — no solo esa petición, **absolutamente todas las peticiones nuevas de cualquier
   usuario**, incluyendo `/api/health` y las llamadas normales del dashboard, quedan en cola
   indefinidamente. Confirmado en vivo: dos incidentes reales durante esta sesión, cada uno
   requirió `docker restart centinela-backend` para recuperarse; con tráfico real de usuarios
   activo al mismo tiempo (visible en los logs por peticiones desde `172.18.0.1`), así que esto
   afectaba producción, no solo mis pruebas. **Corregido eliminando el `@import` por completo** —
   la pila de fuentes ya tenía respaldos locales seguros (`'Segoe UI', system-ui, sans-serif` /
   `'Consolas', monospace`), así que no hay pérdida funcional, solo un cambio cosmético de
   tipografía. Verificado en vivo, repetidamente, tras el fix: ambos reportes CMMI (flota y por
   activo) generan PDFs reales en <2s sin abrir ninguna conexión externa, y `/api/health`
   responde en <1s antes y después de cada prueba.
   **Este bug es preexistente y afecta a los 4 endpoints de reporte anteriores también**, no solo
   a los nuevos de CMMI — cualquier descarga de reporte, en cualquier momento, podía (y
   probablemente ya había) congelado el backend completo sin que quedara rastro claro en logs
   más allá de peticiones colgadas. Vale la pena vigilar si episodios similares de "el dashboard
   no responde" ocurrieron antes sin explicación.
3. **Optimización de rendimiento relacionada, encontrada en el camino**: el reporte CMMI de
   flota (`get_cmmi_v3_asset_audit_report()`) hacía **83 consultas SQL secuenciales** (una por
   activo) en un solo request — aunque no era la causa del colgado (ese fue el problema #2),
   sí era una carga real e innecesaria sobre un backend de un solo worker. Refactorizado a
   **una sola consulta** que trae todos los hallazgos abiertos de una vez y los agrupa en Python
   por activo, preservando exactamente la misma lógica de matcheo (`asset_id` o `url_path ILIKE
   nombre`). De paso se extrajo `evaluate_cmmi_v3_for_asset(cur, asset, vulns=None)` como función
   compartida y reutilizable — usada tanto por el reporte de flota como por el endpoint de
   detalle de activo y los reportes PDF, una sola fuente de verdad para la evaluación CMMI real
   (antes había 3 implementaciones distintas e inconsistentes: una en `compliance_mapper.py`
   nunca conectada al frontend, una fórmula ad-hoc en `main.py`, y una fórmula inventada
   client-side en `Dashboard.jsx`).

**Entregado**: KPI real de CMMI en el dashboard general (promedio real de la flota, ya no una
fórmula inventada basada en conteo de severidades), badge real por activo en las tarjetas de
inventario, panel de detalle con las 7 áreas de práctica CMMI reales y su evidencia, y botones de
descarga de reporte PDF de CMMI tanto a nivel flota como por activo.

**Lección operativa para la próxima vez que se toque cualquier reporte PDF**: nunca depender de
un recurso externo (fuentes, CDNs, APIs) dentro de una petición HTTP síncrona en un servidor de
un solo worker sin timeout explícito — un solo recurso externo lento puede tumbar todo el
servicio, no solo esa función.

## 📅 Fecha: 11 de Agosto, 2026 (Rito de Cierre — sesión completa)

## 🎯 Rito de Cierre (2026-08-11, segunda mitad) — Deuda técnica resuelta + documentación actualizada
Continuación directa de la auditoría documentada más abajo en este mismo archivo. El usuario
pidió corregir *toda* la deuda técnica pendiente, y al finalizar, actualizar la documentación
(manual técnico, resumen ejecutivo, este `STATE.md`) y regenerar la presentación ejecutiva.
Todo lo siguiente fue verificado en vivo, no solo declarado:

1. **`sla_due_date` backfilleado retroactivamente**: 17,561 filas históricas actualizadas con
   `NOW()+interval` a nivel SQL (no Python, ver el bug de zona horaria ya documentado más abajo).
   El KPI de incumplimientos de SLA pasó de reportar 0 a **18 CRITICAL reales**.
2. **Segundo bug real encontrado al investigar el punto anterior, más grave**:
   `log_finding_deduplicated()` comparaba `asset_id = %s` — en SQL, `NULL = NULL` nunca es
   `TRUE`, así que cualquier hallazgo con `asset_id=None` (diseño intencional para alertas
   agregadas como `HEURISTIC-SECURITY-DEBT`) nunca podía encontrar su propia fila anterior y se
   reinsertaba sin fin. Confirmado en vivo: **983 filas duplicadas** de una sola alerta agregada.
   Corregido con `asset_id IS NOT DISTINCT FROM %s` (NULL-safe) en `core/deduplication_engine.py`,
   verificado con un test de regresión real.
3. **Limpieza de datos históricos**: 13,990 filas huérfanas de `cmmi-audit` (pre-fix del punto 3
   de la auditoría original) + 982 duplicados de `HEURISTIC-SECURITY-DEBT` (pre-fix del punto 2
   de aquí arriba) eliminados, tras confirmar 0 referencias en `remediation_history`. **El total
   real de `vulnerability_log` bajó de ~18,000 a 3,448 filas** — la tabla estaba dominada en un
   76-96% por bugs de duplicación, no por hallazgos reales distintos.
4. **`iac-native` verificado end-to-end** con un escenario sintético desechable (5/5 hallazgos
   K8s/Terraform detectados y persistidos correctamente, luego limpiado) — ningún repo real
   clonado tenía violaciones reales de este tipo al momento de la prueba.
5. **Acceso GitLab para la cuenta de servicio `monitor`**: confirmado que `israelm` (token usado
   por el escaneo automatizado) tiene rol Maintainer sobre el grupo `arquitectura/`, suficiente
   en teoría para otorgar acceso Developer — el intento vía API devolvió **403 Forbidden** sin
   causa clara (`membership_lock`/`share_with_group_lock` descartados). No se insistió con
   reintentos ciegos (regla de `.agent/HEURISTICS.md` §2: detenerse tras un fallo, no repetir el
   mismo cambio). Queda pendiente para un administrador real de la instancia GitLab.
6. **`pytest` instalado** (faltaba por completo en ambos contenedores Python pese a ser
   obligatorio por `AGENT.md`/`CLAUDE.md`) y agregado a `requirements.txt`. Se agregaron 9 tests
   nuevos (regresión para cada bug de este ciclo) y se convirtieron 2 archivos de prueba
   "fantasma" (`test_inventory.py`, `test_heuristics_medusa.py` — scripts `__main__` que
   `pytest` nunca detectaba, 0 items collected; uno de ellos además apuntaba a la infraestructura
   fantasma ya eliminada el 2026-08-04, `casmarts-core-db-primary`/`casmarts_security`/usuario
   `admin`) en tests reales descubribles. **30/30 pasan.**
7. **Documentación actualizada para reflejar la realidad verificada**:
   - `.agent/CONTEXT.md` y `.agent/MAP.md` corregidos — describían un stack genérico de la
     plantilla `resident-agent-framework` (Valkey, pgvector, SeaweedFS, PKs UUID, DB
     `casmarts_security`) que nunca existió en este despliegue real.
   - `docs-public/manual-tecnico.html`: nueva sección con la tabla completa de bugs
     encontrados/corregidos y las cifras reales post-limpieza.
   - `RESUMEN_EJECUTIVO_CENTINELA_AI.md`: reescrita la sección 1 (menos jerga técnica), agregada
     sección 1.1 con cifras reales verificadas, corregida la sección de comercialización
     (se quitó una mención a "ClickHouse" — no es parte real de este stack — y una cifra de
     "$80,000 USD/año" no verificada), y reemplazado el claim de "90% de cumplimiento XDR" (sin
     respaldo real) por un resumen honesto que remite a la sección 1.1.
   - `Presentacion_Centinela_AI.pptx` **regenerada completa** (12 slides, `python-pptx`): enfoque
     100% en lenguaje de negocio (sin siglas sin explicar), con una sección dedicada a CMMI/ISO
     explicados para no-técnicos, y una sección de "Estado Actual" con las cifras reales de esta
     auditoría en vez de las cifras infladas anteriores.
8. **Backfill de los ~330 hallazgos con análisis genérico**: lanzado en segundo plano dentro de
   `centinela-ai` (cascada Groq→Gemini→NVIDIA→OpenRouter, deteniéndose tras 15 fallos
   consecutivos de todos los proveedores). Groq se agotó rápido (cuota diaria), cayendo
   correctamente a Gemini/NVIDIA — confirma que la cascada de 4 proveedores funciona en carga
   real, no solo en la prueba puntual ya documentada. **Este proceso corre de forma
   independiente y puede seguir avanzando después de este cierre de sesión** — no se restauró
   `centinela-ai` (se habría interrumpido el proceso) hasta que termine o se decida detenerlo
   manualmente; `centinela-backend`/`centinela-sentinel` sí se reiniciaron sin problema al no
   correr el backfill.

**Pendiente real, no resuelto en este cierre**: (a) el backfill de los ~330 hallazgos puede no
haber terminado al momento de cerrar esta sesión — verificar con
`SELECT COUNT(*) FROM vulnerability_log WHERE executive_summary LIKE '%sin regla determinística%' OR executive_summary LIKE '%sin regla de remediación específica%' OR description LIKE '%Hallazgo de código fuente:%'`
(debería tender a 0); (b) `centinela-ai` no se ha reiniciado desde los 2 últimos fixes de
`deduplication_engine.py` (NULL-safe dedup y `sla_due_date` vía SQL) — su propio loop de fondo
sigue en memoria con la versión anterior hasta que se reinicie, una vez el backfill termine;
(c) acceso GitLab de `monitor` sigue bloqueado (ver punto 5 arriba).

## 🎯 Hitos Recientes (2026-08-11) — Auditoría profunda "¿está todo lo documentado realmente funcionando?"
El usuario pidió un rito de inicio seguido de una auditoría a profundidad de todo lo documentado
(`CLAUDE.md` + este `.agent/`), no solo una lectura de docs. Se encontró que el trabajo más
reciente (commits de CMMI v3.0/CSPM/eBPF de otro agente, "antigravity") nunca actualizó este
`STATE.md` — violando la propia regla de "Rito de Cierre" de `AGENT.md`. Se encontraron y
corrigieron **7 bugs reales**, todos verificados en vivo (no solo por inspección de código):

1. **`auditor_db_hardening.py` nunca funcionó ni una vez**: `get_db_connection()` (un
   `@contextmanager`) se llamaba sin `with` → `AttributeError` silenciada. 0 filas
   `scan_engine='db-hardening'` en toda la historia. Corregido + migrado a
   `log_finding_deduplicated()`. Verificado en vivo contra `casmartdb` (10.4.3.23) y, tras
   reiniciar, contra 3 DBs reales en el loop de producción — 0 errores.
2. **`auditor_iac_k8s.py` perdía el 100% de sus hallazgos**: detectaba violaciones reales de
   K8s/Terraform pero nunca las persistía (sin `INSERT` alguno). Corregido con `asset_id` +
   `log_finding_deduplicated()`. Verificado con un escenario sintético desechable (5/5
   hallazgos detectados y persistidos, luego limpiado).
3. **`auditor_cmmi_v3.py` (la funcionalidad insignia de los commits más recientes,
   "CMMI v3.0 por Activo") nunca vinculaba `asset_id`/`url_path`** — 13,715 filas huérfanas
   (76% de toda la tabla `vulnerability_log`), 55% duplicado exacto por re-scans sin dedup real.
   El reporte `/api/audit/cmmi-v3-report` (documentado en el manual como "reporte cuantitativo
   **empírico**") **nunca usó los datos de su propio motor** — CAR/MSR/PQA por activo mostraban
   coincidencias accidentales de otros motores (palabra "INJECTION"), no evidencia CMMI real.
   Corregido: `asset_id` propagado desde `gitlab_integration.py`, persistencia real. Verificado
   en vivo contra `centinela-cai` (asset_id=102): score cambió de datos accidentales a
   MSR 61 fallas / PQA 34 violaciones reales, antes invisibles.
4. **SpiderFoot OSINT seguía en 0 filas** pese al fix de constraint ya documentado — un segundo
   bug independiente: `a_type == "URL"` nunca se cumple (ningún activo real usa ese tipo
   literal). Ampliado a `("URL","SERVER","AppServer")`. Verificado: primer hallazgo real
   (`tls_issues` en `casmart_authentik`) en la historia de este deployment.
5. **SLA deadline tracking estructuralmente ciego al 96% del backlog real**: el cálculo en
   `/api/remediation` solo era para pantalla, nunca se guardaba; `log_finding_deduplicated()`
   (usado por casi todos los motores) tampoco seteaba `sla_due_date`. 0 de 223 CRITICAL sin
   resolver tenían fecha límite. Corregido en el INSERT compartido, calculado con
   `NOW() + interval` en SQL (no en Python — el servidor de DB corre en `America/Mexico_City`,
   no UTC; un primer intento con `datetime.utcnow()` produjo un delta de 30h en vez de 24h para
   CRITICAL, detectado y corregido en la misma sesión). Backfill retroactivo de 17,561 filas
   históricas ejecutado — el KPI de SLA breaches pasó de reportar 0 a **18 incumplimientos
   CRITICAL reales**.
6. **Bug de fondo, más grave, encontrado al investigar el punto 5**: `log_finding_deduplicated()`
   comparaba `asset_id = %s` — en SQL, `NULL = NULL` nunca es `TRUE`, así que **cualquier
   hallazgo con `asset_id=None`** (diseño intencional para alertas agregadas como
   `HEURISTIC-SECURITY-DEBT`) nunca podía encontrar su propia fila anterior y se reinsertaba sin
   fin. Confirmado en vivo: 983 filas duplicadas de una sola alerta agregada. Corregido con
   `asset_id IS NOT DISTINCT FROM %s` (NULL-safe). Verificado: segunda llamada con descripción
   distinta ahora actualiza la misma fila en vez de duplicar.
7. **Limpieza de datos históricos**: 13,990 filas huérfanas de `cmmi-audit` (pre-fix) y 982
   duplicados de `HEURISTIC-SECURITY-DEBT` (pre-fix del punto 6) eliminados tras confirmar 0
   referencias en `remediation_history`. **El total real de `vulnerability_log` bajó de ~18,000
   a 3,448 filas** — la tabla estaba dominada en un 76-96% por bugs de duplicación, no por
   hallazgos reales distintos. Esto cambia materialmente cualquier lectura ejecutiva/dashboard
   basada en "total de vulnerabilidades" hecha antes de hoy.

**Archivos modificados**: `auditors/auditor_db_hardening.py`, `auditors/auditor_iac_k8s.py`,
`auditors/auditor_cmmi_v3.py`, `auditors/gitlab_integration.py`, `auditors/auditor_ext.py`,
`core/deduplication_engine.py`. Servicios reiniciados y confirmados sin regresiones
(`/api/health` → `Healthy`, 0 errores nuevos en logs de los 3 servicios Python tras el reinicio).

**Pendiente real, no completado hoy**: backfill de ~330 hallazgos con análisis IA genérico
(depende de cuota de proveedores, se relanza aparte); acceso Developer de la cuenta de servicio
`monitor` al grupo GitLab `arquitectura/` (cambio de permisos fuera de este repo, requiere
confirmación explícita antes de ejecutarse por afectar un sistema compartido).

## 📅 Fecha: 10 de Agosto, 2026

## 🎯 Hitos Recientes (2026-08-10) — Verificador de Activos Vivos, WebSocket en Tiempo Real & Diferenciación Offline
- **Verificador Continuo de Estado en Segundo Plano (`poll_asset_status`)**:
  - Implementado bucle worker asíncrono en `main.py` ejecutado en segundo plano cada 10 segundos.
  - Sincronizado con la base de datos PostgreSQL añadiendo la columna `last_seen` en `public.infra_inventory`.
  - Transmite actualizaciones dinámicas de conectividad vía WebSockets (`asset_status_update`) a la interfaz de usuario.
- **Diferenciación de Estados Visuales en Frontend (`Dashboard.jsx`)**:
  - **`Sincronizado` (Verde)**: Activos en línea monitoreados por agente o respuesta ICMP en tiempo real.
  - **`Offline (Desconectado)` (Ámbar)**: Activos previamente sincronizados que perdieron conexión, detallando la fecha y hora exacta del último registro en su tooltip (`last_seen`).
  - **`Offline (Sin Conexión Previa)` (Gris)**: Activos recién registrados en inventario sin historial previo de comunicación.
- **Actualización Instantánea de Activos**:
  - En `handleAddAsset()`, se resetean automáticamente los filtros de búsqueda e inventario y se fuerza la navegación asíncrona a la vista del inventario reflejando inmediatamente el nuevo activo registrado.

## 📅 Fecha: 5 de Agosto, 2026

## 🎯 Hitos Recientes (2026-08-05, segunda mitad) — "los scripts de remediación no remedian nada"
El usuario mostró un caso real: un "fix" de `DOCKER-MISSING-NON-ROOT-USER` que solo imprimía una
advertencia y creaba un usuario Linux local sin relación, sin tocar nunca el Dockerfile. Auditoría
completa de la taxonomía real de hallazgos (`SELECT cve_id, asset_type, COUNT(*) ...`) confirmó
que es sistémico: **~517 hallazgos** (`CODE-INJECTION-EVAL`, `HARDCODED-SECRET`,
`DOCKER-MISSING-NON-ROOT-USER`, `SCA-CVE-*`, `STD-*`, `COGNITIVE-*`, `CMD`/`SQL`/`SSRF-*`) viven
en assets `GitLab-Repo` — no hay host remoto que "endurecer" por SSH, la corrección real es un
cambio de código. `sentinel.py` solo sabía ejecutar Ansible/SSH contra una IP; para estos casos
`asset_ip` es en realidad la URL del repo, así que toda aprobación fallaba en la conexión (o algo
peor si coincidía por accidente con un host real). Ver el detalle completo en `CLAUDE.md`
("AI remediation scripts were cosmetic..."); resumen de lo corregido:

- `remediation/gitlab_autofix.py` (ya conectado a un endpoint real,
  `POST /api/gitlab/autofix/{vuln_id}`, pero nunca llamado desde el frontend) estaba roto de
  punta a punta: usaba `re` sin importarlo, nunca clonaba ni editaba nada, y abría un Merge
  Request con un `source_branch` que jamás se había subido (GitLab siempre rechaza eso).
  Reescrito con clone → parche real → commit/push a una rama `centinela-fix/*` → Merge Request
  (nunca push directo a la rama principal). También tenía `project_id` fijo en `1` sin importar
  el repo real de la vulnerabilidad — ahora se resuelve desde el propio asset.
- Dos parches **determinísticos** (sin LLM, mecánicos y seguros): Dockerfile USER no-root, y
  bump de dependencia SCA a la versión segura conocida. Verificados en vivo contra un proyecto
  GitLab desechable creado y borrado solo para esta prueba (nunca se tocó un repo real ya
  escaneado): ambos generaron un MR real con exactamente el diff esperado.
- Para hallazgos que necesitan entendimiento real de código, `correlate_vulnerability()` ahora
  pide al LLM un `fix_patch` (diff unificado) usando archivo/línea/fragmento real, guardado en
  `vulnerability_log.fix_patch` (columna que ya existía en el esquema, sin usar) y aplicado con
  `git apply` por el mismo pipeline. Verificado el flujo completo (parseo → extracción →
  `git apply` → MR) con una respuesta de LLM simulada y con un diff real generado por
  `git diff` — la cuota diaria de Groq seguía agotada al momento de la prueba, así que la
  llamada real al LLM en producción todavía no se verificó end-to-end.
- `can_automate` estaba **fijo en `True`** en el fallback heurístico y **fijo en `False`**
  (ignorando lo que decía el LLM) en el camino JSON principal — ninguno reflejaba la realidad.
  Corregido en ambos.
- `SCAN-AUDIT` (mensajes de "no se encontraron vulnerabilidades"/"escaneo omitido") caía por
  coincidencia de palabra clave en la rama de **bloqueo de firewall** (`ufw default deny
  incoming` + solo 22/80/443) — aprobar un hallazgo que literalmente dice "sin vulnerabilidades"
  habría aplicado un firewall restrictivo a un host sano sin motivo. Corregido, junto con
  `HEURISTIC-SECURITY-DEBT` (un meta-hallazgo agregado, tampoco "remediable" con un script).
- De paso, encontrados y corregidos: (a) `auditor_master_vulnerabilities.py`/
  `auditor_sca_dependencies.py`/`auditor_compliance_standards.py` capturaban `file`/`line` pero
  nunca los guardaban en la base (ahora en `url_path`), y tenían el mismo bug de `ON CONFLICT DO
  NOTHING` sin constraint real que Medusa/PROWLER-AUDIT (ver gotcha #3) — cada escaneo del org
  de GitLab reinsertaba cada hallazgo como nuevo; (b) el regex de `CODE-INJECTION-EVAL` no tenía
  límite de palabra y disparaba con cualquier identificador que contuviera "eval" (confirmado:
  136 de 140 hallazgos reales eran falsos positivos, ej. `onErrorEval`); (c) para los 641
  hallazgos reales de ZAP (en hosts `SERVER` de verdad, sí automatizables), se construyó un
  generador real de hardening de cabeceras nginx, verificado contra la estructura real de
  `casmart_authentik` (nginx corre en un contenedor `nginx:alpine`, no a nivel de sistema, con
  `conf.d` montado de solo lectura desde el host) — el paso final de aplicar el cambio en vivo
  fue bloqueado por el clasificador de permisos por ser una escritura a infraestructura
  compartida (`casmarts-core-gateway` sirve varias apps más, no solo Authentik); la lógica del
  script sí se validó contra la estructura real del host, pero la ejecución final queda
  pendiente de aprobación manual vía la UI de SOAR.

## 🎯 Hitos Recientes (2026-08-04)
- **ZAP DAST nunca había funcionado ni una sola vez, ni con la imagen corregida.** Al probar un
  scan real de punta a punta salieron **10 bugs independientes apilados uno sobre otro**:
  faltaba `-d` en `docker run` (bloqueaba en foreground), el puerto interno correcto es 8080 no
  8090, `localhost` desde `centinela-ai` nunca puede alcanzar un contenedor lanzado vía
  `docker.sock` montado (son contenedores *hermanos*, no padre-hijo — hay que usar el nombre del
  contenedor en `aura-network`), el volumen de caché apuntaba a una ruta que la imagen nunca usa
  (`/root/.zap/db` en vez de `/home/zap/.ZAP`), permisos del volumen (creado por el host como
  root), ZAP no permite compartir su home dir entre scans concurrentes ("already in use"), ZAP
  se bindea a 127.0.0.1 por defecto (necesita `-host 0.0.0.0`), ZAP también rechaza peticiones
  por `Host` header aunque el puerto sí responda (necesita `-config api.addrs.addr.*`), el
  endpoint de verificación de "listo" usaba `action/version` cuando debía ser `view/version`
  (por eso nunca se detectaba que ya estaba arriba), y el `scanPolicyName` enviado no
  corresponde a ninguna política real de ZAP. Verificado con un scan real completo: spider
  encontró URLs, active scan llegó a 100%, resultado real (vacío en ese caso) — no un fallo
  disfrazado. Ver `CLAUDE.md` para el detalle completo, es un buen caso de estudio de
  docker-outside-of-docker.
- **Los reportes/scripts de remediación IA volvieron a ser detallados y específicos**, no
  genéricos. Causa raíz: `correlate_vulnerability()` en `centinela.py` solo intentaba
  `genai_client` (Google, fallando) y caía directo a la plantilla determinística — nunca
  llamaba a `llm` (el proveedor real, `nvidia_nim`/`groq`, inicializado correctamente en el
  arranque). Dos bugs de fondo: (1) el orden de proveedores ignoraba `AI_PROVIDER=groq` del
  `.env`, siempre probaba `nvidia_nim` primero por el default hardcodeado de
  `AI_PROVIDER_ORDER`; (2) `nvidia_nim` reusaba `AI_MODEL` (un nombre estilo Groq,
  `llama-3.3-70b-versatile`) que no existe en el catálogo de NVIDIA → 404 en cada llamada. Se
  agregó `AI_MODEL_NVIDIA` y se movió el proveedor configurado al frente del orden. Verificado
  en vivo: un escaneo limpio en `prism` ahora genera `can_automate=false` y un resumen
  ejecutivo real de "sin hallazgos críticos", en vez de la plantilla genérica de firewall que
  aparecía antes sin importar el tipo de hallazgo (hasta en repos de GitLab). ~~**Pendiente
  menor**: cuando el LLM no devuelve JSON estricto, el parser de respaldo por regex a veces
  produce contenido pobre porque sus patrones no matchean el formato de prosa real de Groq.~~
  — **resuelto 2026-08-05**: no era el parser de respaldo, era `json.loads()` fallando con
  `JSONDecodeError` porque Groq incrusta saltos de línea literales sin escapar dentro del valor
  string de `remediation_script` (JSON válido en espíritu, inválido en el modo estricto de
  Python). Cambiados ambos call sites en `centinela.py` a `json.loads(content, strict=False)`.

## 🎯 Hitos Recientes (2026-08-05)
- **`auditor_medusa.py` tenía flags de CLI nunca verificados contra la versión real.** El
  comando original (`echo "yes" | medusa scan ... --no-ai-safe`) asumía un prompt interactivo de
  confirmación que no existe en `medusa-security==2026.7.0`: `--no-ai-safe` sí existe en esa
  versión pero es un toggle de ofuscación de payloads, no de prompts; `--no-install` no existe en
  absoluto en esta versión (se vio en pruebas ad-hoc contra un resolve distinto, antes de fijar
  la versión en `requirements.txt`). El fix real no necesita ningún flag especial: sin TTY
  (siempre el caso bajo `subprocess.run`), Medusa detecta solo que no puede preguntar e imprime
  "Non-interactive mode: continuing without optional tools." Comando final:
  `medusa scan "{repo_path}" --format json -o "{output_dir}"`. También se subió el timeout
  interno de `subprocess.run` de 300s a 900s — Medusa invoca `trivy fs --scanners
  vuln,secret,misconfig` como subproceso además de sus ~45 analizadores propios, y una descarga
  en frío de la base de datos de Trivy por sí sola puede agotar los 300s originales. **Trampa
  encontrada durante la verificación**: la primera corrida de prueba después de editar el
  timeout a 900s siguió fallando a los 300.2s exactos — bytecode `__pycache__` obsoleto en
  `centinela-backend` seguía ejecutando la versión vieja del archivo pese al bind-mount en vivo
  (ver gotcha #1 de `CLAUDE.md`). Limpiar `__pycache__` y reiniciar el contenedor lo resolvió;
  confirmado con `inspect.getsource()` que el código realmente cargado coincide con el archivo
  en disco antes de volver a probar. **Incluso corregido eso, el scan seguía fallando** — tres
  bugs más, encontrados solo al verificar la ruta real de punta a punta: (1) el pool de workers
  por defecto de Medusa (`-w` auto, >1) fallaba de forma reproducible con `BrokenPipeError`
  dentro de `multiprocessing.Pool`, tanto con carga alta como con el host en reposo — es un bug
  real del pool en esta versión, no falta de recursos; arreglado forzando `-w 1`. (2) Medusa
  siempre escribe un `scan_history.json` (una lista, no un reporte) junto al reporte real, cuyo
  nombre además lleva timestamp (`medusa-scan-YYYYMMDD-HHMMSS.json`) — tomar "el primer .json de
  la carpeta" es no determinístico y agarró el archivo equivocado, causando `'list' object has
  no attribute 'get'`; arreglado excluyendo `scan_history.json` explícitamente. (3) `cve_id`
  usaba `hash()` nativo de Python sobre `file_path + line`, pero ese hash se aleatoriza por
  proceso (`PYTHONHASHSEED`) — confirmado en vivo que la misma cadena da dos hashes distintos en
  dos invocaciones separadas — así que el mismo hallazgo obtenía un `cve_id` distinto en cada
  reinicio del contenedor, rompiendo silenciosamente el dedupe de `log_vulnerability()` y
  reinsertando todo como "nuevo" en cada reinicio (mismo patrón de falla que el bug original de
  PROWLER-AUDIT, por causa distinta). Arreglado con `hashlib.sha256(...)[:8]` (estable entre
  ejecuciones); también se quitó un prefijo `MEDUSA-` duplicado (`rule_id` de Medusa ya viene
  con ese prefijo). Verificado: correr el mismo scan dos veces dio 21/21 "Updated" (no "Logged")
  en la segunda pasada. De paso, se encontraron y eliminaron **tres contenedores `zap-scan-*`**
  de pruebas anteriores que nunca se habían limpiado de verdad (uno llevaba 40+ minutos
  corriendo) — desperdicio real y probable causa de que el load average del host llegara a 76
  (8 CPUs) durante las pruebas.
- **11er bug de ZAP, encontrado de casualidad mientras se depuraba Medusa** — **resuelto
  2026-08-05**: todos los hallazgos de ZAP se registraban con el mismo `cve_id` genérico
  "ZAP-ZAP-UNKNOWN". Causa: `alert.get("pluginid", ...)` usaba minúscula, pero la API real de
  ZAP devuelve `pluginId` (camelCase) — el lookup nunca coincidía, y el prefijo propio de
  `log_zap_findings()` duplicaba el "ZAP-" resultante. Confirmado con 180 hallazgos reales ya
  guardados en `casmart_authentik`: `cweid`/`wascid` (bien escritos en el código) sí estaban
  poblados en cada fila, `pluginid` nunca — 100% consistente con un typo de mayúsculas, no con
  datos faltantes de ZAP. Esto también generó un síntoma secundario que parecía un loop
  infinito: como 180 hallazgos reales y distintos compartían un solo identificador, las líneas
  de log del motor de correlación IA se veían idénticas una tras otra aunque procesaba 180 filas
  distintas correctamente — confusión de logging, no un loop real. Las 180 filas ya guardadas se
  quedan con su `cve_id` genérico (hallazgos reales y legítimos, 180/180 con URLs distintas, no
  spam duplicado) — no hay forma segura de recuperar el `pluginId` real sin volver a escanear, y
  relanzar un scan activo contra `casmart_authentik` no se intentó aquí. Queda documentado como
  brecha cosmética pendiente.
- **El stack productivo vive en `10.4.3.34`**, no en `10.4.3.208`. Se encontró y eliminó por completo
  una segunda copia huérfana de Centinela-AI que llevaba 4 días corriendo en `10.4.3.208`
  (`/opt/ecosistema-casmarts/centinela-ai`), conectada a la misma base compartida `centinela_db` y
  generando duplicados infinitos del hallazgo `PROWLER-AUDIT`. Contenedores, imágenes, volúmenes y el
  directorio fueron removidos. Ver `CLAUDE.md` para el detalle diagnóstico.
- Bug real corregido en `/api/inventory`: `COUNT(v.id)` inflaba conteos por el fan-out de los JOIN a
  `remediation_history`/`runtime_alerts`; ahora usa `COUNT(DISTINCT v.id)`.
- **Wazuh Manager desplegado por primera vez** como servicio de `docker-compose.yml`
  (`wazuh-manager`, imagen `wazuh/wazuh-manager:4.14.1`, contenedor `casmarts-core-wazuh-manager`
  para compatibilidad con las referencias ya existentes en `main.py`/`discovery.py`). No existía
  ningún manager corriendo antes de hoy. Agentes activos: `centinela` (local), `casmartdb`
  (10.4.3.23), `casmart_authentik` (10.4.3.208).
- Corregidos bugs reales en `discovery/discovery.py`: un crash por `%` literal chocando con el
  parser de parámetros de psycopg2, matching de nombres case-sensitive que creaba activos
  duplicados, y el registro del propio manager (`wazuh-manager (server)`) no se excluía
  correctamente.
- `inventory.ini` apuntaba a `/app/*.key` pero las llaves viven en `/app/keys/*.key` — Ansible
  nunca pudo autenticarse contra ningún host remoto hasta hoy.
- Agregados TruffleHog y `medusa-security` (PyPI) a ambos Dockerfiles/`requirements.txt`;
  imágenes reconstruidas. Corregido el path hardcodeado de Medusa
  (`/home/ia/ecosistema-casmarts/...` → `/app/data/medusa_runs`).
- Quitadas las dependencias de build hacia `../core-casmarts` y `../consulta-smart` en
  `docker-compose.yml` (ya no aplican, el ecosistema se separó en varios servidores).
- Corregido `NEO4J_URI` faltante en el entorno de `centinela-backend` (solo estaba en
  `centinela-ai`) — el health check de BloodHound/Neo4j ahora reporta "Online" correctamente.
- Corregido `centinela-zeek`: escribía sus logs en `/` (raíz del contenedor) en vez de
  `/usr/local/zeek/logs` (el volumen montado), por lo que Centinela nunca podía leer alertas de
  red. Se agregó `working_dir: /usr/local/zeek/logs`.
- **6 activos con IPs no alcanzables fueron eliminados del inventario** a petición del usuario
  (confirmó que 10.4.3.28 ya no existe): `sf_sigeti_superset`, `casmart_ia`,
  `CLONE-COMPRAMEX-DIGITAL`, `CLONE-COMPRAMEX-DIGITAL-BD`, `CLONE-PMCP-BD`, `CLONE-SICOPA-BD`,
  junto con sus hallazgos y remediaciones asociadas. Quedan 12 activos en `infra_inventory`.
  `10.4.3.51` (pmcp) también se quitó de `inventory.ini` por la misma razón.
- Normalizados 3 activos con `asset_type='DATABASE'` (valor no estándar, fuera de
  `cat_asset_types`) a `'Database (SQL)'` — sin esto, `compramex_prod_copia`, `casmartdb` y
  `postgresql-central-23-postgres` quedaban invisibles para el ciclo de escaneo (el `WHERE
  asset_type IN (...)` de `auditor_ext.py:main()` nunca los incluía).
- **Bug real corregido en `scan_appserver()`** (`auditors/auditor_ext.py`): al segundo `nuclei`
  le faltaba `-silent`, así que su banner/warnings en stdout hacían `found_vulns = True` en
  *cada* corrida aunque no hubiera hallazgos reales — resultado: ningún activo `SERVER` sin
  agente Wazuh (`centinela`, `casmart_authentik`, `chat`, `prism`, `casmartsuperset`) generaba
  jamás ni un hallazgo real ni el mensaje de "escaneo limpio". Corregido + hecho más defensivo
  (`found_vulns` solo se marca tras un `json.loads` exitoso).
- **ZAP DAST nunca funcionó**: la imagen Docker referenciada (`owasp/zap2docker-stable`) ya no
  existe en Docker Hub. Corregida a `zaproxy/zap-stable:latest` (imagen oficial actual de OWASP)
  y pre-descargada en este host.
- **Vault (10.4.3.208) ya está desellado y autenticando correctamente.** El usuario recuperó el
  nuevo `ROOT_TOKEN` (generado en un re-init del 4 de agosto) desde
  `core-casmarts/vault/vault-init-keys.txt` en 10.4.3.208 y lo actualizó en `.env`. `Secrets
  Backend (Vault)` reporta "Online". Aún no hay ningún secreto guardado bajo
  `casmarts/ansible/*` — es esperado, nadie pudo escribir ahí mientras estuvo sellado.
- **Pendiente real, fuera de este repo** (nota del usuario): la causa de que Authentik entregue
  el mismo `preferred_username` a usuarios distintos está en la configuración de Authentik
  (`auth.casmart.internal`), no en este monorepo — cualquier fix aquí sería solo defensivo.
- **GitLab: token configurado y escaneo real corrido.** El usuario compartió varios PATs; se
  probaron contra la API para encontrar uno válido con scope suficiente (`sonar_pat`, usuario
  `monitor`) — varios de los otros estaban revocados o sin permisos (401/403). Con
  `POST /api/gitlab/scan` real: 46 de 63 proyectos clonados y auditados, **74 vulnerabilidades
  reales encontradas** (SAST + SCA + estándares).
- **Se verificó el pipeline de remediación de punta a punta** (aprobar → Sentinel lo recoge →
  corre Ansible → actualiza DB) con una aprobación real de prueba sobre `CLONE-COMPRAMEX-CORE`.
  En el camino se encontraron y corrigieron **2 rutas de playbook rotas** en `sentinel.py`
  (`/app/remediate_wildfly.yml` y `/app/remediate_generic.yml` — ambos se movieron a
  `remediation/playbooks/` en la reorganización de hoy y `sentinel.py` nunca se actualizó). Antes
  de este fix, **toda remediación aprobada fallaba silenciosamente** con "playbook could not be
  found".
- **Sentinel ahora soporta remediación por llave SSH, no solo password.** Se agregó
  `get_ssh_private_key()` (lee el campo `ssh_private_key` que `store_vault_secret()` ya
  guardaba en Vault pero nadie leía de vuelta). Probado en vivo: se guardó la llave real de
  `casmart_authentik` en Vault vía el endpoint real, se aprobó un hallazgo pendiente, y Sentinel
  autenticó con la llave y marcó la remediación `COMPLETED`/`RESOLVED`. Se confirmó que
  Authentik siguió sano (HTTP 302) después.
- **Se quitó el fallback falso que marcaba remediaciones fallidas como `COMPLETED`** solo por
  tener un agente Wazuh instalado (nunca llamaba a ninguna API real de Wazuh). Ahora una
  remediación fallida queda honestamente en `FAILED` (`executed_bool=False`, sin marcar el
  hallazgo como `RESOLVED`); re-aprobarla desde la UI hace que Sentinel la reintente. Probado en
  vivo sobre `CLONE-COMPRAMEX-CORE` (sin credenciales): ahora reporta `FAILED` correctamente.
- ~~`prism`/`chat` sin credenciales SSH funcionales~~ — **resuelto 2026-08-04**: el usuario dio
  password para `kiwi@10.4.3.30` (prism) y `chatbotpdf@10.4.3.31` (chat), y autorizó instalar la
  llave pública que ya está en `authorized_keys` de este servidor (la misma de `casmarts.key`/
  `casmart.key`, comentario "CASmartS") en cualquier host que no la tuviera. Se instaló en
  ambos vía `sshpass` + append a `~/.ssh/authorized_keys` (en `chat` el archivo existente no
  terminaba en newline, así que el append corrompió la línea anterior — se corrigió a mano,
  backup en `~/.ssh/authorized_keys.bak` en ese host). Agregados a `inventory.ini` y a Vault
  (`ssh_private_key` para que Sentinel también los pueda remediar). Wazuh instalado y verificado
  activo en ambos — de hecho **ambos ya tenían `wazuh-agent` preinstalado**, solo hacía falta
  apuntarlo al manager y arrancarlo. Descubrimiento adicional: `CLONE-COMPRAMEX-CORE`/`-BD`
  también tenían el agente preinstalado y se auto-enrolaron solos en cuanto existió un manager
  real — quedaron como agentes `compramex`/`compramex-bd`, sincronizados al inventario.
- ~~`casmartsuperset` sin credenciales~~ — **resuelto 2026-08-04**: el usuario SÍ era
  `casmartsuperset`, lo que faltaba era el punto al final del password (`gNng898u.`). Se instaló
  la llave compartida, se agregó a `inventory.ini`/Vault. Su `ossec.conf` seguía apuntando al
  manager viejo muerto (`10.4.3.28`), y el manager tenía un registro huérfano de un
  auto-enrolamiento silencioso previo bajo el mismo nombre — `wazuh-agentd` repetía "Duplicate
  agent name" hasta que se quitó ese registro viejo (`manage_agents -r`) y se limpió
  `client.keys` del agente para forzar un re-enrolamiento limpio. **Los 7 activos SERVER
  quedaron confirmados con Wazuh activo**, tanto localmente como desde el manager.
- **Bug encontrado y corregido en `discovery.py`**: el matching "fuzzy" (agregado hoy mismo)
  hizo un falso positivo — el agente Wazuh `compramex` matcheó por substring contra un
  repositorio de GitLab (`GitLab/edomex-casmart/compramex/...`) porque su path contenía la
  palabra "compramex", asignándole un `agent_id` de Wazuh sin sentido. También falló al no
  encontrar ningún match para el agente `kiwi` (hostname real de prism, sin relación léxica con
  "prism") y creó un activo duplicado. Se corrigió a mano en la base y se restringió el fuzzy
  match a activos `SERVER`/`AppServer` con nombre de agente de al menos 5 caracteres — reduce el
  problema pero no lo elimina del todo: cuando el hostname real de una máquina no se parece en
  nada al nombre de negocio del activo (como `kiwi` vs `prism`), no hay heurística de texto que
  lo resuelva; requeriría guardar el mapeo hostname↔asset_id en el momento de instalar el agente.

## 🎯 Hitos Anteriores (30 de Julio, 2026)
1. **Despliegue e Integración en Gateway (`10.4.3.208`)** — *nota 2026-08-04: este despliegue en
   208 fue el que quedó huérfano y se eliminó hoy; el stack real vive en `10.4.3.34`.*
   - Corrección del enrutamiento de la puerta de enlace Nginx (`casmarts-core-gateway`) para `centinela.casmart.internal`.
   - Sincronización y despliegue del stack completo de contenedores (`centinela-ai`, `centinela-backend`, `centinela-frontend`, `centinela-sentinel`) dentro de la red Docker `aura-network`.
2. **Motor Nativo Omni-Vulnerabilidades & DevSecOps**:
   - **SAST**: Detección nativa AST de inyecciones (SQLi, NoSQLi, Command Injection, SSRF), fallos de autorización (BOLA/BFLA), credenciales expuestas y complejidad cognitiva.
   - **IaC & Docker Hardening**: Verificación de Dockerfiles contra los **CIS Benchmarks v8** (prevención de `USER root`, tags `:latest` no fijados, rutinas de depuración de volumen/disco).
3. **Análisis de Composición de Software (SCA)**:
   - Auditoría nativa de manifestos (`requirements.txt`, `package.json`) para identificar dependencias vulnerables y CVEs conocidos.
4. **Verificación de Estándares de Auditoría de la Industria**:
   - Evaluación contra el **Estándar Maestro de Auditoría** (`docs/estandares-auditoria/ESTANDARES_AUDITORIA_INTEGRAL.md`), incluyendo la Matriz de Amenazas **STRIDE** (JWT asimétrico RS256/Ed25519, logs de no repudio `who`, `what`, `when`), modelo **ISO/IEC 25010** (mantenibilidad) y controles ISO 27001 / NIST SP 800-53.
5. **Integración con Servidores GitLab**:
   - Descubrimiento automático, clonado/actualización y escaneo de todos los repositorios y proyectos alojados en GitLab (`http://10.4.3.10` o URL personalizada) vía REST API v4.
6. **Mantenimiento del Monitoreo de Servidores Físicos y Virtuales**:
   - Se mantiene intacto y potenciado el monitoreo continuo de servidores físicos y virtuales mediante agentes Wazuh (instalación automática vía Ansible), escaneos de red Nmap/Nuclei, auditoría de fuerza bruta Medusa y alertas de tiempo real en Falco/Wazuh.
7. **Reorganización del código raíz**: Los módulos `.py` sueltos se movieron a paquetes (`core/`, `auditors/`, `discovery/`, `remediation/`, `scripts/`, `tests/`, `ui/`). Los entrypoints que invoca Docker (`centinela.py`, `main.py`, `sentinel.py`) se mantuvieron en la raíz.

## 🚧 Pendientes
- Si `casmart_ia` u otros de los activos eliminados vuelven a existir con una IP nueva, volver
  a registrarlos vía "Añadir Activo" para que se les instale el agente Wazuh automáticamente.
- Si vuelve a hacer falta emparejar un agente Wazuh cuyo hostname real no se parece en nada al
  nombre de negocio del activo (como pasó con `kiwi`/`prism`), la heurística de texto en
  `discovery.py` no lo va a resolver sola — hay que capturar el hostname real al momento de
  instalar el agente (vía Ansible) y guardarlo, no adivinarlo después por substring.
- Considerar dar acceso Developer al grupo `arquitectura/` en GitLab a la cuenta de servicio
  `monitor`, para dejar de usar el token personal de `israelm` en el escaneo automatizado.
- Refinar la interfaz web React (Omni-Audit Matrix Tab) para explorar hallazgos por proyecto de GitLab.
- Rotar el PAT de GitLab embebido en la URL del remoto `origin` y la clave `id_rsa_centinela` (quedaron expuestos en el historial de git).
- Evaluar limpieza de historial de git (BFG/filter-repo) para los archivos de secretos ya commiteados, coordinando con el equipo (`10.4.3.10/arquitectura/centinela-cai`).
