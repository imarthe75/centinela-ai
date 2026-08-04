# Estado del Proyecto - Centinela CAI

## 📅 Fecha: 4 de Agosto, 2026

## 🎯 Hitos Recientes (2026-08-04)
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
- Conseguir credenciales SSH (o registrarlas en Vault) para `casmartsuperset` (10.4.3.25),
  `prism` (10.4.3.30) y `chat` (10.4.3.31) — están vivos (puerto 22 abierto) pero sin credencial
  conocida, así que no se les puede instalar el agente Wazuh todavía.
- Configurar `GITLAB_TOKEN` en `.env` para que `POST /api/gitlab/scan` pueda autenticar contra
  `http://10.4.3.10` y auditar los repositorios reales.
- Si `casmart_ia` u otros de los activos eliminados vuelven a existir con una IP nueva, volver
  a registrarlos vía "Añadir Activo" para que se les instale el agente Wazuh automáticamente.
- Validar en vivo los flags de CLI de `auditor_medusa.py` contra el paquete `medusa-security` real
  (se instaló hoy pero no se ha probado un scan real; los flags `--no-ai-safe` y el `echo "yes" |`
  pueden no aplicar a la versión actual del CLI).
- Refinar la interfaz web React (Omni-Audit Matrix Tab) para explorar hallazgos por proyecto de GitLab.
- Rotar el PAT de GitLab embebido en la URL del remoto `origin` y la clave `id_rsa_centinela` (quedaron expuestos en el historial de git).
- Evaluar limpieza de historial de git (BFG/filter-repo) para los archivos de secretos ya commiteados, coordinando con el equipo (`10.4.3.10/arquitectura/centinela-cai`).
