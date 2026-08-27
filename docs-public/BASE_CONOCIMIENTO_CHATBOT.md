# Centinela-AI — Base de Conocimiento

> Documento de contexto amplio para el asistente conversacional (RAG). Consolida el manual
> técnico, el README, el resumen ejecutivo y la funcionalidad real y verificada de la plataforma.
> Última actualización: 13 de agosto de 2026.

---

## 1. Qué es Centinela-AI

Centinela-AI es la plataforma central de ciberseguridad de CASMARTS: un sistema **SOC/SOAR
(Security Operations Center / Security Orchestration, Automation and Response)** que unifica en
un solo flujo el descubrimiento de activos, el escaneo de vulnerabilidades, la correlación con
Inteligencia Artificial y la remediación automatizada supervisada por humanos.

No es un solo escáner ni una sola herramienta: es la **capa de orquestación** que conecta más de
una decena de motores de escaneo especializados, un modelo de lenguaje que interpreta cada
hallazgo técnico y lo traduce a lenguaje de negocio, y un motor de remediación (SOAR) que ejecuta
la corrección real — siempre con un humano aprobando antes de que se aplique cualquier cambio.

**Descripción funcional corta:** Centinela-AI descubre activos automáticamente (servidores, bases
de datos, repositorios de GitLab, contenedores), los audita con más de una decena de motores de
escaneo especializados, usa un modelo de lenguaje para correlacionar cada hallazgo en un reporte
ejecutivo con una remediación concreta, y — cuando un humano aprueba esa remediación — la ejecuta
de forma automatizada: por Ansible sobre un servidor real, o abriendo un Merge Request sobre un
repositorio de código.

### 1.1 Origen y justificación

Antes de Centinela-AI, la vigilancia de seguridad de CASMARTS dependía de más de una decena de
herramientas desconectadas entre sí (escáneres de red, analizadores de código, auditores de
contenedores, cada uno con su propia consola), sin que nadie tuviera el tiempo ni el contexto
para revisarlas todas juntas y correlacionar lo que realmente importaba. El resultado típico de
ese modelo: alertas técnicas ilegibles para quien toma decisiones de negocio, hallazgos
duplicados entre herramientas, y remediaciones que dependían enteramente de la memoria y
disponibilidad de una sola persona.

Centinela-AI resuelve esto con **un solo sistema, un solo panel (dashboard)**, que convierte
alertas técnicas dispersas en explicaciones claras de impacto de negocio y en correcciones
concretas, listas para que un operador las apruebe con un clic.

### 1.2 Propósito y para qué sirve

- Descubrir automáticamente qué activos existen en la infraestructura de CASMARTS (sin depender
  de que alguien los registre manualmente uno por uno).
- Auditar continuamente esos activos contra las categorías de vulnerabilidad y mala configuración
  más relevantes para cada tipo de activo.
- Traducir cada hallazgo técnico a una explicación de riesgo e impacto de negocio comprensible
  para un ejecutivo, no solo para un ingeniero.
- Proponer — y, con aprobación humana, ejecutar — la corrección real: un script de
  infraestructura, o un parche de código listo para revisión en un Merge Request.
- Mapear automáticamente cada hallazgo contra los marcos normativos que la organización necesita
  demostrar cumplimiento (ISO 27001, NIST, PCI-DSS, SOC 2, GDPR, CMMI).
- Ofrecer visibilidad ejecutiva en tiempo real: cuántos hallazgos hay, cuáles son críticos, cuáles
  incumplen su plazo de remediación, y qué porcentaje del panorama regulatorio está cubierto.

---

## 2. Arquitectura del Ecosistema

Todo el stack corre mediante Docker Compose, un servicio por responsabilidad:

| Servicio | Punto de entrada | Rol |
|---|---|---|
| `centinela-ai` | `centinela.py` | Orquestador: bucle de descubrimiento, despacho de todos los motores de escaneo, correlación con IA, ingesta de Falco/Zeek/BloodHound |
| `centinela-backend` | `main.py` (FastAPI) | API REST que consume el dashboard, reportes PDF, health check, acciones sobre agentes Wazuh |
| `centinela-sentinel` | `sentinel.py` | Ejecuta las remediaciones ya aprobadas por un humano — el componente SOAR |
| `centinela-frontend` | React + Vite | Dashboard de mando — la interfaz visual |
| `centinela-neo4j` | — | Grafo de rutas de ataque estilo BloodHound (Active Directory) |
| `centinela-zeek` | — | Sensor de Detección de Intrusos de Red (NDR) |
| `wazuh-manager` | — | Manager de EDR (Endpoint Detection & Response) — recibe telemetría de los agentes instalados en cada servidor |

### Dependencias externas (fuera de este stack)

- **PostgreSQL (`centinela_db`)** — en un servidor separado. Es la fuente de verdad compartida:
  todos los hallazgos, activos e historial de remediación viven aquí.
- **HashiCorp Vault** — guarda las credenciales de Ansible (llaves SSH, contraseñas sudo) por
  activo, nunca en la base de datos ni en el código fuente.
- **Authentik (SSO)** — proveedor de identidad, integrado para detección de amenazas de identidad
  (ITDR).

### Principio de diseño: cero contraseñas compartidas

Conforme a NIST SP 800-53 (IA-2, AC-6), la plataforma elimina el riesgo de compartir contraseñas
de superusuario mediante tres mecanismos:

1. **Llave SSH dedicada con privilegios acotados** — el agente usa una llave sin contraseña cuya
   autorización en el servidor destino está limitada explícitamente a un puñado de binarios
   (`/usr/bin/wazuh-agent`, `/usr/sbin/service`, `/sbin/iptables`) vía `/etc/sudoers.d/centinela`.
2. **Instalación local desatendida (curl \| sudo bash)** — los administradores instalan el agente
   con un token de un solo uso, sin exponer credenciales.
3. **Monitoreo agentless** — para activos donde no se permite instalar software, la detección
   opera por red (ICMP/TCP probes, SNMPv3) y la remediación se aplica en el reverse-proxy
   perimetral (bloqueo de IP), sin necesidad de acceso directo al host.

---

## 3. Ciclo de vida de un hallazgo

Centinela-AI sigue siempre el mismo flujo de cuatro pasos, desde que se descubre un activo hasta
que un riesgo real queda corregido:

### Paso 1 — Descubrimiento

El orquestador registra activos automáticamente: agentes Wazuh que se conectan por su cuenta,
bases de datos configuradas manualmente, y **todos** los proyectos de la organización de GitLab
vía su API (sin necesidad de registrar cada repositorio a mano). Cada activo recibe un tipo
(`SERVER`, `AppServer`, `Database (SQL)`, `GitLab-Repo`, entre otros) que determina qué motores
de escaneo se le aplican — un repositorio de código nunca recibe un escaneo de puertos de red, y
un servidor físico nunca recibe un análisis de dependencias npm.

### Paso 2 — Escaneo

Cada activo se audita con los motores correspondientes a su tipo:

- **Infraestructura real** (servidores, aplicaciones en ejecución) recibe Nuclei, ZAP y Nmap.
- **Repositorios de código** reciben análisis SAST (estático), SCA (dependencias) y de estándares
  de calidad/arquitectura.
- **Contenedores** reciben Trivy y Grype (vulnerabilidades en imágenes Docker).

Cada hallazgo se registra en la tabla `vulnerability_log` de la base de datos con un identificador
propio (`cve_id`), que indica siempre qué motor lo originó.

### Paso 3 — Correlación con Inteligencia Artificial

Un modelo de lenguaje (LLM) analiza cada hallazgo nuevo: lo clasifica según severidad real, redacta
un resumen ejecutivo del riesgo, evalúa el impacto de negocio concreto para CASMARTS, y genera la
remediación específica — un script ejecutable para infraestructura real, o un parche de código
(diff en formato `git apply`) para un hallazgo en un repositorio.

### Paso 4 — Remediación (SOAR)

Un operador humano revisa y aprueba la remediación propuesta desde el dashboard. Solo entonces,
el componente Sentinel la ejecuta:

- **Sobre un servidor real:** corre el script vía Ansible, autenticando con la llave SSH o
  contraseña sudo almacenada en Vault para ese activo específico.
- **Sobre un repositorio de GitLab:** clona el repositorio, aplica el parche (determinístico para
  casos mecánicos como Dockerfiles o versiones de dependencias, o el diff generado por IA para
  casos que requieren entender el código), hace commit y push a una rama nueva
  (`centinela-fix/*`), y abre un Merge Request para revisión humana — **nunca hace push directo
  a la rama principal**.

Si la ejecución falla, el hallazgo queda marcado `FAILED` — nunca se fuerza a `COMPLETED` sin que
la corrección realmente haya ocurrido.

---

## 4. Los seis pilares de auditoría

### 4.1 Auditoría de Código Fuente y Seguridad Estática (SAST)

Inspección profunda del código fuente (Python, JavaScript/TypeScript, Java, C/C++) sin ejecutar
la aplicación, para identificar antipatrones y fallos de diseño:

- **Inyección de SQL** — concatenación dinámica de cadenas en consultas, uso de formateo de
  strings (f-strings, `%s`, `.format()`) en sentencias SQL sin parámetros precompilados.
- **Inyección de Comandos del Sistema** — llamadas inseguras a `os.system`,
  `subprocess.Popen(shell=True)`, `eval()`, `exec()`.
- **Server-Side Request Forgery (SSRF)** — peticiones HTTP salientes cuyo destino (host, no solo
  la ruta) se construye a partir de entrada no validada.
- **Fallos de Autorización (BOLA/BFLA)** — acceso a objetos o funciones administrativas sin
  validar el contexto de sesión.
- **Credenciales y secretos hardcodeados** — llaves privadas, contraseñas, tokens JWT, claves de
  nube embebidas directamente en el código fuente.
- **Complejidad cognitiva y reglas de código limpio** — bajo el estándar ISO/IEC 25010, bloqueo
  de funciones con complejidad cognitiva superior a 15 o más de 60 líneas.

### 4.2 Auditoría de Dependencias y Composición de Software (SCA)

Analiza los manifiestos de paquetes de terceros contra bases de datos globales de vulnerabilidades
conocidas (CVE/NVD/GitHub Security Advisory), consultando **OSV.dev** (el proyecto de Google que
agrega NVD, GitHub Advisories, PyPA y npm en una sola API pública) en vivo, por cada paquete y
versión exacta encontrados — no una tabla estática desactualizada.

Ecosistemas cubiertos: Python (`requirements.txt`, `Pipfile`, `pyproject.toml`), Node.js/JavaScript
(`package.json`), Java (`pom.xml`), Go (`go.mod`) y PHP (`composer.json`).

Cada hallazgo de dependencia vulnerable se etiqueta además con su **alcanzabilidad**
(`REACHABLE` / `UNREACHABLE`): si el paquete realmente se importa en algún lugar del código, o si
solo está declarado en el manifiesto sin usarse — reduciendo drásticamente los falsos positivos
de "dependencia vulnerable" sobre paquetes que nunca se ejecutan.

### 4.3 Hardening de Contenedores e Infraestructura como Código (IaC)

- **Dockerfiles** — detección y corrección automática (con parche determinístico, sin necesidad
  de IA) del antipatrón de ejecución como usuario `root`; prohibición de imágenes base con tags
  flotantes (`:latest`); verificación de limpieza de temporales.
- **Kubernetes y Terraform** — contenedores en modo `privileged: true`, montajes `hostPath`
  inseguros, buckets S3/Security Groups expuestos públicamente.

### 4.4 Gobernanza de Inteligencia Artificial y Modelos LLM (OWASP LLM Top 10)

Auditoría específica para aplicaciones que consumen modelos de lenguaje:

- **Inyección de Prompts (LLM01)** — vectores donde entrada de usuario no saneada puede alterar
  las instrucciones del sistema.
- **Fuga de Datos Sensibles y PII (LLM02)** — información de identificación personal o secretos
  dentro de respuestas o prompts enviados a modelos de IA.
- **Ejecución de Código sin Guardrails (LLM06)** — bloqueo de ejecución de código generado por el
  LLM sin sandbox o aprobación humana explícita.

### 4.5 Auditoría de APIs Fantasma y Desviación de Esquemas (Shadow API)

Comparación entre las rutas reales definidas en el código (FastAPI, Express, Spring) y la
documentación oficial declarada (`openapi.json`/Swagger), para detectar endpoints "fantasma"
expuestos sin documentar — una superficie de ataque invisible para cualquier revisión manual de
la documentación oficial.

### 4.6 Auditoría y Hardening de Bases de Datos

Cubre PostgreSQL, MySQL/MariaDB, Oracle, Microsoft SQL Server, MongoDB, Cassandra, Neo4j,
Elasticsearch/OpenSearch, Trino/Presto y Redis/Valkey: cifrado TLS en tránsito, cifrado TDE en
reposo (vía IaC), exposición de puertos por defecto, e inyección de SQL activa vía SQLMap/Nuclei.

---

## 5. Motores de escaneo (detalle completo)

Cada motor cubre una capa distinta de la superficie de ataque. La columna `scan_engine` es el
valor real que queda registrado junto a cada hallazgo en la base de datos.

| Motor | `scan_engine` | Capa | Detecta |
|---|---|---|---|
| **OWASP ZAP** | `zap` | DAST — app en ejecución | Cabeceras de seguridad ausentes, XSS, fugas de información en URL, configuración insegura de sesión |
| **Nuclei** | — | Web / red | CVEs conocidos y malas configuraciones vía plantillas comunitarias actualizadas por la propia herramienta |
| **Semgrep** | `semgrep` | SAST — código fuente | Patrones de código inseguro, multi-lenguaje |
| **Motor SAST propio** | `sast-native` | SAST — código fuente | `eval()` peligroso, inyección SQL/comandos, SSRF, secretos hardcodeados, complejidad cognitiva |
| **Motor SCA propio** | `sca-native` | Dependencias multi-lenguaje | Paquetes vulnerables (Python, npm, Java, Go, PHP) vía OSV.dev en vivo, con análisis de alcanzabilidad |
| **Auditor IaC K8s & Terraform (propio)** | `iac-native` | Infraestructura como código | Contenedores privilegiados en Kubernetes, montajes hostPath inseguros, recursos públicos en Terraform |
| **Motor de estándares propio** | `standards-audit` | Calidad y arquitectura | ISO/IEC 25010 (mantenibilidad) y modelo de amenazas STRIDE |
| **Trivy / Grype / Syft** | `grype` | Contenedores / SBOM | CVEs en imágenes Docker y sus capas de dependencias |
| **TruffleHog** | `secrets` | Secretos | Credenciales y llaves filtradas en el historial de Git |
| **Prowler** | `prowler` | Nube (CSPM) | Configuración insegura en AWS/GCP/Azure |
| **Checkov** | — | Infraestructura como código | Terraform, Kubernetes, Helm charts |
| **Medusa (`medusa-security`)** | `medusa` | SAST asistido por IA | ~45 analizadores propios más `trivy fs` (vulnerabilidades, secretos, misconfiguraciones), orientado a aplicaciones con componentes GenAI |
| **SQLmap** | — | Web | Inyección SQL activa |
| **ffuf / Kiterunner** | `ffuf`/`kiterunner` | APIs | Rutas y endpoints ocultos vía fuzzing |
| **SpiderFoot** | `spiderfoot` | OSINT | Subdominios, WHOIS, huella digital de tecnología expuesta |
| **BloodHound / Neo4j** | `bloodhound` | Active Directory | Rutas de escalamiento de privilegios hacia Domain Admins |
| **CIS Benchmarks (propio)** | `cis-benchmark` | Hardening de SO | Subconjunto real de ~11 controles CIS Level 1 Linux vía SSH; automático cada 7 días por activo, o bajo demanda |
| **Auditor DB Hardening (propio)** | `db-hardening` | Seguridad de bases de datos | TLS en tránsito, TDE, exposición de puertos por defecto |
| **Auditor CMMI V3.0 (propio)** | `cmmi-audit` | Procesos y calidad | Realineado 25 ago 2026 a 5 áreas reales del modelo tailored de 19 áreas de C&A: análisis causal (`CAR`), higiene de código (`PQA`), gestión de configuración vía historial Git real (`CM`), monitoreo y control (`MC`), verificación (`VV`) — los códigos `SAM`/`MSR` usados antes no eran reales, ver sección de glosario |
| **Auditor de Accesibilidad WCAG 2.1 (propio, nuevo)** | `accessibility-wcag` | Accesibilidad — requisito legal sector público | `alt` faltante, formularios sin etiqueta, enlaces/botones vacíos, `<html>` sin idioma, tabindex positivo, divs clickeables sin rol |
| **Gestor CTI & Threat Feeds (propio)** | `cti-feed` | Inteligencia de amenazas | Correlación de IoCs contra feeds públicos de IPs de comando-y-control activas |

### Origen de los catálogos de vulnerabilidades

- **Nuclei** usa `nuclei-templates`, el repositorio comunitario público que la herramienta
  actualiza por su cuenta.
- **Trivy/Grype** mantienen una base local sincronizada periódicamente contra NVD, GitHub
  Advisory Database y avisos de las distribuciones Linux.
- **`sca-native`** consulta OSV.dev por cada paquete y versión exacta, en tiempo real, en cada
  escaneo — no una tabla fija. Conserva una tabla estática pequeña (7 paquetes) exclusivamente
  como respaldo si OSV.dev no responde.
- **ZAP** trae su catálogo de alertas embebido en la propia herramienta.
- **`sast-native`** y **`standards-audit`** no descargan nada — son patrones (expresiones
  regulares y análisis de sintaxis) escritos específicamente para Centinela, para detectar código
  peligroso y violaciones de STRIDE/ISO 25010.

### Taxonomía de identificadores (`cve_id`)

El prefijo del identificador siempre indica qué motor originó el hallazgo:

| Prefijo | Origen | Ejemplo real |
|---|---|---|
| `ZAP-NNNNN` | Plugin ID del catálogo oficial de OWASP ZAP | `ZAP-10021` — X-Content-Type-Options ausente |
| `SCA-CVE-YYYY-NNNNN` | CVE de MITRE/NVD aplicado a una dependencia | `SCA-CVE-2024-29041` — express vulnerable |
| `CODE-` / `CMD-` / `SQL-` / `SSRF-` / `HARDCODED-` | Reglas propias de `sast-native` | `CODE-INJECTION-EVAL` |
| `STD-STRIDE-` / `STD-ISO25010-` | Reglas propias de `standards-audit` | `STD-STRIDE-JWT-INSECURE-ALG` |
| `DOCKER-` | Auditoría de Dockerfiles | `DOCKER-MISSING-NON-ROOT-USER` |
| `SCAN-AUDIT` / `HEURISTIC-SECURITY-DEBT` | Mensajes de estado propios — no son vulnerabilidades técnicas | "Escaneo completado, sin hallazgos" |

---

## 6. Motor de Inteligencia Artificial

Cada hallazgo nuevo pasa por la función de correlación, que arma un prompt con el tipo de activo,
la severidad, la ubicación exacta y la evidencia técnica, y lo envía a un modelo de lenguaje.

### Cadena de proveedores (cascada de respaldo)

Groq, Google Gemini, NVIDIA NIM y OpenRouter se inicializan de forma independiente al arrancar
(cada uno si tiene una API key configurada). **Cada llamada de correlación individual** — no solo
el arranque del proceso — recorre la cadena en orden hasta obtener una respuesta real:

`groq → google_genai → nvidia_nim → openrouter → motor heurístico`

El orden se eligió por latencia real medida contra el prompt de correlación: Groq y Gemini
responden en segundos (Gemini además con modo JSON nativo real); NVIDIA y OpenRouter son más
lentos e impredecibles, así que se dejaron al final, cada uno con límites de tiempo (`timeout`)
acotados para que un proveedor colgado no bloquee toda la correlación — cada llamada corre en un
hilo separado con un límite de reloj real (wall-clock), independiente de los mecanismos de
timeout internos de cada cliente HTTP.

### Hallazgos sintéticos: sin LLM por diseño

Los hallazgos que son marcadores propios del sistema (`HOST-CONTAINMENT-REQUEST`,
`CTI-IOC-MATCH-*`, `BLOODHOUND-PATH-*`, `SCAN-AUDIT`, `HEURISTIC-SECURITY-DEBT`,
`CIS-BENCHMARK-AUDIT`) nunca se envían al LLM: van directo al motor heurístico, que ya tiene la
respuesta correcta y específica para cada uno. Pedirle a un LLM genérico que "corrija" un
hallazgo sintético como `HOST-CONTAINMENT-REQUEST` puede hacerlo alucinar una acción no
relacionada — un riesgo real si un operador la hubiera aprobado sin leerla con cuidado.

### Qué genera la IA para cada hallazgo real

| Campo | Contenido |
|---|---|
| `riesgo_detectado` | Nombre técnico real de la vulnerabilidad |
| `impacto_negocio` | Consecuencia concreta para CASMARTS si se explota |
| `accion_remediacion` | Pasos claros para un desarrollador u operador |
| `remediation_script` | Script bash ejecutable — para hallazgos de infraestructura real |
| `fix_patch` | Diff unificado (aplicable con `git apply`) — para hallazgos de código en un repositorio |
| `can_automate` | Si Sentinel puede ejecutar la corrección sin intervención de código adicional |

### Motor de respaldo (sin IA disponible)

Si ningún proveedor responde (cuota agotada, sin conexión), Centinela no deja el hallazgo sin
analizar: un motor heurístico determinístico genera texto y — cuando es un caso conocido y
seguro — un script real específico por categoría (hardening SSH, cabeceras nginx para ZAP, `USER`
no-root en Dockerfile, etc.). Cuando no existe una regla determinística para ese caso específico,
lo indica honestamente en vez de simular una corrección que no existe.

### Validación de respuestas de IA de baja calidad

Un LLM que sí responde no garantiza una respuesta útil. Centinela valida el contenido antes de
aceptarlo: si el `remediation_script` devuelto es solo texto de relleno (p. ej. una elipsis con
una nota como "script proporcionado" en vez de un script real) o es demasiado corto para ser un
script real, se descarta y se usa el motor heurístico determinístico en su lugar — nunca se
guarda ni se marca como automatizable un script vacío.

---

## 7. SOAR y remediación automatizada

El componente **Sentinel** monitorea remediaciones aprobadas por un humano (marcadas
`APPROVED`) y las ejecuta según el tipo de activo:

- **Infraestructura real (SERVER, AppServer):** ejecuta el script vía Ansible contra la IP del
  activo, autenticando con la llave SSH o contraseña sudo almacenada en Vault. Si la ejecución
  falla, el hallazgo queda marcado `FAILED` — nunca se fuerza a `COMPLETED` sin una corrección
  real.
- **Repositorios de GitLab:** clona el repositorio, aplica el parche (determinístico para
  Dockerfile/dependencias, o el diff generado por IA), y hace commit + push a una rama nueva
  (`centinela-fix/*`). Abre un Merge Request para revisión humana — **nunca hace push directo a
  la rama principal**.

**La aprobación humana está siempre en el centro:** ningún cambio se aplica sin que un operador
lo apruebe desde el dashboard. La IA propone; Sentinel ejecuta solo lo aprobado; y toda ejecución
queda registrada con su resultado real.

### SOAR 2.0 — Respuesta Autónoma Escalonada

Disparo autónomo sin retraso humano si la confianza de la alerta es ≥95% (ej. parcheo virtual de
una IP confirmada como C2 activo); encolamiento para aprobación manual de un clic si la confianza
es menor a 95%.

### Contención de emergencia de host

Desde el dashboard, un operador puede solicitar el aislamiento de red completo de un activo
comprometido. Como cualquier otra remediación, pasa por el mismo flujo de aprobación humana —
**nunca se ejecuta automáticamente**. El script generado bloquea todo el tráfico entrante y
saliente salvo DNS/NTP, y deliberadamente no tiene rollback automático: una contención de
emergencia no debe poder deshacerse sola.

---

## 8. EDR, NDR y monitoreo de endpoints

### EDR vs. XDR

- **EDR (Endpoint Detection and Response):** tecnología instalada en el sistema operativo del
  activo. Monitorea procesos, llamadas al sistema, archivos y registro para detectar
  comportamientos maliciosos a nivel de host. En Centinela se opera vía el agente **Wazuh**.
- **XDR (Extended Detection and Response):** la evolución que trasciende al host individual,
  correlacionando telemetría de múltiples vectores: agentes EDR + tráfico de red (Zeek) + código
  fuente (SAST/SCA) + identidad (Authentik ITDR) + seguridad IA. Centinela actúa como un
  **Omni-XDR unificado**.

### Instalación de agentes — multi sistema operativo

| Sistema Operativo | Formato de instalador |
|---|---|
| Linux (Ubuntu/Debian/RHEL/CentOS) | Script Bash (`.sh`) |
| Windows (Server 2019/2022, Win 10/11) | Script PowerShell (`.ps1`) |
| macOS (Apple Silicon y Intel) | Script Zsh (`.sh`) |
| Configuración directa | Archivo `ossec.conf` XML preconfigurado |

### Gestión de agentes desde el dashboard

- **Reiniciar Agente** — reinicio remoto del servicio `wazuh-agent`.
- **Escanear FIM (Integridad de Archivos)** — dispara un escaneo `syscheck` en tiempo real.
- **Ver Logs** — últimas 100 líneas del registro de auditoría del agente.
- **Desinstalar Agente** — desregistra el agente del Manager y actualiza el inventario.

### Clasificación de estado de un activo

`poll_asset_status` valida cada 10 segundos la conectividad de los activos registrados:

- **Sincronizado (Online):** responde a sondeos ICMP o tiene comunicación activa del agente.
- **Offline (Desconectado):** estuvo conectado antes (tiene un `last_seen` real), pero ahora es
  inalcanzable.
- **Offline (Sin Conexión Previa):** fue recién agregado al inventario pero nunca ha establecido
  su primer contacto de red.

### Zeek (NDR — Network Detection and Response)

Zeek observa el tráfico de red en vivo y escribe dos tipos de log: `notice.log` (solo eventos que
la política interna de Zeek considera dignos de nota) y `conn.log` (registro continuo de cada
conexión, siempre activo). Centinela procesa `conn.log` en tiempo real, cruzando la IP de origen
y destino de cada conexión contra el feed de inteligencia de amenazas, y emite un latido de
actividad honesto cada 5 minutos con el número real de conexiones observadas — no una señal
simulada.

---

## 9. Puntuación de riesgo e inteligencia de amenazas

### Centinela Risk Score (CRS)

Puntuación de 0 a 100 por hallazgo, combinando:

- **Severidad** (aproximación de CVSS derivada del bucket de severidad que ya asigna el escáner).
- **EPSS real** — probabilidad de explotación en los próximos 30 días, consultada en vivo contra
  la API pública de FIRST.org.
- **Estado real de CISA KEV** — el catálogo público del gobierno de EE.UU. que confirma que una
  vulnerabilidad ya está siendo explotada activamente en el mundo real. Recibe prioridad crítica
  inmediata.
- **Criticidad del activo.**

Se recalcula en segundo plano y se revalida cada 24 horas.

### Feed de Inteligencia de Amenazas (CTI/IoC)

Cruce en vivo contra Feodo Tracker (abuse.ch) — IPs de servidores de comando-y-control activos y
confirmadas — tanto contra los activos registrados en el inventario como contra el tráfico de red
observado en tiempo real por Zeek.

### Matriz MITRE ATT&CK®

Los hallazgos con una técnica de ataque real y verificable se mapean a su ID oficial de ATT&CK.
Los hallazgos de calidad de código (que no son técnicas de ataque en sí mismas) se dejan
intencionalmente sin mapear, en vez de forzar una clasificación falsa.

### Deduplicación cross-tool por huella digital (fingerprint)

Si dos motores distintos detectan el mismo CVE real en el mismo activo de forma independiente, se
fusiona en un solo hallazgo con una nota de detección adicional, en vez de abrir un segundo
ticket duplicado.

### Control de SLA por severidad

Plazos de remediación automáticos: **Crítico 24 horas, Alto 7 días, Medio 30 días, Bajo 90 días**,
con indicador de incumplimiento visible en el dashboard y en el reporte ejecutivo.

### Quality Gates

Evaluación de umbrales de calidad (vulnerabilidades críticas/altas, violaciones ISO 25010) con
resultado pass/fail y grado A/B/F, consultable vía API para integrarse a un pipeline CI/CD.

### Parcheo virtual

Cuando una IP confirmada como C2 activo coincide con uno de los activos registrados, se bloquea a
nivel de reverse-proxy (`deny` en nginx) sin tocar el código de la aplicación ni reiniciar el
servicio.

---

## 10. Integración con GitLab y Auto-Fix

Centinela integra un flujo DevSecOps bidireccional con los servidores GitLab de la organización:

1. **Descubrimiento de repositorios** — consulta automáticamente la API REST v4 para listar
   todos los proyectos de la organización, sin registro manual.
2. **Clonado y auditoría** — clona o actualiza cada repositorio en un entorno aislado de análisis
   y ejecuta el escaneo completo (SAST, SCA, estándares).
3. **Generación del parche**, por dos vías según el tipo de hallazgo:
   - **Parchadores determinísticos (sin IA):** para patrones mecánicos y seguros — agregar o
     corregir la directiva `USER` no-root en un Dockerfile, o subir la versión de un paquete
     vulnerable a la versión mínima conocida como corregida.
   - **Parche asistido por IA:** para hallazgos que requieren entender el código (inyección,
     secretos hardcodeados, SSRF), la IA recibe el archivo/línea/fragmento real y devuelve un
     diff unificado, aplicado con `git apply` — nunca una reescritura libre del archivo completo.
   - En ambos casos, el contenido generado se valida antes de aplicarse: una respuesta de IA vaga
     o de relleno se rechaza y se reemplaza por un mensaje honesto de "sin corrección automática
     disponible", en vez de abrirse como un cambio falso.
4. **Creación automática de Merge Request** — Centinela genera una rama de remediación
   (`centinela-fix/*`) y somete un Merge Request formal con la explicación técnica de la
   corrección y las referencias normativas asociadas. **Nunca hace push directo a la rama
   principal.**

---

## 11. Cumplimiento normativo y estándares

Un módulo de mapeo de cumplimiento no detecta nada por sí mismo — toma los hallazgos que ya
existen y los correlaciona contra los controles de los marcos regulatorios más comunes, para
responder "¿qué controles regulatorios están en riesgo?" sin re-escanear nada.

| Estándar / Marco | Controles cubiertos |
|---|---|
| **STRIDE Threat Model** | Spoofing (JWT RS256/Ed25519 vs. algoritmo débil), Tampering, Repudiation (bitácora de auditoría inmutable), Information Disclosure (cifrado y fuga de PII), Denial of Service, Elevation of Privilege |
| **ISO/IEC 25010** | Calidad del software: adecuación funcional, eficiencia, compatibilidad, usabilidad, confiabilidad, seguridad, mantenibilidad, portabilidad |
| **ISO/IEC 27001:2022** | Controles A.5.15 (Acceso), A.8.8 (Vulnerabilidades técnicas), A.8.9 (Configuración), A.8.12 (Fuga de datos), A.8.15 (Registros de auditoría), A.8.16 (Monitoreo), A.8.24 (Criptografía), A.8.28 (Codificación segura) |
| **NIST SP 800-53 Rev 5** | AC-3, CM-6, SI-10, AU-3, SC-8, SC-28 |
| **NIST CSF 2.0** | PR.PS-01, DE.CM-01 |
| **PCI-DSS v4.0** | 2.2 (Hardening), 6.5.1 (Injection Flaws), 8.3 (Autenticación fuerte), 10.2 (Auditoría automatizada) |
| **SOC 2 Type II** | CC6.1, CC6.8, CC7.2 |
| **GDPR** | Artículos 30 y 32 |
| **CMMI® V3.0 (modelo tailored de C&A, 5 áreas evaluables por código)** | CAR (Causal Analysis and Resolution), PQA (Process Quality Assurance), CM (Configuration Management), MC (Monitor and Control), VV (Verification and Validation) — realineado 25 ago 2026 contra el modelo real de 19 áreas de C&A; SAM/MSR (usados hasta antes) no eran áreas reales de ese modelo. Las otras 14 áreas del modelo de 19 quedan marcadas "no evaluado" (requieren evidencia organizacional fuera del alcance de un escáner de código) |
| **ISO 25010 (Usability — Accessibility)** | Nuevo 25 ago 2026, respaldado por el motor `accessibility-wcag` |

---

## 12. Visión Omni-XDR 2.0 — capacidades avanzadas verificadas

Centinela-AI está evolucionando hacia una plataforma Omni-XDR unificada. Todas las capacidades
siguientes están **verificadas en vivo contra el sistema real**, no son planeadas:

- **Cloud Security Posture Management (CSPM)** — escaneo continuo de postura en nubes híbridas
  (AWS, GCP, Azure) bajo CIS Foundations Benchmarks y CIS Kubernetes v1.8.
- **Kubernetes eBPF Admission Shield** — control de admisión en caliente con verificación de
  firmas de imágenes y validación de SBOM antes del paso a producción.
- **Auditoría CMMI® v3.0 por activo** — reporte cuantitativo empírico para las 5 áreas de
  práctica de CMMI que un escáner de código puede evidenciar honestamente (de las 19 del modelo
  tailored real de C&A), disponible vía API. Realineado 25 ago 2026 tras cruzar el motor contra
  el manual de metodología real de la empresa.
- **Auditoría de accesibilidad WCAG 2.1** — motor nuevo (25 ago 2026), requisito legal para
  sistemas de sector público, no solo una preferencia de diseño.
- **Instaladores multi-sistema operativo** — generación desatendida de scripts para Linux,
  Windows y macOS.
- **Análisis de alcanzabilidad (SCA)** — distingue una dependencia vulnerable realmente usada de
  una solo declarada en el manifiesto.
- **Auditoría de hardening CIS** — subconjunto real de ~11 verificaciones Level 1 vía SSH, con
  grado A-F.
- **Detección de Amenazas de Identidad (ITDR)** — ingesta webhook de eventos del IdP Authentik:
  detección de Password Spraying, fuerza bruta (≥5 intentos fallidos en 60s), y revocación
  autónoma de tokens OIDC en menos de 500ms.
- **Telemetría de kernel Linux (eBPF)** — trazado de syscalls (`execve`, `ptrace`, `/tmp`) para
  capturar ejecuciones anómalas en contenedores y servidores.
- **Grafo de ataques correlacionado (Neo4j)** — construcción de historias de ataque conectando
  nodos de identidad, IPs de origen, servidores y CVEs.
- **Motor UEBA sin firma** — análisis de comportamiento para identificar accesos en horarios no
  habituales (00:00–05:00 UTC) y ráfagas inusuales de tráfico API.
- **Grafo de rutas de ataque hacia Active Directory (BloodHound/Neo4j)** — capacidad real y
  activa, en espera de datos: la consulta Cypher funciona contra cualquier dominio, pero el grafo
  no tiene datos de Active Directory todavía porque requiere ejecutar una herramienta de
  recolección (SharpHound/AzureHound) contra un dominio real con credenciales que hoy no están
  disponibles. Se mantiene corriendo en segundo plano sin costo real, para que el día que exista
  un dominio real solo haga falta importar los datos.

---

## 13. Glosario de conceptos clave

### Términos de negocio y estándares

- **CMMI (Capability Maturity Model Integration):** modelo internacional de madurez de procesos
  de software. Para un ejecutivo: mide qué tan estructurado y repetible es el proceso de
  desarrollo de la empresa. Para un desarrollador: el motor de Centinela evalúa 5 áreas reales
  que un escáner de código puede evidenciar honestamente (análisis causal, higiene de código,
  gestión de configuración, monitoreo, verificación) de las 19 del modelo tailored real de C&A
  — ver el glosario de acrónimos añadido el 25 ago 2026 al manual de metodología de la empresa
  para el resto.
- **ISO/IEC 27001:2022:** norma internacional de Sistemas de Gestión de Seguridad de la
  Información (SGSI).
- **ISO/IEC 25010 (SQuaRE):** estándar que mide la calidad del software — mantenibilidad,
  eficiencia, ausencia de deuda técnica.
- **Shift Left:** filosofía DevSecOps que consiste en detectar fallos de seguridad durante la
  escritura del código, no después de que la aplicación esté en producción.

### Módulos y tecnologías de ciberseguridad

- **SAST (Static Application Security Testing):** analiza el código fuente sin ejecutar la
  aplicación.
- **SCA (Software Composition Analysis):** audita paquetes de terceros y librerías open source.
- **DAST (Dynamic Application Security Testing):** evalúa la aplicación en ejecución simulando
  ataques externos desde la red.
- **EDR (Endpoint Detection and Response):** agente que monitorea llamadas al sistema, procesos y
  archivos sospechosos en tiempo real.
- **NDR (Network Detection and Response):** monitoreo continuo del tráfico de red para detectar
  anomalías.
- **ITDR (Identity Threat Detection and Response):** protección de la capa de identidad ante
  ataques de fuerza bruta, robo de credenciales o suplantación.
- **XDR (Extended Detection and Response):** unifica EDR + NDR + SAST + ITDR en una sola consola.
- **SOAR (Security Orchestration, Automation and Response):** motor que ejecuta respuestas
  automáticas ante incidentes.

### Métricas de priorización de vulnerabilidades

- **CVE (Common Vulnerabilities and Exposures):** identificador universal único de un fallo de
  seguridad conocido a nivel mundial.
- **CVSS (Common Vulnerability Scoring System):** escala del 0 al 10 que mide la gravedad
  teórica de una vulnerabilidad.
- **EPSS (Exploit Prediction Scoring System):** porcentaje que predice la probabilidad real de
  que un atacante intente explotar esa vulnerabilidad en los próximos 30 días.
- **CISA KEV (Known Exploited Vulnerabilities):** catálogo oficial del gobierno de EE.UU. que
  confirma que una vulnerabilidad ya está siendo atacada activamente en el mundo real.

---

## 14. Control de acceso basado en roles (RBAC)

Modelo de 4 niveles, alineado a NIST SP 800-53 (AC-2/AC-3) e ISO 27001:

- 🛡️ **Admin (Administrador de Seguridad):** acceso total al sistema, configuración de agentes,
  gestión de usuarios y llaves de Vault.
- ⚡ **Analyst (Analista SOC Nivel 1/2):** operación de incidentes, ejecución de parches SOAR y
  solicitudes de remediación con IA. Sin acceso a llaves de Vault ni administración de usuarios.
- 📋 **Auditor (Auditor de Ciberseguridad / QA):** acceso a reportes ejecutivos PDF, matrices de
  cumplimiento normativo y visibilidad de vulnerabilidades. Sin capacidad de ejecutar acciones
  remediadoras ni cambiar configuraciones.
- 👁️ **Viewer (Visualizador / Ejecutivo):** acceso de solo lectura a los dashboards macro y
  métricas ejecutivas.

---

## 15. Salud del ecosistema y reportes

El dashboard tiene una vista de "Salud del Ecosistema" que reporta el estado real de cada motor y
servicio — no valores fijos. Para los procesos que corren en segundo plano, el estado se infiere
de evidencia real reciente en la base de datos, no de si el módulo simplemente se pudo importar.
Capacidades bajo demanda (como CIS Benchmarks antes de su primer ciclo, o Contención de
Emergencia, que es deliberadamente manual) se reportan honestamente como "disponible, aún sin
ejecutar" en vez de fingir un estado que no ha ocurrido.

Dos reportes PDF están disponibles desde el dashboard:

- **Reporte Ejecutivo** — nivel de riesgo global calculado a partir del Centinela Risk Score real,
  conteo de hallazgos con CISA KEV confirmado, incumplimientos de SLA, y las 5 técnicas MITRE
  ATT&CK más frecuentes.
- **Reporte de Cobertura** — para cada activo, qué motores corrieron y con qué resultado.

---

## 16. Beneficios organizacionales

- **Visibilidad unificada:** un solo panel reemplaza más de una decena de consolas
  desconectadas.
- **Priorización basada en riesgo real,** no solo en severidad teórica — combinando EPSS y CISA
  KEV, la plataforma distingue una vulnerabilidad teóricamente grave de una que ya está siendo
  explotada activamente en el mundo real.
- **Reducción de tiempo de remediación:** de un hallazgo técnico a un Merge Request o script
  ejecutable listo para aprobar, sin que un desarrollador tenga que investigar manualmente cómo
  corregirlo.
- **Cumplimiento normativo continuo,** sin necesidad de auditorías manuales puntuales — cada
  hallazgo ya viene mapeado a los controles regulatorios relevantes.
- **Arquitectura soberana:** basada en herramientas open source (Wazuh, Zeek, Trivy, Nuclei,
  Vault), sin costo recurrente de licencias, dirigiendo el presupuesto hacia ingeniería y
  personalización interna en vez de tarifas por activo de proveedores comerciales.
- **Supervisión humana en cada paso crítico:** la automatización acelera la detección y la
  propuesta de corrección, pero ninguna remediación se ejecuta sin que un operador humano la
  apruebe explícitamente.

---

## 17. Preguntas frecuentes (para referencia del asistente)

**¿Centinela-AI ejecuta ataques o pruebas de penetración?**
No. Es un sistema estrictamente defensivo: monitoreo, detección de vulnerabilidades, auditoría de
estándares y respuesta automatizada ante incidentes. No genera ataques ni pruebas de intrusión
activas contra terceros.

**¿Qué pasa si ningún proveedor de IA responde?**
El motor heurístico determinístico toma el control: genera un análisis y, cuando existe una regla
conocida y segura para ese tipo de hallazgo, un script real. Si no existe una regla determinística
para ese caso, lo indica honestamente en vez de simular una corrección inexistente.

**¿Puede Centinela-AI aplicar cambios sin que nadie los apruebe?**
Solo en el caso de acciones autónomas de muy alta confianza (≥95%, como el bloqueo de una IP ya
confirmada como servidor de comando-y-control activo). Toda otra remediación — y siempre la
contención de emergencia de un host — requiere aprobación humana explícita desde el dashboard.

**¿Cómo se relaciona el Centinela Risk Score con CVSS?**
El CRS combina la severidad (aproximada del bucket que ya asigna cada escáner), EPSS real y
estado real de CISA KEV, más la criticidad del activo. No sustituye un CVSS oficial de NVD —
es un puntaje propio pensado para priorización, no una certificación normativa.

**¿Qué diferencia hay entre un hallazgo "crítico" y uno con CISA KEV confirmado?**
La severidad "crítica" es una clasificación teórica de qué tan grave sería el impacto si se
explotara. Estar en el catálogo CISA KEV significa que esa vulnerabilidad específica **ya está
siendo explotada activamente en el mundo real**, lo cual eleva su prioridad de remediación por
encima de cualquier otra consideración teórica.
