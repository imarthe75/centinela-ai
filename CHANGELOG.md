# Changelog — Centinela-AI

Todas las actualizaciones y cambios notables en Centinela-AI se documentan en este archivo.

---

## [2026-06-09] — Escaneo Forzado: Servidores 200-207 + ZAP Results

### 🔍 Escaneo Forzado Ejecutado (2026-06-09 Sesión)

#### Hallazgos Nuclei

| Severidad | CVE ID | Asset | Motor |
|-----------|--------|-------|-------|
| HIGH | CVE-2025-14847 (MongoBleed) | 10.4.3.207:27017 | nuclei |
| HIGH | NUCLEI-HAL-MANAGEMENT-PANEL | 10.4.3.206:9990 | nuclei |
| MEDIUM | NUCLEI-HTTP-MISSING-SECURITY-HEADERS-8080 | 10.4.3.206:8080 | nuclei |
| MEDIUM | NGINX-EOL-VERSION-1.18 | 10.4.3.204:80 | nuclei |
| LOW | SSH-SHA1-HMAC-WEAK-206 | 10.4.3.206:22 | nuclei |
| LOW | SSH-SHA1-HMAC-WEAK-204 | 10.4.3.204:22 | nuclei |

#### Hallazgos ZAP Baseline (post-scan)

**WildFly 8080** — 5 WARN, 0 FAIL, 61 PASS:
- ZAP-10020-ANTI-CLICKJACKING [MEDIUM] — X-Frame-Options ausente
- ZAP-10038-CSP-MISSING [MEDIUM] — Content Security Policy ausente
- ZAP-10021-CONTENT-TYPE-OPTIONS [LOW] — X-Content-Type-Options ausente
- ZAP-10063-PERMISSIONS-POLICY [LOW] — Permissions-Policy ausente
- ZAP-90004-CORP-HEADER [LOW] — Cross-Origin-Resource-Policy ausente

**HAL Console 9990** — 7 WARN, 0 FAIL, 59 PASS:
- ZAP-10110-DANGEROUS-JS-FUNCTIONS [MEDIUM] — eval() en hal.nocache.js
- ZAP-10038-CSP-MISSING [MEDIUM] — CSP ausente en panel admin
- ZAP-10096-TIMESTAMP-DISCLOSURE [LOW] — 18 Unix timestamps en external.min.js
- ZAP-10063-PERMISSIONS-POLICY [LOW] — Permissions-Policy ausente
- ZAP-90004-CORP-HEADER [LOW] — CORP Header ausente

#### Correlación Heurística Automática

- **HEURISTIC-MULTI-SCANNER-CONVERGENCE-9990** [CRITICAL] — 3 motores (nmap+nuclei+zap) convergieron en CLONE-SICOPA-ADMIN-CONSOLE (puerto 9990). Cadena de ataque identificada: Puerto libre → HAL Console sin auth → eval() en JS → Deploy WAR → RCE.

#### Totales SICOPA (10.4.3.206 + 207) Post-Escaneo

| Severidad | Cantidad |
|-----------|---------|
| CRITICAL | 2 |
| HIGH | 2 |
| MEDIUM | 8 |
| LOW | 7 |
| Info | 5 |
| **TOTAL** | **24** |

---

## [2026-06-09] — ZAP DAST + Secrets + SpiderFoot OSINT Integration

### 🆕 Nuevos Módulos

#### 1. OWASP ZAP DAST Integration (`auditor_zap.py`)

**Problema:** ZAP encontraba vulnerabilidades en servers 200-207 que Centinela con solo Nuclei no detectaba.  
**Causa raíz:** Nuclei usa plantillas estáticas; no detecta vulnerabilidades dinámicas (CSRF, auth bypass, session flaws).

**Solución:** Integración OWASP ZAP con arquitectura ephemeral + smart caching:
- Containers ZAP lanzados bajo demanda (no siempre activos)
- Caché persistente del DB de vulnerabilidades (volumen `zap-cache`)
- 4 perfiles: `light` (5 min), `balanced` (15 min, default), `aggressive` (30 min), `api` (20 min)
- Deduplicación automática con hallazgos existentes de Nuclei

**Vulnerabilidades DAST que ahora detecta:**
- CSRF Token Validation Bypass
- Authentication/Session Bypass
- Business Logic Flaws
- HTTP Parameter Pollution
- Cache Poisoning
- Polyglot/Encoding Bypasses
- File Upload Bypass
- Race Conditions

#### 2. Secrets Scanning (`auditor_secrets.py`)

**Problema:** Credenciales y API keys hardcodeadas no eran detectadas.

**Solución:** Scanner de 3 fases con truffleHog v3 + pattern matching:
- **PHASE 1** (fast, ~10-20 sec): Working tree — ejecutado cada ciclo
- **PHASE 2** (medium, ~1-5 min): Últimos 50 commits — semanal
- **PHASE 3** (deep, ~5-30 min): Historia completa — bajo demanda

**Detecta:** AWS keys, private keys, GitHub PAT, Slack tokens, DB passwords, connection strings, API tokens

**Whitelisting:** Via `.centinela-secrets-whitelist.json` en cada repo

#### 3. SpiderFoot OSINT (`auditor_spiderfoot.py`)

**Problema:** OSINT era solo pasivo (DNS + Shodan mock); no descubría subdomains, certificados, cabeceras de seguridad.

**Solución:** OSINT activo multi-fuente:
- Subdomain enumeration (DNS brute-force + amass si disponible)
- Certificate Transparency logs (crt.sh API)
- TLS certificate analysis (versión, cipher suite, expiración)
- HTTP security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
- Threat intelligence (AbuseIPDB + AlienVault OTX si API keys configuradas)
- Auto-registro de sub-activos descubiertos en infra_inventory

### 🔧 Cambios en Módulos Existentes

#### `auditor_ext.py`
- `scan_url()`: ZAP DAST se ejecuta después de Nuclei
- `scan_repo()`: Trivy ahora parsea CVEs individuales + Checkov parsea cada check + Secrets scanning PHASE 1
- `scan_appserver()`: ZAP DAST por cada puerto web abierto detectado por Nmap
- `handle_osint_enrichment()`: SpiderFoot ejecutado para activos URL
- Imports condicionales: ZAP/Secrets/SpiderFoot cargan solo si están disponibles (fallback gracioso)

#### `heuristics_engine.py` — 3 nuevas reglas (ahora 6 total)

| Regla | ID | Trigger | Severidad |
|-------|-----|---------|-----------|
| 4 | `HEURISTIC-DAST-AUTH-BYPASS-CHAIN` | ZAP auth vulns + runtime privilege escalation | CRITICAL |
| 5 | `HEURISTIC-SECRETS-EXFIL-RISK` | Secrets encontrados + outbound network activity | CRITICAL |
| 6 | `HEURISTIC-MULTI-SCANNER-CONVERGENCE` | Mismo activo flagged por 3+ scan engines | CRITICAL |

#### `main.py` — Nuevos endpoints

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/scan/dast/{asset_id}` | POST | ZAP DAST on-demand |
| `/api/scan/secrets/{asset_id}` | POST | Secrets scan on-demand (fase 1/2/3) |
| `/api/scan/osint/{asset_id}` | POST | SpiderFoot OSINT on-demand |
| `/api/scan/coverage` | GET | Breakdown por motor de escaneo |
| `/api/health` | GET | Actualizado con status de todos los módulos |

#### `docker-compose.yml`
- Volumen `zap-cache` (tmpfs 150MB) para DB de vulnerabilidades ZAP

### 🗄️ Schema DB Migration

```sql
ALTER TABLE vulnerability_log ADD COLUMN scan_engine VARCHAR(50) DEFAULT 'nuclei';
ALTER TABLE vulnerability_log ADD COLUMN url_path TEXT;
ALTER TABLE vulnerability_log ADD COLUMN zap_scan_id VARCHAR(100);
```

### 📊 Análisis Servidores 200-207 (2026-06-09)

| Servidor | IP | Servicios Detectados | Tipo Actualizado | Risk |
|----------|-----|---------------------|-----------------|------|
| CLONE-COMPRAMEX-DIGITAL | 10.4.3.200 | Sin puertos abiertos | SERVER | Desconocido |
| CLONE-COMPRAMEX-DIGITAL-BD | 10.4.3.201 | Sin puertos abiertos | SERVER | Desconocido |
| CLONE-COMPRAMEX-CORE | 10.4.3.202 | Sin puertos abiertos | SERVER | Desconocido |
| CLONE-COMPRAMEX-CORE-BD | 10.4.3.203 | Sin puertos abiertos | SERVER | Desconocido |
| CLONE-PMCP | 10.4.3.204 | **HTTP:80 (Nginx 1.18)** | AppServer | HIGH |
| CLONE-PMCP-BD | 10.4.3.205 | **PostgreSQL 16 :5432** | Database (SQL) | HIGH |
| CLONE-SICOPA | 10.4.3.206 | **WildFly 8080/8443 + Admin :9990** | AppServer | CRITICAL |
| CLONE-SICOPA-BD | 10.4.3.207 | **PG 9.6 :5432 + MongoDB :27017** | NoSQL | HIGH |

**Nuevos assets registrados para escaneo ZAP:**
- `CLONE-PMCP-HTTP` → http://10.4.3.204:80
- `CLONE-SICOPA-HTTP` → http://10.4.3.206:8080
- `CLONE-SICOPA-HTTPS` → https://10.4.3.206:8443
- `CLONE-SICOPA-ADMIN-CONSOLE` → http://10.4.3.206:9990 [CRITICAL - JBoss admin exposed]

### ✅ Coverage de Vulnerabilidades Post-Integración

| Tipo | Antes | Ahora |
|------|-------|-------|
| CVEs conocidos (templates) | ✅ Nuclei | ✅ Nuclei |
| Dynamic web vulns (CSRF, auth, session) | ❌ | ✅ ZAP DAST |
| Code SAST patterns | ✅ Medusa | ✅ Medusa |
| Secrets/credentials | ❌ | ✅ auditor_secrets |
| Subdomain discovery | ❌ mock | ✅ DNS + CT logs |
| TLS misconfigs | ❌ | ✅ SpiderFoot |
| Missing security headers | ❌ | ✅ SpiderFoot |
| Threat intelligence | ❌ | ✅ AbuseIPDB/OTX |
| IaC misconfigs | ✅ Checkov | ✅ Checkov (mejorado) |
| Container CVEs | ✅ Trivy | ✅ Trivy (mejorado) |
| Runtime FIM/privesc | ✅ Wazuh | ✅ Wazuh |

### 🚀 Despliegue

```bash
cd /home/ia/ecosistema-casmarts/centinela-ai

# Reconstruir backend (no hay nuevas dependencias del sistema)
docker compose up -d --build centinela-backend centinela-ai centinela-sentinel

# Verificar salud con nuevos módulos
curl http://localhost:8302/api/health | python3 -m json.tool

# Disparar escaneo ZAP on-demand en servidor crítico (JBoss admin)
curl -X POST http://localhost:8302/api/scan/dast/338 \
  -H 'Content-Type: application/json' \
  -d '{"profile": "aggressive"}'

# Ver coverage por motor de escaneo
curl http://localhost:8302/api/scan/coverage | python3 -m json.tool
```

---

## [2026-06-02] — Rito de Inicio: Corrección de Generación de PDFs

### 🔧 Cambios

#### Motor de Reportes PDF: Carbone → WeasyPrint

**Problema Identificado:**
- Los PDFs generados estaban corruptos/ilegibles
- Carbone estaba mal configurado para HTML inline
- Carbone está diseñado para templates de documentos, no para HTML directo

**Solución Implementada:**
- Reemplazado `render_pdf_with_carbone()` por `render_pdf_with_weasyprint()`
- WeasyPrint es la solución nativa para HTML+CSS → PDF

**Archivos Modificados:**
- `requirements.txt` — Agregado `WeasyPrint==69.0`
- `Dockerfile.backend` — Dependencias del sistema (Cairo, Pango)
- `main.py` — Nueva función de rendering, 3 endpoints actualizados
- `scratch/debug_pdf.py` — Script de prueba actualizado

**Endpoints Afectados:**
- `GET /api/reports/executive` — ✅ Funcional
- `GET /api/reports/asset/{asset_name}` — ✅ Funcional
- `GET /api/reports/vulnerability/{vuln_id}` — ✅ Funcional

**Beneficios:**
- PDFs válidos (versión 1.7) sin corrupción
- Renderizado más rápido (in-process vs HTTP round-trip)
- Eliminada dependencia de servicio externo
- Estilos CSS completos preservados
- Mejor mantenibilidad (librería pura Python)

### 📚 Documentación Actualizada

- `README.md` — Cambio de Carbone a WeasyPrint, tabla de stack, diagrama de flujo
- `TECHNICAL_DOCS.md` — Detalles de cambio, endpoints actualizados, tabla comparativa
- `USER_GUIDE.md` — Nota de mejora en reportes PDF para usuarios finales
- Memoria del Proyecto — `centinela_pdf_generation_fix.md` con análisis técnico completo

### ✅ Verificación Post-Cambio

```
Reporte Ejecutivo:
  ✅ PDF válido (v1.7, 22KB)
  ✅ Contenido legible: 3871 vulnerabilidades totales
  ✅ Tablas formateadas correctamente
  ✅ Sin corrupción de caracteres

Reporte de Activo (gateway):
  ✅ PDF válido (v1.7)
  ✅ Detalles del activo completos
  ✅ Tabla de vulnerabilidades renderizada
  ✅ Estilos (badges, colores) intactos
```

### 🔄 Stack Impactado

| Componente | Cambio | Estado |
|-----------|--------|--------|
| Backend FastAPI | `render_pdf_with_weasyprint()` | ✅ Actualizado |
| requirements.txt | `+WeasyPrint` | ✅ Agregado |
| Dockerfile.backend | Cairo/Pango libs | ✅ Agregado |
| API Endpoints | 3 endpoints revisados | ✅ Funcional |
| Documentación | README, TECHNICAL, USER | ✅ Actualizado |

### 🚀 Despliegue

```bash
cd /home/ia/ecosistema-casmarts/centinela-ai
docker compose up -d centinela-backend  # Rebuild automático
```

**Nota:** El rebuild incluye nuevas dependencias del sistema; el primer build toma ~1-2 minutos.

---

## Versiones Anteriores

*(Historial de cambios previos irá aquí con actualizaciones futuras)*

---

**Formato:** Cada cambio importante incluye: Problema, Solución, Archivos Modificados, Verificación.
**Mantenedor:** CASMARTS Security Team
**Última Actualización:** 2026-06-02 20:30 UTC-6
