# 🛡️ Centinela-AI: Plataforma Omni-XDR & AI Governance

Centinela-AI es la plataforma **Omni-XDR (Extended Detection and Response) & AI Governance de Alta Fidelidad** del ecosistema CASMARTS. Diseñada bajo un enfoque defensivo estricto, actúa como el centro neurálgico para la correlación de telemetría multinivel, detección omnidireccional de vulnerabilidades (en código fuente, dependencias, contenedores, nubes, APIs e Inteligencia Artificial), auditoría de cumplimiento normativo y remediación autónoma asistida por IA Generativa.

> [!IMPORTANT]
> **Centinela-AI es un sistema estrictamente DEFENSIVO.** 
> El sistema está diseñado exclusivamente para el monitoreo, detección de vulnerabilidades, auditoría de estándares y respuesta automatizada ante incidentes. No se pueden ni se deben generar ataques o pruebas de penetración desde esta plataforma.

---

## 🚀 Abanico Completo de Auditoría y Cobertura Omni-XDR

Centinela-AI ejecuta un abanico exhaustivo de verificaciones de seguridad clasificadas en **6 Pilares de Auditoría Integral**:

### 1. 🔍 Auditoría de Código Fuente y Seguridad Estática (SAST)
Inspección profunda AST (Abstract Syntax Tree) en proyectos Python, JavaScript/TypeScript, Java y C/C++ para identificar antipatrones y fallos de diseño:
- **Inyección de SQL (SQLi / Blind SQLi)**: Detección de concatenación dinámica de cadenas en consultas a bases de datos, uso de formateo de strings (`f""`, `%s`, `.format()`) en declaraciones SQL directas sin binding de parámetros precompilados.
- **Inyección de Comandos del Sistema (CMD Injection)**: Detección de llamadas de ejecuciones inseguras en sistema operativo (`os.system`, `subprocess.Popen(shell=True)`, `eval()`, `exec()`, `passthru()`).
- **Falsificación de Peticiones del Lado del Servidor (SSRF)**: Peticiones HTTP salientes generadas dinámicamente utilizando entradas del usuario no saneadas (`requests.get(url_usuario)`).
- **Fallos de Autorización (BOLA / BFLA)**: Acceso directo a objetos o funciones administrativas sin validación explícita del contexto de sesión o token OIDC.
- **Credenciales & Secretos Hardcodeados**: Identificación de llaves privadas RSA/EC, contraseñas, tokens JWT, claves AWS/GCP y credenciales de bases de datos embebidas directamente en el código fuente.
- **Complejidad Cognitiva y Reglas Clean Code**: Control estricto del modelo de calidad **ISO/IEC 25010**. Bloqueo de funciones con una complejidad cognitiva superior a **15** o una extensión que supere las **60 líneas de código**.

### 2. 📦 Auditoría de Dependencias y Composición de Software (SCA)
Análisis de manifiestos y librerías de terceros contra bases de datos globales de vulnerabilidades (CVE / NVD / GitHub Security Advisory):
- **Ecosistema Python (`requirements.txt`, `Pipfile`, `pyproject.toml`)**: Verificación de versiones obsoletas o descontinuadas de paquetes (`requests`, `urllib3`, `Django`, `FastAPI`, `PyYAML`, `Pillow`, `cryptography`).
- **Ecosistema Node.js / JavaScript (`package.json`, `package-lock.json`)**: Identificación de paquetes vulnerables a **Prototype Pollution**, **ReDoS (Regex Denial of Service)** y **Remote Code Execution (RCE)**.
- **Detección de Licencias Incompatibles**: Alertas sobre dependencias con licencias altamente restrictivas (GPL v3 en entornos corporativos cerrados).

### 3. 🐳 Hardening de Contenedores e Infraestructura como Código (IaC & CIS Benchmarks)
Evaluación estática y dinámica de la postura de infraestructura contra los **CIS Benchmarks v8**:
- **Hardening de Dockerfiles**:
  - Detección y bloqueo del antipatrón de ejecución con usuario `root` (`USER root` implícito o explícito). Debe declararse `USER appuser` o usuario sin privilegios.
  - Prohibición de imágenes base con tags flotantes (`:latest`). Obligatoriedad de versiones fijas o hashes SHA256.
  - Verificación de políticas de limpieza de temporales (`apt-get clean && rm -rf /var/lib/apt/lists/*`) para reducir superficie de ataque.
  - Inexistencia de llaves o secrets expuestos mediante instrucciones `ENV` o `ARG`.
- **Manifiestos de Kubernetes (`.yaml`, Helm Charts)**:
  - Detección de contenedores configurados con `privileged: true` o `allowPrivilegeEscalation: true`.
  - Inexistencia de límites de recursos (`resources.limits.cpu`, `resources.limits.memory`) que expongan el clúster a ataques de Denegación de Servicio (DoS).
  - Montajes inseguros de volúmenes de host (`hostPath: /`).
- **Infraestructura Cloud / Terraform (`.tf`)**:
  - Detección de buckets de almacenamiento S3/GCS configurados con acceso público (`public-read`, `public-read-write`).
  - Grupos de Seguridad (Security Groups) abriendo puertos administrativos (22 SSH, 3389 RDP, 5432 Postgres) hacia la internet global (`0.0.0.0/0`).

### 4. 🤖 Gobernanza de Inteligencia Artificial y Modelos LLM (OWASP LLM Top 10)
Auditoría y control de seguridad específico para aplicaciones que consumen LLMs (Gemini, NVIDIA NIM, Ollama):
- **Inyección de Prompts (OWASP LLM01)**: Evaluación de vectores donde entradas de usuario no saneadas pueden alterar las instrucciones del sistema o manipular el comportamiento del bot.
- **Fuga de Datos Sensibles y PII (OWASP LLM02)**: Detección de presencia de información de identificación personal (PII), credenciales o secretos dentro de las respuestas o prompts enviados a modelos de IA.
- **Ejecución de Código sin Guardrails (OWASP LLM06)**: Bloqueo de interpretadores de código o agentes autónomos que ejecuten comandos generados por el LLM sin entornos sandbox o aprobación explícita.

### 5. 🌐 Auditoría de APIs Fantasma & Desviación de Esquemas (Shadow API)
- **Detección de Shadow APIs**: Escaneo comparativo entre el código fuente (rutas FastAPI, Express, Spring) y la documentación oficial declarada (`openapi.json` / Swagger) para detectar endpoints "fantasma" expuestos sin documentación.
- **API Drift & Parametrización Insegura**: Identificación de parámetros no documentados o esquemas de respuesta que filtran campos internos del sistema.

### 6. 📜 Mapeo de Estándares Maestros de Auditoría y Cumplimiento Normativo
Cada hallazgo detectado en el ecosistema es mapeado de forma automática hacia controles oficiales y matrices de amenaza:

| Estándar / Marco | Controles y Reglas Auditadas |
| :--- | :--- |
| **STRIDE Threat Model** | **S**poofing (JWT RS256/Ed25519 vs HS256 débil), **T**ampering (Integridad de paquetes), **R**epudiation (Bitácora inmutable de auditoría `who`, `what`, `when`), **I**nformation Disclosure (Cifrado de datos y fuga de PII), **D**enial of Service (Límites de memoria y timeouts), **E**levation of Privilege (Verificación RBAC/OIDC). |
| **ISO/IEC 25010** | Calidad del Software: Adecuación Funcional, Eficiencia de Desempeño, Compatibilidad, Usabilidad, Confiabilidad, Seguridad, Mantenibilidad (Complejidad Cognitiva < 15) y Portabilidad. |
| **ISO 27001:2022** | Controles A.5.15 (Acceso), A.8.9 (Gestión de Configuración), A.8.12 (Prevención Fuga Datos), A.8.15 (Registros Auditoría), A.8.24 (Criptografía), A.8.28 (Codificación Segura). |
| **NIST SP 800-53 Rev 5** | Controles AC-3 (Access Control), CM-6 (Configuration Settings), SI-10 (Information Input Validation), AU-3 (Audit Record Content), SC-8 (Transmission Confidentiality), SC-28 (Protection at Rest). |
| **PCI-DSS v4.0** | Requerimientos 2.2 (Hardening), 6.5.1 (Injection Flaws), 8.3 (Autenticación Fuerte), 10.2 (Auditoría Automatizada). |
| **SOC 2 Type II** | Criterios CC6.1 (Seguridad Acceso Lógico), CC6.8 (Hardening de Sistemas), CC7.2 (Monitoreo de Infraestructura). |
| **GDPR** | Artículos 30 (Registro de Actividades de Tratamiento) y 32 (Seguridad del Tratamiento y Cifrado PII). |

---

## 🦊 Integración Automatizada con GitLab & Auto-Fix MR Generator

Centinela-AI integra un flujo **DevSecOps Bidireccional** con servidores GitLab (`http://10.4.3.10`):

1. **Descubrimiento de Repositorios**: Consulta automáticamente la API REST v4 (`/api/v4/projects`) para listar todos los proyectos de la organización.
2. **Clonado y Auditoría**: Clona o actualiza los repositorios en entornos aislados de análisis (`/tmp/centinela_gitlab_scans`) y ejecuta el escaneo Omni-Vulnerabilidades completo.
3. **Generación de Parche Asistido por IA (Gemini 1.5 Flash)**: Cuando se confirma una vulnerabilidad (ej. SQLi o falta de usuario non-root en Dockerfile), el motor de IA analiza el contexto completo del archivo y genera el parche de código corregido.
4. **Creación Automática de Merge Request (MR)**: Centinela genera una rama de remediación (`centinela-autofix/vuln-{id}`) y somete un **Merge Request formal en GitLab** con la explicación técnica de la corrección y las referencias normativas asociadas.

---

## 🖥️ Monitoreo Continuo de Servidores Físicos y Virtuales

Centinela-AI audita servidores físicos y máquinas virtuales (Linux/Windows) en tiempo real:
- **Auto-Instalación de Agentes Wazuh**: Al registrar una nueva dirección IP o servidor en el inventario, el orquestador dispara un Playbook de Ansible que instala y configura automáticamente el agente de Wazuh.
- **Escaneo de Red Perimetral**: Integración con **Nuclei** (plantillas de vulnerabilidades perimetrales), **Nmap** (descubrimiento de puertos y servicios) y **Medusa** (auditoría de contraseñas débiles en SSH, RDP, Postgres).
- **Seguridad Runtime (Falco / Wazuh Syslog)**: Captura de eventos del kernel en caliente para detectar ejecuciones sospechosas de shell, modificación de binarios del sistema o accesos no autorizados.

---

## 📊 Arquitectura del Ecosistema Omni-XDR

```mermaid
flowchart TB
    subgraph Fuentes de Datos & Descubrimiento
        GitLab[Servidores GitLab / Git Repos] -->|API REST v4| OmniBE(FastAPI Backend Engine)
        Wazuh[Agentes Wazuh / OS Telemetry] -->|Syslog / Webhooks| OmniBE
        Falco[Falco Container Telemetry] -->|Alertas Runtime| OmniBE
        Scan[Nuclei / Nmap / Trivy / Medusa] -->|Resultados Escaneo| OmniBE
    end

    subgraph Motores de Auditoría Nativa Omni
        OmniBE --> SAST[SAST & AST Code Auditor]
        OmniBE --> SCA[SCA & Dependency Vulnerabilities]
        OmniBE --> IaC[IaC & Docker CIS Hardening]
        OmniBE --> LLMGov[OWASP LLM & AI Governance]
        OmniBE --> ShadowAPI[Shadow API & OpenAPI Drift]
        OmniBE --> Standards[ISO 27001 / STRIDE / NIST Mapper]
    end

    subgraph Inteligencia Generativa & SOAR
        OmniBE --> Gemini[Google Gemini 1.5 Flash / NIM]
        Gemini -->|Auto-Patching Code| AutoMR[GitLab Auto Merge Request]
        Gemini -->|Playbooks Ansible| Ansible[Ansible Orchestration]
        Ansible -->|SSH / WinRM| TargetHost[Servidor Físico / Virtual]
    end

    subgraph Interfaz de Mando (Frontend)
        OmniBE -->|WebSockets Alerts| WebUI[React + Vite Dashboard]
        WebUI -->|Omni-Audit Matrix Tab| OmniBE
    end

    classDef tech fill:#1E293B,stroke:#38BDF8,stroke-width:1px,color:#fff;
    class GitLab,Wazuh,Falco,Scan,OmniBE,SAST,SCA,IaC,LLMGov,ShadowAPI,Standards,Gemini,AutoMR,Ansible,TargetHost,WebUI tech;
```

---

## 📡 Referencia de Endpoints REST (API Backend)

| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `POST` | `/api/gitlab/scan` | Inicia el escaneo y descubrimiento completo de todos los proyectos de GitLab. |
| `POST` | `/api/gitlab/autofix/{vuln_id}` | Genera parche asistido por IA y abre un Merge Request en GitLab. |
| `GET` | `/api/audit/full-spectrum` | Ejecuta el análisis Omni (SAST, SCA, IaC y Estándares de Auditoría). |
| `GET` | `/api/audit/shadow-api` | Audita APIs fantasma y desviaciones del esquema OpenAPI. |
| `GET` | `/api/audit/llm-governance` | Revisa el cumplimiento de OWASP Top 10 for LLMs y fugas de PII en IA. |
| `GET` | `/api/audit/iac-k8s` | Audita manifiestos de Kubernetes, Helm Charts y Terraform. |
| `GET` | `/api/audit/compliance-mapping` | Retorna la matriz de cumplimiento normativo (ISO 27001, NIST, PCI, SOC2, GDPR). |

---

## 🛠️ Stack Tecnológico Evolucionado

| Componente | Herramientas | Propósito |
| :--- | :--- | :--- |
| **Cerebro Generativo** | Google Gemini 1.5 Flash, NVIDIA NIM | Correlación de amenazas, generación de reportes y parches de código. |
| **Gobernanza de IA** | Auditor Nativo OWASP LLM | Detección de Prompt Injection, fuga de PII y guardrails de modelo. |
| **Runtime Security** | Falco, Wazuh | Monitoreo continuo de servidores físicos y virtuales Linux/Windows. |
| **Escaneo de Red** | Nuclei, Nmap, Medusa | Detección perimetral de vulnerabilidades y fuerza bruta en puertos. |
| **Análisis Estático (SAST)** | Auditor Nativo AST | Detección de SQLi, Command Injection, BOLA/BFLA y Complejidad Cognitiva. |
| **Composición de Software (SCA)** | Auditor Nativo SCA | Detección de dependencias vulnerables en `requirements.txt` y `package.json`. |
| **Hardening IaC & Docker** | Auditor Nativo CIS Benchmarks | Verificación de ejecuciones non-root, Dockerfiles y manifiestos K8s. |
| **Mapeo de Cumplimiento** | Compliance Mapper | Mapeo directo a ISO 27001, NIST SP 800-53, PCI-DSS v4.0, SOC 2 y GDPR. |
| **Integración Git** | GitLab REST API v4, Git CLI, Maven | Clonación automatizada, builds y generación de Merge Requests con parches. |
| **Orquestación SOAR** | Ansible (Playbooks), Docker SDK | Remediación autónoma e instalación automática de agentes. |
| **Frontend & Gateway** | React, Vite, Tailwind CSS, Nginx | Dashboard dinámico con visualización de matriz Omni-Audit y WebSockets. |
| **Backend & API** | FastAPI, Python 3.12, WebSockets | Microservicios de alto rendimiento y endpoints de auditoría omnidireccional. |

---

## 📦 Despliegue en el Ecosistema

Para desplegar Centinela-AI localmente (`10.4.3.34`):

```bash
# Sincronizar directorio del proyecto
cd /opt/centinela-ai

# Desplegar stack Omni-XDR mediante Docker Compose
docker compose up -d --build
```

Acceso al portal central: `http://centinela.casmart.internal` o `http://10.4.3.34`.

---

© 2026 CASMARTS - Sistema de Seguridad Nacional & Gobernanza de IA de Alta Fidelidad.
