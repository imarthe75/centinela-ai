# 🛡️ Centinela-AI: Ecosistema XDR de Alta Fidelidad

Centinela-AI ha evolucionado de un orquestador básico a una plataforma **XDR (Extended Detection and Response) de Alta Fidelidad**. Es el cerebro de seguridad del ecosistema CASMARTS, diseñado para correlacionar telemetría de múltiples fuentes, detectar amenazas en tiempo real y ejecutar remediaciones autónomas mediante inteligencia artificial generativa de vanguardia.

> [!IMPORTANT]
> **Centinela-AI es un sistema estrictamente DEFENSIVO.** 
> No es una herramienta de Pentesting ni de ataque. El sistema está diseñado exclusivamente para el monitoreo, detección de vulnerabilidades y respuesta automatizada ante incidentes. No se pueden ni se deben generar ataques o pruebas de penetración desde esta plataforma.

## 🚀 Capacidades de Nueva Generación

- **Cerebro AI (Gemini 1.5 Flash):** Integración nativa con Google GenAI SDK para realizar análisis multimodales, correlación de logs complejos y generación de reportes ejecutivos con una latencia mínima.
- **Detección de Alta Fidelidad (XDR):** Correlación inteligente entre alertas de runtime (Falco/Wazuh), escaneos externos (Nuclei/Nmap) y auditorías de infraestructura (Trivy/Checkov).
- **SOAR Engine (Remediación Autónoma & Ansible):** Orquestación completa que genera, valida y ejecuta playbooks de Ansible y scripts de solución automáticamente en contenedores o hosts Linux/Windows. Si se detecta un activo nuevo Linux/Windows, instala automáticamente el Agente de Wazuh vía Ansible.
- **Acciones Directas de Agente (Wazuh):** Capacidad del dashboard para controlar agentes de Wazuh en tiempo real (Reiniciar Agente, Ejecutar Escaneo Activo, Consultar Logs en Caliente).
- **Integración con Tickets SOAR (Gitea / Redmine):** Creación automática o manual de incidentes y seguimiento de remediaciones directamente en Gitea o Redmine con un solo clic.
- **Alertas en Tiempo Real (WebSockets):** Streaming constante de detecciones críticas directamente a la interfaz web con notificaciones Toast interactivas.
- **Reportes Ejecutivos en PDF (WeasyPrint):** Generación de reportes ejecutivos de seguridad con estilos profesionales mediante WeasyPrint para HTML→PDF sin dependencias externas.
- **Métricas SOAR ROI:** Gráficos y widgets financieros en el dashboard que contrastan el tiempo de resolución automatizado (SOAR) vs. mitigación manual, reportando el porcentaje de efectividad de la IA.
- **Identidad Unificada (OIDC):** Integración total con el ecosistema de identidad CASMARTS (Authentik) para un control de acceso centralizado y seguro.

## 📊 Arquitectura y Flujo de Información

```mermaid
flowchart TB
    subgraph Monitoreo & Detección
        Wazuh[Agente Wazuh / Logs OS] -->|Syslog / Logs| MainBE(Main API FastAPI Backend)
        Falco[Falco Runtime Container] -->|Webhooks Alertas| MainBE
        Scan[Nuclei / Nmap / Trivy] -->|JSON Reports| MainBE
    end

    subgraph Inteligencia y Correlación
        MainBE -->|Logs & Contexto| Gemini[Google Gemini 1.5 Flash]
        Gemini -->|Generación de Mitigación| Heuristics[Motor de Heurística]
        Heuristics -->|Vector Embeddings| PostgreSQL[(PostgreSQL Store)]
    end

    subgraph Ejecución y SOAR
        MainBE -->|Playbooks Dinámicos| Ansible[Ansible Playbook Engine]
        Ansible -->|SSH / WinRM| TargetHost[Servidor Windows / Linux]
        TargetHost -->|Auto-Instalación| WazuhAgent[Wazuh Agent Deployment]
        
        MainBE -->|API REST| Gitea[Gitea / Redmine Tickets]
        MainBE -->|WeasyPrint Renderer| PDF[Reportes PDF C-Suite]
    end

    subgraph Interfaz de Mando (Frontend)
        MainBE -->|WebSockets Alerts| WebUI[Vite + React Dashboard]
        WebUI -->|Wazuh Direct Actions| MainBE
        WebUI -->|Download PDF / ROI Stats| MainBE
    end

    classDef tech fill:#1E293B,stroke:#38BDF8,stroke-width:1px,color:#fff;
    classDef extern fill:#0F172A,stroke:#64748B,stroke-width:1px,color:#94A3B8;
    class Wazuh,Falco,Scan,MainBE,Gemini,Heuristics,PostgreSQL,Ansible,TargetHost,WazuhAgent,Gitea,PDF,WebUI tech;
```

## 🛠️ Stack Tecnológico Evolucionado

| Componente | Herramientas | Propósito |
| :--- | :--- | :--- |
| **Inteligencia Artificial** | Google Gemini 1.5 Flash | Correlación de amenazas, generación de reportes y scripts. |
| **Runtime Security** | Falco, Wazuh | Monitoreo de comportamiento de procesos y logs en tiempo real. |
| **Escaneo de Activos** | Nuclei, Nmap | Detección proactiva de vulnerabilidades y mapeo de red. |
| **Seguridad de Código** | Trivy, Checkov | Auditoría de imágenes Docker e Infraestructura como Código (IaC). |
| **Orquestación & Despliegue** | Ansible (Playbooks) | Automatización de instalación de agentes y parches de configuración. |
| **Ticketing SOAR** | Gitea, Redmine API | Seguimiento y escalamiento de vulnerabilidades e incidentes. |
| **Motor de PDF** | WeasyPrint | Conversión de HTML+CSS → PDF para reportes ejecutivos estilizados (2026-06-02 ✅). |
| **Frontend de Alto Rendimiento** | React, Vite, Tailwind CSS | Dashboard dinámico con visualización geográfica y SOAR en tiempo real. |
| **Backend & API** | FastAPI, Python 3.12, WebSockets | Microservicios de alto rendimiento y streaming de alertas en caliente. |
| **Base de Datos** | PostgreSQL (Vector Store) | Persistencia de hallazgos y almacenamiento de embeddings para RAG. |

## 📦 Despliegue en el Ecosistema

El sistema se despliega como parte del core de CASMARTS, orquestado por el Gateway central:

```bash
# Sincronizar repositorio
cd ecosistema-casmarts/centinela-ai

# Desplegar stack XDR
docker compose up -d --build
```

## 🖥️ Arquitectura de Mando Regional

Accede a través del portal central: `https://centinela.casmart.internal`

## 🧠 ¿Qué es una Plataforma SOAR? (In-Depth)

**SOAR** responde a las siglas **Security Orchestration, Automation, and Response**. Es una categoría de tecnologías que permite a las organizaciones recopilar datos sobre amenazas de seguridad y responder a incidentes sin intervención humana constante. En Centinela-AI, el motor SOAR actúa como el "brazo ejecutor" de la inteligencia artificial.

### Los Tres Pilares del SOAR en Centinela-AI:

1. **Orquestación (Orchestration):** 
   Es la capacidad de conectar herramientas de seguridad dispares (como Wazuh, Falco, Nmap y Docker) en un flujo de trabajo coherente. Centinela-AI orquesta estos sistemas para que trabajen como un solo organismo: una alerta en Falco puede disparar un escaneo de Nmap y una auditoría de base de datos simultáneamente.

2. **Automatización (Automation):** 
   Se refiere a la ejecución de "Playbooks" o tareas repetitivas sin intervención manual. Cuando Centinela detecta una vulnerabilidad conocida (ej. un puerto abierto innecesariamente), no solo avisa, sino que genera automáticamente el script de mitigación basado en el contexto real del activo.

3. **Respuesta (Response):** 
   Es la culminación del proceso. Centinela-AI no solo propone soluciones, sino que las ejecuta mediante el motor **Aura-Sentinel** y **Ansible Playbooks**. La respuesta puede ser desde el aislamiento de un contenedor sospechoso hasta el blindaje de red perimetral o la reconfiguración de un servidor de aplicaciones como WildFly.

### ¿Por qué es crítico para CASMARTS?
En un entorno de amenazas modernas, la velocidad es la diferencia entre una mitigación exitosa y una brecha de datos masiva. El SOAR de Centinela-AI reduce el **MTTR (Mean Time To Respond)** de horas a segundos, eliminando el error humano y asegurando que cada acción esté documentada por IA con trazabilidad forense completa.

---

## 🛡️ Orquestación de Remediación

Centinela-AI utiliza un enfoque de **Agente Híbrido**:
- **Contenedores Docker:** Remediación **Directa/Agentless** vía Docker SDK.
- **Servidores Externos/IPs (Linux & Windows):** Remediación automática e instalación automatizada del **Agente de Wazuh** gestionado mediante Ansible al configurar credenciales del sistema (sudo/administrator).

## 📚 Documentación

Para una guía detallada del sistema, consulte los siguientes documentos:

- 📖 **[Guía de Usuario Final](file:///home/ia/ecosistema-casmarts/centinela-ai/USER_GUIDE.md)**: Manual de operación del dashboard y gestión de incidentes.
- 🛠️ **[Documentación Técnica](file:///home/ia/ecosistema-casmarts/centinela-ai/TECHNICAL_DOCS.md)**: Detalles de arquitectura, stack tecnológico y manual de despliegue.

## 📝 Actualizaciones Recientes

### 2026-06-02: Migración de Motor PDF — Carbone → WeasyPrint

**Estado:** ✅ RESUELTO

**Cambio:** Reemplazado motor de generación de PDFs de Carbone.io (para templates de documentos) a **WeasyPrint** (para HTML+CSS → PDF).

**Por qué:** Carbone está diseñado para document templates (DOCX, XLSX); no para HTML directo. WeasyPrint es la solución nativa para reportes HTML estilizados.

**Impacto:**
- ✅ Todos los 3 endpoints de reportes generan PDFs válidos
- ✅ Eliminada dependencia de servicio externo
- ✅ Estilos CSS preservados (tablas, badges, gradientes)
- ✅ Renderizado in-process (más rápido)

**Endpoints afectados:**
- `/api/reports/executive` — Reporte ejecutivo de vulnerabilidades
- `/api/reports/asset/{asset_name}` — Reporte de seguridad de activo
- `/api/reports/vulnerability/{vuln_id}` — Detalle de vulnerabilidad

**Archivos modificados:**
- `requirements.txt` — Agregado `WeasyPrint`
- `Dockerfile.backend` — Dependencias Cairo/Pango
- `main.py` — Nueva función `render_pdf_with_weasyprint()`

Ver: [Documentación Técnica](centinela_pdf_generation_fix.md)

---

© 2026 CASMARTS - Sistema de Seguridad Nacional de Alta Fidelidad.

---
*Centinela-AI: La sinergia perfecta entre el talento humano y la inteligencia artificial para la protección del ecosistema CASMARTS.*

