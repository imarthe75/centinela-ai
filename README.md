# 🛡️ Centinela-AI: Ecosistema XDR de Alta Fidelidad

Centinela-AI ha evolucionado de un orquestador básico a una plataforma **XDR (Extended Detection and Response) de Alta Fidelidad**. Es el cerebro de seguridad del ecosistema CASMARTS, diseñado para correlacionar telemetría de múltiples fuentes, detectar amenazas en tiempo real y ejecutar remediaciones autónomas mediante inteligencia artificial generativa de vanguardia.

> [!IMPORTANT]
> **Centinela-AI es un sistema estrictamente DEFENSIVO.** 
> No es una herramienta de Pentesting ni de ataque. El sistema está diseñado exclusivamente para el monitoreo, detección de vulnerabilidades y respuesta automatizada ante incidentes. No se pueden ni se deben generar ataques o pruebas de penetración desde esta plataforma.

## 🚀 Capacidades de Nueva Generación

- **Cerebro AI (Gemini 1.5 Flash):** Integración nativa con Google GenAI SDK para realizar análisis multimodales, correlación de logs complejos y generación de reportes ejecutivos con una latencia mínima.
- **Detección de Alta Fidelidad (XDR):** Correlación inteligente entre alertas de runtime (Falco/Wazuh), escaneos externos (Nuclei/Nmap) y auditorías de infraestructura (Trivy/Checkov).
- **SOAR Engine (Remediación Autónoma):** Orquestación completa que permite generar, validar y ejecutar scripts de solución automáticamente en contenedores o guiar a sysadmins mediante reportes técnicos detallados.
- **Identidad Unificada (OIDC):** Integración total con el ecosistema de identidad CASMARTS (Authentik) para un control de acceso centralizado y seguro.
- **Reportes Nivel "C-Suite":** Cada hallazgo incluye un resumen ejecutivo, análisis de impacto al negocio y pasos de resolución específicos para desarrolladores.

## 🛠️ Stack Tecnológico Evolucionado

| Componente | Herramientas | Propósito |
| :--- | :--- | :--- |
| **Inteligencia Artificial** | Google Gemini 1.5 Flash | Correlación de amenazas, generación de reportes y scripts. |
| **Runtime Security** | Falco, Wazuh | Monitoreo de comportamiento de procesos y logs en tiempo real. |
| **Escaneo de Activos** | Nuclei, Nmap | Detección proactiva de vulnerabilidades y mapeo de red. |
| **Seguridad de Código** | Trivy, Checkov | Auditoría de imágenes Docker e Infraestructura como Código (IaC). |
| **Frontend de Alto Rendimiento** | React, Vite, Tailwind CSS | Dashboard dinámico con visualización geográfica y SOAR. |
| **Backend & API** | FastAPI, Python 3.12 | Microservicios de alto rendimiento y orquestación de tareas. |
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

Accede a través del portal central: `https://arquitectura.casmart.internal/centinela/`

## 🧠 ¿Qué es una Plataforma SOAR? (In-Depth)

**SOAR** responde a las siglas **Security Orchestration, Automation, and Response**. Es una categoría de tecnologías que permite a las organizaciones recopilar datos sobre amenazas de seguridad y responder a incidentes sin intervención humana constante. En Centinela-AI, el motor SOAR actúa como el "brazo ejecutor" de la inteligencia artificial.

### Los Tres Pilares del SOAR en Centinela-AI:

1. **Orquestación (Orchestration):** 
   Es la capacidad de conectar herramientas de seguridad dispares (como Wazuh, Falco, Nmap y Docker) en un flujo de trabajo coherente. Centinela-AI orquesta estos sistemas para que trabajen como un solo organismo: una alerta en Falco puede disparar un escaneo de Nmap y una auditoría de base de datos simultáneamente.

2. **Automatización (Automation):** 
   Se refiere a la ejecución de "Playbooks" o tareas repetitivas sin intervención manual. Cuando Centinela detecta una vulnerabilidad conocida (ej. un puerto abierto innecesariamente), no solo avisa, sino que genera automáticamente el script de mitigación basado en el contexto real del activo.

3. **Respuesta (Response):** 
   Es la culminación del proceso. Centinela-AI no solo propone soluciones, sino que las ejecuta mediante el motor **Aura-Sentinel**. La respuesta puede ser desde el aislamiento de un contenedor sospechoso hasta el blindaje de red perimetral o la reconfiguración de un servidor de aplicaciones como WildFly.

### ¿Por qué es crítico para CASMARTS?
En un entorno de amenazas modernas, la velocidad es la diferencia entre una mitigación exitosa y una brecha de datos masiva. El SOAR de Centinela-AI reduce el **MTTR (Mean Time To Respond)** de horas a segundos, eliminando el error humano y asegurando que cada acción esté documentada por IA con trazabilidad forense completa.

---

## 🛡️ Orquestación de Remediación

Centinela-AI utiliza un enfoque de **Agente Híbrido**:
- **Contenedores Docker:** Remediación **Directa/Agentless** vía Docker SDK.
- **Servidores Externos/IPs:** Para habilitar la remediación automática, es mandatorio instalar el **Agente de Wazuh (Recomendado)** o configurar acceso SSH por llave pública para el usuario `centinela`. De lo contrario, las acciones serán de carácter **Manual Informativo**.

## 📚 Documentación

Para una guía detallada del sistema, consulte los siguientes documentos:

- 📖 **[Guía de Usuario Final](file:///home/ia/ecosistema-casmarts/centinela-ai/USER_GUIDE.md)**: Manual de operación del dashboard y gestión de incidentes.
- 🛠️ **[Documentación Técnica](file:///home/ia/ecosistema-casmarts/centinela-ai/TECHNICAL_DOCS.md)**: Detalles de arquitectura, stack tecnológico y manual de despliegue.

---
© 2026 CASMARTS - Sistema de Seguridad Nacional de Alta Fidelidad.

---
*Centinela-AI: La sinergia perfecta entre el talento humano y la inteligencia artificial para la protección del ecosistema CASMARTS.*
