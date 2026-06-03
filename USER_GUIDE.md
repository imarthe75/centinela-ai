# 📖 Guía de Usuario Final: Centinela-AI (XDR)

Bienvenido a **Centinela-AI**, la plataforma de detección y respuesta extendida (XDR) de alto rendimiento para el ecosistema CASMARTS.

## 1. Alcance y Uso Responsable
**Centinela-AI es una herramienta estrictamente DEFENSIVA.** Su propósito es proteger el ecosistema mediante detección y respuesta (XDR). 
- **Prohibido:** No utilice esta plataforma para intentar realizar ataques, pruebas de penetración o escaneos no autorizados.
- **Uso Correcto:** Monitoreo de activos registrados y aprobación de parches de seguridad.

## 2. Inicio de Sesión
Acceda con sus credenciales institucionales de Authentik (ej. `israelm`) a través de la URL:
`https://centinela.casmart.internal/`

## 3. El Dashboard Principal
Al entrar, verá un resumen de la postura de seguridad nacional en tiempo real:
- **Distribución de Riesgo:** Gráfico circular interactivo de amenazas clasificadas por severidad.
- **Alertas en Caliente (Toasts):** Notificaciones en tiempo real vía WebSockets que aparecen en la esquina inferior derecha.
- **Retorno de Inversión (SOAR ROI):** Comparador dinámico del tiempo medio de respuesta entre la mitigación manual (~48 horas de promedio nacional) vs. la remediación con la IA en segundos.
- **Exportación de Reportes PDF:** Botón "Reporte PDF" en el encabezado para descargar instantáneamente análisis ejecutivos del sistema (motor WeasyPrint, actualizado 2026-06-02).

## 4. Gestión de Inventario
En la sección **"Inventario de Activos"**, puede:
- Ver todos los activos (Docker, K8s, IPs, Servidores Linux & Windows).
- **Registrar Nuevo Activo:** Haga clic en "+" para agregar infraestructura. Si el activo es un equipo Linux o Windows externo, ingrese las credenciales con privilegios elevados (`sudo` / `administrator`). El motor orquestará a **Ansible** para conectarse al host e instalar y registrar automáticamente el agente de Wazuh en el sistema.

## 5. Acciones Directas sobre el Agente de Wazuh
Para los activos que ya cuentan con un agente Wazuh instalado, ahora puede realizar las siguientes operaciones directamente desde su vista de detalles:
- **Reiniciar Agente**: Solicita un reinicio remoto del servicio para aplicar políticas.
- **Ejecutar Escaneo Activo**: Inicia una auditoría Syscheck/Vulnerability-Detector de manera inmediata.
- **Ver Logs**: Despliega los últimos registros forenses del agente en tiempo real.

## 6. Investigación de Amenazas (AI Investigate)
En la tabla de **Alertas en Tiempo Real**, cada entrada tiene un botón **"Investigar"**.
- Al hacer clic, se abre el **Motor de Investigación IA** (Gemini 1.5 Flash).
- El sistema le entregará un reporte detallado con:
    - **Contexto Técnico:** Causa raíz.
    - **Riesgo:** Impacto a la operación y seguridad.
    - **Acción Inmediata:** Plan de mitigación.

## 7. Integración de Tickets SOAR (Ticketing)
Desde la barra lateral de remediación, ahora puede interactuar con plataformas de tickets de desarrollo:
- **Crear Ticket en Gitea / Redmine**: Al hacer clic sobre una alerta de remediación sugerida, el sistema generará automáticamente un caso o reporte técnico detallado en el repositorio Gitea o gestor Redmine institucional asignado, ayudando a los sysadmins a dar seguimiento centralizado.

## 8. Notas de Actualización

### 2026-06-02: Mejora en Generación de Reportes PDF

✅ **Motor de Reportes Actualizado**

Se realizó una migración de Carbone.io a **WeasyPrint** para la generación de PDFs. Esto significa:

- **Reportes más rápidos:** In-process rendering en lugar de HTTP calls
- **Mayor confiabilidad:** PDFs válidos y completos sin corrupción
- **Mejor estilo:** CSS completo respetado en los estilos de reportes

Los reportes que puede descargar ahora son:
- Reporte Ejecutivo (resumen de vulnerabilidades del ecosistema)
- Reporte de Activo (detalles de seguridad de un servidor/contenedor)
- Reporte de Vulnerabilidad (análisis detallado de una amenaza específica)

---
*Para soporte técnico, contacte al administrador de seguridad del ecosistema CASMARTS.*

