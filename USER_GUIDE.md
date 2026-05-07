# 📖 Guía de Usuario Final: Centinela-AI (XDR)

Bienvenido a **Centinela-AI**, la plataforma de detección y respuesta extendida (XDR) de alto rendimiento para el ecosistema CASMARTS.

## 1. Alcance y Uso Responsable
**Centinela-AI es una herramienta estrictamente DEFENSIVA.** Su propósito es proteger el ecosistema mediante detección y respuesta (XDR). 
- **Prohibido:** No utilice esta plataforma para intentar realizar ataques, pruebas de penetración o escaneos no autorizados.
- **Uso Correcto:** Monitoreo de activos registrados y aprobación de parches de seguridad.

## 2. Inicio de Sesión
Acceda con sus credenciales institucionales a través de la URL:
`https://arquitectura.casmart.internal/centinela/`

## 2. El Dashboard Principal
Al entrar, verá un resumen de la postura de seguridad nacional:
- **Distribución de Riesgo:** Gráfico circular que muestra la severidad de las amenazas actuales.
- **Salud del Sistema (Health):** Estado de los motores de IA y latencia de respuesta.
- **Mapa Regional:** Ubicación geográfica de los activos monitoreados.

## 3. Gestión de Inventario
En la sección **"Inventario de Activos"**, puede:
- Ver todos los activos (Docker, K8s, IPs, Servidores, etc.).
- **Registrar Nuevo Activo:** Haga clic en el botón "+" para añadir un nuevo elemento. Seleccione el tipo de activo y su endpoint.
- Al añadir un activo, el sistema iniciará un escaneo automático de vulnerabilidades.

## 4. Investigación de Amenazas (AI Investigate)
En la tabla de **Alertas en Tiempo Real**, cada entrada tiene un botón **"Investigar"**.
- Al hacer clic, se abre el **Motor de Investigación IA**.
- El sistema consultará a Gemini (Primario) o Groq (Respaldo) para entregarte un reporte ejecutivo que incluye:
    - **Contexto Técnico:** ¿Qué está pasando exactamente?
    - **Riesgo:** El impacto real para la continuidad del negocio.
    - **Acción Inmediata:** 3 pasos claros para mitigar el problema.

## 5. Remediación Asistida (SOAR)
En la pestaña **"Remediación"**, encontrará los reportes detallados con scripts listos para ejecutar.
- **Auto-Parcheo:** Si el activo es un contenedor Docker, verá un botón para aplicar la solución automáticamente.
- **Manual:** Para activos externos (Servidores/IPs), deberá seguir las instrucciones manuales.
- **IMPORTANTE:** Para que la IA pueda parchear automáticamente servidores externos, asegúrese de que tengan instalado el **Agente de Wazuh**.

## 6. Instalación del Agente Wazuh (Ubuntu/Debian)
Para habilitar la remediación automática (SOAR) en servidores virtuales o físicos (no contenedores), es indispensable instalar el Agente de Wazuh. Siga estos pasos en el servidor destino:

1. **Descargar e Instalar el Agente:**
   ```bash
   curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x_amd64.deb
   sudo WAZUH_MANAGER="arquitectura.casmart.internal" dpkg -i wazuh-agent*.deb
   ```

2. **Iniciar el Servicio:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable wazuh-agent
   sudo systemctl start wazuh-agent
   ```

3. **Verificación:**
   Una vez iniciado, Centinela-AI detectará automáticamente el servidor en el Inventario y comenzará a enviar telemetría para análisis y remediación.

---
*Para soporte técnico, contacte al administrador de seguridad del ecosistema CASMARTS.*
