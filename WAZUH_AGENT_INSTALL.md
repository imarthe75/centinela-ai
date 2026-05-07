# Guía de Instalación del Agente Wazuh - CASMARTS 2026

Para permitir que **Centinela-AI** ejecute acciones de remediación automática y monitoreo en tiempo real en activos de tipo `SERVER`, `IP` y `DATABASE`, es obligatorio instalar el agente Wazuh.

## 🐧 Instalación Recomendada (Vía Repositorio)

Este método es el preferido para asegurar actualizaciones automáticas y estabilidad en la infraestructura de **Casmarts Core**.

### 1. Configurar Llaves y Repositorio
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
```

### 2. Instalación del Agente
```bash
sudo apt-get install wazuh-agent
```

## ⚙️ Configuración del Manager (Paso Crítico)
Es obligatorio apuntar el agente a la IP del Manager de **IDP Smart**. Edita el archivo de configuración:
`sudo nano /var/ossec/etc/ossec.conf`

**Modifica la sección `<client>` con los siguientes valores específicos:**
```xml
<client>
  <server>
    <address>10.4.3.28</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

## 🚀 Activación del Servicio
```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent
```

## 🛡️ Pruebas de Verificación de Conectividad

Para asegurar que el agente está reportando correctamente a **Centinela-AI**, ejecuta las siguientes pruebas de diagnóstico:

### A. Verificación de Logs (Estado de Conexión)
Busca la confirmación de enlace en los registros locales del sistema:
```bash
sudo grep -i "connected" /var/ossec/logs/ossec.log
```
> **Resultado esperado:** Si la respuesta contiene `Wazuh Agent connected to '10.4.3.28'`, la comunicación es exitosa.

### B. Prueba de Comunicación de Red
Verifica que el puerto de comunicación no esté bloqueado por firewalls intermedios:
```bash
nc -zv 10.4.3.28 1514
```

### C. Consulta de Versión y Estado del Binario
Confirma que el agente está operativo y verifica su versión actual:
```bash
/var/ossec/bin/wazuh-control info
sudo systemctl status wazuh-agent --no-pager
```

---
**Notas Adicionales:** * Los scripts de **Centinela-AI** detectan automáticamente la distribución y utilizarán el gestor correspondiente (`apt`, `yum` o `dnf`) para tareas de remediación.
* Si realizas cambios en el archivo `ossec.conf`, siempre debes reiniciar el servicio para aplicar la nueva configuración.