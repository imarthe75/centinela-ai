# Guía de Instalación del Agente Wazuh - CASMARTS 2026

Para permitir que **Centinela-AI** ejecute acciones de remediación automática y monitoreo en tiempo real en activos de tipo `SERVER`, `IP` y `DATABASE`, es obligatorio instalar el agente Wazuh.

## 🐧 Instalación Universal y Agnóstica

El sistema **Centinela-AI** utiliza la detección automática de distribución. Para instalaciones manuales, utiliza el método correspondiente a tu sistema operativo.

### 🔍 Detección Automática de Distro
Puedes verificar tu tipo de sistema con el siguiente comando antes de instalar:
```bash
cat /etc/os-release | grep -E "^ID="
```

### 📦 Comandos por Familia de Distribución

#### 1. Familia Debian (Ubuntu, Debian, Kali, Mint)
```bash
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x_amd64.deb
sudo dpkg -i wazuh-agent*.deb
```

#### 2. Familia RHEL (CentOS, RHEL, Rocky, AlmaLinux, Amazon Linux, Fedora)
```bash
curl -sO https://packages.wazuh.com/4.x/yum/wazuh-agent-4.x-1.x86_64.rpm
sudo yum localinstall wazuh-agent*.rpm
```

#### 3. Familia Alpine (Contenedores ligeros)
```bash
# Nota: Alpine requiere paquetes específicos o instalación vía script
curl -sO https://packages.wazuh.com/4.x/alpine/v3.12/main/x86_64/wazuh-agent-4.x.apk
apk add --allow-untrusted wazuh-agent*.apk
```

## ⚙️ Configuración del Manager (Paso Crítico)
Independientemente de la distribución, debes configurar la IP del Manager en `/var/ossec/etc/ossec.conf`:
```xml
<client>
  <server>
    <address>TU_IP_DEL_MANAGER</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

## 🚀 Activación del Servicio
```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

## 🛡️ Notas sobre Scripts de Remediación
Los scripts generados por la IA de Centinela están diseñados para detectar automáticamente la distribución. Si un script requiere instalar paquetes, usará el gestor correspondiente (`apt`, `yum` o `dnf`).
