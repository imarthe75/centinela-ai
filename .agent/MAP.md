# 🗺️ Centinela-CAI: MAP.md (Arquitectura de Seguridad)

## 🏗️ Estructura de Servicios
- **Satellite:** `centinela-cai` (Reasoning Engine).
- **Core Sensors:**
  - `casmarts-core-wazuh` (Próximamente).
  - `casmarts-core-netdata` (Métricas de sistema).
  - `casmarts-core-pghero` (Auditoría de DB).

## 🗄️ Flujo de Datos
1. **Detección:** Sensor -> Valkey (`centinela:alerts`) -> Centinela-CAI.
2. **Análisis:** Centinela-CAI -> Vertex AI -> `vulnerability_log`.
3. **Remediación:** `remediation_history` -> Script Generation -> User Approval -> Execution.
4. **Archivo:** Report Generation -> OpenSign -> SeaweedFS.

## 📂 Mapeo de Directorios (Host)
- `./data/centinela-cai/remediation/`: Scripts de corrección generados.
- `./data/centinela-cai/logs/`: Logs de auditoría local.
- `./.agent/STATE.md`: Estado actual de la defensa.
