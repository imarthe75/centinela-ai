# 🌌 Centinela-CAI: CONTEXT.md (Propósito Técnico)

## 🏢 Arquitectura "Cognitive Bridge"
Centinela-CAI opera como el cerebro de seguridad del ecosistema. Mientras que los sensores (Wazuh, Netdata) viven en el Core, la lógica de correlación y toma de decisiones reside en este satélite.

## 🧩 Integraciones Clave
- **Wazuh:** Recepción de alertas de intrusión vía Valkey.
- **Trivy:** Escaneo de vulnerabilidades en imágenes y sistemas de archivos.
- **PostgreSQL (casmarts_security):** Memoria estructurada de inventario y vulnerabilidades.
- **pgvector:** Búsqueda semántica de patrones de ataque y lecciones aprendidas.
- **Valkey (AMS):** Caché operativa y canal de alertas `centinela:alerts`.
- **Vault:** Gestión de tokens de acceso y llaves de cifrado.
- **SeaweedFS:** Almacenamiento forense y repositorio de reportes `/storage/security/reports/`.
