# 📜 System Specifications (SPECS.md)

Este archivo actúa como la capa persistente de especificaciones de OpenSpec. Todo desarrollo, modificación o característica debe estar respaldada por un contrato definido en este documento antes de escribir código.

---

## 📋 Especificaciones Activas

### [EJEMPLO-001] Integración de Memoria Dual (Valkey + Postgres)
- **Estado:** `APROBADO`
- **Requisitos:**
  - El backend debe conectarse a Valkey en el puerto `6379` para almacenamiento de caché semántica a corto plazo.
  - El backend debe conectarse a PostgreSQL para persistencia de largo plazo utilizando `pgvector`.
- **Restricciones:**
  - Las llaves primarias de las tablas deben ser de tipo `uuid` (UUIDv7 preferido).
- **Criterios de Aceptación:**
  - Tiempo de respuesta de caché menor a 10ms.
- **Casos de Borde:**
  - Degradación elegante si Valkey o Postgres no están disponibles.
