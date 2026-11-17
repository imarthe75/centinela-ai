# 🗄️ Database & SQL Style Guidelines (PostgreSQL)

Estándares obligatorios para el modelado, escritura de consultas y migraciones de base de datos en el ecosistema, garantizando consistencia, trazabilidad e idempotencia estructural.

Detalle completo: skill `database-liquibase-postgresql` (`references/guia-de-estilo-sql.md`); auditoría: skill `postgres-audit`.

---

## 📌 1. Convenciones de Nombres

*   **Minúsculas y Snake Case:** Todos los identificadores (tablas, columnas, índices, vistas, funciones) deben estar en `snake_case` y minúsculas. Evita el uso de comillas dobles para forzar mayúsculas.
*   **Tablas en Plural:** Nombres de tablas siempre en plural (ej. `personas`, `ordenes`, `sesiones`).
*   **Columnas en Singular:** Nombres de columnas en singular (ej. `fecha_nacimiento`, `correo_electronico`).
*   **Alias Consistentes:** Usa alias cortos y claros para las tablas en las consultas (ej. `p` para `personas`, `o` para `ordenes`). Evita alias de una sola letra si son ambiguos.

---

## 🗄️ 2. Estructuración por Esquemas (Dominios)

El modelo de base de datos se organiza estrictamente en esquemas para separar responsabilidades:

*   `app` → Dominio transaccional de la aplicación.
*   `ref` → Catálogos maestros y referencias globales.
*   `auditoria` (o `audit`) → Bitácoras y tablas de auditoría.
*   `util` → Funciones de utilería y helpers de idempotencia DDL.
*   `stage` → Tablas temporales de aterrizaje/ETL.
*   `dw` → Estructuras analíticas y Data Warehouse.

---

## 🕵️ 3. Auditoría Obligatoria (Estándar org)

Las reglas completas de PostgreSQL (tipos, llaves, auditoría, conexión, roles) están en [`rules/postgres/rules.md`](../postgres/rules.md);
la fuente es el Estándar de auditoría org (skill `postgres-audit`). Resumen:

1.  Columnas canónicas en toda tabla de negocio: `id` (`uuid DEFAULT uuidv7()`), `ref`, `activo`, `borrado`, `row_version`,
    `fecha_creacion`/`fecha_modificacion` (`timestamptz`), `usuario_creacion`/`usuario_modificacion`.
2.  Triggers con `SELECT auditoria.asignar_triggers('esquema.tabla');` en el changeset de la tabla: `audit_biu` **habilitado siempre**;
    `audit_aiud` y `audit_truncate` deshabilitados hasta `SELECT auditoria.habilitar_auditoria('esquema.tabla');`.
3.  Bloqueo optimista: `auditoria.bloqueo_optimista(tabla, true)` → SQLSTATE `40001` → HTTP 409 (`@Version` en JPA).
4.  La aplicación fija `set_config('app.current_user', usuario, true)` en cada transacción de escritura y se conecta con su rol de DML,
    nunca con `migrator` ni superusuario.

---

## ⚙️ 4. Idempotencia Real y Equivalencia Estructural

Las migraciones de DDL no deben limitarse a sentencias básicas como `CREATE TABLE IF NOT EXISTS`. Deben garantizar la equivalencia de tipos de datos, restricciones e índices.
Se deben utilizar las funciones utilitarias del esquema `util` para verificar la existencia y compatibilidad antes de alterar objetos:

*   `util.ensure_column(schema, table, column, type, nullable, default)`
*   `util.ensure_fk(schema, table, constraint, columns, ref_schema, ref_table, ref_columns, not_valid)`
*   `util.ensure_index_for_columns(schema, table, index_name, columns)`
*   `util.ensure_generated_column(schema, table, column, type, expression)`

---

## 🌐 5. Internacionalización (I18N) y Búsquedas

*   **Codificación:** Base de datos en `UTF8` y colación adecuada (ej. `es_MX.utf8`).
*   **Búsquedas Insensibles:** Utilizar `unaccent()` y trigramas (`pg_trgm`) sobre columnas generadas persistidas (`STORED`) para habilitar búsquedas rápidas que ignoren acentos y mayúsculas.

---

## 🗂️ 6. Documentación Obligatoria

Toda creación o modificación de objetos de base de datos (tablas, columnas, esquemas) debe acompañarse de su comentario correspondiente en PostgreSQL mediante la sentencia `COMMENT ON`:
```sql
COMMENT ON TABLE app.personas IS 'Tabla maestra de datos generales de personas físicas.';
COMMENT ON COLUMN app.personas.ref IS 'UUIDv7 estable para sincronización e integraciones externas.';
```
