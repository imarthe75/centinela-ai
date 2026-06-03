# 🗄️ Database & SQL Style Guidelines (PostgreSQL)

Estándares obligatorios para el modelado, escritura de consultas y migraciones de base de datos en el ecosistema, garantizando consistencia, trazabilidad e idempotencia estructural.

*Nota de Atribución: Estas pautas y convenciones se adaptan de la [Guía de Estilo SQL](file:///home/ia/ecosistema-casmarts/resident-agent-framework/gu%C3%ADa%20de%20estilo%20sql.md) (Licencia MIT).*

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

## 🕵️ 3. Auditoría Obligatoria (Campos y Triggers)

Toda tabla de aplicación (`app.*`) debe incluir los siguientes campos de auditoría para asegurar la trazabilidad y la concurrencia optimista:

1.  `id` → Clave primaria (PK). IDENTITY (autoincremental) o UUIDv7 (en PostgreSQL 18+).
2.  `ref` → Clave estable a lo largo del tiempo (UUIDv7/gen_random_uuid) para persistencia SCD Tipo 2.
3.  `row_version` → Control de concurrencia optimista (inicia en 1, incrementa en cada `UPDATE`).
4.  `fecha_creacion` / `fecha_modificacion` → Marca de tiempo con zona horaria (`timestamptz`).
5.  `usuario_creacion` / `usuario_modificacion` → Nombre del actor/proceso que ejecutó la acción.

### Triggers de Auditoría:
*   **`auditoria.auditoria_biu()`** (BEFORE INSERT/UPDATE): Trigger obligatorio para rellenar de forma automática fechas, usuario, UUID de referencia y autoincrementar la versión de fila.
*   **`auditoria.auditoria_aiud()`** (AFTER INSERT/UPDATE/DELETE): Registra el DML completo en un JSONB dentro de `auditoria.log_auditoria` con hashes criptográficos.

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
