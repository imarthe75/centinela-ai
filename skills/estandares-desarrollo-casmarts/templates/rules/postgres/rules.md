# Reglas de PostgreSQL

Obligatorias en toda base de datos de un proyecto. Fuente de la auditoría: Estándar de auditoría org v2026.10.14
(skill `postgres-audit`, referencia completa en `references/ESTANDAR_AUDITORIA_org_v1.0.md`). Estilo y migraciones: skill
`database-liquibase-postgresql` y `rules/common/database-style.md`. Lo que aquí no se cumple, Centinela lo reporta (reglas `SQL-*`).

## 1. Versión y herramientas
1. PostgreSQL **18+** (se usa `uuidv7()` nativo). Cliente `psql` 13+ (recomendado 18).
2. El esquema cambia **solo por migraciones versionadas** (Liquibase con changesets SQL; Alembic en servicios Python). Nunca a mano en un
   ambiente compartido, nunca `spring.jpa.hibernate.ddl-auto` distinto de `none`/`validate` (`SPRING-JPA-DDL-AUTO-SCHEMA-CHANGE`).
3. Migraciones **idempotentes y equivalentes**: no basta `IF NOT EXISTS`; se verifica tipo, nulabilidad, valor por omisión, llaves e
   índices con las funciones `util.ensure_*`. Un changeset aplicado nunca se edita: se corrige con otro.

## 2. Tipos y llaves
| Uso | Tipo obligatorio | Prohibido | Regla de Centinela |
|---|---|---|---|
| Llave primaria | `uuid DEFAULT uuidv7()` | `serial`, `bigserial`, `IDENTITY`, enteros | `SQL-PK-NOT-UUID` |
| Fecha y hora | `timestamptz` | `timestamp` sin zona | `SQL-TIMESTAMP-WITHOUT-TIMEZONE` |
| Documento | `jsonb` | `json` | `SQL-JSON-NOT-JSONB` |
| Montos | `numeric(p,s)` | `float`, `real`, `double precision`, `money` | `SQL-FLOAT-FOR-MONEY` |
| Texto | `text` o `varchar(n)` con límite de negocio real | — | — |
- Toda tabla tiene llave primaria (`SQL-TABLE-WITHOUT-PRIMARY-KEY`); vale declararla en `CREATE TABLE` o con `ALTER TABLE ... ADD CONSTRAINT`.
- Llaves foráneas declaradas, con índice en la columna que referencia; `ON DELETE` explícito (por omisión `RESTRICT`).
- Restricciones de negocio en la base: `NOT NULL`, `UNIQUE` (la unicidad no se confía solo a una validación en la aplicación: dos peticiones
  simultáneas la saltan), `CHECK`.

## 3. Auditoría (Estándar org)
1. **Columnas canónicas** en toda tabla de negocio: `id`, `ref`, `activo`, `borrado`, `row_version`, `fecha_creacion`,
   `fecha_modificacion`, `usuario_creacion`, `usuario_modificacion` (`SQL-TABLE-WITHOUT-AUDIT-COLUMNS`).
2. **Triggers** en cada tabla, asignados con `SELECT auditoria.asignar_triggers('esquema.tabla');` dentro del changeset que la crea
   (idempotente; las tablas que crea `migrator` los reciben solos por `et_grant_on_create`):
   | Trigger | Estado por omisión | Qué hace |
   |---|---|---|
   | `audit_biu` (BEFORE INSERT/UPDATE) | **habilitado; nunca se desactiva** | `id`/`ref` con `uuidv7()`, `row_version`, fechas, usuarios; `id`, `ref` y datos de creación inmutables |
   | `audit_aiud` (AFTER INSERT/UPDATE/DELETE) | deshabilitado | bitácora fila por fila |
   | `audit_truncate` (BEFORE TRUNCATE) | deshabilitado | registra el TRUNCATE |
3. La bitácora de una tabla se activa con `SELECT auditoria.habilitar_auditoria('esquema.tabla');` cuando el negocio lo exige (datos
   personales, dinero, permisos). Una bitácora vacía en una tabla sin `audit_aiud` no es una falla.
4. **Bloqueo optimista en la base**: `SELECT auditoria.bloqueo_optimista('esquema.tabla', true);` rechaza un `row_version` que no sea el
   vigente ni vigente+1 con SQLSTATE `40001`; la aplicación lo traduce a **HTTP 409**. JPA: `@Version` sobre `row_version`.
5. **Borrado lógico** con `borrado = true` (y `activo = false`); los listados filtran por esas columnas. El borrado físico es excepción
   documentada.
6. Nadie escribe en `auditoria.*`; la bitácora no admite UPDATE/DELETE/TRUNCATE. Verificación: `auditoria.fn_verificar_cadena()` (0 filas =
   íntegra) y `auditoria.reporte_cobertura()` (estado por tabla).
7. Bases con convención legada (`fccreacion`, `dsusuariocreacion`, `boactivo`/`boborrado`): el estándar las marca como «ajena»; se respeta su
   convención y no se mezclan estilos en la misma base.

## 4. Conexión desde la aplicación
1. Al inicio de cada transacción de escritura: `SELECT set_config('app.current_user', :usuario, true);` (alcance de transacción; obligatorio
   con PgBouncer en modo transacción). Sin esto la bitácora registra el usuario técnico.
2. La aplicación se conecta con `app_web_user` (o el rol de DML del proyecto); nunca con `migrator`, `postgres` ni un superusuario.
3. Roles: `migrator` (dueño del esquema, usuario de migraciones), `auditor` (lectura de bitácora), rol de DML de la aplicación. Credenciales
   solo fuera del repositorio (variables de entorno o gestor de secretos).
4. Consultas siempre parametrizadas; nunca concatenar entrada en SQL (tampoco en `ORDER BY`: lista blanca de columnas).
5. Pool con tamaño y tiempo de espera explícitos; `statement_timeout` acotado para la aplicación.

## 5. Nombres y organización
- `snake_case` en minúsculas sin comillas; tablas en plural, columnas en singular.
- Esquemas por dominio: `app` (transaccional), `ref`/`cat` (catálogos), `auditoria`, `util`, `stage`, `dw`. Nada de negocio en `public`.
- Índices `ix_<tabla>_<columnas>`, únicos `ux_...`, llaves foráneas `fk_<tabla>_<referencia>`, checks `ck_...`.

## 6. Documentación y rendimiento
- `COMMENT ON` en cada esquema, tabla, columna, función y vista nueva, en el mismo changeset (`rules/common/documentation.md`).
- Índice para cada columna de búsqueda o filtro frecuente y para cada llave foránea; revisar con `EXPLAIN (ANALYZE, BUFFERS)` las consultas
  de listados antes de entregar.
- Búsqueda sin acentos ni mayúsculas con `unaccent()` + `pg_trgm` sobre columnas generadas `STORED`.
- Paginación por llave (keyset) en tablas grandes; `OFFSET` solo en tablas chicas.

## 7. Pruebas
- Las migraciones y la auditoría se prueban contra una base **desechable** (Testcontainers con PostgreSQL 18), nunca contra un ambiente
  compartido ni con H2.
- Prueba mínima: alta y edición de una fila → `row_version` 1 → 2, usuario correcto en las columnas de auditoría; con `audit_aiud`
  habilitado, dos registros en la bitácora y `fn_verificar_cadena()` vacía; conflicto de versión → 409.
