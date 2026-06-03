---
name: database-liquibase-postgresql
description: "Use when creating or updating PostgreSQL migration SQL for Liquibase with idempotent DDL/DML, audit triggers, naming conventions, and review checklist. Triggers: liquibase, changelog sql, migration script, postgres migration, idempotent sql, audit_biu, audit_aiud."
---

# Database Liquibase PostgreSQL

## Purpose

Use this skill to create, review, or refactor PostgreSQL migration scripts executed by Liquibase.
The output must be idempotent, auditable, and easy to maintain.

## Language And Writing Rules

- Write comments and explanations in Spanish from Mexico.
- Keep a professional, clear, and direct tone.
- Do not use emojis.
- Do not use regional slang.
- Prefer ASCII characters in SQL comments and section separators.

## When This Skill Applies

Activate this skill when the request includes topics such as:

- Liquibase migration script
- New SQL changelog
- Idempotent PostgreSQL DDL/DML
- Audit triggers for new tables
- SQL style and naming standardization

## Output Contract For Liquibase Requests

When asked to generate a script, always provide:

1. Suggested filename using the required convention.
2. Full SQL script ready to paste.
3. Script sections in the mandatory order.
4. Short validation checklist for PR.

## Required Filename Convention

Use this naming format:

YYYYMMDD_NNNN_rpp_dos_punto_cero.sql

Rules:

- YYYYMMDD = script date
- NNNN = daily incremental counter starting at 0001
- Counter resets each day

## Mandatory Header Template

Use this header at the top of every script:

```sql
/*
 * by Im@rthe
 * Fecha: YYYY-MM-DD
 * Archivo: YYYYMMDD_NNNN_rpp_dos_punto_cero.sql
 *
 * Descripcion:
 * [Descripcion multilinea del objetivo del script]
 * [Incluir tablas, columnas y funcionalidades afectadas]
 *
 * Solicitado y aprobado por [Nombre Completo]
 *
 * Motor de Base de Datos: PostgreSQL
 * Version minima requerida: 16
 * Ambiente: desarrollo
 */
```

Authorized names for the header requester line:

- Gustavo Santiago Ruiz
- Jose Angel Lemus
- Rafael Aviles
- Yamil Martinez Mengual
- Daniel Antonio Miranda Cruz

## Mandatory Section Order

Every script must follow this order:

1. Table creation and columns
2. Primary key
3. Foreign keys
4. Comments (COMMENT ON statements)
5. Insert or update data (DML)
6. Audit triggers (BEFORE/AFTER triggers)
7. Technical notes and end marker

---

## Core SQL Rules

### Naming and style

- Use snake_case, lowercase identifiers.
- Use plural table names and singular column names.
- Avoid ambiguous abbreviations.
- Use explicit JOIN types.
- Avoid SELECT * in production queries.

### Prefijos obligatorios de objetos de base de datos

Aplicar los siguientes prefijos para cada tipo de objeto. El prefijo forma parte del nombre y no debe omitirse.

| Prefijo | Tipo de objeto                | Ejemplo                        |
|---------|-------------------------------|--------------------------------|
| `ct_`   | Tabla de catalogo             | `ct_tipos_documento`           |
| `dt_`   | Tabla de detalle              | `dt_partidas_factura`          |
| `vw_`   | Vista simple                  | `vw_clientes_activos`          |
| `mv_`   | Vista materializada           | `mv_resumen_ventas_mes`        |
| `fn_`   | Funcion de dominio            | `fn_calcular_iva`              |
| `trg_`  | Trigger de negocio            | `trg_validar_stock`            |
| `seq_`  | Secuencia                     | `seq_folio_pedido`             |
| `tp_`   | Tipo compuesto o enumerado    | `tp_estado_pedido`             |
| `idx_`  | Indice no primario            | `idx_pedidos_fecha_creacion`   |
| `pk_`   | Llave primaria                | `pk_pedidos`                   |
| `fk_`   | Llave foranea                 | `fk_pedidos_clientes`          |
| `uq_`   | Restriccion de unicidad       | `uq_productos_sku`             |
| `chk_`  | Restriccion de verificacion   | `chk_pedidos_monto_positivo`   |
| `tmp_`  | Tabla temporal de trabajo     | `tmp_carga_catalogo_inicial`   |

Reglas adicionales de prefijo:

- Las tablas transaccionales de dominio principal no llevan prefijo; solo usan nombre en plural: `pedidos`, `clientes`, `facturas`.
- Los prefijos `ct_` y `dt_` aplican a tablas dentro del schema `public` salvo indicacion contraria.
- Las vistas (`vw_`) y vistas materializadas (`mv_`) deben vivir en el schema donde corresponda al dominio consultado.
- Los triggers de auditoria (`audit_biu`, `audit_aiud`) conservan sus nombres canonicos sin prefijo `trg_` para distinguirlos de triggers de negocio.
- Nunca mezclar prefijos de tipo distinto en el mismo objeto.

### Schema conventions

Prefer explicit schema qualification in SQL:

- `util` for migration helpers.
- `public` (or corresponding app schema) for transactional domain.
- `auditoria` for audit functions and logs.
- `dw`, `stage`, `ref` as needed.

Always qualify objects, for example `public.personas` or `auditoria.log_auditoria`.

### Idempotent DDL

- Do not rely only on `IF NOT EXISTS` for complex objects.
- Verify constraints and indexes through `pg_catalog` (using helpers under `util.*`).
- For new tables, create empty table first and then add columns with `ALTER TABLE ADD COLUMN IF NOT EXISTS`.
- Create PK and FK inside DO blocks with existence checks, or use the `util.ensure_fk` helper.

### DML safety and idempotency

- Verify target table existence with `information_schema.tables` before running DML.
- Verify required columns with `information_schema.columns` before DML.
- Use `ON CONFLICT` with business unique keys, not surrogate ID.
- If no unique key exists, use `INSERT ... SELECT ... WHERE NOT EXISTS`.
- Use `RAISE NOTICE` or `RAISE WARNING` in guarded DO blocks to log script steps.

### Data types and modeling

- Prefer integer generated by identity or UUID depending on context.
- **UUID Generation Recommendation:** Use modern UUIDv7 or `gen_random_uuid()` (built-in) instead of depending on `public.uuid_generate_v4()` to avoid dependencies on external extensions like `uuid-ossp`.
- Use `timestamptz` for auditable events.
- Use `jsonb` for JSON payloads.
- Use `text` or `varchar(n)`, avoid `char(n)`.

### Derived and hash columns

- Use `GENERATED ALWAYS AS (...) STORED` only with immutable expressions.
- If normalization needs non-immutable functions, use a trigger.
- Add index for hash columns when used for dedupe/change detection.

### Audit requirements

For tables requiring audit, include audit fields and triggers.

Preferred audit columns:

- `ref` uuid
- `row_version` integer
- `fecha_creacion` timestamptz
- `fecha_modificacion` timestamptz
- `usuario_creacion` text
- `usuario_modificacion` text

Compatibility note:

- If project already uses legacy audit column names (for example `fccreacion`, `fcmodificacion`, `dsusuariocreacion` or `dsusuariomodifica`), preserve the existing convention and do not mix styles in the same table.

Trigger policy:

- `audit_biu` must always exist and be enabled (BEFORE INSERT OR UPDATE).
- `audit_aiud` must be created and disabled by default (`ALTER TABLE ... DISABLE TRIGGER`) unless business requirement explicitly asks to enable it.

### Documentation requirements in SQL

Always include `COMMENT ON` statements for objects touched:

- schema
- table
- column
- constraint
- index
- function
- trigger

---

## Canonical Script Skeleton

```sql
/* header */

-- ===========================
-- 1. Creacion de tabla y columnas
-- ===========================
CREATE TABLE IF NOT EXISTS public.nombre_tabla ();

ALTER TABLE public.nombre_tabla
    ADD COLUMN IF NOT EXISTS id bigint,
    ADD COLUMN IF NOT EXISTS codigo text;

-- ===========================
-- 2. Llave primaria
-- ===========================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.nombre_tabla'::regclass
          AND contype = 'p'
    ) THEN
        ALTER TABLE public.nombre_tabla
            ADD CONSTRAINT nombre_tabla_pk PRIMARY KEY (id);
    END IF;
END $$;

-- ===========================
-- 3. Llaves foraneas
-- ===========================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.nombre_tabla'::regclass
          AND contype = 'f'
          AND conname = 'fk_nombre_tabla_columna'
    ) THEN
        ALTER TABLE public.nombre_tabla
            ADD CONSTRAINT fk_nombre_tabla_columna
            FOREIGN KEY (columna_fk)
            REFERENCES public.tabla_padre(columna_padre);
    END IF;
END $$;

-- ===========================
-- 4. Comentarios
-- ===========================
COMMENT ON TABLE public.nombre_tabla IS 'Descripcion de la tabla.';
COMMENT ON COLUMN public.nombre_tabla.codigo IS 'Descripcion de la columna codigo.';

-- ===========================
-- 5. Insercion o actualizacion de datos
-- ===========================
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = 'nombre_tabla'
    ) THEN
        INSERT INTO public.nombre_tabla(id, codigo)
        VALUES (1, 'CODIGO_BASE')
        ON CONFLICT (codigo) DO NOTHING;

        RAISE NOTICE 'Datos procesados en public.nombre_tabla';
    ELSE
        RAISE WARNING 'Tabla public.nombre_tabla no existe';
    END IF;
END $$;

-- ===========================
-- 6. Triggers de auditoria
-- ===========================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgname = 'audit_biu'
          AND tgrelid = 'public.nombre_tabla'::regclass
    ) THEN
        CREATE TRIGGER audit_biu
        BEFORE INSERT OR UPDATE ON public.nombre_tabla
        FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_biu();
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgname = 'audit_aiud'
          AND tgrelid = 'public.nombre_tabla'::regclass
    ) THEN
        CREATE TRIGGER audit_aiud
        AFTER INSERT OR UPDATE OR DELETE ON public.nombre_tabla
        FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_aiud();

        ALTER TABLE public.nombre_tabla DISABLE TRIGGER audit_aiud;
    END IF;
END $$;

-- ===========================
-- 7. Comentarios tecnicos
-- ===========================
-- 1. Script idempotente para ejecucion multiple.
-- 2. Tabla vacia primero, columnas por ALTER TABLE.
-- 3. audit_biu siempre activo.
-- 4. audit_aiud creado y deshabilitado por defecto.

-- Fin del script
```

---

## Review Checklist For SQL PR

- [ ] `snake_case` and naming conventions are respected.
- [ ] Los objetos de base de datos usan el prefijo obligatorio segun su tipo (`ct_`, `dt_`, `vw_`, `mv_`, `fn_`, `trg_`, `seq_`, `tp_`, `idx_`, `pk_`, `fk_`, `uq_`, `chk_`, `tmp_`).
- [ ] Mandatory section order is respected.
- [ ] DDL is idempotent and uses `pg_catalog` validations where needed.
- [ ] `ON CONFLICT` uses business unique key, not surrogate ID.
- [ ] Explicit schema qualification is used everywhere (e.g. `public.`, `auditoria.`, `util.`).
- [ ] `audit_biu` exists and is enabled.
- [ ] `audit_aiud` exists and is disabled by default unless explicitly required.
- [ ] `COMMENT ON` exists for every object touched.
- [ ] Script keeps ASCII comments and no emojis.

## Safety Rules

- Never drop or truncate production tables unless explicitly requested and approved.
- Never remove audit triggers in standard migration tasks.
- When in doubt, prefer additive, backward-compatible migrations.
