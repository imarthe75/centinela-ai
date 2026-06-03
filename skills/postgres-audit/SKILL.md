---
name: postgres-audit-setup
description: Workflow for initializing and verifying the robust DML auditing schema in PostgreSQL databases.
---

# 🕵️ Skill: PostgreSQL DML Audit Setup

Este skill instruye al Agente sobre cómo inicializar, configurar y validar el esquema y los triggers de auditoría unificados en cualquier base de datos PostgreSQL del ecosistema.

## 📌 1. Cuándo Aplicar este Skill
*   Durante la inicialización de una nueva base de datos o proyecto.
*   Al crear o alterar tablas en el esquema de aplicación (`app`).
*   Cuando se requiera verificar la consistencia e integridad de las bitácoras de auditoría transaccional.

---

## 🛠️ 2. Procedimiento de Inicialización del Esquema

El agente debe seguir estos pasos para desplegar la estructura de auditoría:

### Paso A: Ejecutar DDL Base
Aplicar el archivo maestro de DDL [auditoria.sql](file:///home/ia/ecosistema-casmarts/resident-agent-framework/auditoria.sql) en el catalog objetivo. Este script se encarga de:
1.  Crear el esquema `auditoria`.
2.  Crear la tabla `auditoria.log_auditoria` con los índices necesarios para consultas rápidas de auditoría por tabla, fecha o UUID.
3.  Desplegar la función de trigger `auditoria.auditoria_biu()` (control de UUIDv7/gen_random_uuid, row_version, y marcas de tiempo).
4.  Desplegar la función de trigger `auditoria.auditoria_aiud()` (registro de cambios DML comprimidos en formato JSONB con hashes md5).

### Paso B: Validación de Campos en Tablas de Aplicación
Antes de adjuntar los triggers, el agente debe asegurar que la tabla transaccional (ej. `app.personas`) cuenta con la estructura requerida:
```sql
ALTER TABLE app.personas ADD COLUMN IF NOT EXISTS ref uuid UNIQUE DEFAULT gen_random_uuid();
ALTER TABLE app.personas ADD COLUMN IF NOT EXISTS row_version integer DEFAULT 1;
ALTER TABLE app.personas ADD COLUMN IF NOT EXISTS fccreacion timestamp DEFAULT localtimestamp;
ALTER TABLE app.personas ADD COLUMN IF NOT EXISTS fcmodificacion timestamp;
ALTER TABLE app.personas ADD COLUMN IF NOT EXISTS dsusuariocreacion varchar;
ALTER TABLE app.personas ADD COLUMN IF NOT EXISTS dsusuariomodifica varchar;
```

### Paso C: Registro Idempotente de Triggers
Para cada tabla en `app.*`, registrar los triggers correspondientes verificando previamente que no existan duplicados:

```sql
-- Trigger BEFORE (inicializa metadatos de auditoría)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_auditoria_biu_personas'
      AND tgrelid = 'app.personas'::regclass
  ) THEN
    EXECUTE 'CREATE TRIGGER trg_auditoria_biu_personas
             BEFORE INSERT OR UPDATE ON app.personas
             FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_biu()';
  END IF;
END$$ LANGUAGE plpgsql;

-- Trigger AFTER (guarda en log_auditoria)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_auditoria_aiud_personas'
      AND tgrelid = 'app.personas'::regclass
  ) THEN
    EXECUTE 'CREATE TRIGGER trg_auditoria_aiud_personas
             AFTER INSERT OR UPDATE OR DELETE ON app.personas
             FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_aiud()';
  END IF;
END$$ LANGUAGE plpgsql;
```

---

## 🧪 3. Verificación del Funcionamiento

Una vez configurado, el agente debe validar el flujo ejecutando sentencias de prueba y consultando la bitácora:

```sql
-- 1. Insertar fila de prueba
INSERT INTO app.personas (primer_nombre, primer_apellido) VALUES ('Prueba', 'Audit');

-- 2. Actualizar fila de prueba
UPDATE app.personas SET segundo_nombre = 'Conector' WHERE primer_nombre = 'Prueba';

-- 3. Consultar registros guardados en la bitácora
SELECT schemaname, tablename, username, dmlaction, hash_nuevo, recorddatetime
FROM auditoria.log_auditoria
ORDER BY recorddatetime DESC
LIMIT 5;
```
