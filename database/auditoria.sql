-- =====================================================================================
-- ESTANDAR DE AUDITORIA — instalador unico e inteligente (version consolidada 2026-10-14)
-- Bitacora v2 (solo insercion, particionada por mes, hash SHA-256 encadenado), audit_aiud v2.2, audit_biu v2.1,
-- registro de DDL y ancla de control.
-- =====================================================================================
-- VERSION MINIMA SOPORTADA: PostgreSQL 18 (usa uuidv7() nativo). El script lo verifica y se detiene si es menor.
-- Cliente psql: 13 o superior (usa \if y \gset); se recomienda el de la version 18.
--
-- COMO FUNCIONA: antes de cambiar nada, el script DIAGNOSTICA la base y elige solo la accion:
--   nueva     No hay auditoria. Instala todo desde cero.
--   vigente   Ya esta esta version completa (mismas funciones, event triggers y control). No cambia nada.
--   reparar   Esta version, pero con piezas faltantes o modificadas (funciones, event triggers, control o
--             propiedad). Restituye las piezas. NO toca los datos de la bitacora.
--   anterior  Una version previa de este mismo estandar (bitacora sin particionar, sin columnas de contexto,
--             instalacion incompleta...). La actualiza conservando todos los registros; si el numero de
--             registros no coincide al terminar, revierte todo.
--   ajena     Hay una auditoria que NO es de este estandar (otra estructura de bitacora, objetos desconocidos en
--             el esquema auditoria, event triggers de otro origen con los mismos nombres). No se modifica nada:
--             el script se detiene y explica que encontro. Con  -v ajena=renombrar  conserva lo ajeno
--             renombrandolo (auditoria_previa_<fecha>) e instala el estandar de cero.
--
-- USO (como superusuario, en la base destino):
--     psql -d <base> -v ON_ERROR_STOP=1 -f auditoria_estandar_completo.sql
--   Opciones:  -v solo_diagnostico=si   muestra el diagnostico y la accion que tomaria, sin cambiar nada
--              -v ajena=renombrar       (ver arriba; por defecto: abortar)
--
-- Todo va en una transaccion: o termina completo o no cambia nada. Roles que usa: migrator (dueno del esquema y
-- de las migraciones), auditor (lectura de la bitacora), role_dev_dml y app_web_user. Los que falten se crean
-- SIN LOGIN y el script avisa: asignales LOGIN y contrasena. Si tu proyecto usa otros nombres, reemplazalos en
-- TODO el archivo antes de ejecutarlo.
-- =====================================================================================
\set ON_ERROR_STOP on

\if :{?ajena}
\else
    \set ajena abortar
\endif
\if :{?solo_diagnostico}
\else
    \set solo_diagnostico no
\endif

SELECT (:'ajena' NOT IN ('abortar', 'renombrar')) AS opcion_invalida \gset
\if :opcion_invalida
    \echo 'ERROR: -v ajena debe ser abortar o renombrar'
    \q
\endif

BEGIN;
-- Los event triggers (de cualquier origen) se desactivan solo dentro de esta transaccion: el instalador no debe disparar
-- los de permisos ni de registro de DDL mientras crea o reemplaza objetos. Los del estandar se recrean al final.
SET LOCAL event_triggers = off;

-- 1. PREFLIGHT ---------------------------------------------------------------------
DO $$
BEGIN
    IF current_setting('server_version_num')::int < 180000 THEN
        RAISE EXCEPTION 'Se requiere PostgreSQL 18 o superior (version actual: %)', current_setting('server_version');
    END IF;
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'Ejecuta este script como superusuario (CREATE EVENT TRIGGER lo exige)';
    END IF;
END $$;

-- 2. HUELLA DE LA VERSION VIGENTE (funciones y event triggers de este estandar) ------
CREATE TEMP TABLE _aud_esperado ON COMMIT DROP AS
SELECT * FROM (VALUES
    ('auditoria.asignar_biu(text)', '9bfe11e2dd47403fbddbc6fe7f1b3d9f', 'void'),
    ('auditoria.asignar_triggers(text)', '6865210a69e7c07a05d0b6ac706eb1e4', 'void'),
    ('auditoria.asignar_trigger(text)', '0c15753a34858088418ab04c735c1bd8', 'void'),
    ('auditoria.auditoria_aiud()', '81556ab1415c49692f727fc3867bdd92', 'trigger'),
    ('auditoria.auditoria_biu()', '5970adb288f36588e99d555a7b509b94', 'trigger'),
    ('auditoria.auditoria_truncate()', 'd7e12a86ba29dea6a9187de528e69c5c', 'trigger'),
    ('auditoria.bloqueo_optimista(text,boolean)', '48b22433b6f0f37be5e7794f2944e296', 'void'),
    ('auditoria_control.fn_inmutable()', '9afe30272f1a62b80353e44b83d5d9fc', 'trigger'),
    ('auditoria_control.fn_verificar_y_anclar()', '97fb001dfb6a7c2525fd67623bc2e289', 'text'),
    ('auditoria.deshabilitar_auditoria(text)', '99e6ecbe577aca9870013cc6dda0489b', 'void'),
    ('auditoria.et_fn_grant_on_create()', '4e744abec8750f10af01b2be7a0d9497', 'event_trigger'),
    ('auditoria.et_fn_registrar_ddl()', '3eb6f9cca80c1e25536f348eba93e8d4', 'event_trigger'),
    ('auditoria.et_fn_registrar_drop()', '05d47fe0ac81cb547bbff6d5aafc4063', 'event_trigger'),
    ('auditoria.fn_bitacora_disponible()', 'cdf7d4eaa6dcbf6d55482bda541459ac', 'boolean'),
    ('auditoria.fn_bitacora_inmutable()', '8b8fae4ae26f072386600b688d0da54c', 'trigger'),
    ('auditoria.fn_crear_particiones(integer,date)', '4a5c146f6e00eb7bd9454f5542302a31', 'integer'),
    ('auditoria.fn_monitorear_slots()', 'e0d34a3f38f0f225fda99f7045c5bd20', 'TABLE(slot_name text, active boolean, wal_status text, lag_bytes numeric, lag_mb numeric)'),
    ('auditoria.fn_reconciliar_tabla(text,text)', '0443f73e62d1a47574969d2ed14fb5f1', 'TABLE(uuid_ref uuid, tipo_desajuste text, datos_tabla jsonb, datos_log jsonb)'),
    ('auditoria.fn_registrar_evento(text,text,text,jsonb,jsonb,jsonb,text,uuid)', '093c7f0e44a1fd507d065364e8bfa28f', 'void'),
    ('auditoria.fn_restringir_bitacora(regclass)', '29367991405f82131a5c71fdf037ebe1', 'void'),
    ('auditoria.fn_verificar_cadena()', '1b54b262d5acfbb62576c5b8c32d88b5', 'TABLE(registro_alterado bigint, hash_esperado text, hash_encontrado text)'),
    ('auditoria.habilitar_auditoria(text)', 'a6791956c9c0c963d444f7606848c92b', 'void'),
    ('auditoria.reporte_cobertura()', '4f474154a45edf92b8bc13d0a3962aca', 'TABLE(esquema text, tabla text, tiene_ref boolean, tiene_rv boolean, tiene_biu boolean, tiene_aiud boolean, elegible boolean, estado text)')
) e (fn, huella, resultado);

CREATE TEMP TABLE _aud_esperado_evt ON COMMIT DROP AS
SELECT * FROM (VALUES
    ('et_auditoria_ddl', 'et_auditoria_ddl|ddl_command_end||auditoria.et_fn_registrar_ddl'),
    ('et_auditoria_drop', 'et_auditoria_drop|sql_drop||auditoria.et_fn_registrar_drop'),
    ('et_grant_on_create', 'et_grant_on_create|ddl_command_end|CREATE TABLE,CREATE SEQUENCE,CREATE FUNCTION,CREATE PROCEDURE,CREATE VIEW,CREATE MATERIALIZED VIEW|auditoria.et_fn_grant_on_create')
) e (nombre, huella);

-- 3. DIAGNOSTICO ----------------------------------------------------------------------
CREATE FUNCTION pg_temp.auditoria_diagnostico(OUT estado text, OUT tabla_ausente boolean, OUT tabla_actual boolean,
        OUT filas_previas bigint, OUT esq_ajeno boolean, OUT evt_ajeno boolean, OUT ctrl_ajeno boolean, OUT detalle text)
LANGUAGE plpgsql AS $diag$
DECLARE
    v_esq        boolean := to_regnamespace('auditoria') IS NOT NULL;
    v_ctrl       boolean := to_regnamespace('auditoria_control') IS NOT NULL;
    v_tabla      oid     := to_regclass('auditoria.log_auditoria');
    v_cols       text[];
    v_fam        boolean := false;
    v_extras     text[]  := '{}';
    v_dif        text[]  := '{}';
    v_falta      text[]  := '{}';
    v_presentes  int     := 0;
    v_evt_dif    text[]  := '{}';
    v_evt_prest  int     := 0;
    v_evt_ajeno  text[]  := '{}';
    v_ctrl_ajeno text[]  := '{}';
    v_motivos    text[]  := '{}';
    v_dueno_ok   boolean := false;
    r            record;
    v_fp         text;
    v_esq_fn     text;
BEGIN
    tabla_ausente := v_tabla IS NULL;
    tabla_actual  := false;
    filas_previas := -1;
    esq_ajeno := false; evt_ajeno := false; ctrl_ajeno := false;

    -- (a) la bitacora
    IF v_tabla IS NOT NULL THEN
        SELECT array_agg(attname::text) INTO v_cols FROM pg_attribute WHERE attrelid = v_tabla AND attnum > 0 AND NOT attisdropped;
        v_fam := v_cols @> ARRAY['id', 'schemaname', 'tablename', 'username', 'dmlaction', 'originaldata', 'executednewdata',
                                 'executedsql', 'uuid_ref', 'recorddatetime'];
        IF v_fam THEN
            tabla_actual := (SELECT relkind FROM pg_class WHERE oid = v_tabla) = 'p'
                AND v_cols @> ARRAY['changed_fields', 'hash_nuevo', 'hash_original', 'hash_anterior', 'transaccion', 'cliente',
                                    'aplicacion', 'version_hash']
                AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = v_tabla AND tgname = 'bitacora_inmutable')
                AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = v_tabla AND tgname = 'bitacora_inmutable_truncate');
            IF NOT tabla_actual THEN
                EXECUTE 'SELECT count(*) FROM auditoria.log_auditoria' INTO filas_previas;
            END IF;
        ELSE
            v_motivos := v_motivos || format('auditoria.log_auditoria tiene otra estructura (columnas: %s)', array_to_string(v_cols, ', '));
            esq_ajeno := true;
        END IF;
    END IF;

    -- (b) objetos del esquema auditoria que no son de este estandar
    IF v_esq THEN
        SELECT coalesce(array_agg(o ORDER BY o), '{}') INTO v_extras FROM (
            SELECT c.relkind::text || ':' || c.relname AS o FROM pg_class c
             WHERE c.relnamespace = 'auditoria'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
               AND c.relname NOT IN ('log_auditoria', 'log_auditoria_default', 'log_auditoria_previa', 'log_auditoria_id_seq')
               AND c.relname !~ '^log_auditoria_p[0-9]{6}$'
            UNION ALL
            SELECT 'f:' || p.proname FROM pg_proc p
             WHERE p.pronamespace = 'auditoria'::regnamespace AND p.proname NOT IN ('asignar_biu', 'asignar_trigger', 'asignar_triggers', 'auditoria_aiud', 'auditoria_biu', 'auditoria_truncate', 'bloqueo_optimista', 'deshabilitar_auditoria', 'et_fn_grant_on_create', 'et_fn_registrar_ddl', 'et_fn_registrar_drop', 'fn_bitacora_disponible', 'fn_bitacora_inmutable', 'fn_crear_particiones', 'fn_monitorear_slots', 'fn_reconciliar_tabla', 'fn_registrar_evento', 'fn_restringir_bitacora', 'fn_verificar_cadena', 'habilitar_auditoria', 'reporte_cobertura') AND p.proname <> 'uuid_generate_v7'
        ) s;
        IF v_tabla IS NULL AND cardinality(v_extras) > 0 THEN
            v_motivos := v_motivos || format('el esquema auditoria tiene objetos que no son de este estandar: %s', array_to_string(v_extras, ', '));
            esq_ajeno := true;
        END IF;
    END IF;

    -- (c) funciones propias: presentes, modificadas o faltantes
    FOR r IN SELECT * FROM _aud_esperado WHERE fn IS NOT NULL LOOP
        IF to_regprocedure(r.fn) IS NULL THEN
            v_falta := v_falta || r.fn;
        ELSE
            v_presentes := v_presentes + 1;
            IF md5(pg_get_functiondef(to_regprocedure(r.fn))) <> r.huella THEN v_dif := v_dif || r.fn; END IF;
        END IF;
    END LOOP;

    -- (d) event triggers propios
    FOR r IN SELECT * FROM _aud_esperado_evt WHERE nombre IS NOT NULL LOOP
        SELECT t.evtname || '|' || t.evtevent || '|' || coalesce(array_to_string(t.evttags, ','), '') || '|' || n.nspname || '.' || p.proname,
               n.nspname
          INTO v_fp, v_esq_fn
          FROM pg_event_trigger t JOIN pg_proc p ON p.oid = t.evtfoid JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE t.evtname = r.nombre;
        IF NOT FOUND THEN
            v_evt_dif := v_evt_dif || (r.nombre || ' (falta)');
        ELSE
            v_evt_prest := v_evt_prest + 1;
            IF v_esq_fn <> 'auditoria' THEN v_evt_ajeno := v_evt_ajeno || r.nombre;
            ELSIF v_fp <> r.huella THEN v_evt_dif := v_evt_dif || (r.nombre || ' (distinto)');
            END IF;
        END IF;
    END LOOP;
    IF cardinality(v_evt_ajeno) > 0 THEN
        v_motivos := v_motivos || format('event triggers con nombre de este estandar pero de otro origen: %s', array_to_string(v_evt_ajeno, ', '));
        evt_ajeno := true;
    END IF;

    -- (e) esquema de control
    IF v_ctrl THEN
        SELECT coalesce(array_agg(o ORDER BY o), '{}') INTO v_ctrl_ajeno FROM (
            SELECT c.relkind::text || ':' || c.relname AS o FROM pg_class c
             WHERE c.relnamespace = 'auditoria_control'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND c.relname <> 'ancla'
            UNION ALL
            SELECT 'f:' || p.proname FROM pg_proc p
             WHERE p.pronamespace = 'auditoria_control'::regnamespace AND p.proname NOT IN ('fn_inmutable', 'fn_verificar_y_anclar')
        ) s;
        IF cardinality(v_ctrl_ajeno) > 0 THEN
            v_motivos := v_motivos || format('auditoria_control tiene objetos que no son de este estandar: %s', array_to_string(v_ctrl_ajeno, ', '));
            ctrl_ajeno := true;
        END IF;
    END IF;

    v_dueno_ok := v_esq AND (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'auditoria')
                            = 'migrator';

    -- (f) decision
    IF cardinality(v_motivos) > 0 THEN
        estado := 'ajena';
    ELSIF v_tabla IS NULL AND v_presentes = 0 AND NOT v_ctrl AND v_evt_prest = 0 THEN
        estado := 'nueva';
    ELSIF tabla_actual AND cardinality(v_dif) = 0 AND cardinality(v_falta) = 0 AND cardinality(v_evt_dif) = 0 AND v_dueno_ok THEN
        estado := 'vigente';
    ELSIF tabla_actual THEN
        estado := 'reparar';
    ELSE
        estado := 'anterior';
    END IF;

    detalle := format(E'  estado: %s\n  bitacora: %s%s\n  funciones: %s presentes, %s modificadas, %s faltantes\n  event triggers: %s presentes, %s con diferencias\n  esquema de control: %s\n  dueno del esquema auditoria = migrator: %s',
        estado,
        CASE WHEN v_tabla IS NULL THEN 'no existe' WHEN NOT v_fam THEN 'estructura ajena' WHEN tabla_actual THEN 'version vigente' ELSE 'version anterior' END,
        CASE WHEN filas_previas >= 0 THEN format(' (%s registros)', filas_previas) ELSE '' END,
        v_presentes, cardinality(v_dif), cardinality(v_falta),
        v_evt_prest, cardinality(v_evt_dif) + cardinality(v_evt_ajeno),
        CASE WHEN NOT v_ctrl THEN 'no existe' ELSE 'existe' END, v_dueno_ok)
        || CASE WHEN cardinality(v_dif) > 0 THEN E'\n  funciones modificadas: ' || array_to_string(v_dif, ', ') ELSE '' END
        || CASE WHEN cardinality(v_motivos) > 0 THEN E'\n  MOTIVOS DE "ajena": ' || array_to_string(v_motivos, E'\n    - ') ELSE '' END
        || CASE WHEN v_tabla IS NOT NULL AND v_fam AND cardinality(v_extras) > 0
                THEN E'\n  objetos adicionales en el esquema (se conservan): ' || array_to_string(v_extras, ', ') ELSE '' END;
END
$diag$;

SELECT * FROM pg_temp.auditoria_diagnostico() \gset

\echo
\echo '=== DIAGNOSTICO DE LA AUDITORIA EXISTENTE ==='
\echo :detalle
SELECT (:'estado' = 'ajena')    AS es_ajena,
       (:'estado' = 'vigente')  AS es_vigente,
       (:'ajena' = 'renombrar') AS renombrar,
       (:'solo_diagnostico' = 'si') AS solo_diag \gset

-- 4. DECISION -------------------------------------------------------------------------
\if :solo_diag
    \echo '=== solo_diagnostico=si: no se cambio nada ==='
    \q
\endif
\if :es_vigente
    \echo '=== Ya esta instalada esta version completa: no hay nada que hacer ==='
    \q
\endif
\if :es_ajena
    \if :renombrar
        \echo '=== Se conserva lo ajeno renombrandolo (ajena=renombrar) y se instala el estandar de cero ==='
        DO $$
        DECLARE
            v_suf text := to_char(now(), 'YYYYMMDD_HH24MISS');
            r record;
        BEGIN
            IF (SELECT esq_ajeno FROM pg_temp.auditoria_diagnostico()) AND to_regnamespace('auditoria') IS NOT NULL THEN
                EXECUTE format('ALTER SCHEMA auditoria RENAME TO %I', 'auditoria_previa_' || v_suf);
                RAISE NOTICE 'esquema auditoria renombrado a auditoria_previa_%', v_suf;
            END IF;
            IF (SELECT ctrl_ajeno FROM pg_temp.auditoria_diagnostico()) AND to_regnamespace('auditoria_control') IS NOT NULL THEN
                EXECUTE format('ALTER SCHEMA auditoria_control RENAME TO %I', 'auditoria_control_previa_' || v_suf);
                RAISE NOTICE 'esquema auditoria_control renombrado a auditoria_control_previa_%', v_suf;
            END IF;
            FOR r IN SELECT t.evtname FROM pg_event_trigger t JOIN pg_proc p ON p.oid = t.evtfoid
                      WHERE t.evtname IN ('et_auditoria_ddl', 'et_auditoria_drop', 'et_grant_on_create') AND p.pronamespace::regnamespace::text NOT LIKE 'auditoria%' LOOP
                EXECUTE format('ALTER EVENT TRIGGER %I RENAME TO %I', r.evtname, r.evtname || '_previo_' || v_suf);
                RAISE NOTICE 'event trigger % renombrado a %_previo_%', r.evtname, r.evtname, v_suf;
            END LOOP;
        END $$;
        SELECT * FROM pg_temp.auditoria_diagnostico() \gset
        \echo :detalle
    \else
        \echo
        \echo '=== SE DETIENE SIN CAMBIAR NADA: la base tiene una auditoria que no es de este estandar ==='
        \echo 'Revisa los motivos de arriba. Opciones: (a) conservar lo ajeno y continuar:  -v ajena=renombrar'
        \echo '                                      (b) usar otra base o retirar manualmente lo ajeno.'
        DO $$ BEGIN RAISE EXCEPTION 'auditoria ajena: instalacion abortada sin cambios (ver diagnostico)'; END $$;
    \endif
\endif

-- 5. ROLES (se crean sin LOGIN solo si faltan) ---------------------------------------
DO $$
DECLARE
    v_rol text;
BEGIN
    FOREACH v_rol IN ARRAY ARRAY['migrator', 'auditor', 'role_dev_dml', 'app_web_user'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_rol) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', v_rol);
            RAISE NOTICE 'Rol % creado SIN LOGIN: asignale LOGIN y contrasena si debe conectarse', v_rol;
        END IF;
    END LOOP;
END $$;

-- 6. EVENT TRIGGERS PROPIOS: se retiran ahora y se recrean al final (la instalacion no deja ruido de DDL) ----
DROP EVENT TRIGGER IF EXISTS et_grant_on_create;
DROP EVENT TRIGGER IF EXISTS et_auditoria_ddl;
DROP EVENT TRIGGER IF EXISTS et_auditoria_drop;

-- 7. FUNCIONES -------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS auditoria;

-- Funciones del estandar cuyo tipo de retorno cambio entre versiones (CREATE OR REPLACE no puede cambiarlo) y sobrecargas
-- antiguas que ya no existen: se eliminan para recrearlas. Los triggers de las tablas se conservan: las funciones de trigger
-- devuelven siempre "trigger" y se reemplazan en su lugar.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT e.fn FROM _aud_esperado e
              WHERE e.fn IS NOT NULL AND to_regprocedure(e.fn) IS NOT NULL
                AND pg_get_function_result(to_regprocedure(e.fn)) <> e.resultado LOOP
        EXECUTE format('DROP FUNCTION %s', r.fn);
        RAISE NOTICE 'funcion % eliminada para recrearla con el tipo de retorno vigente', r.fn;
    END LOOP;
    FOR r IN SELECT p.oid::regprocedure::text AS fn FROM pg_proc p
              WHERE p.pronamespace = 'auditoria'::regnamespace AND p.proname IN ('asignar_biu', 'asignar_trigger', 'asignar_triggers', 'auditoria_aiud', 'auditoria_biu', 'auditoria_truncate', 'bloqueo_optimista', 'deshabilitar_auditoria', 'et_fn_grant_on_create', 'et_fn_registrar_ddl', 'et_fn_registrar_drop', 'fn_bitacora_disponible', 'fn_bitacora_inmutable', 'fn_crear_particiones', 'fn_monitorear_slots', 'fn_reconciliar_tabla', 'fn_registrar_evento', 'fn_restringir_bitacora', 'fn_verificar_cadena', 'habilitar_auditoria', 'reporte_cobertura')
                AND p.oid::regprocedure::text NOT IN (SELECT fn FROM _aud_esperado WHERE fn IS NOT NULL) LOOP
        EXECUTE format('DROP FUNCTION %s', r.fn);
        RAISE NOTICE 'sobrecarga antigua % eliminada', r.fn;
    END LOOP;
    DROP FUNCTION IF EXISTS auditoria.uuid_generate_v7();
END $$;

SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;

-- FUNCTION: asignar_biu(text)
CREATE OR REPLACE FUNCTION auditoria.asignar_biu(p_tabla text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'audit_biu'
          AND tgrelid = p_tabla::regclass
    ) THEN
        EXECUTE format(
            'CREATE TRIGGER audit_biu
             BEFORE INSERT OR UPDATE ON %s
             FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_biu()',
            p_tabla
        );
        RAISE NOTICE 'audit_biu creado en %', p_tabla;
    END IF;
END;
$$;

-- FUNCTION: asignar_trigger(text)
CREATE OR REPLACE FUNCTION auditoria.asignar_trigger(p_tabla text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM auditoria.asignar_triggers(p_tabla);
END;
$$;

-- FUNCTION: asignar_triggers(text)
CREATE OR REPLACE FUNCTION auditoria.asignar_triggers(p_tabla text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- audit_biu: BEFORE INSERT OR UPDATE
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'audit_biu'
          AND tgrelid = p_tabla::regclass
    ) THEN
        EXECUTE format(
            'CREATE TRIGGER audit_biu
             BEFORE INSERT OR UPDATE ON %s
             FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_biu()',
            p_tabla
        );
        RAISE NOTICE 'audit_biu creado en %', p_tabla;
    END IF;

    -- audit_aiud: AFTER INSERT OR UPDATE OR DELETE (deshabilitado por defecto; lo habilita el desarrollador)
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'audit_aiud'
          AND tgrelid = p_tabla::regclass
    ) THEN
        EXECUTE format(
            'CREATE TRIGGER audit_aiud
             AFTER INSERT OR UPDATE OR DELETE ON %s
             FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_aiud()',
            p_tabla
        );
        EXECUTE format('ALTER TABLE %s DISABLE TRIGGER audit_aiud', p_tabla);
        RAISE NOTICE 'audit_aiud creado (deshabilitado) en %', p_tabla;
    END IF;

    -- audit_truncate: BEFORE TRUNCATE por sentencia (deshabilitado por defecto, igual que audit_aiud)
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'audit_truncate'
          AND tgrelid = p_tabla::regclass
    ) THEN
        EXECUTE format(
            'CREATE TRIGGER audit_truncate
             BEFORE TRUNCATE ON %s
             FOR EACH STATEMENT EXECUTE FUNCTION auditoria.auditoria_truncate()',
            p_tabla
        );
        EXECUTE format('ALTER TABLE %s DISABLE TRIGGER audit_truncate', p_tabla);
        RAISE NOTICE 'audit_truncate creado (deshabilitado) en %', p_tabla;
    END IF;
END;
$$;

-- FUNCTION: auditoria_aiud()
CREATE OR REPLACE FUNCTION auditoria.auditoria_aiud() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET "TimeZone" TO 'America/Mexico_City'
    SET "DateStyle" TO 'ISO, MDY'
    AS $$
DECLARE
    v_old_jsonb JSONB;
    v_new_jsonb JSONB;
    v_delta     JSONB;
    v_guc       TEXT := nullif(current_setting('app.current_user', true), '');
    v_usuario   TEXT;
    v_uuid_ref  UUID;
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        v_old_jsonb := to_jsonb(OLD);
        v_uuid_ref  := (v_old_jsonb ->> 'ref')::uuid;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        v_new_jsonb := to_jsonb(NEW);
        IF v_uuid_ref IS NULL THEN
            v_uuid_ref := (v_new_jsonb ->> 'ref')::uuid;
        END IF;
    END IF;

    IF TG_OP = 'INSERT' THEN
        v_usuario := coalesce(v_new_jsonb ->> 'usuario_creacion', v_guc, session_user);
    ELSIF TG_OP = 'UPDATE' THEN
        v_usuario := coalesce(v_new_jsonb ->> 'usuario_modificacion', v_guc, session_user);
    ELSE
        v_usuario := coalesce(v_guc, session_user);
    END IF;

    IF TG_OP = 'UPDATE' THEN
        SELECT jsonb_object_agg(n.key, n.value) INTO v_delta
        FROM jsonb_each(v_new_jsonb) n
        LEFT JOIN jsonb_each(v_old_jsonb) o ON n.key = o.key
        WHERE n.value IS DISTINCT FROM o.value;
        -- Sin cambios reales: solo las columnas que mantiene audit_biu.
        IF v_delta IS NULL
           OR (v_delta - ARRAY['row_version', 'fecha_modificacion', 'usuario_modificacion']) = '{}'::jsonb THEN
            RETURN NEW;
        END IF;
    END IF;

    PERFORM auditoria.fn_registrar_evento(TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP,
                                          v_old_jsonb, v_new_jsonb, v_delta, v_usuario, v_uuid_ref);

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

-- FUNCTION: auditoria_biu()
CREATE OR REPLACE FUNCTION auditoria.auditoria_biu() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_ahora    timestamptz := clock_timestamp();
    v_usuario  text        := coalesce(nullif(current_setting('app.current_user', true), ''), session_user);
    v_bloqueo  boolean     := TG_NARGS > 0 AND 'bloqueo_optimista' = ANY (TG_ARGV);
    v_fila     jsonb;
    v_ant      jsonb;
    v_cambios  jsonb := '{}'::jsonb;
    v_original record;
BEGIN
    v_original := NEW;
    -- Via directa (tablas con las 9 columnas canonicas). Si falta alguna, PostgreSQL lanza
    -- undefined_column; se restaura la fila original y se usa la via tolerante.
    BEGIN
        IF TG_OP = 'INSERT' THEN
            NEW.id                   := coalesce(NEW.id, uuidv7());
            NEW.ref                  := coalesce(NEW.ref, uuidv7());
            NEW.row_version          := 1;
            NEW.fecha_creacion       := coalesce(NEW.fecha_creacion, v_ahora);
            NEW.fecha_modificacion   := NEW.fecha_creacion;
            NEW.usuario_creacion     := coalesce(NEW.usuario_creacion, v_usuario);
            NEW.usuario_modificacion := coalesce(NEW.usuario_modificacion, NEW.usuario_creacion);
            NEW.activo               := coalesce(NEW.activo, true);
            NEW.borrado              := coalesce(NEW.borrado, false);
        ELSE
            IF v_bloqueo
               AND NEW.row_version IS DISTINCT FROM OLD.row_version
               AND NEW.row_version IS DISTINCT FROM coalesce(OLD.row_version, 0) + 1 THEN
                RAISE EXCEPTION '%.%: el registro fue modificado por otra transaccion (row_version enviado %, vigente %)',
                    TG_TABLE_SCHEMA, TG_TABLE_NAME, NEW.row_version, OLD.row_version
                    USING ERRCODE = 'serialization_failure';
            END IF;
            NEW.id                 := OLD.id;
            NEW.ref                := coalesce(OLD.ref, NEW.ref, uuidv7());
            NEW.fecha_creacion     := OLD.fecha_creacion;
            NEW.usuario_creacion   := OLD.usuario_creacion;
            NEW.row_version        := coalesce(OLD.row_version, 0) + 1;
            NEW.fecha_modificacion := v_ahora;
            IF NEW.usuario_modificacion IS NULL
               OR NEW.usuario_modificacion IS NOT DISTINCT FROM OLD.usuario_modificacion THEN
                NEW.usuario_modificacion := v_usuario;
            END IF;
        END IF;
        RETURN NEW;
    EXCEPTION WHEN undefined_column THEN
        NEW := v_original;
    END;

    -- Via tolerante: solo actua sobre las columnas canonicas que existan en la tabla.
    v_fila := to_jsonb(NEW);
    IF TG_OP = 'INSERT' THEN
        IF v_fila ? 'id'  AND v_fila->>'id'  IS NULL THEN
            v_cambios := v_cambios || jsonb_build_object('id', uuidv7());
        END IF;
        IF v_fila ? 'ref' AND v_fila->>'ref' IS NULL THEN
            v_cambios := v_cambios || jsonb_build_object('ref', uuidv7());
        END IF;
        IF v_fila ? 'row_version'          THEN v_cambios := v_cambios || jsonb_build_object('row_version', 1); END IF;
        IF v_fila ? 'fecha_creacion'       THEN v_cambios := v_cambios || jsonb_build_object('fecha_creacion', coalesce((v_fila->>'fecha_creacion')::timestamptz, v_ahora)); END IF;
        IF v_fila ? 'fecha_modificacion'   THEN v_cambios := v_cambios || jsonb_build_object('fecha_modificacion', coalesce((v_fila->>'fecha_creacion')::timestamptz, v_ahora)); END IF;
        IF v_fila ? 'usuario_creacion'     THEN v_cambios := v_cambios || jsonb_build_object('usuario_creacion', coalesce(v_fila->>'usuario_creacion', v_usuario)); END IF;
        IF v_fila ? 'usuario_modificacion' THEN v_cambios := v_cambios || jsonb_build_object('usuario_modificacion', coalesce(v_fila->>'usuario_modificacion', v_fila->>'usuario_creacion', v_usuario)); END IF;
        IF v_fila ? 'activo'  AND v_fila->>'activo'  IS NULL THEN v_cambios := v_cambios || jsonb_build_object('activo', true);  END IF;
        IF v_fila ? 'borrado' AND v_fila->>'borrado' IS NULL THEN v_cambios := v_cambios || jsonb_build_object('borrado', false); END IF;
    ELSE
        v_ant := to_jsonb(OLD);
        IF v_bloqueo AND v_fila ? 'row_version'
           AND v_fila->'row_version' IS DISTINCT FROM v_ant->'row_version'
           AND (v_fila->>'row_version')::bigint IS DISTINCT FROM coalesce((v_ant->>'row_version')::bigint, 0) + 1 THEN
            RAISE EXCEPTION '%.%: el registro fue modificado por otra transaccion (row_version enviado %, vigente %)',
                TG_TABLE_SCHEMA, TG_TABLE_NAME, v_fila->>'row_version', v_ant->>'row_version'
                USING ERRCODE = 'serialization_failure';
        END IF;
        IF v_fila ? 'id' THEN v_cambios := v_cambios || jsonb_build_object('id', v_ant->'id'); END IF;
        IF v_fila ? 'ref' THEN
            v_cambios := v_cambios || jsonb_build_object('ref', coalesce(v_ant->'ref', v_fila->'ref', to_jsonb(uuidv7())));
        END IF;
        IF v_fila ? 'fecha_creacion'     THEN v_cambios := v_cambios || jsonb_build_object('fecha_creacion', v_ant->'fecha_creacion'); END IF;
        IF v_fila ? 'usuario_creacion'   THEN v_cambios := v_cambios || jsonb_build_object('usuario_creacion', v_ant->'usuario_creacion'); END IF;
        IF v_fila ? 'row_version'        THEN v_cambios := v_cambios || jsonb_build_object('row_version', coalesce((v_ant->>'row_version')::int, 0) + 1); END IF;
        IF v_fila ? 'fecha_modificacion' THEN v_cambios := v_cambios || jsonb_build_object('fecha_modificacion', v_ahora); END IF;
        IF v_fila ? 'usuario_modificacion' THEN
            v_cambios := v_cambios || jsonb_build_object('usuario_modificacion',
                CASE WHEN v_fila->>'usuario_modificacion' IS NOT NULL
                          AND v_fila->'usuario_modificacion' IS DISTINCT FROM v_ant->'usuario_modificacion'
                     THEN v_fila->>'usuario_modificacion' ELSE v_usuario END);
        END IF;
    END IF;

    IF v_cambios <> '{}'::jsonb THEN
        NEW := jsonb_populate_record(NEW, v_cambios);
    END IF;
    RETURN NEW;
END;
$$;

-- FUNCTION: auditoria_truncate()
CREATE OR REPLACE FUNCTION auditoria.auditoria_truncate() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    v_paginas integer;
    v_filas   bigint;
    v_datos   jsonb;
BEGIN
    SELECT relpages, reltuples::bigint INTO v_paginas, v_filas FROM pg_class WHERE oid = TG_RELID;
    v_datos := jsonb_build_object('filas_estimadas', greatest(v_filas, 0));
    IF v_paginas < 1000 THEN
        BEGIN
            EXECUTE format('SELECT count(*) FROM %s', TG_RELID::regclass) INTO v_filas;
            v_datos := jsonb_build_object('filas', v_filas);
        EXCEPTION WHEN insufficient_privilege THEN
            NULL;  -- se conserva el estimado
        END;
    END IF;

    PERFORM auditoria.fn_registrar_evento(TG_TABLE_SCHEMA, TG_TABLE_NAME, 'TRUNCATE', v_datos, NULL, NULL,
        coalesce(nullif(current_setting('app.current_user', true), ''), session_user), NULL);
    RETURN NULL;
END;
$$;

-- FUNCTION: bloqueo_optimista(text, boolean)
CREATE OR REPLACE FUNCTION auditoria.bloqueo_optimista(p_tabla text, p_activar boolean DEFAULT true) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_estado "char";
BEGIN
    SELECT tgenabled INTO v_estado FROM pg_trigger WHERE tgrelid = p_tabla::regclass AND tgname = 'audit_biu';
    EXECUTE format('CREATE OR REPLACE TRIGGER audit_biu BEFORE INSERT OR UPDATE ON %s
                    FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_biu(%s)',
                   p_tabla, CASE WHEN p_activar THEN quote_literal('bloqueo_optimista') ELSE '' END);
    IF v_estado = 'D' THEN
        EXECUTE format('ALTER TABLE %s DISABLE TRIGGER audit_biu', p_tabla);
    END IF;
END;
$$;

-- FUNCTION: deshabilitar_auditoria(text)
CREATE OR REPLACE FUNCTION auditoria.deshabilitar_auditoria(p_tabla text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    EXECUTE format('ALTER TABLE %s DISABLE TRIGGER audit_aiud', p_tabla);
    EXECUTE format('ALTER TABLE %s DISABLE TRIGGER audit_truncate', p_tabla);
END;
$$;

-- FUNCTION: et_fn_grant_on_create()
CREATE OR REPLACE FUNCTION auditoria.et_fn_grant_on_create() RETURNS event_trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE
    obj             RECORD;
    tbl             TEXT;
BEGIN
    FOR obj IN
        SELECT * FROM pg_event_trigger_ddl_commands()
        WHERE command_tag IN ('CREATE TABLE','CREATE SEQUENCE',
                              'CREATE FUNCTION','CREATE PROCEDURE',
                              'CREATE VIEW','CREATE MATERIALIZED VIEW')
          AND coalesce(schema_name, '') NOT IN ('auditoria', 'auditoria_control')
    LOOP
        BEGIN
            IF obj.command_tag = 'CREATE TABLE'
               AND (SELECT relpersistence FROM pg_class WHERE oid = obj.objid) = 't' THEN
                NULL;  -- tablas temporales: sin permisos ni triggers de auditoria
            ELSIF obj.command_tag = 'CREATE TABLE' THEN
                tbl := obj.object_identity;
                -- Triggers de auditoria, independientes del resultado de los permisos.
                BEGIN
                    IF EXISTS (SELECT 1 FROM pg_attribute
                               WHERE attrelid = obj.objid AND attname = 'row_version'
                                 AND attnum > 0 AND NOT attisdropped) THEN
                        EXECUTE format(
                            'CREATE TRIGGER audit_biu BEFORE INSERT OR UPDATE ON %s
                             FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_biu()', tbl);
                        EXECUTE format(
                            'CREATE TRIGGER audit_aiud AFTER INSERT OR UPDATE OR DELETE ON %s
                             FOR EACH ROW EXECUTE FUNCTION auditoria.auditoria_aiud()', tbl);
                        EXECUTE format('ALTER TABLE %s DISABLE TRIGGER audit_aiud', tbl);
                        IF to_regprocedure('auditoria.auditoria_truncate()') IS NOT NULL THEN
                            EXECUTE format(
                                'CREATE TRIGGER audit_truncate BEFORE TRUNCATE ON %s
                                 FOR EACH STATEMENT EXECUTE FUNCTION auditoria.auditoria_truncate()', tbl);
                            EXECUTE format('ALTER TABLE %s DISABLE TRIGGER audit_truncate', tbl);
                        END IF;
                    END IF;
                EXCEPTION WHEN OTHERS THEN
                    RAISE WARNING 'et_grant_on_create: triggers de auditoria en % no se crearon: %', tbl, SQLERRM;
                END;
                -- Permisos en bloque propio: un fallo aqui no revierte los triggers ya creados.
                BEGIN
                    EXECUTE format(
                        'GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO role_dev_dml, app_web_user', tbl);
                    EXECUTE format('GRANT SELECT ON %s TO auditor', tbl);
                EXCEPTION WHEN OTHERS THEN
                    RAISE WARNING 'et_grant_on_create: permisos sobre % no se otorgaron: %', tbl, SQLERRM;
                END;
            ELSIF obj.command_tag = 'CREATE SEQUENCE' THEN
                EXECUTE format('GRANT USAGE, SELECT, UPDATE ON %s TO role_dev_dml', obj.object_identity);
                EXECUTE format('GRANT USAGE, SELECT ON %s TO app_web_user', obj.object_identity);
            ELSIF obj.command_tag = 'CREATE FUNCTION' THEN
                EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO role_dev_dml, app_web_user', obj.object_identity);
            ELSIF obj.command_tag = 'CREATE PROCEDURE' THEN
                EXECUTE format('GRANT EXECUTE ON PROCEDURE %s TO role_dev_dml, app_web_user', obj.object_identity);
            ELSIF obj.command_tag IN ('CREATE VIEW','CREATE MATERIALIZED VIEW') THEN
                EXECUTE format('GRANT SELECT ON %s TO role_dev_dml, app_web_user, auditor', obj.object_identity);
            END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'et_grant_on_create: % sobre % no se completo: %',
                obj.command_tag, obj.object_identity, SQLERRM;
        END;
    END LOOP;
END
$$;

-- FUNCTION: et_fn_registrar_ddl()
CREATE OR REPLACE FUNCTION auditoria.et_fn_registrar_ddl() RETURNS event_trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    obj       record;
    v_sql     text := current_query();
    v_usuario text := coalesce(nullif(current_setting('app.current_user', true), ''), session_user);
    v_nombre  text;
BEGIN
    IF NOT auditoria.fn_bitacora_disponible() THEN
        RETURN;
    END IF;
    FOR obj IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
        IF obj.schema_name = 'auditoria'
           OR (obj.command_tag = 'ALTER TABLE'
               AND v_sql ~* '(enable|disable)\s+(always\s+|replica\s+)?trigger\s+("?audit_|all\M|user\M)') THEN
            BEGIN
                v_nombre := CASE WHEN obj.classid = 'pg_class'::regclass
                                 THEN (SELECT relname FROM pg_class WHERE oid = obj.objid)
                                 ELSE obj.object_identity END;
                PERFORM auditoria.fn_registrar_evento(coalesce(obj.schema_name, ''), coalesce(v_nombre, ''), 'DDL', NULL,
                    jsonb_build_object('command_tag', obj.command_tag, 'object_type', obj.object_type,
                                       'object_identity', obj.object_identity),
                    NULL, v_usuario, NULL);
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'auditoria: el DDL % sobre % no se registro: %', obj.command_tag, obj.object_identity, SQLERRM;
            END;
        END IF;
    END LOOP;
END;
$$;

-- FUNCTION: et_fn_registrar_drop()
CREATE OR REPLACE FUNCTION auditoria.et_fn_registrar_drop() RETURNS event_trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    obj       record;
    v_usuario text := coalesce(nullif(current_setting('app.current_user', true), ''), session_user);
BEGIN
    IF NOT auditoria.fn_bitacora_disponible() THEN
        RETURN;
    END IF;
    FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects() LOOP
        IF (obj.schema_name = 'auditoria' AND obj.original)
           OR (obj.object_type = 'trigger' AND obj.object_identity ~ '^"?audit_'
               AND coalesce(obj.schema_name, '') !~ '^pg_temp') THEN
            BEGIN
                PERFORM auditoria.fn_registrar_evento(coalesce(obj.schema_name, ''),
                    coalesce(obj.object_name, obj.object_identity), 'DDL', NULL,
                    jsonb_build_object('command_tag', tg_tag, 'object_type', obj.object_type,
                                       'object_identity', obj.object_identity),
                    NULL, v_usuario, NULL);
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'auditoria: el DROP de % no se registro: %', obj.object_identity, SQLERRM;
            END;
        END IF;
    END LOOP;
END;
$$;

-- FUNCTION: fn_bitacora_disponible()
CREATE OR REPLACE FUNCTION auditoria.fn_bitacora_disponible() RETURNS boolean
    LANGUAGE sql STABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
    SELECT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = to_regclass('auditoria.log_auditoria')
                     AND attname = 'version_hash' AND NOT attisdropped)
       AND to_regprocedure('auditoria.fn_registrar_evento(text,text,text,jsonb,jsonb,jsonb,text,uuid)') IS NOT NULL;
$$;

-- FUNCTION: fn_bitacora_inmutable()
CREATE OR REPLACE FUNCTION auditoria.fn_bitacora_inmutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'auditoria: % sobre %.% no permitido; la bitacora es de solo insercion', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- FUNCTION: fn_crear_particiones(integer, date)
CREATE OR REPLACE FUNCTION auditoria.fn_crear_particiones(p_meses_adelante integer DEFAULT 3, p_desde date DEFAULT NULL::date) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET "TimeZone" TO 'America/Mexico_City'
    AS $$
DECLARE
    v_mes     date;
    v_fin     date;
    v_nombre  text;
    v_creadas integer := 0;
BEGIN
    IF (SELECT relkind FROM pg_class WHERE oid = to_regclass('auditoria.log_auditoria')) IS DISTINCT FROM 'p' THEN
        RETURN 0;
    END IF;
    v_mes := date_trunc('month', coalesce(p_desde, current_date))::date;
    v_fin := (date_trunc('month', current_date) + make_interval(months => p_meses_adelante))::date;
    WHILE v_mes <= v_fin LOOP
        v_nombre := 'log_auditoria_p' || to_char(v_mes, 'YYYYMM');
        IF to_regclass(format('auditoria.%I', v_nombre)) IS NULL THEN
            BEGIN
                EXECUTE format('CREATE TABLE auditoria.%I PARTITION OF auditoria.log_auditoria FOR VALUES FROM (%L) TO (%L)',
                               v_nombre, v_mes::timestamptz, (v_mes + interval '1 month')::timestamptz);
                EXECUTE format('CREATE TRIGGER bitacora_inmutable_truncate BEFORE TRUNCATE ON auditoria.%I
                                FOR EACH STATEMENT EXECUTE FUNCTION auditoria.fn_bitacora_inmutable()', v_nombre);
                PERFORM auditoria.fn_restringir_bitacora(format('auditoria.%I', v_nombre)::regclass);
                v_creadas := v_creadas + 1;
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'auditoria.fn_crear_particiones: la particion % no se creo: %', v_nombre, SQLERRM;
            END;
        END IF;
        v_mes := (v_mes + interval '1 month')::date;
    END LOOP;
    RETURN v_creadas;
END;
$$;

-- FUNCTION: fn_monitorear_slots()
CREATE OR REPLACE FUNCTION auditoria.fn_monitorear_slots() RETURNS TABLE(slot_name text, active boolean, wal_status text, lag_bytes numeric, lag_mb numeric)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.slot_name::TEXT,
        s.active,
        s.wal_status::TEXT,
        pg_wal_lsn_diff(pg_current_wal_lsn(), s.restart_lsn)::NUMERIC AS lag_bytes,
        round((pg_wal_lsn_diff(pg_current_wal_lsn(), s.restart_lsn) / 1024.0 / 1024.0), 2) AS lag_mb
    FROM pg_replication_slots s;
END;
$$;

-- FUNCTION: fn_reconciliar_tabla(text, text)
CREATE OR REPLACE FUNCTION auditoria.fn_reconciliar_tabla(p_schema text, p_table text) RETURNS TABLE(uuid_ref uuid, tipo_desajuste text, datos_tabla jsonb, datos_log jsonb)
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_sql TEXT;
BEGIN
    v_sql := format('
        WITH ultimo_log AS (
            SELECT DISTINCT ON (uuid_ref) 
                uuid_ref, 
                dmlaction,
                executednewdata
            FROM auditoria.log_auditoria
            WHERE schemaname = %1$L AND tablename = %2$L
            ORDER BY uuid_ref, id DESC
        ),
        tabla_viva AS (
            SELECT ref AS uuid_ref, to_jsonb(t.*) AS datos
            FROM %1$I.%2$I t
            WHERE t.borrado = false
        )
        SELECT 
            coalesce(tv.uuid_ref, ul.uuid_ref) AS uuid_ref,
            CASE 
                WHEN tv.uuid_ref IS NULL AND ul.dmlaction <> %3$L THEN %4$L
                WHEN ul.uuid_ref IS NULL THEN %5$L
                WHEN tv.datos IS DISTINCT FROM ul.executednewdata::jsonb THEN %6$L
            END AS tipo_desajuste,
            tv.datos AS datos_tabla,
            ul.executednewdata::jsonb AS datos_log
        FROM tabla_viva tv
        FULL JOIN ultimo_log ul ON tv.uuid_ref = ul.uuid_ref
        WHERE 
            (tv.datos IS DISTINCT FROM ul.executednewdata::jsonb)
            OR (ul.uuid_ref IS NULL)
            OR (tv.uuid_ref IS NULL AND ul.dmlaction <> %3$L)
    ', p_schema, p_table, 'D', 'LOG_SIN_REGISTRO', 'REGISTRO_SIN_LOG', 'MODIFICACION_SIN_LOG');

    RETURN QUERY EXECUTE v_sql;
END;
$_$;

-- FUNCTION: fn_registrar_evento(text, text, text, jsonb, jsonb, jsonb, text, uuid)
CREATE OR REPLACE FUNCTION auditoria.fn_registrar_evento(p_esquema text, p_tabla text, p_operacion text, p_original jsonb, p_nuevo jsonb, p_cambios jsonb, p_usuario text, p_uuid_ref uuid) RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET "TimeZone" TO 'America/Mexico_City'
    SET "DateStyle" TO 'ISO, MDY'
    AS $$
DECLARE
    v_transaccion    xid8 := pg_current_xact_id();
    v_cliente        inet := inet_client_addr();
    v_aplicacion     text := nullif(current_setting('application_name', true), '');
    v_hash_anterior  text;
    v_hash_nuevo     text;
    v_recorddatetime timestamptz;
BEGIN
    -- Serializa la cadena: una sola transaccion a la vez toma el ultimo eslabon.
    PERFORM pg_advisory_xact_lock(hashtext('estandar_auditoria'), hashtext('auditoria.log_auditoria'));

    v_recorddatetime := clock_timestamp();

    SELECT hash_nuevo INTO v_hash_anterior
    FROM auditoria.log_auditoria
    ORDER BY id DESC
    LIMIT 1;
    v_hash_anterior := coalesce(v_hash_anterior, 'GENESIS');

    v_hash_nuevo := encode(sha256(convert_to(
        v_hash_anterior ||
        p_esquema ||
        p_tabla ||
        p_operacion ||
        coalesce(p_original::text, '') ||
        coalesce(p_nuevo::text, '') ||
        p_usuario ||
        v_recorddatetime::text ||
        v_transaccion::text ||
        coalesce(v_cliente::text, '') ||
        coalesce(v_aplicacion, ''), 'UTF8')), 'hex');

    INSERT INTO auditoria.log_auditoria (
        schemaname, tablename, username, dmlaction,
        originaldata, executednewdata, changed_fields,
        hash_original, hash_nuevo, hash_anterior,
        uuid_ref, executedsql, recorddatetime,
        transaccion, cliente, aplicacion, version_hash
    ) VALUES (
        p_esquema, p_tabla, p_usuario, p_operacion,
        p_original, p_nuevo, p_cambios,
        CASE WHEN p_original IS NOT NULL
             THEN encode(sha256(convert_to(p_original::text, 'UTF8')), 'hex') END,
        v_hash_nuevo, v_hash_anterior,
        p_uuid_ref, current_query(), v_recorddatetime,
        v_transaccion, v_cliente, v_aplicacion, 2
    );
END;
$$;

-- FUNCTION: fn_restringir_bitacora(regclass)
CREATE OR REPLACE FUNCTION auditoria.fn_restringir_bitacora(p_objeto regclass) RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT DISTINCT a.grantee
             FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
             WHERE c.oid = p_objeto AND a.grantee <> c.relowner
    LOOP
        EXECUTE format('REVOKE ALL ON %s FROM %s', p_objeto,
                       CASE WHEN r.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(r.grantee)) END);
    END LOOP;
    IF (SELECT relkind FROM pg_class WHERE oid = p_objeto) IN ('r', 'p')
       AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditor') THEN
        EXECUTE format('GRANT SELECT ON %s TO auditor', p_objeto);
    END IF;
END;
$$;

-- FUNCTION: fn_verificar_cadena()
CREATE OR REPLACE FUNCTION auditoria.fn_verificar_cadena() RETURNS TABLE(registro_alterado bigint, hash_esperado text, hash_encontrado text)
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET "TimeZone" TO 'America/Mexico_City'
    SET "DateStyle" TO 'ISO, MDY'
    AS $$
DECLARE
    r RECORD;
    v_hash_acumulado TEXT := 'GENESIS';
    v_hash_calculado TEXT;
BEGIN
    FOR r IN (
        SELECT id, schemaname, tablename, dmlaction,
               originaldata, executednewdata, username,
               recorddatetime, hash_nuevo, hash_anterior,
               transaccion, cliente, aplicacion, version_hash
        FROM auditoria.log_auditoria
        ORDER BY id ASC
    ) LOOP
        IF r.hash_anterior IS DISTINCT FROM v_hash_acumulado THEN
            registro_alterado := r.id;
            hash_esperado     := v_hash_acumulado;
            hash_encontrado   := r.hash_anterior;
            RETURN NEXT;
            RETURN;
        END IF;

        v_hash_calculado := encode(sha256(convert_to(
            v_hash_acumulado ||
            r.schemaname ||
            r.tablename ||
            r.dmlaction ||
            coalesce(r.originaldata::text, '') ||
            coalesce(r.executednewdata::text, '') ||
            r.username ||
            r.recorddatetime::text ||
            CASE WHEN r.version_hash >= 2
                 THEN r.transaccion::text || coalesce(r.cliente::text, '') || coalesce(r.aplicacion, '')
                 ELSE '' END, 'UTF8')), 'hex');

        IF r.hash_nuevo IS DISTINCT FROM v_hash_calculado THEN
            registro_alterado := r.id;
            hash_esperado     := v_hash_calculado;
            hash_encontrado   := r.hash_nuevo;
            RETURN NEXT;
            RETURN;
        END IF;

        v_hash_acumulado := r.hash_nuevo;
    END LOOP;
END;
$$;

-- FUNCTION: habilitar_auditoria(text)
CREATE OR REPLACE FUNCTION auditoria.habilitar_auditoria(p_tabla text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM auditoria.asignar_triggers(p_tabla);
    EXECUTE format('ALTER TABLE %s ENABLE TRIGGER audit_aiud', p_tabla);
    EXECUTE format('ALTER TABLE %s ENABLE TRIGGER audit_truncate', p_tabla);
END;
$$;

-- FUNCTION: reporte_cobertura()
CREATE OR REPLACE FUNCTION auditoria.reporte_cobertura() RETURNS TABLE(esquema text, tabla text, tiene_ref boolean, tiene_rv boolean, tiene_biu boolean, tiene_aiud boolean, elegible boolean, estado text)
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    RETURN QUERY
    SELECT
        t.schemaname::TEXT AS esquema,
        t.tablename::TEXT AS tabla,
        bool_or(c.column_name = 'ref'),
        bool_or(c.column_name = 'row_version'),
        EXISTS(SELECT 1 FROM pg_trigger tr WHERE tr.tgname='audit_biu'  AND tr.tgrelid=format('%I.%I', t.schemaname, t.tablename)::regclass),
        EXISTS(SELECT 1 FROM pg_trigger tr WHERE tr.tgname='audit_aiud' AND tr.tgrelid=format('%I.%I', t.schemaname, t.tablename)::regclass),
        bool_or(c.column_name='ref') AND bool_or(c.column_name='row_version') AND bool_or(c.column_name='fecha_creacion'),
        CASE
          WHEN NOT bool_or(c.column_name='ref') THEN 'SIN_COLUMNAS_AUDITORIA'
          WHEN NOT EXISTS(SELECT 1 FROM pg_trigger tr WHERE tr.tgname='audit_biu' AND tr.tgrelid=format('%I.%I', t.schemaname, t.tablename)::regclass)
               THEN 'PENDIENTE_BIU'
          WHEN NOT EXISTS(SELECT 1 FROM pg_trigger tr WHERE tr.tgname='audit_aiud' AND tr.tgrelid=format('%I.%I', t.schemaname, t.tablename)::regclass)
               THEN 'PENDIENTE_AIUD'
          ELSE 'COMPLETO'
        END
    FROM pg_tables t
    LEFT JOIN information_schema.columns c
        ON c.table_schema = t.schemaname AND c.table_name = t.tablename
    WHERE t.schemaname NOT IN ('information_schema', 'pg_catalog', 'auditoria', 'topology', 'tiger')
    GROUP BY t.schemaname, t.tablename
    ORDER BY t.schemaname, t.tablename;
END;
$$;

RESET check_function_bodies;
RESET search_path;

-- 7b. PROPIEDAD TEMPRANA: las funciones SECURITY DEFINER (fn_crear_particiones) corren como migrator; antes de tocar la bitacora
--     el esquema y todo lo que contiene deben ser de migrator (una auditoria previa puede tener otro dueno).
DO $$
DECLARE
    r record;
BEGIN
    ALTER SCHEMA auditoria OWNER TO migrator;
    FOR r IN SELECT c.oid::regclass AS obj, c.relkind FROM pg_class c
             WHERE c.relnamespace = 'auditoria'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
               AND pg_get_userbyid(c.relowner) <> 'migrator' ORDER BY c.relkind DESC
    LOOP
        IF pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid = r.obj)) <> 'migrator' THEN
            EXECUTE format('ALTER %s %s OWNER TO migrator',
                           CASE r.relkind WHEN 'S' THEN 'SEQUENCE' WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE 'TABLE' END, r.obj);
        END IF;
    END LOOP;
    FOR r IN SELECT p.oid::regprocedure AS obj FROM pg_proc p
             WHERE p.pronamespace = 'auditoria'::regnamespace AND pg_get_userbyid(p.proowner) <> 'migrator'
    LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO migrator', r.obj);
    END LOOP;
END $$;

-- 8. BITACORA ---------------------------------------------------------------------------
SELECT :'tabla_ausente'::boolean AS ausente, :'tabla_actual'::boolean AS actual, :'filas_previas'::bigint AS filas \gset
\if :ausente
    \echo '=== Bitacora nueva ==='
    SELECT pg_catalog.set_config('search_path', '', false);
    SET check_function_bodies = false;

-- TABLE: log_auditoria
CREATE TABLE auditoria.log_auditoria (
    id bigint NOT NULL,
    schemaname text NOT NULL,
    tablename text NOT NULL,
    username text,
    dmlaction text NOT NULL,
    originaldata jsonb,
    executednewdata jsonb,
    changed_fields jsonb,
    executedsql text,
    uuid_ref uuid,
    hash_nuevo text,
    hash_original text,
    hash_anterior text,
    recorddatetime timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    transaccion xid8,
    cliente inet,
    aplicacion text,
    version_hash smallint DEFAULT 1 NOT NULL
)
PARTITION BY RANGE (recorddatetime);

-- SEQUENCE: log_auditoria_id_seq
CREATE SEQUENCE auditoria.log_auditoria_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: log_auditoria_id_seq
ALTER SEQUENCE auditoria.log_auditoria_id_seq OWNED BY auditoria.log_auditoria.id;


SET default_table_access_method = heap;

-- TABLE: log_auditoria_default
CREATE TABLE auditoria.log_auditoria_default (
    id bigint DEFAULT nextval('auditoria.log_auditoria_id_seq'::regclass) CONSTRAINT log_auditoria_id_not_null NOT NULL,
    schemaname text CONSTRAINT log_auditoria_schemaname_not_null NOT NULL,
    tablename text CONSTRAINT log_auditoria_tablename_not_null NOT NULL,
    username text,
    dmlaction text CONSTRAINT log_auditoria_dmlaction_not_null NOT NULL,
    originaldata jsonb,
    executednewdata jsonb,
    changed_fields jsonb,
    executedsql text,
    uuid_ref uuid,
    hash_nuevo text,
    hash_original text,
    hash_anterior text,
    recorddatetime timestamp with time zone DEFAULT CURRENT_TIMESTAMP CONSTRAINT log_auditoria_recorddatetime_not_null NOT NULL,
    transaccion xid8,
    cliente inet,
    aplicacion text,
    version_hash smallint DEFAULT 1 CONSTRAINT log_auditoria_version_hash_not_null NOT NULL
);

-- TABLE ATTACH: log_auditoria_default
ALTER TABLE ONLY auditoria.log_auditoria ATTACH PARTITION auditoria.log_auditoria_default DEFAULT;

-- DEFAULT: log_auditoria id
ALTER TABLE ONLY auditoria.log_auditoria ALTER COLUMN id SET DEFAULT nextval('auditoria.log_auditoria_id_seq'::regclass);

-- CONSTRAINT: log_auditoria log_auditoria_pk
ALTER TABLE ONLY auditoria.log_auditoria
    ADD CONSTRAINT log_auditoria_pk PRIMARY KEY (id, recorddatetime);

-- CONSTRAINT: log_auditoria_default log_auditoria_default_pkey
ALTER TABLE ONLY auditoria.log_auditoria_default
    ADD CONSTRAINT log_auditoria_default_pkey PRIMARY KEY (id, recorddatetime);

-- INDEX: aiud_dmlaction_idx
CREATE INDEX aiud_dmlaction_idx ON ONLY auditoria.log_auditoria USING btree (dmlaction);

-- INDEX: aiud_recordtime_idx
CREATE INDEX aiud_recordtime_idx ON ONLY auditoria.log_auditoria USING btree (recorddatetime);

-- INDEX: aiud_ref_idx
CREATE INDEX aiud_ref_idx ON ONLY auditoria.log_auditoria USING btree (uuid_ref);

-- INDEX: aiud_tablename_idx
CREATE INDEX aiud_tablename_idx ON ONLY auditoria.log_auditoria USING btree (tablename);

-- INDEX: log_auditoria_default_dmlaction_idx
CREATE INDEX log_auditoria_default_dmlaction_idx ON auditoria.log_auditoria_default USING btree (dmlaction);

-- INDEX: log_auditoria_default_recorddatetime_idx
CREATE INDEX log_auditoria_default_recorddatetime_idx ON auditoria.log_auditoria_default USING btree (recorddatetime);

-- INDEX: log_auditoria_default_tablename_idx
CREATE INDEX log_auditoria_default_tablename_idx ON auditoria.log_auditoria_default USING btree (tablename);

-- INDEX: log_auditoria_default_uuid_ref_idx
CREATE INDEX log_auditoria_default_uuid_ref_idx ON auditoria.log_auditoria_default USING btree (uuid_ref);

-- INDEX ATTACH: log_auditoria_default_dmlaction_idx
ALTER INDEX auditoria.aiud_dmlaction_idx ATTACH PARTITION auditoria.log_auditoria_default_dmlaction_idx;

-- INDEX ATTACH: log_auditoria_default_pkey
ALTER INDEX auditoria.log_auditoria_pk ATTACH PARTITION auditoria.log_auditoria_default_pkey;

-- INDEX ATTACH: log_auditoria_default_recorddatetime_idx
ALTER INDEX auditoria.aiud_recordtime_idx ATTACH PARTITION auditoria.log_auditoria_default_recorddatetime_idx;

-- INDEX ATTACH: log_auditoria_default_tablename_idx
ALTER INDEX auditoria.aiud_tablename_idx ATTACH PARTITION auditoria.log_auditoria_default_tablename_idx;

-- INDEX ATTACH: log_auditoria_default_uuid_ref_idx
ALTER INDEX auditoria.aiud_ref_idx ATTACH PARTITION auditoria.log_auditoria_default_uuid_ref_idx;

-- TRIGGER: log_auditoria bitacora_inmutable
CREATE TRIGGER bitacora_inmutable BEFORE DELETE OR UPDATE ON auditoria.log_auditoria FOR EACH ROW EXECUTE FUNCTION auditoria.fn_bitacora_inmutable();

-- TRIGGER: log_auditoria bitacora_inmutable_truncate
CREATE TRIGGER bitacora_inmutable_truncate BEFORE TRUNCATE ON auditoria.log_auditoria FOR EACH STATEMENT EXECUTE FUNCTION auditoria.fn_bitacora_inmutable();

-- TRIGGER: log_auditoria_default bitacora_inmutable_truncate
CREATE TRIGGER bitacora_inmutable_truncate BEFORE TRUNCATE ON auditoria.log_auditoria_default FOR EACH STATEMENT EXECUTE FUNCTION auditoria.fn_bitacora_inmutable();

    RESET check_function_bodies;
    RESET search_path;
\elif :actual
    \echo '=== Bitacora ya en la version vigente: no se modifica ==='
\else
    \echo '=== Bitacora de una version anterior: se actualiza conservando los registros ==='

    -- (a) columnas y tipos (version 2.1 en adelante)
    ALTER TABLE auditoria.log_auditoria ADD COLUMN IF NOT EXISTS changed_fields jsonb;
    ALTER TABLE auditoria.log_auditoria ADD COLUMN IF NOT EXISTS hash_nuevo     text;
    ALTER TABLE auditoria.log_auditoria ADD COLUMN IF NOT EXISTS hash_original  text;
    ALTER TABLE auditoria.log_auditoria ADD COLUMN IF NOT EXISTS hash_anterior  text;
    ALTER TABLE auditoria.log_auditoria ADD COLUMN IF NOT EXISTS transaccion    xid8;
    ALTER TABLE auditoria.log_auditoria ADD COLUMN IF NOT EXISTS cliente        inet;
    ALTER TABLE auditoria.log_auditoria ADD COLUMN IF NOT EXISTS aplicacion     text;
    ALTER TABLE auditoria.log_auditoria ADD COLUMN IF NOT EXISTS version_hash   smallint NOT NULL DEFAULT 1;
    DO $$
    BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'auditoria' AND table_name = 'log_auditoria'
                   AND column_name = 'dmlaction' AND data_type = 'character') THEN
            ALTER TABLE auditoria.log_auditoria ALTER COLUMN dmlaction TYPE text;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'auditoria' AND table_name = 'log_auditoria'
                   AND column_name = 'recorddatetime' AND data_type = 'timestamp without time zone') THEN
            ALTER TABLE auditoria.log_auditoria ALTER COLUMN recorddatetime TYPE timestamptz
                USING recorddatetime AT TIME ZONE 'America/Mexico_City';
        END IF;
    END $$;

    -- (b) conversion a tabla particionada por mes (una sola vez)
    DO $$
    DECLARE
        v_desde     date;
        v_secuencia text;
        v_filas     bigint;
        v_dueno     text;
    BEGIN
        IF (SELECT relkind FROM pg_class WHERE oid = 'auditoria.log_auditoria'::regclass) = 'p' THEN
            RETURN;
        END IF;
        LOCK TABLE auditoria.log_auditoria IN ACCESS EXCLUSIVE MODE;
        v_secuencia := pg_get_serial_sequence('auditoria.log_auditoria', 'id');
        v_dueno     := (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'auditoria.log_auditoria'::regclass);
        ALTER TABLE auditoria.log_auditoria RENAME TO log_auditoria_previa;
        CREATE TABLE auditoria.log_auditoria (
            LIKE auditoria.log_auditoria_previa INCLUDING DEFAULTS INCLUDING COMMENTS INCLUDING STORAGE INCLUDING COMPRESSION
        ) PARTITION BY RANGE (recorddatetime);
        IF v_dueno <> current_user THEN
            EXECUTE format('ALTER TABLE auditoria.log_auditoria OWNER TO %I', v_dueno);
        END IF;
        ALTER TABLE auditoria.log_auditoria ADD CONSTRAINT log_auditoria_pk PRIMARY KEY (id, recorddatetime);
        CREATE TABLE auditoria.log_auditoria_default PARTITION OF auditoria.log_auditoria DEFAULT;
        SELECT min(recorddatetime)::date INTO v_desde FROM auditoria.log_auditoria_previa;
        PERFORM auditoria.fn_crear_particiones(3, v_desde);
        INSERT INTO auditoria.log_auditoria SELECT * FROM auditoria.log_auditoria_previa ORDER BY id;
        GET DIAGNOSTICS v_filas = ROW_COUNT;
        IF v_secuencia IS NOT NULL THEN
            EXECUTE format('ALTER SEQUENCE %s OWNED BY auditoria.log_auditoria.id', v_secuencia);
        END IF;
        DROP TABLE auditoria.log_auditoria_previa;
        RAISE NOTICE 'auditoria.log_auditoria particionada por mes; % registros copiados sin cambios', v_filas;
    END $$;

    -- (c) indices y triggers de inmutabilidad
    CREATE INDEX IF NOT EXISTS aiud_tablename_idx  ON auditoria.log_auditoria (tablename);
    CREATE INDEX IF NOT EXISTS aiud_dmlaction_idx  ON auditoria.log_auditoria (dmlaction);
    CREATE INDEX IF NOT EXISTS aiud_ref_idx        ON auditoria.log_auditoria (uuid_ref);
    CREATE INDEX IF NOT EXISTS aiud_recordtime_idx ON auditoria.log_auditoria (recorddatetime);
    DO $$
    DECLARE
        r record;
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'auditoria.log_auditoria'::regclass AND tgname = 'bitacora_inmutable') THEN
            CREATE TRIGGER bitacora_inmutable BEFORE UPDATE OR DELETE ON auditoria.log_auditoria
                FOR EACH ROW EXECUTE FUNCTION auditoria.fn_bitacora_inmutable();
        END IF;
        FOR r IN SELECT 'auditoria.log_auditoria'::regclass AS obj
                 UNION ALL SELECT inhrelid::regclass FROM pg_inherits WHERE inhparent = 'auditoria.log_auditoria'::regclass LOOP
            IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = r.obj AND tgname = 'bitacora_inmutable_truncate') THEN
                EXECUTE format('CREATE TRIGGER bitacora_inmutable_truncate BEFORE TRUNCATE ON %s
                                FOR EACH STATEMENT EXECUTE FUNCTION auditoria.fn_bitacora_inmutable()', r.obj);
            END IF;
        END LOOP;
    END $$;

    -- (d) comprobacion: no puede perderse ni un registro
    SELECT (count(*) = :filas) AS filas_ok FROM auditoria.log_auditoria \gset
    \if :filas_ok
    \else
        DO $$ BEGIN RAISE EXCEPTION 'la actualizacion de la bitacora cambio el numero de registros; se revierte todo'; END $$;
    \endif
\endif

-- 9. COMENTARIOS Y MARCA DE VERSION ---------------------------------------------------
-- COMMENT: FUNCTION asignar_biu(p_tabla text)
COMMENT ON FUNCTION auditoria.asignar_biu(p_tabla text) IS 'Crea el trigger audit_biu en la tabla indicada si no existe.';

-- COMMENT: FUNCTION asignar_trigger(p_tabla text)
COMMENT ON FUNCTION auditoria.asignar_trigger(p_tabla text) IS 'Alias de auditoria.asignar_triggers(text).';

-- COMMENT: FUNCTION asignar_triggers(p_tabla text)
COMMENT ON FUNCTION auditoria.asignar_triggers(p_tabla text) IS 'Crea audit_biu (habilitado), audit_aiud y audit_truncate (deshabilitados) en la tabla indicada si no existen.';

-- COMMENT: FUNCTION auditoria_aiud()
COMMENT ON FUNCTION auditoria.auditoria_aiud() IS 'Estandar de auditoria v2.2: registra INSERT/UPDATE/DELETE (UPDATE solo con cambios reales) en auditoria.log_auditoria. SECURITY DEFINER; trigger audit_aiud deshabilitado por defecto.';

-- COMMENT: FUNCTION auditoria_biu()
COMMENT ON FUNCTION auditoria.auditoria_biu() IS 'Estandar de auditoria v2.1: trigger BEFORE INSERT OR UPDATE. Asigna id/ref (uuidv7), row_version, fechas y usuarios de creacion/modificacion (GUC app.current_user o session_user); id y datos de creacion inmutables; bloqueo optimista opcional (argumento bloqueo_optimista); tolera tablas sin columnas canonicas.';

-- COMMENT: FUNCTION auditoria_truncate()
COMMENT ON FUNCTION auditoria.auditoria_truncate() IS 'Registra TRUNCATE (numero de filas) en auditoria.log_auditoria. SECURITY DEFINER; trigger audit_truncate deshabilitado por defecto.';

-- COMMENT: FUNCTION bloqueo_optimista(p_tabla text, p_activar boolean)
COMMENT ON FUNCTION auditoria.bloqueo_optimista(p_tabla text, p_activar boolean) IS 'Activa (true) o desactiva (false) el bloqueo optimista por row_version en audit_biu de la tabla. Requiere ser dueno de la tabla.';

-- COMMENT: FUNCTION deshabilitar_auditoria(p_tabla text)
COMMENT ON FUNCTION auditoria.deshabilitar_auditoria(p_tabla text) IS 'Deshabilita audit_aiud y audit_truncate en la tabla. Requiere ser dueno de la tabla.';

-- COMMENT: FUNCTION et_fn_grant_on_create()
COMMENT ON FUNCTION auditoria.et_fn_grant_on_create() IS 'Event trigger ddl_command_end: permisos para tablas, secuencias, funciones, procedimientos y vistas nuevos (excepto en auditoria y auditoria_control), y triggers de auditoria (audit_aiud y audit_truncate deshabilitados) en tablas con row_version.';

-- COMMENT: FUNCTION et_fn_registrar_ddl()
COMMENT ON FUNCTION auditoria.et_fn_registrar_ddl() IS 'Event trigger ddl_command_end: registra ENABLE/DISABLE de triggers audit_*/ALL/USER y el DDL del esquema auditoria.';

-- COMMENT: FUNCTION et_fn_registrar_drop()
COMMENT ON FUNCTION auditoria.et_fn_registrar_drop() IS 'Event trigger sql_drop: registra el DROP de triggers audit_* y de objetos del esquema auditoria.';

-- COMMENT: FUNCTION fn_bitacora_disponible()
COMMENT ON FUNCTION auditoria.fn_bitacora_disponible() IS 'true si auditoria.log_auditoria tiene la estructura v2.2 y existe auditoria.fn_registrar_evento.';

-- COMMENT: FUNCTION fn_bitacora_inmutable()
COMMENT ON FUNCTION auditoria.fn_bitacora_inmutable() IS 'Trigger: rechaza UPDATE, DELETE y TRUNCATE sobre la bitacora.';

-- COMMENT: FUNCTION fn_crear_particiones(p_meses_adelante integer, p_desde date)
COMMENT ON FUNCTION auditoria.fn_crear_particiones(p_meses_adelante integer, p_desde date) IS 'Crea las particiones mensuales de la bitacora desde p_desde (o el mes actual) hasta p_meses_adelante meses despues.';

-- COMMENT: FUNCTION fn_monitorear_slots()
COMMENT ON FUNCTION auditoria.fn_monitorear_slots() IS 'Estado y retraso (bytes y MB) de los slots de replicacion.';

-- COMMENT: FUNCTION fn_reconciliar_tabla(p_schema text, p_table text)
COMMENT ON FUNCTION auditoria.fn_reconciliar_tabla(p_schema text, p_table text) IS 'Diferencias entre la tabla viva y el ultimo registro de auditoria.log_auditoria por ref.';

-- COMMENT: FUNCTION fn_registrar_evento(p_esquema text, p_tabla text, p_operacion text, p_original jsonb, p_nuevo jsonb, p_cambios jsonb, p_usuario text, p_uuid_ref uuid)
COMMENT ON FUNCTION auditoria.fn_registrar_evento(p_esquema text, p_tabla text, p_operacion text, p_original jsonb, p_nuevo jsonb, p_cambios jsonb, p_usuario text, p_uuid_ref uuid) IS 'Uso interno: candado, eslabon SHA-256 (version_hash 2: incluye transaccion, cliente y aplicacion) e INSERT en la bitacora.';

-- COMMENT: FUNCTION fn_restringir_bitacora(p_objeto regclass)
COMMENT ON FUNCTION auditoria.fn_restringir_bitacora(p_objeto regclass) IS 'Quita todos los permisos salvo los del dueno y otorga SELECT a auditor.';

-- COMMENT: FUNCTION fn_verificar_cadena()
COMMENT ON FUNCTION auditoria.fn_verificar_cadena() IS 'Recorre auditoria.log_auditoria por id y recalcula cada eslabon (version_hash 1 y 2). Sin filas = cadena integra; con fila = primer registro alterado, borrado o insertado fuera de los triggers.';

-- COMMENT: FUNCTION habilitar_auditoria(p_tabla text)
COMMENT ON FUNCTION auditoria.habilitar_auditoria(p_tabla text) IS 'Habilita audit_aiud y audit_truncate en la tabla (los crea si faltan). Requiere ser dueno de la tabla.';

-- COMMENT: FUNCTION reporte_cobertura()
COMMENT ON FUNCTION auditoria.reporte_cobertura() IS 'Cobertura de auditoria por tabla: columnas ref/row_version y triggers audit_biu/audit_aiud.';


SET default_tablespace = '';

-- COMMENT: TABLE log_auditoria
COMMENT ON TABLE auditoria.log_auditoria IS 'Bitacora del estandar de auditoria: solo insercion, particionada por mes (recorddatetime), encadenada con SHA-256.';

-- COMMENT: COLUMN log_auditoria.dmlaction
COMMENT ON COLUMN auditoria.log_auditoria.dmlaction IS 'Operacion: INSERT, UPDATE o DELETE (TG_OP).';

-- COMMENT: COLUMN log_auditoria.changed_fields
COMMENT ON COLUMN auditoria.log_auditoria.changed_fields IS 'Solo UPDATE: campos modificados con su valor nuevo.';

-- COMMENT: COLUMN log_auditoria.hash_nuevo
COMMENT ON COLUMN auditoria.log_auditoria.hash_nuevo IS 'Eslabon SHA-256 (hex) de hash_anterior, esquema, tabla, operacion, datos, usuario y recorddatetime.';

-- COMMENT: COLUMN log_auditoria.hash_original
COMMENT ON COLUMN auditoria.log_auditoria.hash_original IS 'SHA-256 (hex) de la fila anterior (UPDATE/DELETE).';

-- COMMENT: COLUMN log_auditoria.hash_anterior
COMMENT ON COLUMN auditoria.log_auditoria.hash_anterior IS 'hash_nuevo del registro previo de la cadena (GENESIS en el primero).';

-- COMMENT: COLUMN log_auditoria.recorddatetime
COMMENT ON COLUMN auditoria.log_auditoria.recorddatetime IS 'Momento del evento (clock_timestamp).';

-- COMMENT: COLUMN log_auditoria.transaccion
COMMENT ON COLUMN auditoria.log_auditoria.transaccion IS 'Transaccion que origino el evento (pg_current_xact_id).';

-- COMMENT: COLUMN log_auditoria.cliente
COMMENT ON COLUMN auditoria.log_auditoria.cliente IS 'Direccion IP del cliente (inet_client_addr); con PgBouncer es la IP de PgBouncer. NULL por socket local.';

-- COMMENT: COLUMN log_auditoria.aplicacion
COMMENT ON COLUMN auditoria.log_auditoria.aplicacion IS 'application_name de la sesion.';

-- COMMENT: COLUMN log_auditoria.version_hash
COMMENT ON COLUMN auditoria.log_auditoria.version_hash IS 'Formula del eslabon: 1 = v2.1 (sin contexto), 2 = incluye transaccion, cliente y aplicacion.';

COMMENT ON SCHEMA auditoria IS 'Estandar de auditoria v2026.10.14 (bitacora v2, aiud v2.2, biu v2.1, registro de DDL).';

-- 10. PROPIEDAD Y ACCESO: todo el esquema a nombre de migrator; la bitacora, sus particiones y su secuencia solo
--     para su dueno (las aplicaciones escriben a traves de triggers SECURITY DEFINER) y SELECT para auditor.
DO $$
DECLARE
    r record;
BEGIN
    ALTER SCHEMA auditoria OWNER TO migrator;
    FOR r IN SELECT c.oid::regclass AS obj, c.relkind
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'auditoria' AND c.relkind IN ('r', 'p', 'v', 'm', 'S') AND pg_get_userbyid(c.relowner) <> 'migrator'
             ORDER BY c.relkind DESC   -- tablas antes que secuencias (las secuencias propias se transfieren con su tabla)
    LOOP
        IF pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid = r.obj)) <> 'migrator' THEN
            EXECUTE format('ALTER %s %s OWNER TO migrator',
                           CASE r.relkind WHEN 'S' THEN 'SEQUENCE' WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE 'TABLE' END, r.obj);
        END IF;
    END LOOP;
    FOR r IN SELECT p.oid::regprocedure AS obj FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'auditoria' AND pg_get_userbyid(p.proowner) <> 'migrator'
    LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO migrator', r.obj);
    END LOOP;
    FOR r IN SELECT c.oid::regclass AS obj FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'auditoria' AND c.relkind IN ('r', 'p', 'S')
    LOOP
        PERFORM auditoria.fn_restringir_bitacora(r.obj);
    END LOOP;
END $$;

-- 11b. PARTICIONES (mes en curso y los 3 siguientes; la verificacion diaria crea las siguientes) --------
SELECT auditoria.fn_crear_particiones(3);

-- Acceso al esquema: los desarrolladores y la aplicacion necesitan USAGE para llamar a habilitar_auditoria() y similares;
-- auditor lo necesita para leer la bitacora.
GRANT USAGE ON SCHEMA auditoria TO role_dev_dml, app_web_user, auditor;

-- Permisos de ejecucion de las funciones (los que el event trigger et_grant_on_create otorgaria al crearlas)
REVOKE ALL ON FUNCTION auditoria.fn_crear_particiones(integer,date) FROM PUBLIC;
REVOKE ALL ON FUNCTION auditoria.fn_registrar_evento(text,text,text,jsonb,jsonb,jsonb,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION auditoria.fn_restringir_bitacora(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auditoria.asignar_triggers(text) TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.auditoria_aiud() TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.auditoria_biu() TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.auditoria_truncate() TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.bloqueo_optimista(text,boolean) TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.deshabilitar_auditoria(text) TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.et_fn_grant_on_create() TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.et_fn_registrar_ddl() TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.et_fn_registrar_drop() TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.fn_bitacora_disponible() TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.fn_bitacora_inmutable() TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.fn_crear_particiones(integer,date) TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.fn_registrar_evento(text,text,text,jsonb,jsonb,jsonb,text,uuid) TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.fn_restringir_bitacora(regclass) TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.fn_verificar_cadena() TO app_web_user, role_dev_dml;
GRANT EXECUTE ON FUNCTION auditoria.habilitar_auditoria(text) TO app_web_user, role_dev_dml;

-- 12. ESQUEMA DE CONTROL: ancla de solo insercion y verificacion (dueno postgres, fuera del alcance de migrator) ----
CREATE SCHEMA IF NOT EXISTS auditoria_control AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA auditoria_control FROM PUBLIC;

CREATE TABLE IF NOT EXISTS auditoria_control.ancla (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    fecha           timestamptz NOT NULL DEFAULT clock_timestamp(),
    ultimo_id       bigint,
    ultimo_hash     text,
    total_registros bigint      NOT NULL,
    detalle         text
);
ALTER TABLE auditoria_control.ancla OWNER TO postgres;

COMMENT ON TABLE  auditoria_control.ancla                 IS 'Ancla de la bitacora auditoria.log_auditoria: estado al terminar cada verificacion correcta. Solo insercion.';
COMMENT ON COLUMN auditoria_control.ancla.ultimo_id       IS 'id del ultimo registro de la bitacora (NULL si estaba vacia).';
COMMENT ON COLUMN auditoria_control.ancla.ultimo_hash     IS 'hash_nuevo del ultimo registro.';
COMMENT ON COLUMN auditoria_control.ancla.total_registros IS 'Registros de la bitacora al anclar; la bitacora nunca debe tener menos.';
COMMENT ON COLUMN auditoria_control.ancla.detalle         IS 'Particiones creadas en la verificacion.';

CREATE OR REPLACE FUNCTION auditoria_control.fn_inmutable()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'auditoria_control: % sobre %.% no permitido; el ancla es de solo insercion', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$function$;
ALTER FUNCTION auditoria_control.fn_inmutable() OWNER TO postgres;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'auditoria_control.ancla'::regclass AND tgname = 'ancla_inmutable') THEN
        CREATE TRIGGER ancla_inmutable BEFORE UPDATE OR DELETE ON auditoria_control.ancla
            FOR EACH ROW EXECUTE FUNCTION auditoria_control.fn_inmutable();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'auditoria_control.ancla'::regclass AND tgname = 'ancla_inmutable_truncate') THEN
        CREATE TRIGGER ancla_inmutable_truncate BEFORE TRUNCATE ON auditoria_control.ancla
            FOR EACH STATEMENT EXECUTE FUNCTION auditoria_control.fn_inmutable();
    END IF;
END $$;

CREATE OR REPLACE FUNCTION auditoria_control.fn_verificar_y_anclar()
 RETURNS text
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
    a          record;
    v_ultimo   record;
    v_falla    record;
    v_total    bigint;
    v_creadas  integer := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = to_regclass('auditoria.log_auditoria')
                     AND attname = 'hash_nuevo' AND NOT attisdropped)
       OR NOT EXISTS (SELECT 1 FROM pg_attribute
                      WHERE attrelid = to_regclass('auditoria.log_auditoria')
                        AND attname = 'tablename' AND NOT attisdropped) THEN
        RETURN 'NO_APLICA: la base no tiene la bitacora del estandar de auditoria';
    END IF;

    IF to_regprocedure('auditoria.fn_crear_particiones(integer,date)') IS NOT NULL THEN
        v_creadas := auditoria.fn_crear_particiones(3);
    END IF;

    SELECT * INTO a FROM auditoria_control.ancla ORDER BY fecha DESC, id DESC LIMIT 1;
    SELECT count(*) INTO v_total FROM auditoria.log_auditoria;
    SELECT id, hash_nuevo INTO v_ultimo FROM auditoria.log_auditoria ORDER BY id DESC LIMIT 1;

    IF a.id IS NOT NULL THEN
        IF v_total < a.total_registros THEN
            RAISE EXCEPTION 'auditoria: la bitacora tiene % registros y el ancla del % registra %: faltan registros',
                v_total, a.fecha, a.total_registros;
        END IF;
        IF a.ultimo_id IS NOT NULL AND NOT EXISTS (
               SELECT 1 FROM auditoria.log_auditoria WHERE id = a.ultimo_id AND hash_nuevo = a.ultimo_hash) THEN
            RAISE EXCEPTION 'auditoria: el registro anclado id=% (ancla del %) no existe o cambio su hash',
                a.ultimo_id, a.fecha;
        END IF;
    END IF;

    SELECT * INTO v_falla FROM auditoria.fn_verificar_cadena() LIMIT 1;
    IF v_falla.registro_alterado IS NOT NULL THEN
        RAISE EXCEPTION 'auditoria: cadena rota en el registro % (esperado %, encontrado %)',
            v_falla.registro_alterado, v_falla.hash_esperado, v_falla.hash_encontrado;
    END IF;

    INSERT INTO auditoria_control.ancla (ultimo_id, ultimo_hash, total_registros, detalle)
    VALUES (v_ultimo.id, v_ultimo.hash_nuevo, v_total, format('particiones creadas: %s', v_creadas));

    RETURN format('OK: %s registros, ultimo id %s, particiones creadas %s',
                  v_total, coalesce(v_ultimo.id::text, '-'), v_creadas);
END;
$function$;
ALTER FUNCTION auditoria_control.fn_verificar_y_anclar() OWNER TO postgres;
COMMENT ON FUNCTION auditoria_control.fn_verificar_y_anclar() IS
    'Crea particiones, comprueba el ancla anterior y la cadena completa, y registra una nueva ancla. Excepcion si detecta alteracion.';

REVOKE ALL ON auditoria_control.ancla FROM PUBLIC;
REVOKE ALL ON FUNCTION auditoria_control.fn_verificar_y_anclar(), auditoria_control.fn_inmutable() FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditor') THEN
        GRANT USAGE ON SCHEMA auditoria_control TO auditor;
        GRANT SELECT ON auditoria_control.ancla TO auditor;
    END IF;
END $$;

-- 13. EVENT TRIGGERS (al final, para que la instalacion no deje registros de DDL en la bitacora) ----
CREATE EVENT TRIGGER et_auditoria_ddl ON ddl_command_end
        EXECUTE FUNCTION auditoria.et_fn_registrar_ddl();

CREATE EVENT TRIGGER et_auditoria_drop ON sql_drop
        EXECUTE FUNCTION auditoria.et_fn_registrar_drop();

CREATE EVENT TRIGGER et_grant_on_create ON ddl_command_end
        WHEN TAG IN ('CREATE TABLE', 'CREATE SEQUENCE', 'CREATE FUNCTION', 'CREATE PROCEDURE', 'CREATE VIEW', 'CREATE MATERIALIZED VIEW')
        EXECUTE FUNCTION auditoria.et_fn_grant_on_create();

-- 14. COMPROBACION FINAL (si algo no cuadra aborta y la transaccion se revierte) -----------------
DO $$
DECLARE
    v_funciones int; v_particiones int; v_triggers_bitacora int; v_event int; v_rotos int;
BEGIN
    SELECT count(*) INTO v_funciones FROM pg_proc WHERE pronamespace = 'auditoria'::regnamespace;
    SELECT count(*) INTO v_particiones FROM pg_inherits WHERE inhparent = 'auditoria.log_auditoria'::regclass;
    SELECT count(*) INTO v_triggers_bitacora FROM pg_trigger WHERE tgrelid = 'auditoria.log_auditoria'::regclass AND NOT tgisinternal;
    SELECT count(*) INTO v_event FROM pg_event_trigger WHERE evtname IN ('et_auditoria_ddl', 'et_auditoria_drop', 'et_grant_on_create');
    IF v_funciones < 21 OR v_particiones < 5 OR v_triggers_bitacora <> 2 OR v_event <> 3 THEN
        RAISE EXCEPTION 'Instalacion incompleta: funciones=% particiones=% triggers_bitacora=% event_triggers=%',
            v_funciones, v_particiones, v_triggers_bitacora, v_event;
    END IF;
    SELECT count(*) INTO v_rotos FROM auditoria.fn_verificar_cadena();
    IF v_rotos > 0 THEN
        RAISE WARNING 'La cadena de la bitacora tiene % eslabones que no verifican (puede venir de antes de esta instalacion)', v_rotos;
    END IF;
    RAISE NOTICE 'Estandar de auditoria listo: % funciones, % particiones, 3 event triggers; eslabones rotos: %.', v_funciones, v_particiones, v_rotos;
END $$;

COMMIT;
\echo
\echo '=== Estandar de auditoria instalado. Estado inicial de la base: ' :estado ' ==='

-- =====================================================================================
-- DESPUES DE INSTALAR
-- =====================================================================================
-- a) Asigna LOGIN y contrasena a los roles que el script creo sin LOGIN (migrator, etc.).
-- b) Las tablas que cree migrator reciben audit_biu automaticamente. Para auditar INSERT/UPDATE/DELETE/TRUNCATE:
--        SELECT auditoria.habilitar_auditoria('<esquema>.<tabla>');       -- lo ejecuta el dueno de la tabla
--    Si otro usuario crea la tabla, agrega los triggers con auditoria.asignar_triggers('<esquema>.<tabla>').
-- c) Verificacion diaria con pg_cron (se programa en la base `postgres`; opcional):
--        SELECT cron.schedule_in_database('auditoria_verificar_<base>', '30 2 * * *',
--               'SELECT auditoria_control.fn_verificar_y_anclar()', '<base>');
-- d) Con PgBouncer en modo transaccion, fija el usuario de la aplicacion dentro de cada transaccion:
--        SELECT set_config('app.current_user', '<usuario>', true);
