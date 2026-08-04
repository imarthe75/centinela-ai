/*
 Navicat Premium Dump SQL

 Source Server         : RPP CASmart
 Source Server Type    : PostgreSQL
 Source Server Version : 180003 (180003)
 Source Host           : 10.4.3.23:9999
 Source Catalog        : agendador_db
 Source Schema         : auditoria

 Target Server Type    : PostgreSQL
 Target Server Version : 180003 (180003)
 File Encoding         : 65001

 Date: 03/06/2026 08:24:52
*/


-- ----------------------------
-- Create schema if not exists
-- ----------------------------
CREATE SCHEMA IF NOT EXISTS "auditoria";

-- ----------------------------
-- Table structure for log_auditoria
-- ----------------------------
DROP TABLE IF EXISTS "auditoria"."log_auditoria";
CREATE TABLE "auditoria"."log_auditoria" (
  "schemaname" varchar COLLATE "pg_catalog"."default",
  "tablename" varchar COLLATE "pg_catalog"."default",
  "username" varchar COLLATE "pg_catalog"."default",
  "dmlaction" varchar COLLATE "pg_catalog"."default",
  "originaldata" text COLLATE "pg_catalog"."default",
  "executednewdata" text COLLATE "pg_catalog"."default",
  "executedsql" text COLLATE "pg_catalog"."default",
  "uuid_ref" uuid,
  "hash_nuevo" text COLLATE "pg_catalog"."default",
  "hash_original" text COLLATE "pg_catalog"."default",
  "recorddatetime" timestamp(6) DEFAULT now()
);

-- ----------------------------
-- Function structure for auditoria_aiud
-- ----------------------------
DROP FUNCTION IF EXISTS "auditoria"."auditoria_aiud"();
CREATE FUNCTION "auditoria"."auditoria_aiud"()
  RETURNS "pg_catalog"."trigger" AS $BODY$
DECLARE
    OldData TEXT;
    NewData TEXT;
    hash_nuevo text;
    hash_original text;
    usuario text;
    uuid_ref uuid;
BEGIN 
 
    IF (TG_OP = 'UPDATE') then
        hash_nuevo := md5(CAST(row(new.*) AS text));
        OldData := ROW(OLD.*);
        hash_original := (select a.hash_original from auditoria.log_auditoria as a where a.executednewdata = OldData limit 1);
        NewData := ROW(NEW.*);
        usuario := coalesce(new.dsusuariomodifica, current_user);
        uuid_ref := old.ref;
        INSERT INTO auditoria.log_auditoria 
        (
            schemaname
            ,tablename
            ,username
            ,dmlaction
            ,originaldata
            ,executednewdata
            ,executedsql
            ,hash_nuevo 
            ,hash_original 
            ,uuid_ref
        ) 
        VALUES 
        (
            TG_TABLE_SCHEMA::TEXT
            ,TG_TABLE_NAME::TEXT
            ,usuario
            ,substring(TG_OP,1,1)
            ,OldData
            ,NewData
            ,current_query()
            ,hash_nuevo
            ,hash_original
            ,uuid_ref
        );
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        OldData := ROW(OLD.*);
        hash_original := (select a.hash_original from auditoria.log_auditoria as a where a.executednewdata = OldData limit 1);
        hash_nuevo := (select a.hash_original from auditoria.log_auditoria as a where a.executednewdata = OldData limit 1);
        uuid_ref := old.ref;
        INSERT INTO auditoria.log_auditoria 
        (
            schemaname
            ,tablename
            ,username
            ,dmlaction
            ,originaldata
            ,executedsql
            ,hash_nuevo 
            ,hash_original
            ,uuid_ref
        )
        VALUES 
        (
            TG_TABLE_SCHEMA::TEXT
            ,TG_TABLE_NAME::TEXT
            ,session_user::TEXT
            ,substring(TG_OP,1,1)
            ,OldData
            ,current_query()
            ,hash_nuevo 
            ,hash_original
            ,uuid_ref
        );
        RETURN OLD;
    ELSIF (TG_OP = 'INSERT') THEN
        NewData := ROW(NEW.*);
        hash_original := md5(CAST(row(new.*) AS text));
        usuario := coalesce(new.dsusuariocreacion, current_user);
        uuid_ref := new.ref;
        INSERT INTO auditoria.log_auditoria 
        (
            schemaname
            ,tablename
            ,username
            ,dmlaction
            ,executednewdata
            ,executedsql
            ,hash_original
            ,uuid_ref
        )
        VALUES 
        (
            TG_TABLE_SCHEMA::TEXT
            ,TG_TABLE_NAME::TEXT
            ,usuario
            ,substring(TG_OP,1,1)
            ,NewData
            ,current_query()
            ,hash_original
            ,uuid_ref
        );
        RETURN NEW;
    ELSE
        RAISE WARNING '[AuditTable.trg_AuditDML] - Other action occurred: %, at %',TG_OP,now();
        RETURN NULL;
    END IF;
END;
$BODY$
  LANGUAGE plpgsql VOLATILE
  COST 100;

-- ----------------------------
-- Function structure for auditoria_biu
-- ----------------------------
DROP FUNCTION IF EXISTS "auditoria"."auditoria_biu"();
CREATE FUNCTION "auditoria"."auditoria_biu"()
  RETURNS "pg_catalog"."trigger" AS $BODY$
BEGIN
    if NEW.ref is null then
        BEGIN
            -- Intentar usar uuidv7 (disponible en PG18)
            NEW.ref := uuidv7();
        EXCEPTION WHEN undefined_function THEN
            -- Fallback a gen_random_uuid si no está PG18
            NEW.ref := gen_random_uuid();
        END;
    end if;
    if TG_OP = 'INSERT' then
        NEW.row_version := 1;
        if new.fccreacion is null then
            NEW.fccreacion := localtimestamp;
        END if;
        if new.dsusuariocreacion is null then
            NEW.dsusuariocreacion := user;
        end if;
    elsif TG_OP = 'UPDATE' then
        NEW.row_version := coalesce(OLD.row_version,0) + 1;
        if new.fcmodificacion is null then
            NEW.fcmodificacion := localtimestamp;
        end if;
        if new.dsusuariomodifica is null then
            NEW.dsusuariomodifica := user;
        end if;
    end if;
    RETURN NEW;
END;
$BODY$
  LANGUAGE plpgsql VOLATILE
  COST 100;

-- ----------------------------
-- Indexes structure for table log_auditoria
-- ----------------------------
CREATE INDEX "aiud_dmlaction_idx" ON "auditoria"."log_auditoria" USING btree (
  "dmlaction" COLLATE "pg_catalog"."default" "pg_catalog"."text_ops" ASC NULLS LAST
);
CREATE INDEX "aiud_recordtime_idx" ON "auditoria"."log_auditoria" USING btree (
  "recorddatetime" "pg_catalog"."timestamp_ops" ASC NULLS LAST
);
CREATE INDEX "aiud_ref_idx" ON "auditoria"."log_auditoria" USING btree (
  "uuid_ref" "pg_catalog"."uuid_ops" ASC NULLS LAST
);
CREATE INDEX "aiud_tablename_idx" ON "auditoria"."log_auditoria" USING btree (
  "tablename" COLLATE "pg_catalog"."default" "pg_catalog"."text_ops" ASC NULLS LAST
);
