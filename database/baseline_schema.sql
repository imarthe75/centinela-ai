--
-- PostgreSQL database dump
--

\restrict evF02t13fkaMDo7BPimaxjo1THd0yX1MLMjK6zb1zPacrOoW7xhNl2uosgM1XAQ

-- Dumped from database version 18.4 (Debian 18.4-1.pgdg12+1)
-- Dumped by pg_dump version 18.6 (Debian 18.6-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: auditoria; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA auditoria;


--
-- Name: hstore; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS hstore WITH SCHEMA public;


--
-- Name: EXTENSION hstore; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION hstore IS 'data type for storing sets of (key, value) pairs';


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: unaccent; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS unaccent WITH SCHEMA public;


--
-- Name: EXTENSION unaccent; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION unaccent IS 'text search dictionary that removes accents';


--
-- Name: auditoria_aiud(); Type: FUNCTION; Schema: auditoria; Owner: -
--

CREATE FUNCTION auditoria.auditoria_aiud() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: auditoria_biu(); Type: FUNCTION; Schema: auditoria; Owner: -
--

CREATE FUNCTION auditoria.auditoria_biu() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: f_unaccent(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.f_unaccent(text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
            SELECT public.unaccent($1)
        $_$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: log_auditoria; Type: TABLE; Schema: auditoria; Owner: -
--

CREATE TABLE auditoria.log_auditoria (
    schemaname character varying,
    tablename character varying,
    username character varying,
    dmlaction character varying,
    originaldata text,
    executednewdata text,
    executedsql text,
    uuid_ref uuid,
    hash_nuevo text,
    hash_original text,
    recorddatetime timestamp(6) without time zone DEFAULT now()
);


--
-- Name: agent_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_actions (
    action_type text NOT NULL,
    actor text DEFAULT 'centinela-ai'::text NOT NULL,
    entity_type text,
    summary text NOT NULL,
    detail jsonb,
    evidence text,
    outcome text DEFAULT 'success'::text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT uuidv7() CONSTRAINT agent_actions_id_new_not_null NOT NULL,
    asset_id uuid,
    entity_id text
);


--
-- Name: ai_provider_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_provider_usage (
    id uuid DEFAULT uuidv7() NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    tier text NOT NULL,
    model text,
    ok boolean NOT NULL,
    prompt_tokens integer,
    completion_tokens integer,
    latency_ms integer,
    error_kind text,
    error_text text,
    cooldown_until timestamp with time zone
);


--
-- Name: autoresponse_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.autoresponse_policy (
    action_kind text NOT NULL,
    max_severity_auto text,
    asset_scope text DEFAULT 'NON_CRITICAL'::text NOT NULL,
    require_cti_confirmed boolean DEFAULT true NOT NULL,
    daily_cap integer DEFAULT 3 NOT NULL,
    dry_run boolean DEFAULT true NOT NULL,
    active boolean DEFAULT false NOT NULL,
    updated_by text,
    updated_at timestamp without time zone DEFAULT now(),
    id uuid DEFAULT uuidv7() CONSTRAINT autoresponse_policy_id_new_not_null NOT NULL
);


--
-- Name: cat_asset_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cat_asset_types (
    code character varying(50) NOT NULL,
    label character varying(100) NOT NULL,
    badge_class character varying(255) NOT NULL,
    icon_name character varying(50) NOT NULL
);


--
-- Name: cat_compliance_standards; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cat_compliance_standards (
    code character varying(50) NOT NULL,
    name character varying(100) NOT NULL,
    domain character varying(100) NOT NULL,
    description text NOT NULL
);


--
-- Name: cat_criticality; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cat_criticality (
    code character varying(20) NOT NULL,
    label character varying(50) NOT NULL,
    badge_class character varying(255) NOT NULL
);


--
-- Name: cat_detection_engines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cat_detection_engines (
    code character varying(50) NOT NULL,
    label character varying(100) NOT NULL,
    description character varying(255) NOT NULL
);


--
-- Name: cat_incident_categories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cat_incident_categories (
    code character varying(50) NOT NULL,
    title character varying(100) NOT NULL,
    mitre_tactic character varying(50) NOT NULL,
    badge_class character varying(255) NOT NULL
);


--
-- Name: cat_severities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cat_severities (
    code character varying(20) NOT NULL,
    label character varying(50) NOT NULL,
    badge_class character varying(255) NOT NULL,
    display_order integer DEFAULT 0
);


--
-- Name: cat_statuses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cat_statuses (
    code character varying(30) NOT NULL,
    label character varying(50) NOT NULL,
    text_class character varying(255) NOT NULL,
    display_order integer DEFAULT 0
);


--
-- Name: cmmi_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cmmi_evidence (
    id uuid DEFAULT uuidv7() NOT NULL,
    scope text NOT NULL,
    asset_id uuid,
    area text NOT NULL,
    item_key text NOT NULL,
    level text DEFAULT 'L1'::text NOT NULL,
    status text NOT NULL,
    detail jsonb,
    evidence_ref text,
    collected_at timestamp without time zone DEFAULT now() NOT NULL,
    valid_until timestamp without time zone,
    attested_by text
);


--
-- Name: finding_suppressions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_suppressions (
    cve_id text,
    url_path_pattern text,
    fingerprint_hash text,
    reason text NOT NULL,
    scope text DEFAULT 'FALSE_POSITIVE'::text NOT NULL,
    created_by text DEFAULT 'analyst'::text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    match_count integer DEFAULT 0 NOT NULL,
    last_matched_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    expires_at timestamp without time zone,
    id uuid DEFAULT uuidv7() CONSTRAINT finding_suppressions_id_new_not_null NOT NULL,
    asset_id uuid,
    review_status text,
    reviewed_by text,
    reviewed_at timestamp without time zone,
    review_note text
);


--
-- Name: incident_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_events (
    source text NOT NULL,
    occurred_at timestamp without time zone NOT NULL,
    tactic text,
    severity text,
    summary text,
    incident_id uuid NOT NULL,
    source_id uuid NOT NULL
);


--
-- Name: incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incidents (
    title text NOT NULL,
    category_code text,
    severity text DEFAULT 'MEDIUM'::text NOT NULL,
    status text DEFAULT 'OPEN'::text NOT NULL,
    kill_chain text[],
    indicators jsonb,
    narrative text,
    ai_summary text,
    analyst_notes text,
    recommended_containment text,
    first_event_at timestamp without time zone,
    last_event_at timestamp without time zone,
    detected_at timestamp without time zone DEFAULT now() NOT NULL,
    contained_at timestamp without time zone,
    closed_at timestamp without time zone,
    event_count integer DEFAULT 0 NOT NULL,
    fingerprint text,
    id uuid DEFAULT uuidv7() CONSTRAINT incidents_id_new_not_null NOT NULL,
    asset_id uuid
);


--
-- Name: infra_inventory; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.infra_inventory (
    asset_type character varying(50),
    endpoint character varying(255),
    status character varying(50) DEFAULT 'ACTIVE'::character varying,
    last_scanned timestamp without time zone DEFAULT now(),
    asset_name character varying(255),
    agent_id character varying(255),
    criticality character varying(50) DEFAULT 'MEDIUM'::character varying,
    location_lat character varying(255),
    location_lon character varying(255),
    country_code character varying(255),
    last_audit character varying(255),
    last_seen timestamp without time zone,
    cis_grade character varying(20),
    cis_percentage numeric(5,1),
    cis_checked_at timestamp without time zone,
    hostname character varying(255),
    id uuid DEFAULT uuidv7() CONSTRAINT infra_inventory_id_new_not_null NOT NULL
);


--
-- Name: remediation_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remediation_history (
    action_taken text,
    status character varying(50),
    executed_at timestamp without time zone DEFAULT now(),
    output text,
    approval_token character varying(255),
    executed_bool boolean DEFAULT false,
    script_path text,
    can_automate text,
    log_output text,
    id uuid DEFAULT uuidv7() CONSTRAINT remediation_history_id_new_not_null NOT NULL,
    vuln_id uuid
);


--
-- Name: runtime_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.runtime_alerts (
    priority character varying(50),
    rule_name character varying(255),
    alert_text text,
    detected_at timestamp without time zone DEFAULT now(),
    output_fields jsonb,
    id uuid DEFAULT uuidv7() CONSTRAINT runtime_alerts_id_new_not_null NOT NULL,
    asset_id uuid
);


--
-- Name: soar_ip_blocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.soar_ip_blocks (
    ip text NOT NULL,
    rule_name text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    unblocked_at timestamp without time zone,
    id uuid DEFAULT uuidv7() CONSTRAINT soar_ip_blocks_id_new_not_null NOT NULL,
    asset_id uuid,
    vuln_id uuid,
    remediation_id uuid,
    unblock_vuln_id uuid,
    unblock_remediation_id uuid
);


--
-- Name: system_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_settings (
    key character varying(255) NOT NULL,
    value text,
    category character varying(100),
    description text,
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: vulnerability_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerability_log (
    cve_id character varying(100),
    severity character varying(50),
    description text,
    status character varying(50) DEFAULT 'OPEN'::character varying,
    detected_at timestamp without time zone DEFAULT now(),
    fix_patch text,
    standards text,
    executive_summary text,
    business_impact text,
    developer_steps text,
    scan_engine character varying(50),
    url_path text,
    fingerprint_hash character varying(64),
    reachability_status character varying(20) DEFAULT 'REACHABLE'::character varying,
    sla_due_date timestamp without time zone,
    epss_score numeric(5,4) DEFAULT 0.0,
    is_cisa_kev boolean DEFAULT false,
    risk_score numeric(5,2) DEFAULT 0.0,
    threat_intel_checked_at timestamp without time zone,
    finding_category character varying(20) DEFAULT 'VULNERABILITY'::character varying NOT NULL,
    id uuid DEFAULT uuidv7() CONSTRAINT vulnerability_log_id_new_not_null NOT NULL,
    asset_id uuid,
    real_severity text,
    risk_verdict text
);


--
-- Name: vulnerability_log_fixpatch_backup_20260923; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerability_log_fixpatch_backup_20260923 (
    id integer,
    asset_id integer,
    cve_id character varying(100),
    description text,
    fix_patch text,
    executive_summary text,
    business_impact text,
    developer_steps text
);


--
-- Name: vulnerability_log_vendored_noise_backup_20260923; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerability_log_vendored_noise_backup_20260923 (
    id integer,
    asset_id integer,
    cve_id character varying(100),
    severity character varying(50),
    status character varying(50),
    url_path text,
    detected_at timestamp without time zone,
    fingerprint_hash character varying(64)
);


--
-- Name: agent_actions agent_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_actions
    ADD CONSTRAINT agent_actions_pkey PRIMARY KEY (id);


--
-- Name: ai_provider_usage ai_provider_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_provider_usage
    ADD CONSTRAINT ai_provider_usage_pkey PRIMARY KEY (id);


--
-- Name: autoresponse_policy autoresponse_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.autoresponse_policy
    ADD CONSTRAINT autoresponse_policy_pkey PRIMARY KEY (id);


--
-- Name: cat_asset_types cat_asset_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cat_asset_types
    ADD CONSTRAINT cat_asset_types_pkey PRIMARY KEY (code);


--
-- Name: cat_compliance_standards cat_compliance_standards_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cat_compliance_standards
    ADD CONSTRAINT cat_compliance_standards_pkey PRIMARY KEY (code);


--
-- Name: cat_criticality cat_criticality_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cat_criticality
    ADD CONSTRAINT cat_criticality_pkey PRIMARY KEY (code);


--
-- Name: cat_detection_engines cat_detection_engines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cat_detection_engines
    ADD CONSTRAINT cat_detection_engines_pkey PRIMARY KEY (code);


--
-- Name: cat_incident_categories cat_incident_categories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cat_incident_categories
    ADD CONSTRAINT cat_incident_categories_pkey PRIMARY KEY (code);


--
-- Name: cat_severities cat_severities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cat_severities
    ADD CONSTRAINT cat_severities_pkey PRIMARY KEY (code);


--
-- Name: cat_statuses cat_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cat_statuses
    ADD CONSTRAINT cat_statuses_pkey PRIMARY KEY (code);


--
-- Name: cmmi_evidence cmmi_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cmmi_evidence
    ADD CONSTRAINT cmmi_evidence_pkey PRIMARY KEY (id);


--
-- Name: finding_suppressions finding_suppressions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_suppressions
    ADD CONSTRAINT finding_suppressions_pkey PRIMARY KEY (id);


--
-- Name: incident_events incident_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_events
    ADD CONSTRAINT incident_events_pkey PRIMARY KEY (incident_id, source, source_id);


--
-- Name: incidents incidents_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_fingerprint_key UNIQUE (fingerprint);


--
-- Name: incidents incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_pkey PRIMARY KEY (id);


--
-- Name: infra_inventory infra_inventory_asset_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.infra_inventory
    ADD CONSTRAINT infra_inventory_asset_name_key UNIQUE (asset_name);


--
-- Name: infra_inventory infra_inventory_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.infra_inventory
    ADD CONSTRAINT infra_inventory_pkey PRIMARY KEY (id);


--
-- Name: remediation_history remediation_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remediation_history
    ADD CONSTRAINT remediation_history_pkey PRIMARY KEY (id);


--
-- Name: runtime_alerts runtime_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_alerts
    ADD CONSTRAINT runtime_alerts_pkey PRIMARY KEY (id);


--
-- Name: soar_ip_blocks soar_ip_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soar_ip_blocks
    ADD CONSTRAINT soar_ip_blocks_pkey PRIMARY KEY (id);


--
-- Name: system_settings system_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_pkey PRIMARY KEY (key);


--
-- Name: vulnerability_log vulnerability_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_log
    ADD CONSTRAINT vulnerability_log_pkey PRIMARY KEY (id);


--
-- Name: aiud_dmlaction_idx; Type: INDEX; Schema: auditoria; Owner: -
--

CREATE INDEX aiud_dmlaction_idx ON auditoria.log_auditoria USING btree (dmlaction);


--
-- Name: aiud_recordtime_idx; Type: INDEX; Schema: auditoria; Owner: -
--

CREATE INDEX aiud_recordtime_idx ON auditoria.log_auditoria USING btree (recorddatetime);


--
-- Name: aiud_ref_idx; Type: INDEX; Schema: auditoria; Owner: -
--

CREATE INDEX aiud_ref_idx ON auditoria.log_auditoria USING btree (uuid_ref);


--
-- Name: aiud_tablename_idx; Type: INDEX; Schema: auditoria; Owner: -
--

CREATE INDEX aiud_tablename_idx ON auditoria.log_auditoria USING btree (tablename);


--
-- Name: idx_agent_actions_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_actions_created ON public.agent_actions USING btree (created_at DESC);


--
-- Name: idx_agent_actions_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_actions_type ON public.agent_actions USING btree (action_type, created_at DESC);


--
-- Name: idx_ai_provider_usage_tier_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_provider_usage_tier_ts ON public.ai_provider_usage USING btree (tier, ts DESC);


--
-- Name: idx_cmmi_evidence_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cmmi_evidence_asset ON public.cmmi_evidence USING btree (asset_id);


--
-- Name: idx_finding_suppressions_fp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_suppressions_fp ON public.finding_suppressions USING btree (fingerprint_hash) WHERE (fingerprint_hash IS NOT NULL);


--
-- Name: idx_finding_suppressions_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_suppressions_lookup ON public.finding_suppressions USING btree (active, asset_id, cve_id);


--
-- Name: idx_incident_events_src; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incident_events_src ON public.incident_events USING btree (source, source_id);


--
-- Name: idx_incidents_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incidents_status ON public.incidents USING btree (status, detected_at DESC);


--
-- Name: idx_infra_inventory_asset_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_infra_inventory_asset_name ON public.infra_inventory USING btree (asset_name);


--
-- Name: idx_infra_inventory_asset_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_infra_inventory_asset_type ON public.infra_inventory USING btree (asset_type);


--
-- Name: idx_infra_inventory_endpoint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_infra_inventory_endpoint ON public.infra_inventory USING btree (endpoint);


--
-- Name: idx_remediation_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_remediation_vuln_id ON public.remediation_history USING btree (vuln_id);


--
-- Name: idx_runtime_alerts_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_runtime_alerts_asset_id ON public.runtime_alerts USING btree (asset_id);


--
-- Name: idx_runtime_alerts_detected_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_runtime_alerts_detected_at ON public.runtime_alerts USING btree (detected_at DESC);


--
-- Name: idx_soar_ip_blocks_open; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_soar_ip_blocks_open ON public.soar_ip_blocks USING btree (expires_at) WHERE (unblocked_at IS NULL);


--
-- Name: idx_vuln_log_asset_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vuln_log_asset_id ON public.vulnerability_log USING btree (asset_id);


--
-- Name: idx_vuln_log_cve_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vuln_log_cve_id ON public.vulnerability_log USING btree (cve_id);


--
-- Name: idx_vuln_log_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vuln_log_severity ON public.vulnerability_log USING btree (severity);


--
-- Name: idx_vuln_log_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vuln_log_status ON public.vulnerability_log USING btree (status);


--
-- Name: idx_vulnerability_log_fingerprint_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_vulnerability_log_fingerprint_unique ON public.vulnerability_log USING btree (fingerprint_hash) WHERE (fingerprint_hash IS NOT NULL);


--
-- Name: uq_autoresponse_policy_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_autoresponse_policy_kind ON public.autoresponse_policy USING btree (action_kind);


--
-- Name: uq_cmmi_evidence; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_cmmi_evidence ON public.cmmi_evidence USING btree (scope, COALESCE(asset_id, '00000000-0000-0000-0000-000000000000'::uuid), area, item_key);


--
-- Name: agent_actions agent_actions_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_actions
    ADD CONSTRAINT agent_actions_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.infra_inventory(id) ON DELETE SET NULL;


--
-- Name: cmmi_evidence cmmi_evidence_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cmmi_evidence
    ADD CONSTRAINT cmmi_evidence_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.infra_inventory(id) ON DELETE CASCADE;


--
-- Name: finding_suppressions finding_suppressions_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_suppressions
    ADD CONSTRAINT finding_suppressions_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.infra_inventory(id) ON DELETE CASCADE;


--
-- Name: incident_events incident_events_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_events
    ADD CONSTRAINT incident_events_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id) ON DELETE CASCADE;


--
-- Name: incidents incidents_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.infra_inventory(id) ON DELETE SET NULL;


--
-- Name: soar_ip_blocks soar_ip_blocks_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soar_ip_blocks
    ADD CONSTRAINT soar_ip_blocks_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.infra_inventory(id) ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--

\unrestrict evF02t13fkaMDo7BPimaxjo1THd0yX1MLMjK6zb1zPacrOoW7xhNl2uosgM1XAQ

