-- =====================================================================================
-- Centinela-AI -- CORE schema (reconstructed 2026-09-07 for the autonomous local deploy)
-- =====================================================================================
-- The four core tables (infra_inventory, vulnerability_log, remediation_history,
-- runtime_alerts) plus the catalog/settings tables predate this repo and had NO DDL
-- anywhere in it (see core/schema.py's own docstring). They lived only on the external
-- centinela_db at 10.4.3.23. This file rebuilds them from every INSERT / SELECT / UPDATE
-- reference found in the codebase so a fresh, self-contained database can stand up.
--
-- Every statement is idempotent (IF NOT EXISTS). core/schema.py's ensure_core_schema()
-- still runs on every service start and creates the newer tables (finding_suppressions,
-- agent_actions, incidents, incident_events) on top of this.
-- =====================================================================================

-- ------------------------------------------------------------------ infra_inventory
CREATE TABLE IF NOT EXISTS public.infra_inventory (
    id              SERIAL PRIMARY KEY,
    asset_name      TEXT NOT NULL,
    asset_type      TEXT,
    endpoint        TEXT,
    ip_address      TEXT,
    criticality     TEXT DEFAULT 'MEDIUM',
    status          TEXT DEFAULT 'unknown',
    agent_id        TEXT,
    hostname        TEXT,
    last_audit      TIMESTAMP,
    last_scanned    TIMESTAMP,
    last_seen       TIMESTAMP,
    location_lat    DOUBLE PRECISION,
    location_lon    DOUBLE PRECISION,
    country_code    TEXT,
    cis_grade       TEXT,
    cis_percentage  NUMERIC,
    cis_checked_at  TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_infra_inventory_asset_name
    ON public.infra_inventory (asset_name);

-- ------------------------------------------------------------------ vulnerability_log
CREATE TABLE IF NOT EXISTS public.vulnerability_log (
    id                      SERIAL PRIMARY KEY,
    asset_id                INTEGER REFERENCES public.infra_inventory(id) ON DELETE CASCADE,
    cve_id                  TEXT,
    severity                TEXT,
    description             TEXT,
    status                  TEXT DEFAULT 'NEW',
    scan_engine             TEXT,
    tool_source             TEXT,
    detected_at             TIMESTAMP DEFAULT NOW(),
    url_path                TEXT,
    fingerprint_hash        TEXT,
    reachability_status     TEXT,
    standards               TEXT,
    sla_due_date            TIMESTAMP,
    finding_category        TEXT DEFAULT 'VULNERABILITY',
    risk_score              NUMERIC,
    epss_score              NUMERIC,
    is_cisa_kev             BOOLEAN DEFAULT FALSE,
    threat_intel_checked_at TIMESTAMP,
    business_impact         TEXT,
    executive_summary       TEXT,
    developer_steps         TEXT,
    fix_patch               TEXT
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_log_asset
    ON public.vulnerability_log (asset_id);
-- The codebase dedupes with `ON CONFLICT (fingerprint_hash)` -- it needs a real partial
-- unique index on that column alone (see CLAUDE.md gotcha #3).
CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerability_log_fingerprint
    ON public.vulnerability_log (fingerprint_hash) WHERE fingerprint_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vulnerability_log_status
    ON public.vulnerability_log (status);

-- ------------------------------------------------------------------ remediation_history
CREATE TABLE IF NOT EXISTS public.remediation_history (
    id             SERIAL PRIMARY KEY,
    vuln_id        INTEGER REFERENCES public.vulnerability_log(id) ON DELETE CASCADE,
    asset_id       INTEGER REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
    script_path    TEXT,
    approval_token TEXT DEFAULT 'PENDING_APPROVAL',
    can_automate   BOOLEAN DEFAULT FALSE,
    executed_bool  BOOLEAN DEFAULT FALSE,
    executed_at    TIMESTAMP,
    log_output     TEXT,
    status         TEXT,
    detected_at    TIMESTAMP DEFAULT NOW(),
    created_at     TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_remediation_history_vuln
    ON public.remediation_history (vuln_id);

-- ------------------------------------------------------------------ runtime_alerts
CREATE TABLE IF NOT EXISTS public.runtime_alerts (
    id            SERIAL PRIMARY KEY,
    asset_id      INTEGER REFERENCES public.infra_inventory(id) ON DELETE SET NULL,
    priority      TEXT,
    rule_name     TEXT,
    alert_text    TEXT,
    output_fields JSONB,
    detected_at   TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_runtime_alerts_asset
    ON public.runtime_alerts (asset_id);

-- ------------------------------------------------------------------ catalog tables
-- All LEFT JOIN'd from the API (a missing row degrades to a COALESCE default), but the
-- relations themselves must exist. Seeded with the values the code/frontend expect.
CREATE TABLE IF NOT EXISTS public.cat_severities (
    code        TEXT PRIMARY KEY,
    label       TEXT,
    badge_class TEXT
);
CREATE TABLE IF NOT EXISTS public.cat_statuses (
    code       TEXT PRIMARY KEY,
    label      TEXT,
    text_class TEXT
);
CREATE TABLE IF NOT EXISTS public.cat_compliance_standards (
    code TEXT PRIMARY KEY,
    name TEXT
);
CREATE TABLE IF NOT EXISTS public.cat_asset_types (
    code        TEXT PRIMARY KEY,
    label       TEXT,
    badge_class TEXT
);
CREATE TABLE IF NOT EXISTS public.system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    category    TEXT,
    description TEXT,
    updated_at  TIMESTAMP DEFAULT NOW()
);

INSERT INTO public.cat_severities (code, label, badge_class) VALUES
    ('CRITICAL', 'CRÍTICA', 'bg-red-500/20 text-red-400 border border-red-500/30'),
    ('HIGH',     'ALTA',    'bg-orange-500/20 text-orange-400 border border-orange-500/30'),
    ('MEDIUM',   'MEDIA',   'bg-amber-500/20 text-amber-400 border border-amber-500/30'),
    ('LOW',      'BAJA',    'bg-sky-500/20 text-sky-400 border border-sky-500/30'),
    ('INFO',     'INFO',    'bg-slate-500/20 text-slate-400 border border-slate-500/30'),
    ('NONE',     'NINGUNA', 'bg-slate-500/20 text-slate-400 border border-slate-500/30')
ON CONFLICT (code) DO NOTHING;

INSERT INTO public.cat_statuses (code, label, text_class) VALUES
    ('NEW',        'PENDIENTE IA',       'text-orange-500'),
    ('PENDING',    'PENDIENTE IA',       'text-orange-500'),
    ('OPEN',       'ABIERTA',            'text-orange-500'),
    ('CORRELATED', 'LISTO PARA APROBAR', 'text-[#06B6D4]'),
    ('AI_FAILED',  'FALLO IA',           'text-red-400'),
    ('AI_ERROR',   'ERROR IA',           'text-red-400'),
    ('REOPENED',   'REABIERTA',          'text-orange-500'),
    ('RESOLVED',   'RESUELTA',           'text-emerald-500'),
    ('SUPPRESSED', 'SUPRIMIDA',          'text-slate-500')
ON CONFLICT (code) DO NOTHING;

INSERT INTO public.cat_compliance_standards (code, name) VALUES
    ('ISO-27001-A12', 'ISO 27001 A.12 - Seguridad de las operaciones'),
    ('NIST-CSF-DE',   'NIST CSF - Detección (DE)')
ON CONFLICT (code) DO NOTHING;

INSERT INTO public.cat_asset_types (code, label, badge_class) VALUES
    ('SERVER',      'Servidor',        'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'),
    ('AppServer',   'App Server',      'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'),
    ('WORKSTATION', 'Estación',        'bg-teal-500/10 text-teal-400 border border-teal-500/20'),
    ('GitLab-Repo', 'Repositorio',     'bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20'),
    ('URL',         'URL / Servicio',  'bg-sky-500/10 text-sky-400 border border-sky-500/20'),
    ('IP',          'Host IP',         'bg-slate-500/10 text-slate-400 border border-slate-500/20'),
    ('DATABASE',    'Base de datos',   'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20')
ON CONFLICT (code) DO NOTHING;
