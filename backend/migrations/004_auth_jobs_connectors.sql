CREATE TABLE IF NOT EXISTS analyst_users (
    tenant_id TEXT NOT NULL,
    analyst_id TEXT NOT NULL,
    email TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_by TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    PRIMARY KEY (tenant_id, analyst_id),
    UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_analyst_users_email ON analyst_users(tenant_id, email);

CREATE TABLE IF NOT EXISTS security_audit_events (
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT,
    actor_role TEXT,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_security_audit_created ON security_audit_events(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS jobs (
    tenant_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    result_json TEXT,
    priority INTEGER NOT NULL DEFAULT 100,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    run_after TEXT NOT NULL,
    lease_expires_at TEXT,
    created_by TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    PRIMARY KEY (tenant_id, job_id)
);

CREATE INDEX IF NOT EXISTS idx_jobs_ready ON jobs(status, run_after, priority, created_at);

CREATE TABLE IF NOT EXISTS connector_configs (
    tenant_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    route TEXT NOT NULL,
    source_path TEXT NOT NULL,
    config_json TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_by TEXT,
    created_at TEXT NOT NULL,
    last_run_at TEXT,
    PRIMARY KEY (tenant_id, connector_id)
);

CREATE INDEX IF NOT EXISTS idx_connector_configs_route ON connector_configs(tenant_id, route, is_active);

ALTER TABLE model_versions ADD COLUMN stage TEXT NOT NULL DEFAULT 'candidate';
ALTER TABLE model_versions ADD COLUMN is_active INTEGER NOT NULL DEFAULT 0;
ALTER TABLE model_versions ADD COLUMN training_job_id TEXT;
ALTER TABLE model_versions ADD COLUMN promoted_at TEXT;

CREATE INDEX IF NOT EXISTS idx_model_versions_active ON model_versions(tenant_id, model_name, is_active, created_at DESC);
