CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    key_name TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE IF NOT EXISTS users (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    pan_hash TEXT,
    phone_hash TEXT,
    aadhaar_last4 TEXT,
    email_hash TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    last_ip_country TEXT DEFAULT 'IN',
    clean_streak_days INTEGER DEFAULT 0,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS devices (
    tenant_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    os TEXT,
    screen_res TEXT,
    is_rooted INTEGER DEFAULT 0,
    sim_count INTEGER DEFAULT 1,
    first_seen_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS user_devices (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id, device_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    tenant_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    fraud_score INTEGER NOT NULL,
    action TEXT NOT NULL,
    ip_country TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);

CREATE TABLE IF NOT EXISTS transactions (
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    amount_paise INTEGER NOT NULL,
    payee_vpa_hash TEXT NOT NULL,
    payee_vpa_raw TEXT NOT NULL,
    session_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    upi_remark TEXT,
    fraud_score INTEGER NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    route TEXT NOT NULL,
    user_id TEXT,
    fraud_score INTEGER NOT NULL,
    action TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    factors_json TEXT NOT NULL,
    request_json TEXT NOT NULL,
    case_status TEXT NOT NULL DEFAULT 'OPEN',
    assigned_to TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS feedback (
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    label TEXT NOT NULL,
    notes TEXT,
    reported_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    tenant_id TEXT NOT NULL,
    route TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, route, idempotency_key)
);

CREATE TABLE IF NOT EXISTS webhook_endpoints (
    tenant_id TEXT NOT NULL,
    webhook_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, webhook_id)
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    tenant_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    webhook_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    request_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    attempted_at TEXT NOT NULL,
    error_message TEXT,
    PRIMARY KEY (tenant_id, delivery_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_txn_user_created ON transactions(tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user_created ON sessions(tenant_id, user_id, created_at DESC);
