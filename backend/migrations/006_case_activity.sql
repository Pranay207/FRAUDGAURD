CREATE TABLE IF NOT EXISTS case_activity (
    tenant_id TEXT NOT NULL,
    activity_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, activity_id)
);

CREATE INDEX IF NOT EXISTS idx_case_activity_request_created ON case_activity(tenant_id, request_id, created_at DESC);
