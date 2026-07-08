CREATE TABLE IF NOT EXISTS model_versions (
    tenant_id TEXT NOT NULL,
    model_name TEXT NOT NULL,
    version_id TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, model_name, version_id)
);

CREATE INDEX IF NOT EXISTS idx_model_versions_created ON model_versions(tenant_id, created_at DESC);
