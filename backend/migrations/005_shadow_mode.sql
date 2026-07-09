CREATE TABLE IF NOT EXISTS shadow_decisions (
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    route TEXT NOT NULL,
    challenger_version TEXT NOT NULL,
    production_score INTEGER NOT NULL,
    production_action TEXT NOT NULL,
    shadow_score INTEGER NOT NULL,
    shadow_action TEXT NOT NULL,
    delta_score INTEGER NOT NULL,
    diverged INTEGER NOT NULL DEFAULT 0,
    shadow_reasons_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, request_id)
);

CREATE INDEX IF NOT EXISTS idx_shadow_decisions_created ON shadow_decisions(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shadow_decisions_diverged ON shadow_decisions(tenant_id, diverged, created_at DESC);
