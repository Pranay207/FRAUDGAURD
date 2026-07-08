ALTER TABLE webhook_deliveries ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webhook_deliveries ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3;
ALTER TABLE webhook_deliveries ADD COLUMN next_attempt_at TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN last_http_status INTEGER;

UPDATE webhook_deliveries
SET next_attempt_at = attempted_at
WHERE next_attempt_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_next_attempt ON webhook_deliveries(tenant_id, status, next_attempt_at);
