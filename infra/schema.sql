CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY,
    pan_hash VARCHAR(64) NOT NULL,
    phone_hash VARCHAR(64) NOT NULL,
    aadhaar_last4 VARCHAR(4),
    email_hash VARCHAR(64),
    kyc_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    synthetic_id_score SMALLINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(128) PRIMARY KEY,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    os VARCHAR(50),
    screen_res VARCHAR(20),
    is_rooted BOOLEAN DEFAULT FALSE,
    sim_count SMALLINT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_devices (
    user_id UUID NOT NULL REFERENCES users(user_id),
    device_id VARCHAR(128) NOT NULL REFERENCES devices(device_id),
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS transactions (
    txn_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    amount_paise BIGINT NOT NULL,
    payee_vpa_hash VARCHAR(64) NOT NULL,
    device_id VARCHAR(128),
    fraud_score SMALLINT NOT NULL,
    action_taken VARCHAR(20) NOT NULL,
    upi_remark TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS feedback (
    feedback_id UUID PRIMARY KEY,
    txn_id UUID,
    user_id UUID,
    label VARCHAR(32) NOT NULL,
    reported_by VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
