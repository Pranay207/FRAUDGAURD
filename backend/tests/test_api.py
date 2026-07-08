import importlib
import sqlite3

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    (raw_dir / "creditcard.csv").write_text(
        'Time,V1,V2,V3,V4,V5,V6,Amount,Class\n0,1,2,3,4,5,6,10.5,0\n120,1,2,3,4,5,6,12.0,1\n',
        encoding="utf-8",
    )
    (raw_dir / "phishing_websites.arff").write_text(
        '@relation phishing\n@attribute having_IP_Address {-1,1}\n@attribute Result {-1,1}\n@data\n1,1\n-1,-1\n',
        encoding="utf-8",
    )

    monkeypatch.setenv("FRAUDGUARD_DATABASE_PATH", str(tmp_path / "fraudguard.db"))
    monkeypatch.delenv("FRAUDGUARD_DATABASE_URL", raising=False)
    monkeypatch.setenv("FRAUDGUARD_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("FRAUDGUARD_API_KEY", "test_key")
    monkeypatch.setenv("FRAUDGUARD_MODEL_ARTIFACT_DIR", str(tmp_path / "models"))
    monkeypatch.setenv("FRAUDGUARD_TRAINING_DATA_DIR", str(raw_dir))

    import app.config as config
    config.get_settings.cache_clear()

    import app.db as db
    importlib.reload(db)

    import app.security as security_module
    importlib.reload(security_module)

    import app.services.repository as repository_module
    importlib.reload(repository_module)

    import app.services.models as models_module
    importlib.reload(models_module)

    import app.services.training as training_module
    importlib.reload(training_module)

    import app.services.webhooks as webhooks_module
    importlib.reload(webhooks_module)

    import app.services.scoring as scoring_module
    importlib.reload(scoring_module)

    import app.main as main_module
    importlib.reload(main_module)

    with TestClient(main_module.app) as test_client:
        yield test_client, webhooks_module, db, main_module


AUTH = {"Authorization": "Bearer test_key"}


def test_health_tenant_and_migrations(client) -> None:
    test_client, _, db, _ = client
    db.apply_migrations()
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ready", "tenant_seeded": True}

    tenant = test_client.get("/v1/tenant", headers=AUTH)
    assert tenant.status_code == 200
    assert tenant.json()["tenant_id"] == "demo-tenant"


def test_dashboard_shell_and_assets_load(client) -> None:
    test_client, _, _, _ = client
    root = test_client.get("/")
    dashboard = test_client.get("/dashboard")
    script = test_client.get("/dashboard/assets/app.js")
    styles = test_client.get("/dashboard/assets/styles.css")

    assert root.status_code == 200
    assert dashboard.status_code == 200
    assert "FraudGuard Console" in dashboard.text
    assert script.status_code == 200
    assert "loadGraphEntity" in script.text
    assert styles.status_code == 200
    assert ".graph-card" in styles.text


def test_legacy_sqlite_database_is_backed_up_and_rebuilt(tmp_path, monkeypatch) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    database_path = tmp_path / "fraudguard.db"

    connection = sqlite3.connect(database_path)
    connection.execute("CREATE TABLE audit_events (request_id TEXT PRIMARY KEY, route TEXT NOT NULL, fraud_score INTEGER NOT NULL)")
    connection.commit()
    connection.close()

    monkeypatch.setenv("FRAUDGUARD_DATABASE_PATH", str(database_path))
    monkeypatch.delenv("FRAUDGUARD_DATABASE_URL", raising=False)
    monkeypatch.setenv("FRAUDGUARD_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("FRAUDGUARD_API_KEY", "test_key")
    monkeypatch.setenv("FRAUDGUARD_MODEL_ARTIFACT_DIR", str(tmp_path / "models"))
    monkeypatch.setenv("FRAUDGUARD_TRAINING_DATA_DIR", str(raw_dir))

    import app.config as config
    config.get_settings.cache_clear()

    import app.db as db
    importlib.reload(db)

    db.init_db()

    backups = list(tmp_path.glob("fraudguard.legacy-*.db"))
    assert len(backups) == 1

    connection = sqlite3.connect(database_path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)").fetchall()}
        assert "tenant_id" in columns
        tenant = connection.execute("SELECT tenant_id FROM tenants").fetchone()
        assert tenant[0] == "demo-tenant"
    finally:
        connection.close()


def test_dashboard_seed_summary_and_api_keys(client) -> None:
    test_client, _, _, _ = client
    created = test_client.post("/v1/ops/api-keys", headers=AUTH, json={"key_name": "secondary"})
    assert created.status_code == 200
    assert created.json()["raw_key"].startswith("fg_")

    keys = test_client.get("/v1/ops/api-keys", headers=AUTH)
    assert keys.status_code == 200
    assert len(keys.json()) >= 2

    seed = test_client.post("/v1/dev/seed", headers=AUTH)
    assert seed.status_code == 200
    assert seed.json()["generated_cases"] == 15

    summary = test_client.get("/v1/ops/summary", headers=AUTH)
    assert summary.status_code == 200
    payload = summary.json()
    assert len(payload["metrics"]) == 6
    assert len(payload["recent_cases"]) > 0
    assert len(payload["top_signals"]) > 0


def test_dataset_inventory_endpoint(client) -> None:
    test_client, _, _, _ = client
    response = test_client.get("/v1/ops/datasets", headers=AUTH)
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 6
    datasets = {item["dataset_name"]: item for item in payload}
    assert datasets["creditcard"]["present"] is True
    assert datasets["creditcard"]["record_count"] == 2
    assert datasets["phishing_websites"]["record_count"] == 2
    assert datasets["sms_spam"]["present"] is False
    assert datasets["paysim"]["present"] is False


def test_transaction_idempotency_case_status_and_feedback_flow(client) -> None:
    test_client, _, _, _ = client
    session = test_client.post(
        "/v1/score/session",
        headers=AUTH,
        json={
            "user_id": "user-2",
            "session_id": "sess-2",
            "device_id": "device-2",
            "keystroke_mean_ms": 150,
            "session_duration_s": 80,
            "hour_of_day": 11,
            "ip_country": "IN",
        },
    )
    assert session.status_code == 200

    headers = {**AUTH, "Idempotency-Key": "txn-123"}
    payload = {
        "user_id": "user-2",
        "amount_paise": 155000,
        "payee_vpa": "urgent-clearance@upi",
        "upi_remark": "Government clearance payment",
        "session_id": "sess-2",
        "device_id": "device-2",
        "ip_country": "IN",
    }
    response1 = test_client.post("/v1/score/transaction", headers=headers, json=payload)
    response2 = test_client.post("/v1/score/transaction", headers=headers, json=payload)
    assert response1.status_code == 200
    assert response2.status_code == 200
    body1 = response1.json()
    body2 = response2.json()
    assert body1["request_id"] == body2["request_id"]
    assert body1["action"] in {"CHALLENGE", "BLOCK"}

    explain = test_client.get(f"/v1/explain/{body1['request_id']}", headers=AUTH)
    assert explain.status_code == 200
    assert explain.json()["route"] == "transaction"

    case_status = test_client.patch(
        f"/v1/ops/cases/{body1['request_id']}/status",
        headers=AUTH,
        json={"case_status": "INVESTIGATING", "assigned_to": "analyst-1"},
    )
    assert case_status.status_code == 200
    assert case_status.json()["case_status"] == "INVESTIGATING"

    detail = test_client.get(f"/v1/ops/cases/{body1['request_id']}", headers=AUTH)
    assert detail.status_code == 200
    detail_payload = detail.json()
    assert detail_payload["assigned_to"] == "analyst-1"
    assert detail_payload["case_status"] == "INVESTIGATING"

    feedback = test_client.post(
        f"/v1/ops/cases/{body1['request_id']}/feedback",
        headers=AUTH,
        json={"label": "CONFIRMED_FRAUD", "notes": "Matched scam complaint", "reported_by": "tester"},
    )
    assert feedback.status_code == 200
    assert feedback.json()["label"] == "CONFIRMED_FRAUD"


def test_onboard_webhook_queue_and_dispatch(client, monkeypatch) -> None:
    test_client, webhooks_module, _, _ = client

    webhook = test_client.post(
        "/v1/ops/webhooks",
        headers=AUTH,
        json={"event_type": "fraud.case.created", "url": "https://example.com/webhook", "secret": "abc"},
    )
    assert webhook.status_code == 200

    async def fake_deliver(item):
        return None

    monkeypatch.setattr(webhooks_module.dispatcher, "_deliver", fake_deliver)

    first = test_client.post(
        "/v1/score/onboard",
        headers=AUTH,
        json={
            "user_id": "onboard-1",
            "pan_hash": "a" * 64,
            "phone_hash": "b" * 64,
            "aadhaar_last4": "1234",
            "device": {"device_id": "shared-device", "sim_count": 1},
            "selfie_check_score": 0.1,
            "kyc_name_match_score": 0.95,
        },
    )
    assert first.status_code == 200

    second = test_client.post(
        "/v1/score/onboard",
        headers=AUTH,
        json={
            "user_id": "onboard-2",
            "pan_hash": "c" * 64,
            "phone_hash": "d" * 64,
            "aadhaar_last4": "5678",
            "device": {"device_id": "shared-device", "sim_count": 3, "is_rooted": True},
            "selfie_check_score": 0.8,
            "kyc_name_match_score": 0.5,
        },
    )
    assert second.status_code == 200
    payload = second.json()
    assert payload["fraud_score"] >= 700
    assert payload["action"] == "BLOCK"

    deliveries = test_client.get("/v1/ops/webhook-deliveries", headers=AUTH)
    assert deliveries.status_code == 200
    assert len(deliveries.json()) >= 1

    dispatch = test_client.post("/v1/ops/webhook-deliveries/dispatch", headers=AUTH)
    assert dispatch.status_code == 200
    assert dispatch.json()["failed"] == 0


def test_phishing_scoring_and_explain_flow(client) -> None:
    test_client, _, _, _ = client

    headers = {**AUTH, "Idempotency-Key": "phish-123"}
    payload = {
        "url": "http://192.168.0.1/verify-account",
        "source": "manual",
        "having_ip_address": -1,
        "url_length": 1,
        "shortening_service": 1,
        "having_at_symbol": 1,
        "double_slash_redirecting": -1,
        "prefix_suffix": -1,
        "having_sub_domain": 1,
        "sslfinal_state": -1,
        "domain_registration_length": -1,
        "favicon": 1,
        "port": 1,
        "https_token": 1,
        "request_url": 1,
        "url_of_anchor": 1,
        "links_in_tags": 1,
        "sfh": 1,
        "submitting_to_email": 1,
        "abnormal_url": 1,
        "redirect": 1,
        "on_mouseover": 1,
        "rightclick": 1,
        "popup_window": 1,
        "iframe": 1,
        "age_of_domain": -1,
        "dnsrecord": -1,
        "web_traffic": 1,
        "page_rank": -1,
        "google_index": 1,
        "links_pointing_to_page": 1,
        "statistical_report": 1,
    }

    response1 = test_client.post("/v1/score/phishing", headers=headers, json=payload)
    response2 = test_client.post("/v1/score/phishing", headers=headers, json=payload)
    assert response1.status_code == 200
    assert response2.status_code == 200
    body1 = response1.json()
    body2 = response2.json()
    assert body1["request_id"] == body2["request_id"]
    assert body1["action"] in {"CHALLENGE", "BLOCK"}

    explain = test_client.get(f"/v1/explain/{body1['request_id']}", headers=AUTH)
    assert explain.status_code == 200
    assert explain.json()["route"] == "phishing"


def test_train_models_and_model_registry(client, monkeypatch) -> None:
    test_client, _, _, main_module = client

    def fake_train_baseline_models():
        return {
            "behavioral": {"artifact_path": "data/models/behavioral_risk.joblib", "metrics": {"auc": 0.91, "precision": 0.84, "recall": 0.79}, "version_id": "ver-beh"},
            "identity": {"artifact_path": "data/models/identity_risk.joblib", "metrics": {"auc": 0.89, "precision": 0.8, "recall": 0.76}, "version_id": "ver-id"},
        }

    monkeypatch.setattr(main_module, "train_baseline_models", fake_train_baseline_models)

    response = test_client.post("/v1/dev/train-models", headers=AUTH)
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["metrics"]["behavioral"]["auc"] == 0.91

    models = test_client.get("/v1/ops/models", headers=AUTH)
    assert models.status_code == 200
    assert len(models.json()) >= 2
