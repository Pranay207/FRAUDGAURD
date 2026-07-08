import importlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

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
    project_root = Path(__file__).resolve().parents[2]
    (project_root / "MODEL_EVALUATION_SUMMARY.json").write_text(
        '{"generated_at": "2026-07-08T10:23:20.488043+00:00", "models": {"behavioral": {"version_id": "demo-version", "artifact_path": "data/models/behavioral_risk.joblib", "metrics": {"auc": 0.94, "precision": 0.86, "recall": 0.8, "f1": 0.83}}}}',
        encoding="utf-8",
    )

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
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ready"
    assert body["tenant_seeded"] is True

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

def test_bulk_ingestion_endpoints(client) -> None:
    test_client, _, _, _ = client

    onboard_batch = test_client.post(
        "/v1/ingest/onboard",
        headers=AUTH,
        json={
            "events": [
                {
                    "user_id": "batch-onboard-1",
                    "pan_hash": "1" * 64,
                    "phone_hash": "2" * 64,
                    "aadhaar_last4": "1234",
                    "device": {"device_id": "batch-device-1", "sim_count": 1},
                    "selfie_check_score": 0.1,
                    "kyc_name_match_score": 0.95,
                },
                {
                    "user_id": "batch-onboard-2",
                    "pan_hash": "3" * 64,
                    "phone_hash": "4" * 64,
                    "aadhaar_last4": "5678",
                    "device": {"device_id": "batch-device-1", "sim_count": 3, "is_rooted": True},
                    "selfie_check_score": 0.8,
                    "kyc_name_match_score": 0.5,
                },
            ]
        },
    )
    assert onboard_batch.status_code == 200
    onboard_payload = onboard_batch.json()
    assert onboard_payload["route"] == "onboard"
    assert onboard_payload["accepted"] == 2
    assert onboard_payload["rejected"] == 0

    session_batch = test_client.post(
        "/v1/ingest/session",
        headers=AUTH,
        json={
            "events": [
                {
                    "user_id": "batch-onboard-1",
                    "session_id": "batch-session-1",
                    "device_id": "batch-device-1",
                    "keystroke_mean_ms": 145,
                    "session_duration_s": 70,
                    "hour_of_day": 10,
                    "ip_country": "IN",
                },
                {
                    "user_id": "batch-onboard-2",
                    "session_id": "batch-session-2",
                    "device_id": "batch-device-1",
                    "keystroke_mean_ms": 260,
                    "session_duration_s": 15,
                    "hour_of_day": 2,
                    "ip_country": "AE",
                },
            ]
        },
    )
    assert session_batch.status_code == 200
    assert session_batch.json()["accepted"] == 2

    transaction_batch = test_client.post(
        "/v1/ingest/transaction",
        headers=AUTH,
        json={
            "events": [
                {
                    "user_id": "batch-onboard-1",
                    "amount_paise": 25000,
                    "payee_vpa": "merchant@upi",
                    "upi_remark": "groceries",
                    "session_id": "batch-session-1",
                    "device_id": "batch-device-1",
                    "ip_country": "IN",
                    "transaction_type": "TRANSFER",
                    "source_balance_paise": 80000,
                    "destination_balance_paise": 10000,
                },
                {
                    "user_id": "batch-onboard-2",
                    "amount_paise": 175000,
                    "payee_vpa": "urgent-clearance@upi",
                    "upi_remark": "Government clearance payment",
                    "session_id": "batch-session-2",
                    "device_id": "batch-device-1",
                    "ip_country": "AE",
                    "transaction_type": "TRANSFER",
                    "source_balance_paise": 180000,
                    "destination_balance_paise": 0,
                },
            ]
        },
    )
    assert transaction_batch.status_code == 200
    transaction_payload = transaction_batch.json()
    assert transaction_payload["route"] == "transaction"
    assert transaction_payload["accepted"] == 2
    assert len(transaction_payload["results"]) == 2

    phishing_batch = test_client.post(
        "/v1/ingest/phishing",
        headers=AUTH,
        json={
            "events": [
                {
                    "url": "http://192.168.0.1/verify-account",
                    "source": "batch",
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
            ]
        },
    )
    assert phishing_batch.status_code == 200
    assert phishing_batch.json()["accepted"] == 1

def test_webhook_retry_and_dead_letter_flow(client, monkeypatch) -> None:
    test_client, webhooks_module, _, _ = client

    webhook = test_client.post(
        "/v1/ops/webhooks",
        headers=AUTH,
        json={"event_type": "fraud.case.created", "url": "https://example.com/webhook", "secret": "abc"},
    )
    assert webhook.status_code == 200

    async def always_fail(item):
        raise RuntimeError("network down")

    monkeypatch.setattr(webhooks_module.dispatcher, "_deliver", always_fail)

    blocked = test_client.post(
        "/v1/score/onboard",
        headers=AUTH,
        json={
            "user_id": "retry-onboard-1",
            "pan_hash": "9" * 64,
            "phone_hash": "8" * 64,
            "aadhaar_last4": "9999",
            "device": {"device_id": "retry-device", "sim_count": 3, "is_rooted": True},
            "selfie_check_score": 0.9,
            "kyc_name_match_score": 0.4,
        },
    )
    assert blocked.status_code == 200
    assert blocked.json()["action"] == "BLOCK"

    first_dispatch = test_client.post("/v1/ops/webhook-deliveries/dispatch", headers=AUTH)
    assert first_dispatch.status_code == 200

    deliveries = test_client.get("/v1/ops/webhook-deliveries", headers=AUTH)
    assert deliveries.status_code == 200
    latest = deliveries.json()[0]
    assert latest["retry_count"] >= 1
    assert latest["status"] == "QUEUED"

    from app.config import get_settings

    database_path = get_settings().database_path
    for _ in range(2):
        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "UPDATE webhook_deliveries SET next_attempt_at = ? WHERE delivery_id = ?",
                (datetime.now(UTC).isoformat(), latest["delivery_id"]),
            )
            connection.commit()
        finally:
            connection.close()
        next_dispatch = test_client.post("/v1/ops/webhook-deliveries/dispatch", headers=AUTH)
        assert next_dispatch.status_code == 200

    deliveries_after = test_client.get("/v1/ops/webhook-deliveries", headers=AUTH)
    latest_after = deliveries_after.json()[0]
    assert latest_after["status"] == "DEAD_LETTER"
    assert latest_after["retry_count"] >= latest_after["max_attempts"]




def test_bootstrap_login_and_rbac_flow(client) -> None:
    test_client, _, _, _ = client

    bootstrap = test_client.post(
        "/v1/auth/bootstrap",
        headers=AUTH,
        json={"email": "admin@fraudguard.local", "password": "StrongPass!234", "full_name": "Admin User"},
    )
    assert bootstrap.status_code == 200
    assert bootstrap.json()["role"] == "admin"

    login = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "admin@fraudguard.local", "password": "StrongPass!234"},
    )
    assert login.status_code == 200
    admin_token = login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    me = test_client.get("/v1/auth/me", headers=admin_headers)
    assert me.status_code == 200
    assert me.json()["role"] == "admin"

    viewer = test_client.post(
        "/v1/ops/analysts",
        headers=admin_headers,
        json={"email": "viewer@fraudguard.local", "password": "ViewerPass!234", "full_name": "Viewer User", "role": "viewer"},
    )
    assert viewer.status_code == 200
    assert viewer.json()["role"] == "viewer"

    viewer_login = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "viewer@fraudguard.local", "password": "ViewerPass!234"},
    )
    assert viewer_login.status_code == 200
    viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}

    forbidden = test_client.post("/v1/ops/api-keys", headers=viewer_headers, json={"key_name": "nope"})
    assert forbidden.status_code == 403


def test_retraining_jobs_connectors_and_monitoring(client, tmp_path) -> None:
    test_client, _, _, _ = client

    retrain = test_client.post(
        "/v1/dev/retraining-jobs",
        headers=AUTH,
        json={"promote_stage": "candidate", "activate_after_training": False},
    )
    assert retrain.status_code == 200
    assert retrain.json()["status"] == "QUEUED"

    source_path = tmp_path / "connector-events.json"
    source_path.write_text(
        '{"events": [{"user_id": "connector-user", "session_id": "connector-session", "device_id": "connector-device", "keystroke_mean_ms": 140, "session_duration_s": 60, "hour_of_day": 10, "ip_country": "IN"}]}',
        encoding="utf-8",
    )

    connector = test_client.post(
        "/v1/ops/connectors",
        headers=AUTH,
        json={"connector_type": "file_drop", "route": "session", "source_path": str(source_path), "config": {}},
    )
    assert connector.status_code == 200
    connector_id = connector.json()["connector_id"]

    run = test_client.post(f"/v1/ops/connectors/{connector_id}/run", headers=AUTH)
    assert run.status_code == 200
    assert run.json()["status"] == "QUEUED"

    jobs = test_client.get("/v1/ops/jobs", headers=AUTH)
    assert jobs.status_code == 200
    assert len(jobs.json()) >= 2

    monitoring_response = test_client.get("/v1/ops/monitoring", headers=AUTH)
    assert monitoring_response.status_code == 200
    assert monitoring_response.json()["queued_jobs"] >= 2

    metrics = test_client.get("/metrics", headers=AUTH)
    assert metrics.status_code == 200
    assert "fraudguard_queued_jobs" in metrics.text


def test_model_evaluation_summary_endpoint(client) -> None:
    test_client, _, _, _ = client
    response = test_client.get("/v1/ops/model-evaluation-summary", headers=AUTH)
    assert response.status_code == 200
    payload = response.json()
    assert "generated_at" in payload
    assert "behavioral" in payload["models"]
    assert payload["models"]["behavioral"]["metrics"]["auc"] == 0.94

