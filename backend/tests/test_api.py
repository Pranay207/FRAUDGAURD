import asyncio
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
        "{\"generated_at\": \"2026-07-09T09:42:00+00:00\", \"models\": {\"behavioral\": {\"version_id\": \"demo-version\", \"artifact_path\": \"data/models/behavioral_risk.joblib\", \"metrics\": {\"auc\": 0.94, \"precision\": 0.86, \"recall\": 0.8, \"f1\": 0.83, \"accuracy\": 0.91, \"true_negatives\": 812, \"false_positives\": 54, \"false_negatives\": 39, \"true_positives\": 156, \"negative_support\": 866, \"positive_support\": 195, \"total_test_samples\": 1061}}, \"identity\": {\"version_id\": \"demo-identity-version\", \"artifact_path\": \"data/models/identity_risk.joblib\", \"metrics\": {\"auc\": 0.91, \"precision\": 0.82, \"recall\": 0.78, \"f1\": 0.8, \"accuracy\": 0.89, \"true_negatives\": 621, \"false_positives\": 46, \"false_negatives\": 33, \"true_positives\": 118, \"negative_support\": 667, \"positive_support\": 151, \"total_test_samples\": 818}}}}",
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


def load_run_worker_module():
    project_root = Path(__file__).resolve().parents[1]
    worker_path = project_root / "scripts" / "run_worker.py"
    spec = importlib.util.spec_from_file_location("fraudguard_run_worker", worker_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load run_worker module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    assert "linked-case-graph-jump" in script.text
    assert "Evaluation snapshot" in script.text
    assert "No model evidence recorded for this case" in script.text
    assert "Challenger interpretation" in script.text
    assert "Recall / TPR" in script.text
    assert "FPR" in script.text
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


def test_shadow_summary_and_pilot_report_endpoints(client) -> None:
    test_client, _, _, _ = client

    seed = test_client.post("/v1/dev/seed", headers=AUTH)
    assert seed.status_code == 200

    shadow = test_client.get("/v1/ops/shadow-summary", headers=AUTH)
    assert shadow.status_code == 200
    shadow_payload = shadow.json()
    assert shadow_payload["challenger_version"] == "challenger_v1"
    assert shadow_payload["total"] == 15
    assert len(shadow_payload["route_breakdown"]) >= 3

    shadow_items = test_client.get("/v1/ops/shadow-decisions?limit=5&diverged_only=true", headers=AUTH)
    assert shadow_items.status_code == 200
    items_payload = shadow_items.json()["items"]
    assert len(items_payload) >= 1
    assert all(item["diverged"] is True for item in items_payload)
    first_request_id = items_payload[0]["request_id"]

    shadow_detail = test_client.get(f"/v1/ops/shadow-decisions/{first_request_id}", headers=AUTH)
    assert shadow_detail.status_code == 200
    detail_payload = shadow_detail.json()
    assert detail_payload["request_id"] == first_request_id
    assert detail_payload["challenger_version"] == "challenger_v1"

    pilot = test_client.get("/v1/ops/pilot-report", headers=AUTH)
    assert pilot.status_code == 200
    pilot_payload = pilot.json()
    assert pilot_payload["compared_events"] == shadow_payload["total"]
    assert pilot_payload["challenger_version"] == "challenger_v1"
    assert "Shadow challenger reviewed" in pilot_payload["notes"][0]

    exported = test_client.get("/v1/ops/pilot-report/export", headers=AUTH)
    assert exported.status_code == 200
    assert "text/markdown" in exported.headers["content-type"]
    assert "FraudGuard Pilot Report" in exported.text
    assert "demo-tenant" in exported.text

    shadow_export = test_client.get("/v1/ops/shadow-decisions/export?limit=5&diverged_only=true", headers=AUTH)
    assert shadow_export.status_code == 200
    assert "text/csv" in shadow_export.headers["content-type"]
    assert "request_id,route,challenger_version,production_score,production_action,shadow_score,shadow_action,delta_score,diverged,shadow_reasons,created_at" in shadow_export.text
    assert first_request_id in shadow_export.text
    assert "challenger_v1" in shadow_export.text


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

    activity_export = test_client.get(f"/v1/ops/cases/{body1['request_id']}/activity/export", headers=AUTH)
    assert activity_export.status_code == 200
    assert "text/csv" in activity_export.headers["content-type"]
    assert "activity_id,request_id,event_type,actor_id,details,created_at" in activity_export.text
    assert "case.status_updated" in activity_export.text
    assert body1["request_id"] in activity_export.text

    case_export = test_client.get(f"/v1/ops/cases/{body1['request_id']}/export", headers=AUTH)
    assert case_export.status_code == 200
    assert "text/markdown" in case_export.headers["content-type"]
    assert "FraudGuard Case Report" in case_export.text
    assert "## Model Evidence" in case_export.text
    assert "CONFIRMED_FRAUD" in case_export.text
    assert body1["request_id"] in case_export.text


def test_bulk_case_status_endpoint(client) -> None:
    test_client, _, _, _ = client

    seed = test_client.post("/v1/dev/seed", headers=AUTH)
    assert seed.status_code == 200

    cases = test_client.get("/v1/ops/cases?limit=2&case_status=OPEN", headers=AUTH)
    assert cases.status_code == 200
    request_ids = [item["request_id"] for item in cases.json()["items"][:2]]
    assert len(request_ids) == 2

    bulk = test_client.post(
        "/v1/ops/cases/bulk-status",
        headers=AUTH,
        json={"request_ids": request_ids, "case_status": "INVESTIGATING", "assigned_to": "bulk-analyst"},
    )
    assert bulk.status_code == 200
    payload = bulk.json()
    assert payload["updated"] == 2
    assert payload["assigned_to"] == "bulk-analyst"

    for request_id in request_ids:
        detail = test_client.get(f"/v1/ops/cases/{request_id}", headers=AUTH)
        assert detail.status_code == 200
        body = detail.json()
        assert body["case_status"] == "INVESTIGATING"
        assert body["assigned_to"] == "bulk-analyst"
        assert any(item["event_type"] == "case.status_bulk_updated" for item in body["activity"])



def test_case_list_search_filter(client) -> None:
    test_client, _, _, _ = client

    baseline = test_client.post(
        "/v1/score/session",
        headers=AUTH,
        json={
            "user_id": "baseline-user",
            "session_id": "baseline-session",
            "device_id": "baseline-device",
            "keystroke_mean_ms": 110,
            "session_duration_s": 180,
            "hour_of_day": 11,
            "ip_country": "IN",
        },
    )
    assert baseline.status_code == 200

    session = test_client.post(
        "/v1/score/session",
        headers=AUTH,
        json={
            "user_id": "search-user-1",
            "session_id": "search-session-1",
            "device_id": "search-device-1",
            "keystroke_mean_ms": 140,
            "session_duration_s": 90,
            "hour_of_day": 12,
            "ip_country": "IN",
        },
    )
    assert session.status_code == 200

    transaction = test_client.post(
        "/v1/score/transaction",
        headers=AUTH,
        json={
            "user_id": "search-user-1",
            "amount_paise": 120000,
            "payee_vpa": "search-risk@upi",
            "upi_remark": "priority verification",
            "session_id": "search-session-1",
            "device_id": "search-device-1",
            "ip_country": "IN",
        },
    )
    assert transaction.status_code == 200
    request_id = transaction.json()["request_id"]

    by_user = test_client.get("/v1/ops/cases?search=search-user-1", headers=AUTH)
    assert by_user.status_code == 200
    user_items = by_user.json()["items"]
    assert any(item["request_id"] == request_id for item in user_items)
    assert all("search-user-1" in (item.get("user_id") or "") for item in user_items)

    by_request = test_client.get(f"/v1/ops/cases?search={request_id[-8:]}", headers=AUTH)
    assert by_request.status_code == 200
    request_items = by_request.json()["items"]
    assert len(request_items) == 1
    assert request_items[0]["request_id"] == request_id

    exported = test_client.get("/v1/ops/cases/export?search=search-user-1", headers=AUTH)
    assert exported.status_code == 200
    assert request_id in exported.text
    assert "baseline-user" not in exported.text



def test_case_queue_export_endpoint(client) -> None:
    test_client, _, _, _ = client

    seed = test_client.post("/v1/dev/seed", headers=AUTH)
    assert seed.status_code == 200

    cases = test_client.get("/v1/ops/cases?limit=1", headers=AUTH)
    assert cases.status_code == 200
    first = cases.json()["items"][0]

    updated = test_client.patch(
        f"/v1/ops/cases/{first['request_id']}/status",
        headers=AUTH,
        json={"case_status": "INVESTIGATING", "assigned_to": "queue-analyst"},
    )
    assert updated.status_code == 200

    feedback = test_client.post(
        f"/v1/ops/cases/{first['request_id']}/feedback",
        headers=AUTH,
        json={"label": "CONFIRMED_FRAUD", "notes": "Escalated from queue export test", "reported_by": "tester"},
    )
    assert feedback.status_code == 200

    exported = test_client.get("/v1/ops/cases/export?limit=10&case_status=INVESTIGATING", headers=AUTH)
    assert exported.status_code == 200
    assert "text/csv" in exported.headers["content-type"]
    assert "request_id,route,user_id,fraud_score,action,case_status,assigned_to,feedback_label" in exported.text
    assert first["request_id"] in exported.text
    assert "queue-analyst" in exported.text
    assert "CONFIRMED_FRAUD" in exported.text



def test_case_detail_includes_model_evidence(client) -> None:
    test_client, _, _, _ = client

    response = test_client.post(
        "/v1/score/session",
        headers=AUTH,
        json={
            "user_id": "evidence-user",
            "session_id": "evidence-session",
            "device_id": "evidence-device",
            "keystroke_mean_ms": 240,
            "session_duration_s": 22,
            "hour_of_day": 2,
            "ip_country": "IN",
        },
    )
    assert response.status_code == 200

    detail = test_client.get(f"/v1/ops/cases/{response.json()['request_id']}", headers=AUTH)
    assert detail.status_code == 200
    body = detail.json()
    assert len(body["model_evidence"]) >= 1
    evidence = body["model_evidence"][0]
    assert evidence["component"] == "behavioral"
    assert evidence["model_name"] == "behavioral"
    assert evidence["source"] in {"fallback_logic", "trained_artifact", "packaged_artifact"}
    assert "model_evidence" not in body["request_payload"]


def test_case_detail_includes_linked_cases(client) -> None:
    test_client, _, _, _ = client

    first = test_client.post(
        "/v1/score/onboard",
        headers=AUTH,
        json={
            "user_id": "linked-user-1",
            "pan_hash": "1" * 64,
            "phone_hash": "2" * 64,
            "aadhaar_last4": "1234",
            "device": {"device_id": "linked-device-1", "sim_count": 2},
            "selfie_check_score": 0.1,
            "kyc_name_match_score": 0.95,
        },
    )
    assert first.status_code == 200

    second = test_client.post(
        "/v1/score/onboard",
        headers=AUTH,
        json={
            "user_id": "linked-user-2",
            "pan_hash": "3" * 64,
            "phone_hash": "4" * 64,
            "aadhaar_last4": "5678",
            "device": {"device_id": "linked-device-1", "sim_count": 1},
            "selfie_check_score": 0.3,
            "kyc_name_match_score": 0.85,
        },
    )
    assert second.status_code == 200

    detail = test_client.get(f"/v1/ops/cases/{first.json()['request_id']}", headers=AUTH)
    assert detail.status_code == 200
    linked_cases = detail.json()["linked_cases"]
    assert any(item["request_id"] == second.json()["request_id"] for item in linked_cases)
    linked = next(item for item in linked_cases if item["request_id"] == second.json()["request_id"])
    assert "shared_device" in linked["matched_signals"]


def test_onboard_webhook_queue_and_dispatch(client, monkeypatch) -> None:
    test_client, webhooks_module, _, _ = client
    from app.services.repository import repository

    webhook = test_client.post(
        "/v1/ops/webhooks",
        headers=AUTH,
        json={"event_type": "fraud.case.created", "url": "https://example.com/webhook", "secret": "abc12345"},
    )
    assert webhook.status_code == 200
    webhook_id = webhook.json()["webhook_id"]
    assert webhook.json()["has_secret"] is True
    assert "secret" not in webhook.json()

    listed = test_client.get("/v1/ops/webhooks", headers=AUTH)
    assert listed.status_code == 200
    listed_item = next(item for item in listed.json() if item["webhook_id"] == webhook_id)
    assert listed_item["has_secret"] is True
    assert "secret" not in listed_item

    rotated = test_client.patch(
        f"/v1/ops/webhooks/{webhook_id}/secret",
        headers=AUTH,
        json={"secret": "rotated-secret-123"},
    )
    assert rotated.status_code == 200
    assert rotated.json()["has_secret"] is True

    captured = []

    async def fake_deliver(item):
        captured.append(item)
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

    queued = repository.list_queued_webhook_deliveries("demo-tenant", limit=10)
    assert any(item["webhook_id"] == webhook_id and item["secret"] == "rotated-secret-123" for item in queued)

    dispatch = test_client.post("/v1/ops/webhook-deliveries/dispatch", headers=AUTH)
    assert dispatch.status_code == 200
    assert dispatch.json()["failed"] == 0
    assert any(item["secret"] == "rotated-secret-123" for item in captured)


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
    runs = [
        {
            "behavioral": {
                "artifact_path": "data/models/behavioral_risk_v1.joblib",
                "metrics": {"auc": 0.91, "precision": 0.84, "recall": 0.79, "f1": 0.81, "accuracy": 0.9},
                "version_id": "ver-beh-1",
            },
            "identity": {
                "artifact_path": "data/models/identity_risk_v1.joblib",
                "metrics": {"auc": 0.89, "precision": 0.8, "recall": 0.76, "f1": 0.78, "accuracy": 0.88},
                "version_id": "ver-id-1",
            },
        },
        {
            "behavioral": {
                "artifact_path": "data/models/behavioral_risk_v2.joblib",
                "metrics": {"auc": 0.94, "precision": 0.87, "recall": 0.82, "f1": 0.84, "accuracy": 0.92},
                "version_id": "ver-beh-2",
            }
        },
    ]

    def fake_train_baseline_models():
        return runs.pop(0)

    monkeypatch.setattr(main_module, "train_baseline_models", fake_train_baseline_models)

    response = test_client.post("/v1/dev/train-models", headers=AUTH)
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["metrics"]["behavioral"]["auc"] == 0.91

    second_response = test_client.post("/v1/dev/train-models", headers=AUTH)
    assert second_response.status_code == 200
    second_payload = second_response.json()
    assert second_payload["metrics"]["behavioral"]["auc"] == 0.94

    models = test_client.get("/v1/ops/models", headers=AUTH)
    assert models.status_code == 200
    models_payload = models.json()
    assert len(models_payload) >= 3
    behavioral_versions = [item for item in models_payload if item["model_name"] == "behavioral"]
    assert {item["version_id"] for item in behavioral_versions} >= {"ver-beh-1", "ver-beh-2"}
    assert all(item["is_active"] is False for item in behavioral_versions)
    assert all(item["training_job_id"].startswith("sync-train-") for item in models_payload)

    activate_first = test_client.post(
        "/v1/ops/models/behavioral/ver-beh-1/activate",
        headers=AUTH,
        json={"stage": "production"},
    )
    assert activate_first.status_code == 200
    assert activate_first.json()["is_active"] is True

    activate_second = test_client.post(
        "/v1/ops/models/behavioral/ver-beh-2/activate",
        headers=AUTH,
        json={"stage": "shadow"},
    )
    assert activate_second.status_code == 200
    assert activate_second.json()["version_id"] == "ver-beh-2"
    assert activate_second.json()["stage"] == "shadow"

    refreshed_models = test_client.get("/v1/ops/models", headers=AUTH)
    assert refreshed_models.status_code == 200
    refreshed_payload = refreshed_models.json()
    behavioral_after = [item for item in refreshed_payload if item["model_name"] == "behavioral"]
    active_behavioral = [item for item in behavioral_after if item["is_active"]]
    assert len(active_behavioral) == 1
    assert active_behavioral[0]["version_id"] == "ver-beh-2"
    assert active_behavioral[0]["stage"] == "shadow"
    prior_version = next(item for item in behavioral_after if item["version_id"] == "ver-beh-1")
    assert prior_version["is_active"] is False

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

    second_bootstrap = test_client.post(
        "/v1/auth/bootstrap",
        headers=AUTH,
        json={"email": "admin2@fraudguard.local", "password": "StrongPass!234", "full_name": "Admin User 2"},
    )
    assert second_bootstrap.status_code == 409

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
    assert me.json()["auth_method"] == "bearer"

    analyst = test_client.post(
        "/v1/ops/analysts",
        headers=admin_headers,
        json={"email": "analyst@fraudguard.local", "password": "AnalystPass!234", "full_name": "Analyst User", "role": "analyst"},
    )
    assert analyst.status_code == 200
    assert analyst.json()["role"] == "analyst"

    viewer = test_client.post(
        "/v1/ops/analysts",
        headers=admin_headers,
        json={"email": "viewer@fraudguard.local", "password": "ViewerPass!234", "full_name": "Viewer User", "role": "viewer"},
    )
    assert viewer.status_code == 200
    assert viewer.json()["role"] == "viewer"

    analyst_login = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "analyst@fraudguard.local", "password": "AnalystPass!234"},
    )
    assert analyst_login.status_code == 200
    analyst_headers = {"Authorization": f"Bearer {analyst_login.json()['access_token']}"}

    viewer_login = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "viewer@fraudguard.local", "password": "ViewerPass!234"},
    )
    assert viewer_login.status_code == 200
    viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}

    seed = test_client.post("/v1/dev/seed", headers=AUTH)
    assert seed.status_code == 200
    cases = test_client.get("/v1/ops/cases?limit=1", headers=AUTH)
    assert cases.status_code == 200
    request_id = cases.json()["items"][0]["request_id"]

    viewer_cases = test_client.get("/v1/ops/cases?limit=1", headers=viewer_headers)
    assert viewer_cases.status_code == 200

    viewer_forbidden_key = test_client.post("/v1/ops/api-keys", headers=viewer_headers, json={"key_name": "nope"})
    assert viewer_forbidden_key.status_code == 403

    viewer_forbidden_feedback = test_client.post(
        f"/v1/ops/cases/{request_id}/feedback",
        headers=viewer_headers,
        json={"label": "FALSE_POSITIVE", "notes": "viewer cannot mutate", "reported_by": "viewer"},
    )
    assert viewer_forbidden_feedback.status_code == 403

    viewer_forbidden_webhook_secret = test_client.patch(
        "/v1/ops/webhooks/nonexistent/secret",
        headers=viewer_headers,
        json={"secret": "viewer-cannot-rotate"},
    )
    assert viewer_forbidden_webhook_secret.status_code == 403

    analyst_summary = test_client.get("/v1/ops/summary", headers=analyst_headers)
    assert analyst_summary.status_code == 200

    analyst_case_update = test_client.patch(
        f"/v1/ops/cases/{request_id}/status",
        headers=analyst_headers,
        json={"case_status": "INVESTIGATING", "assigned_to": "analyst@fraudguard.local"},
    )
    assert analyst_case_update.status_code == 200
    assert analyst_case_update.json()["assigned_to"] == "analyst@fraudguard.local"

    analyst_feedback = test_client.post(
        f"/v1/ops/cases/{request_id}/feedback",
        headers=analyst_headers,
        json={"label": "CONFIRMED_FRAUD", "notes": "analyst escalation", "reported_by": "analyst@fraudguard.local"},
    )
    assert analyst_feedback.status_code == 200
    assert analyst_feedback.json()["label"] == "CONFIRMED_FRAUD"

    self_deactivate = test_client.patch(
        f"/v1/ops/analysts/{analyst.json()['analyst_id']}/status",
        headers=analyst_headers,
        json={"is_active": False},
    )
    assert self_deactivate.status_code == 403

    deactivate_analyst = test_client.patch(
        f"/v1/ops/analysts/{analyst.json()['analyst_id']}/status",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert deactivate_analyst.status_code == 200
    assert deactivate_analyst.json()["is_active"] is False

    inactive_me = test_client.get("/v1/auth/me", headers=analyst_headers)
    assert inactive_me.status_code == 401

    inactive_login = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "analyst@fraudguard.local", "password": "AnalystPass!234"},
    )
    assert inactive_login.status_code == 401

    reactivate_analyst = test_client.patch(
        f"/v1/ops/analysts/{analyst.json()['analyst_id']}/status",
        headers=admin_headers,
        json={"is_active": True},
    )
    assert reactivate_analyst.status_code == 200
    assert reactivate_analyst.json()["is_active"] is True

    relogin_analyst = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "analyst@fraudguard.local", "password": "AnalystPass!234"},
    )
    assert relogin_analyst.status_code == 200

    analyst_forbidden_analyst_create = test_client.post(
        "/v1/ops/analysts",
        headers=analyst_headers,
        json={"email": "blocked@fraudguard.local", "password": "BlockedPass!234", "full_name": "Blocked", "role": "viewer"},
    )
    assert analyst_forbidden_analyst_create.status_code == 403

    analyst_forbidden_retraining = test_client.post(
        "/v1/dev/retraining-jobs",
        headers=analyst_headers,
        json={"promote_stage": "candidate", "activate_after_training": False},
    )
    assert analyst_forbidden_retraining.status_code == 403

    admin_api_key = test_client.post("/v1/ops/api-keys", headers=admin_headers, json={"key_name": "admin-created"})
    assert admin_api_key.status_code == 200

    admin_audit = test_client.get("/v1/ops/security-audit?event_type=analyst.status_updated", headers=admin_headers)
    assert admin_audit.status_code == 200
    assert any(item["details"]["analyst_id"] == analyst.json()["analyst_id"] for item in admin_audit.json())




def test_security_posture_endpoint(client) -> None:
    test_client, _, _, _ = client

    response = test_client.get("/v1/ops/security-posture", headers=AUTH)
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "needs_attention"
    assert payload["highest_severity"] == "critical"
    finding_ids = {item["id"] for item in payload["findings"]}
    assert "default_api_key" in finding_ids
    assert "default_auth_secret" in finding_ids
    assert "sqlite_runtime" in finding_ids

    bootstrap = test_client.post(
        "/v1/auth/bootstrap",
        headers=AUTH,
        json={"email": "posture-admin@fraudguard.local", "password": "StrongPass!234", "full_name": "Posture Admin"},
    )
    assert bootstrap.status_code == 200
    login = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "posture-admin@fraudguard.local", "password": "StrongPass!234"},
    )
    assert login.status_code == 200
    admin_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    viewer = test_client.post(
        "/v1/ops/analysts",
        headers=admin_headers,
        json={"email": "posture-viewer@fraudguard.local", "password": "ViewerPass!234", "full_name": "Posture Viewer", "role": "viewer"},
    )
    assert viewer.status_code == 200
    viewer_login = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "posture-viewer@fraudguard.local", "password": "ViewerPass!234"},
    )
    assert viewer_login.status_code == 200
    viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}
    forbidden = test_client.get("/v1/ops/security-posture", headers=viewer_headers)
    assert forbidden.status_code == 403


def test_security_posture_flags_placeholder_secrets(monkeypatch) -> None:
    monkeypatch.setenv("FRAUDGUARD_API_KEY", "replace-with-strong-api-key")
    monkeypatch.setenv("FRAUDGUARD_AUTH_SECRET", "replace-with-a-strong-secret")
    monkeypatch.setenv("FRAUDGUARD_DATABASE_URL", "postgresql://fg:replace-with-db-password@postgres:5432/fraudguard")

    import app.config as config

    config.get_settings.cache_clear()
    settings = config.get_settings()
    posture = settings.security_posture()
    finding_ids = {item["id"] for item in posture["findings"]}
    assert "placeholder_api_key" in finding_ids
    assert "placeholder_auth_secret" in finding_ids

def test_security_audit_filters_and_export(client, tmp_path) -> None:
    test_client, _, _, _ = client

    bootstrap = test_client.post(
        "/v1/auth/bootstrap",
        headers=AUTH,
        json={"email": "audit-admin@fraudguard.local", "password": "StrongPass!234", "full_name": "Audit Admin"},
    )
    assert bootstrap.status_code == 200

    login = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "audit-admin@fraudguard.local", "password": "StrongPass!234"},
    )
    assert login.status_code == 200
    admin_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    analyst = test_client.post(
        "/v1/ops/analysts",
        headers=admin_headers,
        json={"email": "audit-viewer@fraudguard.local", "password": "ViewerPass!234", "full_name": "Audit Viewer", "role": "viewer"},
    )
    assert analyst.status_code == 200

    api_key = test_client.post("/v1/ops/api-keys", headers=admin_headers, json={"key_name": "audit-key"})
    assert api_key.status_code == 200

    connector_source = tmp_path / "audit-connector.json"
    connector_source.write_text('{"events": []}', encoding="utf-8")
    connector = test_client.post(
        "/v1/ops/connectors",
        headers=admin_headers,
        json={"connector_type": "file_drop", "route": "session", "source_path": str(connector_source), "config": {}},
    )
    assert connector.status_code == 200

    webhook = test_client.post(
        "/v1/ops/webhooks",
        headers=admin_headers,
        json={"event_type": "fraud.case.created", "url": "https://audit.example/webhook", "secret": "auditsecret1"},
    )
    assert webhook.status_code == 200
    rotate = test_client.patch(
        f"/v1/ops/webhooks/{webhook.json()['webhook_id']}/secret",
        headers=admin_headers,
        json={"secret": "auditsecret2"},
    )
    assert rotate.status_code == 200

    retrain = test_client.post(
        "/v1/dev/retraining-jobs",
        headers=admin_headers,
        json={"promote_stage": "candidate", "activate_after_training": False},
    )
    assert retrain.status_code == 200

    audit = test_client.get("/v1/ops/security-audit?limit=20", headers=admin_headers)
    assert audit.status_code == 200
    events = audit.json()
    event_types = {item["event_type"] for item in events}
    assert "auth.bootstrap" in event_types
    assert "auth.login" in event_types
    assert "analyst.created" in event_types
    assert "api_key.created" in event_types
    assert "connector.created" in event_types
    assert "webhook.secret_rotated" in event_types
    assert "models.retraining.enqueued" in event_types

    actor_id = next(item["actor_id"] for item in events if item["event_type"] == "auth.login")
    filtered_by_type = test_client.get("/v1/ops/security-audit?event_type=api_key.created&limit=10", headers=admin_headers)
    assert filtered_by_type.status_code == 200
    filtered_type_events = filtered_by_type.json()
    assert len(filtered_type_events) >= 1
    assert all(item["event_type"] == "api_key.created" for item in filtered_type_events)
    assert filtered_type_events[0]["details"]["key_name"] == "audit-key"

    filtered_by_actor = test_client.get(f"/v1/ops/security-audit?actor_id={actor_id}&limit=20", headers=admin_headers)
    assert filtered_by_actor.status_code == 200
    filtered_actor_events = filtered_by_actor.json()
    assert len(filtered_actor_events) >= 1
    assert all(item["actor_id"] == actor_id for item in filtered_actor_events)

    exported = test_client.get("/v1/ops/security-audit/export?event_type=connector.created&limit=10", headers=admin_headers)
    assert exported.status_code == 200
    assert "text/csv" in exported.headers["content-type"]
    assert "event_id,event_type,actor_id,actor_role,details,created_at" in exported.text
    assert "connector.created" in exported.text
    assert connector_source.name in exported.text

    viewer_login = test_client.post(
        "/v1/auth/login",
        headers={"X-Tenant-Id": "demo-tenant"},
        json={"email": "audit-viewer@fraudguard.local", "password": "ViewerPass!234"},
    )
    assert viewer_login.status_code == 200
    viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}
    viewer_forbidden = test_client.get("/v1/ops/security-audit", headers=viewer_headers)
    assert viewer_forbidden.status_code == 403

    forbidden = test_client.get("/v1/ops/security-audit", headers={"Authorization": "Bearer invalid-token"})
    assert forbidden.status_code == 401

def test_retraining_jobs_connectors_and_monitoring(client, tmp_path, monkeypatch) -> None:
    test_client, _, _, main_module = client
    run_worker = load_run_worker_module()
    from app.services.repository import repository

    def fake_train_baseline_models():
        return {
            "behavioral": {
                "artifact_path": "data/models/behavioral_async.joblib",
                "metrics": {"auc": 0.93, "precision": 0.85, "recall": 0.8, "f1": 0.82, "accuracy": 0.91},
                "version_id": "async-beh-1",
            },
            "identity": {
                "artifact_path": "data/models/identity_async.joblib",
                "metrics": {"auc": 0.9, "precision": 0.81, "recall": 0.77, "f1": 0.79, "accuracy": 0.88},
                "version_id": "async-id-1",
            },
        }

    monkeypatch.setattr(main_module, "train_baseline_models", fake_train_baseline_models)
    monkeypatch.setattr(run_worker, "train_baseline_models", fake_train_baseline_models)

    feedback = test_client.post(
        "/v1/ops/cases/demo-case-001/feedback",
        headers=AUTH,
        json={"label": "CONFIRMED_FRAUD", "notes": "confirmed during retraining test", "reported_by": "ops@test"},
    )
    assert feedback.status_code in {200, 404}

    retrain = test_client.post(
        "/v1/dev/retraining-jobs",
        headers=AUTH,
        json={
            "promote_stage": "candidate",
            "activate_after_training": False,
            "use_feedback_labels": True,
            "minimum_feedback_labels": 1,
        },
    )
    assert retrain.status_code == 200
    retrain_job_id = retrain.json()["job_id"]
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
    connector_job_id = run.json()["job_id"]
    assert run.json()["status"] == "QUEUED"

    jobs = test_client.get("/v1/ops/jobs", headers=AUTH)
    assert jobs.status_code == 200
    assert len(jobs.json()) >= 2

    claimed = repository.claim_jobs("test-worker", limit=10, lease_seconds=30)
    claimed_ids = {job["job_id"] for job in claimed}
    assert {retrain_job_id, connector_job_id}.issubset(claimed_ids)

    for job in claimed:
        result = asyncio.run(run_worker._process_job(job))
        repository.complete_job(job["tenant_id"], job["job_id"], result)

    refreshed_jobs = test_client.get("/v1/ops/jobs", headers=AUTH)
    assert refreshed_jobs.status_code == 200
    refreshed_payload = refreshed_jobs.json()
    retrain_job = next(item for item in refreshed_payload if item["job_id"] == retrain_job_id)
    connector_job = next(item for item in refreshed_payload if item["job_id"] == connector_job_id)
    assert retrain_job["status"] == "SUCCEEDED"
    assert retrain_job["attempts"] == 1
    assert retrain_job["payload"]["use_feedback_labels"] is True
    assert retrain_job["payload"]["minimum_feedback_labels"] == 1
    assert retrain_job["result"]["training_manifest"]["feedback_summary"]["total_feedback_labels"] >= 0
    assert retrain_job["result"]["report_paths"]["project_summary"].endswith("MODEL_EVALUATION_SUMMARY.json")
    assert retrain_job["result"]["models"]["behavioral"]["version_id"] == "async-beh-1"
    assert connector_job["status"] == "SUCCEEDED"
    assert connector_job["result"]["accepted"] == 1
    assert connector_job["result"]["route"] == "session"

    monitoring_response = test_client.get("/v1/ops/monitoring", headers=AUTH)
    assert monitoring_response.status_code == 200
    assert monitoring_response.json()["queued_jobs"] == 0
    assert monitoring_response.json()["model_versions"] >= 2

    connectors = test_client.get("/v1/ops/connectors", headers=AUTH)
    assert connectors.status_code == 200
    connector_state = next(item for item in connectors.json() if item["connector_id"] == connector_id)
    assert connector_state["last_run_at"] is not None

    models = test_client.get("/v1/ops/models", headers=AUTH)
    assert models.status_code == 200
    assert any(item["version_id"] == "async-beh-1" for item in models.json())

    metrics = test_client.get("/metrics", headers=AUTH)
    assert metrics.status_code == 200
    assert "fraudguard_queued_jobs 0" in metrics.text



def test_job_retry_and_failure_lifecycle(client, tmp_path) -> None:
    test_client, _, _, _ = client
    run_worker = load_run_worker_module()
    from app.services.repository import repository

    missing_source = tmp_path / "missing-connector.json"
    connector = test_client.post(
        "/v1/ops/connectors",
        headers=AUTH,
        json={"connector_type": "file_drop", "route": "session", "source_path": str(missing_source), "config": {}},
    )
    assert connector.status_code == 200
    connector_id = connector.json()["connector_id"]

    run = test_client.post(f"/v1/ops/connectors/{connector_id}/run", headers=AUTH)
    assert run.status_code == 200
    job_id = run.json()["job_id"]

    claimed_first = repository.claim_jobs("failure-worker", limit=5, lease_seconds=30)
    failed_job = next(item for item in claimed_first if item["job_id"] == job_id)
    with pytest.raises(RuntimeError, match="connector source file not found"):
        asyncio.run(run_worker._process_job(failed_job))
    retry_state = repository.fail_job(failed_job["tenant_id"], failed_job["job_id"], "connector source file not found", retry_delay_seconds=0)
    assert retry_state["status"] == "RETRYING"

    claimed_second = repository.claim_jobs("failure-worker", limit=5, lease_seconds=30)
    retry_job = next(item for item in claimed_second if item["job_id"] == job_id)
    with pytest.raises(RuntimeError, match="connector source file not found"):
        asyncio.run(run_worker._process_job(retry_job))
    second_failure = repository.fail_job(retry_job["tenant_id"], retry_job["job_id"], "connector source file not found", retry_delay_seconds=0)
    assert second_failure["status"] == "RETRYING"

    claimed_third = repository.claim_jobs("failure-worker", limit=5, lease_seconds=30)
    final_job = next(item for item in claimed_third if item["job_id"] == job_id)
    with pytest.raises(RuntimeError, match="connector source file not found"):
        asyncio.run(run_worker._process_job(final_job))
    failed_state = repository.fail_job(final_job["tenant_id"], final_job["job_id"], "connector source file not found", retry_delay_seconds=0)
    assert failed_state["status"] == "FAILED"

    jobs = test_client.get("/v1/ops/jobs", headers=AUTH)
    assert jobs.status_code == 200
    job_payload = next(item for item in jobs.json() if item["job_id"] == job_id)
    assert job_payload["status"] == "FAILED"
    assert job_payload["attempts"] == 3
    assert "connector source file not found" in job_payload["error_message"]

    monitoring = test_client.get("/v1/ops/monitoring", headers=AUTH)
    assert monitoring.status_code == 200
    assert monitoring.json()["failed_jobs"] >= 1

def test_model_evaluation_summary_endpoint(client) -> None:
    test_client, _, _, _ = client
    response = test_client.get("/v1/ops/model-evaluation-summary", headers=AUTH)
    assert response.status_code == 200
    payload = response.json()
    assert "generated_at" in payload
    assert "behavioral" in payload["models"]
    assert payload["models"]["behavioral"]["metrics"]["auc"] == 0.94
    assert payload["models"]["identity"]["metrics"]["accuracy"] == 0.89




