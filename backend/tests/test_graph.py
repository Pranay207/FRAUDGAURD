import importlib

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
        yield test_client


AUTH = {"Authorization": "Bearer test_key"}


def test_graph_device_and_payee_views(client) -> None:
    onboard = client.post(
        "/v1/score/onboard",
        headers=AUTH,
        json={
            "user_id": "graph-user-1",
            "pan_hash": "e" * 64,
            "phone_hash": "f" * 64,
            "aadhaar_last4": "2222",
            "device": {"device_id": "graph-device", "sim_count": 3, "is_rooted": True},
            "selfie_check_score": 0.7,
            "kyc_name_match_score": 0.5,
        },
    )
    assert onboard.status_code == 200

    txn = client.post(
        "/v1/score/transaction",
        headers=AUTH,
        json={
            "user_id": "graph-user-1",
            "amount_paise": 155000,
            "payee_vpa": "collector@upi",
            "upi_remark": "Government clearance payment",
            "session_id": "sess-graph",
            "device_id": "graph-device",
            "ip_country": "IN",
            "transaction_type": "TRANSFER",
            "source_balance_paise": 160000,
            "destination_balance_paise": 0,
        },
    )
    assert txn.status_code == 200

    device_graph = client.get("/v1/ops/graph/device/graph-device", headers=AUTH)
    assert device_graph.status_code == 200
    assert "rooted_device" in device_graph.json()["risk_flags"]

    payee_graph = client.get("/v1/ops/graph/payee/collector@upi", headers=AUTH)
    assert payee_graph.status_code == 200
    assert payee_graph.json()["stats"]["transaction_count"] >= 1
