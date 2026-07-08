import json
from pathlib import Path

from app.services.training import (
    build_creditcard_transaction_dataset,
    load_paysim_transaction_dataset,
    load_phishing_feature_dataset,
    load_sms_spam_dataset,
    train_baseline_models,
)


def test_build_creditcard_transaction_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "creditcard.csv"
    dataset.write_text(
        'Time,V1,V2,V3,V4,V5,V6,Amount,Class\n'
        '0,1.0,2.0,3.0,4.0,5.0,6.0,10.5,0\n'
        '120,1.0,2.0,3.0,4.0,5.0,6.0,12.0,1\n'
        '400,1.0,2.0,3.0,7.0,8.0,9.0,8.0,0\n',
        encoding='utf-8',
    )

    rows, labels = build_creditcard_transaction_dataset(dataset)

    assert labels == [0, 1, 0]
    assert rows[0][:4] == [1050.0, 1.0, 0.0, 0.0]
    assert len(rows[0]) == 8
    assert rows[1][1] == 0.0
    assert rows[1][2] == 1.0
    assert rows[2][1] == 1.0


def test_load_paysim_transaction_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "paysim.csv"
    dataset.write_text(
        'step,type,amount,nameOrig,oldbalanceOrg,newbalanceOrig,nameDest,oldbalanceDest,newbalanceDest,isFraud,isFlaggedFraud\n'
        '1,TRANSFER,100.0,C1,150.0,50.0,C2,0.0,0.0,1,0\n'
        '2,CASH_OUT,50.0,C1,50.0,0.0,C3,0.0,50.0,0,0\n'
        '3,PAYMENT,30.0,C1,100.0,70.0,M1,0.0,0.0,0,0\n',
        encoding='utf-8',
    )

    rows, labels = load_paysim_transaction_dataset(dataset, max_rows=10, negative_keep_mod=1)

    assert labels == [1, 0, 0]
    assert len(rows[0]) == 8
    assert rows[0][0] == 10000.0
    assert rows[0][4] == 1.0


def test_load_phishing_feature_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "phishing.arff"
    dataset.write_text(
        '@relation phishing\n'
        '@attribute having_IP_Address {-1,1}\n'
        '@attribute URL_Length {1,0,-1}\n'
        '@attribute Result {-1,1}\n'
        '@data\n'
        '1,0,1\n'
        '-1,-1,-1\n',
        encoding='utf-8',
    )

    rows, labels, feature_names = load_phishing_feature_dataset(dataset)

    assert feature_names == ["having_IP_Address", "URL_Length"]
    assert rows == [[1.0, 0.0], [-1.0, -1.0]]
    assert labels == [0, 1]


def test_load_sms_spam_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "SMSSpamCollection"
    dataset.write_text(
        'ham\tSee you at 7\n'
        'spam\tUrgent reward waiting, claim now\n',
        encoding='utf-8',
    )

    texts, labels = load_sms_spam_dataset(dataset)

    assert texts == ["See you at 7", "Urgent reward waiting, claim now"]
    assert labels == [0, 1]


def test_train_baseline_models_writes_consolidated_metrics_report(tmp_path: Path, monkeypatch) -> None:
    training_dir = tmp_path / "raw"
    training_dir.mkdir()
    artifact_dir = tmp_path / "models"

    (training_dir / "creditcard.csv").write_text(
        'Time,V1,V2,V3,V4,V5,V6,Amount,Class\n'
        '0,1,2,3,4,5,6,10.5,0\n'
        '120,1,2,3,4,5,6,12.0,1\n'
        '240,1,2,3,4,5,6,14.0,0\n'
        '360,1,2,3,4,5,6,16.0,1\n'
        '480,1,2,3,7,8,9,18.0,0\n'
        '600,1,2,3,7,8,9,20.0,1\n'
        '720,1,2,3,7,8,9,22.0,0\n'
        '840,1,2,3,7,8,9,24.0,1\n',
        encoding='utf-8',
    )
    (training_dir / "phishing_websites.arff").write_text(
        '@relation phishing\n'
        '@attribute having_IP_Address {-1,1}\n'
        '@attribute URL_Length {1,0,-1}\n'
        '@attribute Result {-1,1}\n'
        '@data\n'
        '1,0,1\n'
        '-1,-1,-1\n'
        '1,1,1\n'
        '-1,0,-1\n'
        '1,-1,1\n'
        '-1,1,-1\n'
        '1,0,1\n'
        '-1,0,-1\n',
        encoding='utf-8',
    )
    sms_dir = training_dir / "sms_spam"
    sms_dir.mkdir()
    (sms_dir / "SMSSpamCollection").write_text(
        'ham\tNormal grocery update\n'
        'spam\tUrgent KYC update fee\n'
        'ham\tFamily payment done\n'
        'spam\tPolice escrow release payment\n',
        encoding='utf-8',
    )

    monkeypatch.setenv("FRAUDGUARD_TRAINING_DATA_DIR", str(training_dir))
    monkeypatch.setenv("FRAUDGUARD_MODEL_ARTIFACT_DIR", str(artifact_dir))
    monkeypatch.delenv("FRAUDGUARD_CREDITCARD_DATASET_PATH", raising=False)
    monkeypatch.delenv("FRAUDGUARD_PHISHING_DATASET_PATH", raising=False)

    from app.config import get_settings
    get_settings.cache_clear()

    results = train_baseline_models()

    assert set(results) >= {"behavioral", "identity", "transaction", "remark", "phishing_feature"}
    assert results["transaction"]["artifact_path"].endswith("transaction_risk.joblib")
    assert "f1" in results["transaction"]["metrics"]
    assert "accuracy" in results["transaction"]["metrics"]
    assert "true_positives" in results["transaction"]["metrics"]
    assert "false_positives" in results["transaction"]["metrics"]
    assert "total_test_samples" in results["transaction"]["metrics"]


