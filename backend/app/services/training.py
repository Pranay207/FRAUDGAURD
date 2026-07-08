from __future__ import annotations

import csv
import json
import zlib
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.config import get_settings
from app.services.models import model_registry


SAFE_TEXTS = [
    "groceries and essentials",
    "rent payment",
    "coffee shop bill",
    "monthly utility payment",
    "salary transfer",
    "family support transfer",
    "restaurant payment",
]

SCAM_TEXTS = [
    "government clearance payment",
    "digital arrest settlement",
    "kyc update fee urgent",
    "trai verification charge",
    "police escrow release",
    "refund verification transfer",
    "clearance payment for release",
]


def resolve_training_dataset_path(explicit_path: Path | None, fallback_path: Path) -> Path | None:
    candidates = [explicit_path, fallback_path]
    for candidate in candidates:
        if candidate is not None and Path(candidate).exists():
            return Path(candidate)
    return None


def build_creditcard_transaction_dataset(dataset_path: Path) -> tuple[list[list[float]], list[int]]:
    rows: list[list[float]] = []
    labels: list[int] = []
    user_windows: dict[int, deque[float]] = defaultdict(deque)
    user_payees: dict[int, set[int]] = defaultdict(set)
    user_first_seen: dict[int, float] = {}
    user_last_fraud: dict[int, float | None] = {}

    with Path(dataset_path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for record in reader:
            amount_paise = int(round(float(record["Amount"]) * 100))
            event_time = float(record["Time"])
            label = int(record["Class"])

            v1 = float(record["V1"])
            v2 = float(record["V2"])
            v3 = float(record["V3"])
            v4 = float(record["V4"])
            v5 = float(record["V5"])
            v6 = float(record["V6"])

            user_id = _stable_bucket(v1, v2, v3, modulo=4096)
            payee_id = _stable_bucket(v4, v5, v6, modulo=8192)

            if user_id not in user_first_seen:
                user_first_seen[user_id] = event_time
                user_last_fraud[user_id] = None

            recent_events = user_windows[user_id]
            while recent_events and event_time - recent_events[0] > 300:
                recent_events.popleft()

            first_time_payee = int(payee_id not in user_payees[user_id])
            velocity = min(len(recent_events), 6)
            clean_streak_days = _clean_streak_days(
                event_time=event_time,
                first_seen_time=user_first_seen[user_id],
                last_fraud_time=user_last_fraud[user_id],
            )

            rows.append([
                float(amount_paise),
                float(first_time_payee),
                float(velocity),
                float(clean_streak_days),
                1.0,
                0.0,
                0.0,
                1.0,
            ])
            labels.append(label)

            recent_events.append(event_time)
            user_payees[user_id].add(payee_id)
            if label == 1:
                user_last_fraud[user_id] = event_time

    return rows, labels


def load_paysim_transaction_dataset(dataset_path: Path, max_rows: int = 220_000, negative_keep_mod: int = 45) -> tuple[list[list[float]], list[int]]:
    rows: list[list[float]] = []
    labels: list[int] = []
    user_windows: dict[str, deque[int]] = defaultdict(deque)
    user_payees: dict[str, set[str]] = defaultdict(set)
    user_first_seen: dict[str, int] = {}
    user_last_fraud: dict[str, int | None] = {}

    with Path(dataset_path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for record in reader:
            label = int(record["isFraud"])
            if label == 0 and not _keep_negative_paysim(record, negative_keep_mod):
                continue
            if len(rows) >= max_rows:
                break

            user_id = record["nameOrig"]
            payee_id = record["nameDest"]
            step = int(record["step"])
            amount = float(record["amount"])
            amount_paise = int(round(amount * 100))
            old_balance_org = float(record["oldbalanceOrg"])
            old_balance_dest = float(record["oldbalanceDest"])
            transaction_type = record["type"].upper()

            if user_id not in user_first_seen:
                user_first_seen[user_id] = step
                user_last_fraud[user_id] = None

            recent_steps = user_windows[user_id]
            while recent_steps and step - recent_steps[0] > 3:
                recent_steps.popleft()

            first_time_payee = int(payee_id not in user_payees[user_id])
            velocity = min(len(recent_steps), 6)
            clean_streak_days = _clean_streak_days(
                event_time=float(step),
                first_seen_time=float(user_first_seen[user_id]),
                last_fraud_time=float(user_last_fraud[user_id]) if user_last_fraud[user_id] is not None else None,
                unit_scale=24.0,
            )
            transaction_type_risk = 1 if transaction_type in {"TRANSFER", "CASH_OUT"} else 0
            source_balance_paise = int(round(old_balance_org * 100))
            destination_balance_paise = int(round(old_balance_dest * 100))
            drain_ratio = min(2.0, amount / old_balance_org) if old_balance_org > 0 else (2.0 if amount > 0 else 0.0)

            rows.append([
                float(amount_paise),
                float(first_time_payee),
                float(velocity),
                float(clean_streak_days),
                float(transaction_type_risk),
                float(source_balance_paise),
                float(destination_balance_paise),
                float(drain_ratio),
            ])
            labels.append(label)

            recent_steps.append(step)
            user_payees[user_id].add(payee_id)
            if label == 1:
                user_last_fraud[user_id] = step

    return rows, labels


def load_phishing_feature_dataset(dataset_path: Path) -> tuple[list[list[float]], list[int], list[str]]:
    feature_names: list[str] = []
    rows: list[list[float]] = []
    labels: list[int] = []
    in_data = False

    with Path(dataset_path).open("r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("%"):
                continue
            lower_line = line.lower()
            if not in_data:
                if lower_line.startswith("@attribute"):
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[1].strip("'\"")
                        if name.lower() != "result":
                            feature_names.append(name)
                elif lower_line.startswith("@data"):
                    in_data = True
                continue

            values = [value.strip() for value in line.split(",")]
            if len(values) != len(feature_names) + 1:
                continue
            rows.append([float(value) for value in values[:-1]])
            labels.append(1 if values[-1] == "-1" else 0)

    return rows, labels, feature_names


def load_sms_spam_dataset(dataset_path: Path) -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []

    with Path(dataset_path).open("r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split("\t", maxsplit=1)
            if len(parts) != 2:
                continue
            label, text = parts
            texts.append(text.strip())
            labels.append(1 if label.lower() == "spam" else 0)

    return texts, labels



def _build_classification_metrics(y_true, probabilities, predictions) -> dict[str, float | int]:
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    return {
        "auc": round(float(roc_auc_score(y_true, probabilities)), 4),
        "precision": round(float(precision_score(y_true, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, predictions, zero_division=0)), 4),
        "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "negative_support": int(tn + fp),
        "positive_support": int(fn + tp),
        "total_test_samples": int(tn + fp + fn + tp),
    }


def _write_metrics_summary(report_path: Path, results: dict[str, dict]) -> None:
    report_payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "models": {
            model_name: {
                "version_id": payload["version_id"],
                "artifact_path": payload["artifact_path"],
                "metrics": payload["metrics"],
            }
            for model_name, payload in sorted(results.items())
        },
    }
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
def train_baseline_models() -> dict[str, dict]:
    try:
        import joblib
        import numpy as np
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Training baseline models requires numpy, scikit-learn, and joblib. Reinstall dependencies from backend/pyproject.toml."
        ) from exc

    settings = get_settings()
    rng = np.random.default_rng(42)
    artifact_dir = Path(settings.model_artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    training_dir = Path(settings.training_data_dir)
    creditcard_path = resolve_training_dataset_path(settings.creditcard_dataset_path, training_dir / "creditcard.csv")
    phishing_path = resolve_training_dataset_path(settings.phishing_dataset_path, training_dir / "phishing_websites.arff")
    paysim_path = training_dir / "paysim" / "PS_20174392719_1491204439457_log.csv"
    sms_spam_path = training_dir / "sms_spam" / "SMSSpamCollection"

    results: dict[str, dict] = {} 
    metrics_report_path = artifact_dir / 'model_metrics_summary.json'

    def evaluate_numeric(model, X_train, X_test, y_train, y_test, artifact_name: str, model_name: str):
        model.fit(X_train, y_train)
        probabilities = model.predict_proba(X_test)[:, 1]
        predictions = (probabilities >= 0.5).astype(int)
        artifact_path = artifact_dir / artifact_name
        joblib.dump(model, artifact_path)
        metrics = _build_classification_metrics(y_test, probabilities, predictions)

        results[model_name] = {
            "artifact_path": str(artifact_path),
            "metrics": metrics,
            "version_id": str(uuid4()),
        }

    behavioral_X = []
    behavioral_y = []
    for _ in range(1200):
        deviation = abs(rng.normal(60, 55))
        new_device = int(rng.random() < 0.3)
        odd_hour = float(rng.choice([0.15, 1.0], p=[0.75, 0.25]))
        duration_shift = abs(rng.normal(0.3, 0.35))
        ip_change = int(rng.random() < 0.2)
        velocity = int(rng.integers(0, 5))
        days_idle = abs(rng.normal(8, 10))
        latent = deviation * 0.009 + new_device * 1.2 + odd_hour * 1.5 + duration_shift * 1.1 + ip_change * 1.0 + velocity * 0.35 + days_idle * 0.03
        label = int(latent + rng.normal(0, 0.7) > 3.4)
        behavioral_X.append([deviation, new_device, odd_hour, duration_shift, ip_change, velocity, days_idle])
        behavioral_y.append(label)
    X_train, X_test, y_train, y_test = train_test_split(np.array(behavioral_X), np.array(behavioral_y), test_size=0.25, random_state=42, stratify=np.array(behavioral_y))
    behavioral_model = Pipeline([("scale", StandardScaler()), ("clf", LogisticRegression(max_iter=500))])
    evaluate_numeric(behavioral_model, X_train, X_test, y_train, y_test, "behavioral_risk.joblib", "behavioral")

    identity_X = []
    identity_y = []
    for _ in range(1000):
        device_users = int(rng.integers(0, 5))
        phone_users = int(rng.integers(0, 4))
        pan_users = int(rng.integers(0, 3))
        selfie_risk = float(rng.uniform(0, 1))
        kyc_gap = float(rng.uniform(0, 1))
        rooted_multisim = int(rng.integers(0, 2))
        latent = device_users * 0.9 + phone_users * 0.8 + pan_users * 1.0 + selfie_risk * 1.8 + kyc_gap * 1.3 + rooted_multisim * 0.6
        label = int(latent + rng.normal(0, 0.8) > 3.3)
        identity_X.append([device_users, phone_users, pan_users, selfie_risk, kyc_gap, rooted_multisim])
        identity_y.append(label)
    X_train, X_test, y_train, y_test = train_test_split(np.array(identity_X), np.array(identity_y), test_size=0.25, random_state=42, stratify=np.array(identity_y))
    identity_model = Pipeline([("scale", StandardScaler()), ("clf", LogisticRegression(max_iter=500))])
    evaluate_numeric(identity_model, X_train, X_test, y_train, y_test, "identity_risk.joblib", "identity")

    if paysim_path.exists():
        transaction_X, transaction_y = load_paysim_transaction_dataset(paysim_path)
    elif creditcard_path is not None:
        transaction_X, transaction_y = build_creditcard_transaction_dataset(creditcard_path)
    else:
        transaction_X = []
        transaction_y = []
        for _ in range(1400):
            amount = int(rng.integers(1000, 250000))
            first_time_payee = int(rng.integers(0, 2))
            velocity = int(rng.integers(0, 6))
            clean_streak = int(rng.integers(0, 140))
            transaction_type_risk = int(rng.integers(0, 2))
            source_balance = int(rng.integers(0, 400000))
            destination_balance = int(rng.integers(0, 250000))
            drain_ratio = min(2.0, amount / max(source_balance, 1)) if source_balance > 0 else 2.0
            latent = amount / 70000 + first_time_payee * 1.2 + velocity * 0.9 + transaction_type_risk * 1.0 + drain_ratio * 1.3 + (1 if clean_streak >= 90 and amount >= 75000 else 0) * 1.4
            label = int(latent + rng.normal(0, 0.7) > 3.8)
            transaction_X.append([amount, first_time_payee, velocity, clean_streak, transaction_type_risk, source_balance, destination_balance, drain_ratio])
            transaction_y.append(label)
    X_train, X_test, y_train, y_test = train_test_split(np.array(transaction_X), np.array(transaction_y), test_size=0.25, random_state=42, stratify=np.array(transaction_y))
    transaction_model = Pipeline([("scale", StandardScaler()), ("clf", LogisticRegression(max_iter=800, class_weight="balanced"))])
    evaluate_numeric(transaction_model, X_train, X_test, y_train, y_test, "transaction_risk.joblib", "transaction")

    if sms_spam_path.exists():
        remark_texts, remark_y = load_sms_spam_dataset(sms_spam_path)
        remark_texts.extend(SAFE_TEXTS)
        remark_y.extend([0] * len(SAFE_TEXTS))
        remark_texts.extend(SCAM_TEXTS)
        remark_y.extend([1] * len(SCAM_TEXTS))
    else:
        remark_texts = []
        remark_y = []
        for _ in range(500):
            remark_texts.append(rng.choice(SAFE_TEXTS))
            remark_y.append(0)
            remark_texts.append(rng.choice(SCAM_TEXTS))
            remark_y.append(1)
    X_train, X_test, y_train, y_test = train_test_split(remark_texts, np.array(remark_y), test_size=0.25, random_state=42, stratify=np.array(remark_y))
    remark_model = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2))), ("clf", LogisticRegression(max_iter=500, class_weight="balanced"))])
    remark_model.fit(X_train, y_train)
    probabilities = remark_model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    artifact_path = artifact_dir / "remark_risk.joblib"
    joblib.dump(remark_model, artifact_path)
    results["remark"] = {
        "artifact_path": str(artifact_path),
        "metrics": _build_classification_metrics(y_test, probabilities, predictions),
        "version_id": str(uuid4()),
    }

    if phishing_path is not None:
        phishing_X, phishing_y, _ = load_phishing_feature_dataset(phishing_path)
        if phishing_X and len(set(phishing_y)) > 1:
            X_train, X_test, y_train, y_test = train_test_split(
                np.array(phishing_X),
                np.array(phishing_y),
                test_size=0.25,
                random_state=42,
                stratify=np.array(phishing_y),
            )
            phishing_model = Pipeline([("scale", StandardScaler()), ("clf", LogisticRegression(max_iter=800))])
            evaluate_numeric(phishing_model, X_train, X_test, y_train, y_test, "phishing_feature_risk.joblib", "phishing_feature")

    model_registry.clear_cache()
    return results


def _stable_bucket(*values: float, modulo: int) -> int:
    scaled = sum(int(abs(value) * 1000) * (index + 1) for index, value in enumerate(values))
    return scaled % modulo


def _keep_negative_paysim(record: dict[str, str], keep_mod: int) -> bool:
    key = f"{record['step']}|{record['nameOrig']}|{record['nameDest']}|{record['amount']}"
    return zlib.crc32(key.encode("utf-8")) % keep_mod == 0


def _clean_streak_days(event_time: float, first_seen_time: float, last_fraud_time: float | None, unit_scale: float = 86400.0) -> int:
    reference_time = last_fraud_time if last_fraud_time is not None else first_seen_time
    return max(0, min(180, int((event_time - reference_time) / unit_scale)))


def get_dataset_inventory() -> list[dict[str, object]]:
    settings = get_settings()
    training_dir = Path(settings.training_data_dir)
    creditcard_path = resolve_training_dataset_path(settings.creditcard_dataset_path, training_dir / "creditcard.csv")
    phishing_path = resolve_training_dataset_path(settings.phishing_dataset_path, training_dir / "phishing_websites.arff")
    paysim_path = training_dir / "paysim" / "PS_20174392719_1491204439457_log.csv"
    amlsim_path = training_dir / "amlsim" / "AMLSim-master"
    elliptic_path = training_dir / "ellipticplusplus" / "EllipticPlusPlus-main"
    sms_spam_path = training_dir / "sms_spam" / "SMSSpamCollection"

    items = [
        {
            "dataset_name": "creditcard",
            "kind": "transaction",
            "path": str(creditcard_path or (training_dir / "creditcard.csv")),
            "present": creditcard_path is not None,
            "size_bytes": creditcard_path.stat().st_size if creditcard_path is not None else None,
            "record_count": _count_dataset_records(creditcard_path) if creditcard_path is not None else None,
            "linked_models": ["transaction"],
        },
        {
            "dataset_name": "phishing_websites",
            "kind": "phishing",
            "path": str(phishing_path or (training_dir / "phishing_websites.arff")),
            "present": phishing_path is not None,
            "size_bytes": phishing_path.stat().st_size if phishing_path is not None else None,
            "record_count": _count_dataset_records(phishing_path) if phishing_path is not None else None,
            "linked_models": ["phishing_feature"],
        },
        {
            "dataset_name": "paysim",
            "kind": "transaction",
            "path": str(paysim_path),
            "present": paysim_path.exists(),
            "size_bytes": paysim_path.stat().st_size if paysim_path.exists() else None,
            "record_count": None,
            "linked_models": ["transaction"],
        },
        {
            "dataset_name": "amlsim",
            "kind": "graph_aml",
            "path": str(amlsim_path),
            "present": amlsim_path.exists(),
            "size_bytes": None,
            "record_count": None,
            "linked_models": ["identity", "graph"],
        },
        {
            "dataset_name": "ellipticplusplus",
            "kind": "crypto_graph",
            "path": str(elliptic_path),
            "present": elliptic_path.exists(),
            "size_bytes": None,
            "record_count": None,
            "linked_models": ["transaction", "graph"],
        },
        {
            "dataset_name": "sms_spam",
            "kind": "text",
            "path": str(sms_spam_path),
            "present": sms_spam_path.exists(),
            "size_bytes": sms_spam_path.stat().st_size if sms_spam_path.exists() else None,
            "record_count": _count_dataset_records(sms_spam_path) if sms_spam_path.exists() else None,
            "linked_models": ["remark", "phishing_text"],
        },
    ]

    return items


def _count_dataset_records(dataset_path: Path) -> int | None:
    suffix = dataset_path.suffix.lower()
    if suffix == ".csv":
        with dataset_path.open("r", encoding="utf-8", newline="") as handle:
            next(handle, None)
            return sum(1 for _ in handle)
    if suffix == ".arff":
        in_data = False
        count = 0
        with dataset_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("%"):
                    continue
                if not in_data:
                    if line.lower().startswith("@data"):
                        in_data = True
                    continue
                count += 1
        return count
    if dataset_path.name == "SMSSpamCollection":
        with dataset_path.open("r", encoding="utf-8", errors="ignore") as handle:
            return sum(1 for _ in handle if _.strip())
    return None




