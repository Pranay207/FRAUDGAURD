from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.config import get_settings
from app.engine.features import BehavioralFeatures
from app.services.repository import repository


@dataclass
class ModelPrediction:
    score: int
    model_used: bool


MODEL_DEFAULTS = {
    "behavioral": "behavioral_risk.joblib",
    "identity": "identity_risk.joblib",
    "transaction": "transaction_risk.joblib",
    "remark": "remark_risk.joblib",
    "phishing_feature": "phishing_feature_risk.joblib",
}


class ModelRegistry:
    def __init__(self) -> None:
        self._cache: dict[str, object] = {}
        self._artifact_dir = Path(get_settings().model_artifact_dir)

    def behavioral_score(self, tenant_id: str, features: BehavioralFeatures, fallback: int) -> ModelPrediction:
        vector = [[
            features.keystroke_interval_deviation,
            features.is_new_device,
            features.hour_of_day_anomaly_score,
            features.session_duration_zscore,
            features.ip_country_change,
            features.txn_velocity_5min,
            features.days_since_last_login,
        ]]
        return self._predict_numeric(tenant_id, "behavioral", vector, fallback)

    def identity_score(self, tenant_id: str, feature_values: list[float], fallback: int) -> ModelPrediction:
        return self._predict_numeric(tenant_id, "identity", [feature_values], fallback)

    def transaction_score(self, tenant_id: str, feature_values: list[float], fallback: int) -> ModelPrediction:
        return self._predict_numeric(tenant_id, "transaction", [feature_values], fallback)

    def remark_score(self, tenant_id: str, text: str, fallback: int) -> ModelPrediction:
        return self._predict_text(tenant_id, "remark", [text], fallback)

    def phishing_feature_score(self, tenant_id: str, feature_values: list[float], fallback: int) -> ModelPrediction:
        return self._predict_numeric(tenant_id, "phishing_feature", [feature_values], fallback)

    def _predict_numeric(self, tenant_id: str, model_name: str, vector: list[list[float]], fallback: int) -> ModelPrediction:
        model = self._load_model(tenant_id, model_name)
        if model is None:
            return ModelPrediction(score=fallback, model_used=False)
        probability = float(model.predict_proba(vector)[0][1])
        return ModelPrediction(score=max(0, min(1000, int(probability * 1000))), model_used=True)

    def _predict_text(self, tenant_id: str, model_name: str, texts: list[str], fallback: int) -> ModelPrediction:
        model = self._load_model(tenant_id, model_name)
        if model is None:
            return ModelPrediction(score=fallback, model_used=False)
        probability = float(model.predict_proba(texts)[0][1])
        return ModelPrediction(score=max(0, min(1000, int(probability * 1000))), model_used=True)

    def _resolve_artifact_path(self, tenant_id: str, model_name: str) -> Path:
        active_version = repository.get_active_model_version(tenant_id, model_name)
        if active_version:
            artifact_path = Path(active_version["artifact_path"])
            if artifact_path.exists():
                return artifact_path
        return self._artifact_dir / MODEL_DEFAULTS[model_name]

    def _load_model(self, tenant_id: str, model_name: str):
        path = self._resolve_artifact_path(tenant_id, model_name)
        cache_key = str(path.resolve()) if path.exists() else str(path)
        if cache_key in self._cache:
            return self._cache[cache_key]

        if not path.exists():
            self._cache[cache_key] = None
            return None

        try:
            import joblib
        except ImportError:
            self._cache[cache_key] = None
            return None

        model = joblib.load(path)
        self._cache[cache_key] = model
        return model

    def clear_cache(self) -> None:
        self._cache.clear()


model_registry = ModelRegistry()
