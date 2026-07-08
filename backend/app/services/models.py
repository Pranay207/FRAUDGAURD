from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.config import get_settings
from app.engine.features import BehavioralFeatures


@dataclass
class ModelPrediction:
    score: int
    model_used: bool


class ModelRegistry:
    def __init__(self) -> None:
        self._cache: dict[str, object] = {}
        self._artifact_dir = Path(get_settings().model_artifact_dir)

    def behavioral_score(self, features: BehavioralFeatures, fallback: int) -> ModelPrediction:
        vector = [[
            features.keystroke_interval_deviation,
            features.is_new_device,
            features.hour_of_day_anomaly_score,
            features.session_duration_zscore,
            features.ip_country_change,
            features.txn_velocity_5min,
            features.days_since_last_login,
        ]]
        return self._predict_numeric("behavioral_risk.joblib", vector, fallback)

    def identity_score(self, feature_values: list[float], fallback: int) -> ModelPrediction:
        return self._predict_numeric("identity_risk.joblib", [feature_values], fallback)

    def transaction_score(self, feature_values: list[float], fallback: int) -> ModelPrediction:
        return self._predict_numeric("transaction_risk.joblib", [feature_values], fallback)

    def remark_score(self, text: str, fallback: int) -> ModelPrediction:
        return self._predict_text("remark_risk.joblib", [text], fallback)

    def phishing_feature_score(self, feature_values: list[float], fallback: int) -> ModelPrediction:
        return self._predict_numeric("phishing_feature_risk.joblib", [feature_values], fallback)

    def _predict_numeric(self, artifact_name: str, vector: list[list[float]], fallback: int) -> ModelPrediction:
        model = self._load_model(artifact_name)
        if model is None:
            return ModelPrediction(score=fallback, model_used=False)
        probability = float(model.predict_proba(vector)[0][1])
        return ModelPrediction(score=max(0, min(1000, int(probability * 1000))), model_used=True)

    def _predict_text(self, artifact_name: str, texts: list[str], fallback: int) -> ModelPrediction:
        model = self._load_model(artifact_name)
        if model is None:
            return ModelPrediction(score=fallback, model_used=False)
        probability = float(model.predict_proba(texts)[0][1])
        return ModelPrediction(score=max(0, min(1000, int(probability * 1000))), model_used=True)

    def _load_model(self, artifact_name: str):
        if artifact_name in self._cache:
            return self._cache[artifact_name]

        path = self._artifact_dir / artifact_name
        if not path.exists():
            self._cache[artifact_name] = None
            return None

        try:
            import joblib
        except ImportError:
            self._cache[artifact_name] = None
            return None

        model = joblib.load(path)
        self._cache[artifact_name] = model
        return model

    def clear_cache(self) -> None:
        self._cache.clear()


model_registry = ModelRegistry()
