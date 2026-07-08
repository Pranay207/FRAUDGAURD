from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "FraudGuard API"
    api_key: str = "test_key"
    default_tenant_name: str = "Demo Fintech"
    audit_log_path: Path = Path("data/audit_logs.jsonl")
    database_path: Path = Path("data/fraudguard.db")
    database_url: str | None = None
    model_artifact_dir: Path = Path("data/models")
    training_data_dir: Path = Path("data/raw")
    creditcard_dataset_path: Path | None = None
    phishing_dataset_path: Path | None = None

    model_config = SettingsConfigDict(
        env_prefix="FRAUDGUARD_",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
