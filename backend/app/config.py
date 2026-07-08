from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "FraudGuard API"
    api_key: str = "test_key"
    default_tenant_name: str = "Demo Fintech"
    auth_secret: str = "change-me-for-production"
    access_token_ttl_minutes: int = 60
    worker_lease_seconds: int = 300
    worker_poll_interval_seconds: int = 5
    redis_url: str | None = "redis://redis:6379/0"
    redis_channel: str = "fraudguard.jobs"
    audit_log_path: Path = Path("data/audit_logs.jsonl")
    database_path: Path = Path("data/fraudguard.db")
    database_url: str | None = None
    model_artifact_dir: Path = Path("data/models")
    training_data_dir: Path = Path("data/raw")
    creditcard_dataset_path: Path | None = None
    phishing_dataset_path: Path | None = None
    connector_workspace: Path = Path("data/connectors")
    metrics_enabled: bool = True

    model_config = SettingsConfigDict(
        env_prefix="FRAUDGUARD_",
        extra="ignore",
        env_file=".env",
        env_file_encoding="utf-8",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
