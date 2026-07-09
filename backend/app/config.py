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
    report_output_dir: Path = Path("data/reports")
    metrics_enabled: bool = True

    def security_posture(self) -> dict:
        findings: list[dict[str, str]] = []
        insecure_api_keys = {
            "test_key",
            "replace-with-strong-api-key",
            "replace_me",
            "changeme",
        }
        insecure_auth_secrets = {
            "change-me-for-production",
            "replace-with-a-strong-secret",
            "replace_me",
            "changeme",
        }
        if self.api_key in insecure_api_keys:
            findings.append({
                "id": "default_api_key" if self.api_key == "test_key" else "placeholder_api_key",
                "severity": "critical",
                "message": "Default API key is still enabled. Rotate FRAUDGUARD_API_KEY before production use.",
            })
        if self.auth_secret in insecure_auth_secrets:
            findings.append({
                "id": "default_auth_secret" if self.auth_secret == "change-me-for-production" else "placeholder_auth_secret",
                "severity": "critical",
                "message": "Default bearer token signing secret is configured. Rotate FRAUDGUARD_AUTH_SECRET before production use.",
            })
        if self.database_url is None:
            findings.append({
                "id": "sqlite_runtime",
                "severity": "high",
                "message": "SQLite is configured instead of an external database. Use FRAUDGUARD_DATABASE_URL for production deployments.",
            })
        if not self.redis_url:
            findings.append({
                "id": "redis_disabled",
                "severity": "medium",
                "message": "Redis is disabled. Background queue fan-out will run without a shared broker.",
            })
        if self.access_token_ttl_minutes > 480:
            findings.append({
                "id": "long_token_ttl",
                "severity": "medium",
                "message": "Access token lifetime exceeds 8 hours. Shorter-lived tokens are recommended for admin consoles.",
            })
        severity_order = ["critical", "high", "medium", "low"]
        highest = next((level for level in severity_order if any(item["severity"] == level for item in findings)), "none")
        return {
            "status": "needs_attention" if findings else "ready",
            "highest_severity": highest,
            "findings": findings,
        }

    model_config = SettingsConfigDict(
        env_prefix="FRAUDGUARD_",
        extra="ignore",
        env_file=".env",
        env_file_encoding="utf-8",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
