from __future__ import annotations

from app.config import get_settings
from app.services.repository import repository


class JobBus:
    def __init__(self) -> None:
        self._settings = get_settings()

    def _redis_client(self):
        if not self._settings.redis_url:
            return None
        try:
            import redis
        except ImportError:
            return None
        try:
            return redis.from_url(self._settings.redis_url)
        except Exception:
            return None

    def redis_status(self) -> str:
        client = self._redis_client()
        if client is None:
            return "disabled"
        try:
            client.ping()
            return "ready"
        except Exception:
            return "unavailable"

    def publish_job(self, job_id: str) -> None:
        client = self._redis_client()
        if client is None:
            return
        try:
            client.publish(self._settings.redis_channel, job_id)
        except Exception:
            return

    def enqueue_webhook_dispatch(self, tenant_id: str, created_by: str | None, limit: int = 50) -> dict:
        job = repository.enqueue_job(tenant_id, "dispatch_webhooks", {"limit": limit}, created_by=created_by, priority=120, max_attempts=5)
        self.publish_job(job["job_id"])
        return job

    def enqueue_retraining(self, tenant_id: str, created_by: str | None, promote_stage: str, activate_after_training: bool) -> dict:
        job = repository.enqueue_job(
            tenant_id,
            "train_models",
            {"promote_stage": promote_stage, "activate_after_training": activate_after_training},
            created_by=created_by,
            priority=90,
            max_attempts=2,
        )
        self.publish_job(job["job_id"])
        return job

    def enqueue_connector_sync(self, tenant_id: str, connector_id: str, created_by: str | None) -> dict:
        job = repository.enqueue_job(
            tenant_id,
            "sync_connector",
            {"connector_id": connector_id},
            created_by=created_by,
            priority=100,
            max_attempts=3,
        )
        self.publish_job(job["job_id"])
        return job


job_bus = JobBus()
