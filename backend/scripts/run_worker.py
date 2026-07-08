from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from app.config import get_settings
from app.db import init_db
from app.schemas import OnboardRequest, PhishingScoreRequest, SessionScoreRequest, TransactionScoreRequest
from app.security import TenantContext
from app.services.models import model_registry
from app.services.queue import job_bus
from app.services.repository import repository
from app.services.scoring import engine
from app.services.training import train_baseline_models


def _service_tenant_context(tenant_id: str) -> TenantContext:
    tenant = repository.get_tenant(tenant_id, "worker")
    return TenantContext(
        tenant_id=tenant["tenant_id"],
        tenant_name=tenant["name"],
        key_name="worker",
        actor_id="worker",
        actor_type="service",
        role="service",
        auth_method="worker",
        email=None,
    )


def _normalize_events(route: str, events: list[dict]) -> list:
    if route == "session":
        return [SessionScoreRequest(**item) for item in events]
    if route == "onboard":
        return [OnboardRequest(**item) for item in events]
    if route == "transaction":
        return [TransactionScoreRequest(**item) for item in events]
    if route == "phishing":
        return [PhishingScoreRequest(**item) for item in events]
    raise RuntimeError(f"unsupported connector route {route}")


async def _process_connector_job(tenant_id: str, connector_id: str) -> dict:
    connector = repository.get_connector_config(tenant_id, connector_id)
    if connector is None:
        raise RuntimeError(f"connector {connector_id} not found")
    source_path = Path(connector["source_path"])
    if not source_path.exists():
        raise RuntimeError(f"connector source file not found: {source_path}")

    payload = json.loads(source_path.read_text(encoding="utf-8"))
    events = payload["events"] if isinstance(payload, dict) and "events" in payload else payload
    if not isinstance(events, list):
        raise RuntimeError("connector source must be a JSON array or {\"events\": [...]} object")

    tenant = _service_tenant_context(tenant_id)
    route = connector["route"]
    normalized = _normalize_events(route, events)
    if route == "session":
        result = await engine.score_session_batch(tenant, normalized)
    elif route == "onboard":
        result = await engine.score_onboard_batch(tenant, normalized)
    elif route == "transaction":
        result = await engine.score_transaction_batch(tenant, normalized)
    else:
        result = await engine.score_phishing_batch(tenant, normalized)

    repository.mark_connector_run(tenant_id, connector_id)
    return result.model_dump(mode="json")


def _process_training_job(tenant_id: str, payload: dict) -> dict:
    training_result = train_baseline_models()
    promote_stage = payload.get("promote_stage", "candidate")
    activate_after_training = bool(payload.get("activate_after_training", False))
    for name, info in training_result.items():
        repository.save_model_version(
            tenant_id,
            name,
            info["version_id"],
            info["artifact_path"],
            info["metrics"],
            stage=promote_stage,
            is_active=activate_after_training,
        )
        if activate_after_training:
            repository.activate_model_version(tenant_id, name, info["version_id"], stage=promote_stage)
    model_registry.clear_cache()
    return {
        "status": "ok",
        "models": {
            name: {
                "version_id": info["version_id"],
                "artifact_path": info["artifact_path"],
                "metrics": info["metrics"],
            }
            for name, info in training_result.items()
        },
    }


async def engine_dispatch_webhooks(tenant: TenantContext, limit: int) -> dict:
    from app.services.webhooks import dispatcher

    return await dispatcher.dispatch_pending(tenant, limit)


async def _process_job(job: dict) -> dict:
    tenant_id = job["tenant_id"]
    payload = job["payload"]
    if job["job_type"] == "dispatch_webhooks":
        tenant = _service_tenant_context(tenant_id)
        return await engine_dispatch_webhooks(tenant, int(payload.get("limit", 50)))
    if job["job_type"] == "train_models":
        return _process_training_job(tenant_id, payload)
    if job["job_type"] == "sync_connector":
        return await _process_connector_job(tenant_id, payload["connector_id"])
    raise RuntimeError(f"unknown job type {job['job_type']}")


def run_worker_loop() -> None:
    settings = get_settings()
    init_db()
    print(f"worker starting; redis={job_bus.redis_status()} poll={settings.worker_poll_interval_seconds}s")
    while True:
        claimed = repository.claim_jobs("worker-1", limit=5, lease_seconds=settings.worker_lease_seconds)
        if not claimed:
            time.sleep(settings.worker_poll_interval_seconds)
            continue

        for job in claimed:
            try:
                result = asyncio.run(_process_job(job))
                repository.complete_job(job["tenant_id"], job["job_id"], result)
            except Exception as exc:
                repository.fail_job(job["tenant_id"], job["job_id"], str(exc), retry_delay_seconds=60)


if __name__ == "__main__":
    run_worker_loop()
