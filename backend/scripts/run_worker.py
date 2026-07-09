from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from app.config import get_settings
from app.db import init_db
from app.schemas import OnboardRequest, PhishingScoreRequest, SessionScoreRequest, TransactionScoreRequest
from app.security import TenantContext
from app.services.models import model_registry
from app.services.queue import job_bus
from app.services.repository import repository
from app.services.scoring import engine
from app.services.training import get_dataset_inventory, train_baseline_models


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
    promote_stage = payload.get("promote_stage", "candidate")
    activate_after_training = bool(payload.get("activate_after_training", False))
    use_feedback_labels = bool(payload.get("use_feedback_labels", True))
    minimum_feedback_labels = int(payload.get("minimum_feedback_labels", 1))
    feedback_summary = repository.feedback_training_summary(tenant_id)
    feedback_gate_passed = (not use_feedback_labels) or feedback_summary["total_feedback_labels"] >= minimum_feedback_labels
    training_job_id = payload.get("training_job_id") or f"async-train-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"

    training_result = train_baseline_models()
    for name, info in training_result.items():
        repository.save_model_version(
            tenant_id,
            name,
            info["version_id"],
            info["artifact_path"],
            info["metrics"],
            stage=promote_stage,
            is_active=activate_after_training,
            training_job_id=training_job_id,
        )
        if activate_after_training:
            repository.activate_model_version(tenant_id, name, info["version_id"], stage=promote_stage)

    settings = get_settings()
    project_root = Path(__file__).resolve().parents[2]
    artifact_dir = Path(settings.model_artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    training_manifest = {
        "training_job_id": training_job_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": tenant_id,
        "promote_stage": promote_stage,
        "activate_after_training": activate_after_training,
        "use_feedback_labels": use_feedback_labels,
        "minimum_feedback_labels": minimum_feedback_labels,
        "feedback_gate_passed": feedback_gate_passed,
        "feedback_summary": feedback_summary,
        "dataset_inventory": get_dataset_inventory(),
    }
    models_payload = {
        name: {
            "version_id": info["version_id"],
            "artifact_path": info["artifact_path"],
            "metrics": info["metrics"],
        }
        for name, info in training_result.items()
    }
    evaluation_payload = {
        "generated_at": training_manifest["generated_at"],
        "training_manifest": training_manifest,
        "models": models_payload,
    }
    latest_manifest_path = artifact_dir / "latest_training_manifest.json"
    latest_result_path = artifact_dir / "latest_training_result.json"
    report_path = project_root / "MODEL_EVALUATION_SUMMARY.json"
    latest_manifest_path.write_text(json.dumps(training_manifest, indent=2), encoding="utf-8")
    latest_result_path.write_text(json.dumps(evaluation_payload, indent=2), encoding="utf-8")
    report_path.write_text(json.dumps(evaluation_payload, indent=2), encoding="utf-8")

    model_registry.clear_cache()
    return {
        "status": "ok",
        "training_job_id": training_job_id,
        "training_manifest": training_manifest,
        "report_paths": {
            "project_summary": str(report_path),
            "latest_manifest": str(latest_manifest_path),
            "latest_result": str(latest_result_path),
        },
        "models": models_payload,
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
