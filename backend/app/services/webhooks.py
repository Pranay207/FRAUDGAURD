from __future__ import annotations

import hashlib
import hmac
import json

import httpx

from app.security import TenantContext
from app.services.repository import repository


class WebhookDispatcher:
    async def dispatch_pending(self, tenant: TenantContext, limit: int = 25) -> dict[str, int]:
        queued = repository.list_queued_webhook_deliveries(tenant.tenant_id, limit)
        dispatched = 0
        failed = 0
        retried = 0
        dead_lettered = 0
        for item in queued:
            try:
                http_status = await self._deliver(item)
                repository.mark_webhook_delivery_success(tenant.tenant_id, item["delivery_id"], http_status)
                dispatched += 1
            except httpx.HTTPStatusError as exc:  # pragma: no cover - operational branch
                outcome = repository.mark_webhook_delivery_failure(
                    tenant.tenant_id,
                    item["delivery_id"],
                    str(exc),
                    exc.response.status_code,
                )
                failed += 1
                if outcome and outcome["status"] == "DEAD_LETTER":
                    dead_lettered += 1
                elif outcome:
                    retried += 1
            except Exception as exc:  # pragma: no cover - kept broad for operational safety
                outcome = repository.mark_webhook_delivery_failure(
                    tenant.tenant_id,
                    item["delivery_id"],
                    str(exc),
                    None,
                )
                failed += 1
                if outcome and outcome["status"] == "DEAD_LETTER":
                    dead_lettered += 1
                elif outcome:
                    retried += 1
        remaining = len(repository.list_queued_webhook_deliveries(tenant.tenant_id, limit=1000))
        return {"dispatched": dispatched, "failed": failed, "retried": retried, "dead_lettered": dead_lettered, "queued_remaining": remaining}

    async def _deliver(self, item: dict) -> int:
        payload = json.loads(item["payload_json"])
        headers = {
            "Content-Type": "application/json",
            "X-FraudGuard-Event": item["event_type"],
            "X-FraudGuard-Delivery": item["delivery_id"],
        }
        secret = item.get("secret")
        body = json.dumps(payload).encode("utf-8")
        if secret:
            signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-FraudGuard-Signature"] = signature
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(item["url"], content=body, headers=headers)
            response.raise_for_status()
            return response.status_code


dispatcher = WebhookDispatcher()
