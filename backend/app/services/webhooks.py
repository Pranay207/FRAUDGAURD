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
        for item in queued:
            try:
                await self._deliver(item)
                repository.mark_webhook_delivery(tenant.tenant_id, item["delivery_id"], "DELIVERED")
                dispatched += 1
            except Exception as exc:  # pragma: no cover - kept broad for operational safety
                repository.mark_webhook_delivery(tenant.tenant_id, item["delivery_id"], "FAILED", str(exc))
                failed += 1
        remaining = len(repository.list_queued_webhook_deliveries(tenant.tenant_id, limit=1000))
        return {"dispatched": dispatched, "failed": failed, "queued_remaining": remaining}

    async def _deliver(self, item: dict) -> None:
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


dispatcher = WebhookDispatcher()
