from __future__ import annotations

import json
from pathlib import Path

from app.config import get_settings
from app.services.store import store


class AuditLog:
    def __init__(self) -> None:
        self.path = Path(get_settings().audit_log_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    async def write(self, payload: dict) -> None:
        line = json.dumps(payload)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        store.audit_index[payload["request_id"]] = payload

    async def fetch(self, request_id: str) -> dict | None:
        cached = store.audit_index.get(request_id)
        if cached:
            return cached

        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                payload = json.loads(line)
                if payload["request_id"] == request_id:
                    store.audit_index[request_id] = payload
                    return payload
        return None


audit_log = AuditLog()
