from __future__ import annotations

import hashlib
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from app.db import get_connection


@dataclass
class TenantContext:
    tenant_id: str
    tenant_name: str
    key_name: str


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


async def verify_api_key(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> TenantContext:
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "", 1).strip()
    elif x_api_key:
        token = x_api_key.strip()

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    key_hash = _hash_api_key(token)
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT t.tenant_id, t.name, a.key_name
            FROM api_keys a
            JOIN tenants t ON t.tenant_id = a.tenant_id
            WHERE a.key_hash = ? AND a.is_active = 1 AND t.status = 'active'
            """,
            (key_hash,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        connection.execute(
            "UPDATE api_keys SET last_used_at = datetime('now') WHERE key_hash = ?",
            (key_hash,),
        )
        connection.commit()
    return TenantContext(tenant_id=row["tenant_id"], tenant_name=row["name"], key_name=row["key_name"])
