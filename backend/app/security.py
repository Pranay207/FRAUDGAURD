from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Header, HTTPException, status

from app.config import get_settings
from app.db import get_connection


@dataclass
class TenantContext:
    tenant_id: str
    tenant_name: str
    key_name: str
    actor_id: str
    actor_type: str
    role: str
    auth_method: str
    email: str | None = None


@dataclass
class AuthenticatedAnalyst:
    tenant_id: str
    analyst_id: str
    email: str
    full_name: str
    role: str
    password_hash: str
    password_salt: str
    is_active: bool


ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"
ROLE_SERVICE = "service"


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    derived_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), derived_salt.encode("utf-8"), 200_000)
    return digest.hex(), derived_salt


def verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    computed_hash, _ = hash_password(password, password_salt)
    return secrets.compare_digest(computed_hash, password_hash)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("utf-8"))


def issue_access_token(analyst: AuthenticatedAnalyst, tenant_name: str) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "tenant_id": analyst.tenant_id,
        "tenant_name": tenant_name,
        "actor_id": analyst.analyst_id,
        "actor_type": "analyst",
        "role": analyst.role,
        "email": analyst.email,
        "key_name": "analyst-session",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_ttl_minutes)).timestamp()),
    }
    payload_segment = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(settings.auth_secret.encode("utf-8"), payload_segment.encode("utf-8"), hashlib.sha256).digest()
    return f"fgat.{payload_segment}.{_b64url_encode(signature)}"


def _verify_analyst_token(token: str) -> TenantContext:
    try:
        prefix, payload_segment, signature_segment = token.split(".", 2)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token") from exc
    if prefix != "fgat":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")

    expected_signature = hmac.new(
        get_settings().auth_secret.encode("utf-8"),
        payload_segment.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(_b64url_encode(expected_signature), signature_segment):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")

    payload = json.loads(_b64url_decode(payload_segment).decode("utf-8"))
    if int(payload["exp"]) < int(datetime.now(UTC).timestamp()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Expired bearer token")

    with get_connection() as connection:
        row = connection.execute(
            "SELECT 1 FROM analyst_users WHERE tenant_id = ? AND analyst_id = ? AND is_active = 1",
            (payload["tenant_id"], payload["actor_id"]),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive analyst")

    return TenantContext(
        tenant_id=payload["tenant_id"],
        tenant_name=payload["tenant_name"],
        key_name=payload.get("key_name", "analyst-session"),
        actor_id=payload["actor_id"],
        actor_type=payload["actor_type"],
        role=payload["role"],
        auth_method="bearer",
        email=payload.get("email"),
    )


def _verify_api_key_token(token: str) -> TenantContext:
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
            "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_hash = ?",
            (key_hash,),
        )
        connection.commit()
    return TenantContext(
        tenant_id=row["tenant_id"],
        tenant_name=row["name"],
        key_name=row["key_name"],
        actor_id=f"api-key:{row['key_name']}",
        actor_type="service",
        role=ROLE_SERVICE,
        auth_method="api_key",
        email=None,
    )


async def verify_principal(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> TenantContext:
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "", 1).strip()
    elif x_api_key:
        token = x_api_key.strip()

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key or bearer token")

    if token.startswith("fgat."):
        return _verify_analyst_token(token)
    return _verify_api_key_token(token)


async def verify_service_or_admin(principal: TenantContext = Depends(verify_principal)) -> TenantContext:
    if principal.role not in {ROLE_SERVICE, ROLE_ADMIN}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
    return principal


def require_roles(*roles: str):
    async def dependency(principal: TenantContext = Depends(verify_principal)) -> TenantContext:
        if principal.role not in set(roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return principal

    return dependency
