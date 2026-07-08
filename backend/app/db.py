from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from app.config import get_settings


REQUIRED_SQLITE_COLUMNS = {
    "tenants": {"tenant_id", "name", "status", "created_at"},
    "api_keys": {"key_hash", "tenant_id", "key_name", "is_active", "created_at"},
    "users": {"tenant_id", "user_id", "created_at"},
    "devices": {"tenant_id", "device_id", "first_seen_at"},
    "user_devices": {"tenant_id", "user_id", "device_id", "linked_at"},
    "sessions": {"tenant_id", "session_id", "user_id", "device_id", "fraud_score", "action", "ip_country", "created_at"},
    "transactions": {"tenant_id", "request_id", "user_id", "amount_paise", "payee_vpa_hash", "payee_vpa_raw", "session_id", "device_id", "fraud_score", "action", "created_at"},
    "audit_events": {"tenant_id", "request_id", "route", "fraud_score", "action", "reasons_json", "factors_json", "request_json", "case_status", "created_at"},
    "feedback": {"tenant_id", "request_id", "label", "reported_by", "created_at"},
    "idempotency_keys": {"tenant_id", "route", "idempotency_key", "response_json", "created_at"},
    "webhook_endpoints": {"tenant_id", "webhook_id", "event_type", "url", "is_active", "created_at"},
    "webhook_deliveries": {"tenant_id", "delivery_id", "webhook_id", "event_type", "request_id", "status", "payload_json", "attempted_at"},
}


class DBConnection:
    def __init__(self, kind: str, connection):
        self.kind = kind
        self.connection = connection

    def __enter__(self) -> DBConnection:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is not None:
                self.connection.rollback()
        finally:
            self.connection.close()

    def execute(self, query: str, params: tuple | list | None = None):
        params = tuple(params or ())
        if self.kind == "postgres":
            query = query.replace("?", "%s")
        return self.connection.execute(query, params)

    def executescript(self, script: str) -> None:
        if self.kind == "sqlite":
            self.connection.executescript(script)
            return

        statements = [statement.strip() for statement in script.split(";") if statement.strip()]
        with self.connection.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)

    def commit(self) -> None:
        self.connection.commit()


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _build_database_url() -> str:
    settings = get_settings()
    if settings.database_url:
        return settings.database_url
    path = Path(settings.database_path)
    return f"sqlite:///{path.as_posix()}"


def _sqlite_path_from_url(database_url: str) -> Path:
    parsed = urlparse(database_url)
    if parsed.scheme != "sqlite":
        raise ValueError(f"Unsupported SQLite URL: {database_url}")
    raw_path = (parsed.netloc + parsed.path).lstrip("/") if parsed.netloc else parsed.path.lstrip("/")
    return Path(raw_path or "data/fraudguard.db")


def _connect_sqlite(database_url: str) -> DBConnection:
    path = _sqlite_path_from_url(database_url)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return DBConnection("sqlite", connection)


def _connect_postgres(database_url: str) -> DBConnection:
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Postgres support requires psycopg. Install project dependencies again after the pyproject update."
        ) from exc

    connection = psycopg.connect(database_url, row_factory=dict_row)
    return DBConnection("postgres", connection)


@contextmanager
def get_connection() -> Iterator[DBConnection]:
    database_url = _build_database_url()
    if database_url.startswith("sqlite://"):
        connection = _connect_sqlite(database_url)
    elif database_url.startswith("postgresql://") or database_url.startswith("postgres://"):
        connection = _connect_postgres(database_url)
    else:
        raise ValueError(f"Unsupported database URL scheme in {database_url}")

    with connection as managed:
        yield managed


def _migration_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "migrations"


def _sqlite_existing_tables(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {row[0] for row in rows}


def _sqlite_table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row[1] for row in rows}


def _sqlite_database_is_legacy(path: Path) -> bool:
    if not path.exists():
        return False

    connection = sqlite3.connect(path)
    try:
        existing_tables = _sqlite_existing_tables(connection)
        app_tables = set(REQUIRED_SQLITE_COLUMNS)
        if not (existing_tables & app_tables):
            return False

        for table_name, required_columns in REQUIRED_SQLITE_COLUMNS.items():
            if table_name not in existing_tables:
                continue
            present_columns = _sqlite_table_columns(connection, table_name)
            if not required_columns.issubset(present_columns):
                return True
        return False
    finally:
        connection.close()


def _backup_legacy_sqlite_database(path: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    backup_path = path.with_name(f"{path.stem}.legacy-{stamp}{path.suffix}")
    path.replace(backup_path)
    return backup_path


def _prepare_database() -> None:
    database_url = _build_database_url()
    if not database_url.startswith("sqlite://"):
        return

    path = _sqlite_path_from_url(database_url)
    path.parent.mkdir(parents=True, exist_ok=True)
    if _sqlite_database_is_legacy(path):
        _backup_legacy_sqlite_database(path)


def apply_migrations() -> None:
    migration_dir = _migration_dir()
    migration_files = sorted(migration_dir.glob("*.sql"))
    if not migration_files:
        return

    with get_connection() as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        connection.commit()
        rows = connection.execute("SELECT version FROM schema_migrations").fetchall()
        applied_versions = {row["version"] for row in rows}

        for migration_file in migration_files:
            version = migration_file.stem
            if version in applied_versions:
                continue
            script = migration_file.read_text(encoding="utf-8")
            connection.executescript(script)
            connection.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)",
                (version,),
            )
            connection.commit()


def init_db() -> None:
    settings = get_settings()
    _prepare_database()
    apply_migrations()
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO tenants (tenant_id, name, status, created_at) VALUES ('demo-tenant', ?, 'active', CURRENT_TIMESTAMP) ON CONFLICT(tenant_id) DO NOTHING",
            (settings.default_tenant_name,),
        )
        connection.execute(
            "INSERT INTO api_keys (key_hash, tenant_id, key_name, is_active, created_at) VALUES (?, 'demo-tenant', 'default', 1, CURRENT_TIMESTAMP) ON CONFLICT(key_hash) DO NOTHING",
            (_hash_api_key(settings.api_key),),
        )
        connection.commit()
