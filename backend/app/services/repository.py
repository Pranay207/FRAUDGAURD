from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any
from uuid import uuid4

from app.db import get_connection


class FraudRepository:
    def upsert_user_identity(self, tenant_id: str, user_id: str, pan_hash: str | None, phone_hash: str | None, aadhaar_last4: str | None, email_hash: str | None) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO users (tenant_id, user_id, pan_hash, phone_hash, aadhaar_last4, email_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, user_id) DO UPDATE SET
                    pan_hash = COALESCE(excluded.pan_hash, users.pan_hash),
                    phone_hash = COALESCE(excluded.phone_hash, users.phone_hash),
                    aadhaar_last4 = COALESCE(excluded.aadhaar_last4, users.aadhaar_last4),
                    email_hash = COALESCE(excluded.email_hash, users.email_hash)
                """,
                (tenant_id, user_id, pan_hash, phone_hash, aadhaar_last4, email_hash, now),
            )
            connection.commit()

    def upsert_device(self, tenant_id: str, device: dict[str, Any]) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO devices (tenant_id, device_id, os, screen_res, is_rooted, sim_count, first_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, device_id) DO UPDATE SET
                    os = COALESCE(excluded.os, devices.os),
                    screen_res = COALESCE(excluded.screen_res, devices.screen_res),
                    is_rooted = excluded.is_rooted,
                    sim_count = excluded.sim_count
                """,
                (tenant_id, device["device_id"], device.get("os"), device.get("screen_res"), int(device.get("is_rooted", False)), int(device.get("sim_count", 1)), now),
            )
            connection.commit()

    def link_user_device(self, tenant_id: str, user_id: str, device_id: str) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO user_devices (tenant_id, user_id, device_id, linked_at) VALUES (?, ?, ?, ?) ON CONFLICT(tenant_id, user_id, device_id) DO NOTHING",
                (tenant_id, user_id, device_id, now),
            )
            connection.commit()

    def get_user_profile(self, tenant_id: str, user_id: str) -> dict[str, Any]:
        with get_connection() as connection:
            user = connection.execute("SELECT * FROM users WHERE tenant_id = ? AND user_id = ?", (tenant_id, user_id)).fetchone()
            devices = connection.execute("SELECT device_id FROM user_devices WHERE tenant_id = ? AND user_id = ?", (tenant_id, user_id)).fetchall()
            payees = connection.execute("SELECT DISTINCT payee_vpa_raw FROM transactions WHERE tenant_id = ? AND user_id = ?", (tenant_id, user_id)).fetchall()
            tx_count = connection.execute("SELECT COUNT(*) AS count FROM transactions WHERE tenant_id = ? AND user_id = ?", (tenant_id, user_id)).fetchone()["count"]
        return {
            "exists": user is not None,
            "last_login_at": user["last_login_at"] if user else None,
            "last_ip_country": user["last_ip_country"] if user else "IN",
            "clean_streak_days": user["clean_streak_days"] if user else 0,
            "known_devices": {row["device_id"] for row in devices},
            "payees": {row["payee_vpa_raw"] for row in payees},
            "total_transactions": tx_count,
        }

    def get_device_link_counts(self, tenant_id: str, device_id: str, phone_hash: str, pan_hash: str) -> dict[str, int]:
        with get_connection() as connection:
            device_count = connection.execute("SELECT COUNT(DISTINCT user_id) AS count FROM user_devices WHERE tenant_id = ? AND device_id = ?", (tenant_id, device_id)).fetchone()["count"]
            phone_count = connection.execute("SELECT COUNT(*) AS count FROM users WHERE tenant_id = ? AND phone_hash = ?", (tenant_id, phone_hash)).fetchone()["count"]
            pan_count = connection.execute("SELECT COUNT(*) AS count FROM users WHERE tenant_id = ? AND pan_hash = ?", (tenant_id, pan_hash)).fetchone()["count"]
        return {"device_users": device_count, "phone_users": phone_count, "pan_users": pan_count}

    def get_payee_graph_counts(self, tenant_id: str, payee_vpa: str) -> dict[str, int]:
        payee_hash = sha256(payee_vpa.encode("utf-8")).hexdigest()
        with get_connection() as connection:
            distinct_users = connection.execute(
                "SELECT COUNT(DISTINCT user_id) AS count FROM transactions WHERE tenant_id = ? AND payee_vpa_hash = ?",
                (tenant_id, payee_hash),
            ).fetchone()["count"]
            total_transactions = connection.execute(
                "SELECT COUNT(*) AS count FROM transactions WHERE tenant_id = ? AND payee_vpa_hash = ?",
                (tenant_id, payee_hash),
            ).fetchone()["count"]
            blocked_transactions = connection.execute(
                "SELECT COUNT(*) AS count FROM transactions WHERE tenant_id = ? AND payee_vpa_hash = ? AND action = 'BLOCK'",
                (tenant_id, payee_hash),
            ).fetchone()["count"]
        return {
            "payee_users": distinct_users,
            "payee_transactions": total_transactions,
            "blocked_transactions": blocked_transactions,
        }

    def get_graph_entity_summary(self, tenant_id: str, entity_type: str, entity_id: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            if entity_type == "user":
                user = connection.execute("SELECT * FROM users WHERE tenant_id = ? AND user_id = ?", (tenant_id, entity_id)).fetchone()
                if user is None:
                    return None
                device_count = connection.execute("SELECT COUNT(DISTINCT device_id) AS count FROM user_devices WHERE tenant_id = ? AND user_id = ?", (tenant_id, entity_id)).fetchone()["count"]
                payee_count = connection.execute("SELECT COUNT(DISTINCT payee_vpa_hash) AS count FROM transactions WHERE tenant_id = ? AND user_id = ?", (tenant_id, entity_id)).fetchone()["count"]
                tx_count = connection.execute("SELECT COUNT(*) AS count FROM transactions WHERE tenant_id = ? AND user_id = ?", (tenant_id, entity_id)).fetchone()["count"]
                return {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "risk_flags": [flag for flag, active in {
                        "shared_phone": bool(user["phone_hash"] and self._count_users_by_field(connection, tenant_id, "phone_hash", user["phone_hash"]) > 1),
                        "shared_pan": bool(user["pan_hash"] and self._count_users_by_field(connection, tenant_id, "pan_hash", user["pan_hash"]) > 1),
                        "multi_device_user": device_count > 2,
                        "multi_payee_user": payee_count > 3,
                    }.items() if active],
                    "stats": {
                        "device_count": device_count,
                        "payee_count": payee_count,
                        "transaction_count": tx_count,
                    },
                }

            if entity_type == "device":
                device = connection.execute("SELECT * FROM devices WHERE tenant_id = ? AND device_id = ?", (tenant_id, entity_id)).fetchone()
                if device is None:
                    return None
                user_count = connection.execute("SELECT COUNT(DISTINCT user_id) AS count FROM user_devices WHERE tenant_id = ? AND device_id = ?", (tenant_id, entity_id)).fetchone()["count"]
                return {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "risk_flags": [flag for flag, active in {
                        "shared_device": user_count > 1,
                        "rooted_device": bool(device["is_rooted"]),
                        "multi_sim_device": int(device["sim_count"] or 1) >= 3,
                    }.items() if active],
                    "stats": {
                        "user_count": user_count,
                        "sim_count": int(device["sim_count"] or 1),
                    },
                }

            if entity_type == "payee":
                payee_hash = sha256(entity_id.encode("utf-8")).hexdigest()
                total = connection.execute("SELECT COUNT(*) AS count FROM transactions WHERE tenant_id = ? AND payee_vpa_hash = ?", (tenant_id, payee_hash)).fetchone()["count"]
                if total == 0:
                    return None
                user_count = connection.execute("SELECT COUNT(DISTINCT user_id) AS count FROM transactions WHERE tenant_id = ? AND payee_vpa_hash = ?", (tenant_id, payee_hash)).fetchone()["count"]
                blocked_count = connection.execute("SELECT COUNT(*) AS count FROM transactions WHERE tenant_id = ? AND payee_vpa_hash = ? AND action = 'BLOCK'", (tenant_id, payee_hash)).fetchone()["count"]
                return {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "risk_flags": [flag for flag, active in {
                        "shared_payee": user_count > 1,
                        "high_risk_payee": blocked_count > 0,
                        "collector_pattern": user_count >= 3,
                    }.items() if active],
                    "stats": {
                        "user_count": user_count,
                        "transaction_count": total,
                        "blocked_count": blocked_count,
                    },
                }

            if entity_type in {"phone_hash", "pan_hash"}:
                count = self._count_users_by_field(connection, tenant_id, entity_type, entity_id)
                if count == 0:
                    return None
                return {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "risk_flags": ["shared_identifier"] if count > 1 else [],
                    "stats": {
                        "user_count": count,
                    },
                }
        return None

    def _count_users_by_field(self, connection, tenant_id: str, field_name: str, field_value: str) -> int:
        query = f"SELECT COUNT(*) AS count FROM users WHERE tenant_id = ? AND {field_name} = ?"
        return connection.execute(query, (tenant_id, field_value)).fetchone()["count"]

    def update_login(self, tenant_id: str, user_id: str, ip_country: str) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO users (tenant_id, user_id, created_at, last_login_at, last_ip_country)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, user_id) DO UPDATE SET
                    last_login_at = excluded.last_login_at,
                    last_ip_country = excluded.last_ip_country
                """,
                (tenant_id, user_id, now, now, ip_country),
            )
            connection.commit()

    def create_session(self, tenant_id: str, session_id: str, user_id: str, device_id: str, fraud_score: int, action: str, ip_country: str) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO sessions (tenant_id, session_id, user_id, device_id, fraud_score, action, ip_country, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, session_id) DO UPDATE SET user_id = excluded.user_id, device_id = excluded.device_id, fraud_score = excluded.fraud_score, action = excluded.action, ip_country = excluded.ip_country, created_at = excluded.created_at",
                (tenant_id, session_id, user_id, device_id, fraud_score, action, ip_country, now),
            )
            connection.commit()

    def transaction_velocity(self, tenant_id: str, user_id: str) -> int:
        cutoff = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        with get_connection() as connection:
            count = connection.execute("SELECT COUNT(*) AS count FROM transactions WHERE tenant_id = ? AND user_id = ? AND created_at >= ?", (tenant_id, user_id, cutoff)).fetchone()["count"]
        return count

    def create_transaction(self, tenant_id: str, request_id: str, user_id: str, amount_paise: int, payee_vpa: str, session_id: str, device_id: str, upi_remark: str, fraud_score: int, action: str) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO transactions (tenant_id, request_id, user_id, amount_paise, payee_vpa_hash, payee_vpa_raw, session_id, device_id, upi_remark, fraud_score, action, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, request_id, user_id, amount_paise, sha256(payee_vpa.encode("utf-8")).hexdigest(), payee_vpa, session_id, device_id, upi_remark, fraud_score, action, now),
            )
            connection.commit()

    def write_audit_event(self, tenant_id: str, request_id: str, route: str, user_id: str | None, fraud_score: int, action: str, reasons: list[str], factors: list[dict[str, Any]], request_payload: dict[str, Any]) -> None:
        now = datetime.now(UTC).isoformat()
        case_status = "OPEN" if action in {"CHALLENGE", "BLOCK"} else "RESOLVED"
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO audit_events (tenant_id, request_id, route, user_id, fraud_score, action, reasons_json, factors_json, request_json, case_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, request_id) DO UPDATE SET route = excluded.route, user_id = excluded.user_id, fraud_score = excluded.fraud_score, action = excluded.action, reasons_json = excluded.reasons_json, factors_json = excluded.factors_json, request_json = excluded.request_json, case_status = excluded.case_status, created_at = excluded.created_at",
                (tenant_id, request_id, route, user_id, fraud_score, action, json.dumps(reasons), json.dumps(factors), json.dumps(request_payload), case_status, now),
            )
            connection.commit()

    def get_audit_event(self, tenant_id: str, request_id: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT a.*, f.label AS feedback_label, f.notes AS feedback_notes FROM audit_events a LEFT JOIN feedback f ON f.tenant_id = a.tenant_id AND f.request_id = a.request_id WHERE a.tenant_id = ? AND a.request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
        return None if row is None else self._audit_row_to_dict(row)

    def list_cases(self, tenant_id: str, limit: int = 20, action: str | None = None, case_status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT a.*, f.label AS feedback_label, f.notes AS feedback_notes FROM audit_events a LEFT JOIN feedback f ON f.tenant_id = a.tenant_id AND f.request_id = a.request_id WHERE a.tenant_id = ?"
        params: list[Any] = [tenant_id]
        if action:
            query += " AND a.action = ?"
            params.append(action)
        if case_status:
            query += " AND a.case_status = ?"
            params.append(case_status)
        query += " ORDER BY a.created_at DESC LIMIT ?"
        params.append(limit)
        with get_connection() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._audit_row_to_dict(row) for row in rows]

    def submit_feedback(self, tenant_id: str, request_id: str, label: str, notes: str | None, reported_by: str) -> dict[str, Any] | None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            exists = connection.execute("SELECT request_id FROM audit_events WHERE tenant_id = ? AND request_id = ?", (tenant_id, request_id)).fetchone()
            if exists is None:
                return None
            connection.execute(
                "INSERT INTO feedback (tenant_id, request_id, label, notes, reported_by, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, request_id) DO UPDATE SET label = excluded.label, notes = excluded.notes, reported_by = excluded.reported_by, created_at = excluded.created_at",
                (tenant_id, request_id, label, notes, reported_by, now),
            )
            connection.commit()
        return {"request_id": request_id, "label": label, "notes": notes, "reported_by": reported_by}

    def update_case_status(self, tenant_id: str, request_id: str, case_status: str, assigned_to: str | None) -> dict[str, Any] | None:
        with get_connection() as connection:
            exists = connection.execute("SELECT request_id FROM audit_events WHERE tenant_id = ? AND request_id = ?", (tenant_id, request_id)).fetchone()
            if exists is None:
                return None
            connection.execute("UPDATE audit_events SET case_status = ?, assigned_to = ? WHERE tenant_id = ? AND request_id = ?", (case_status, assigned_to, tenant_id, request_id))
            connection.commit()
        return {"request_id": request_id, "case_status": case_status, "assigned_to": assigned_to}

    def dashboard_summary(self, tenant_id: str) -> dict[str, Any]:
        with get_connection() as connection:
            total = connection.execute("SELECT COUNT(*) AS count FROM audit_events WHERE tenant_id = ?", (tenant_id,)).fetchone()["count"]
            blocked = connection.execute("SELECT COUNT(*) AS count FROM audit_events WHERE tenant_id = ? AND action = 'BLOCK'", (tenant_id,)).fetchone()["count"]
            challenged = connection.execute("SELECT COUNT(*) AS count FROM audit_events WHERE tenant_id = ? AND action = 'CHALLENGE'", (tenant_id,)).fetchone()["count"]
            open_cases = connection.execute("SELECT COUNT(*) AS count FROM audit_events WHERE tenant_id = ? AND case_status != 'RESOLVED'", (tenant_id,)).fetchone()["count"]
            feedback = connection.execute("SELECT COUNT(*) AS count FROM feedback WHERE tenant_id = ?", (tenant_id,)).fetchone()["count"]
            queued = connection.execute("SELECT COUNT(*) AS count FROM webhook_deliveries WHERE tenant_id = ? AND status = 'QUEUED'", (tenant_id,)).fetchone()["count"]
            signal_rows = connection.execute("SELECT factors_json FROM audit_events WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 50", (tenant_id,)).fetchall()
        top_signals: dict[str, dict[str, Any]] = {}
        for row in signal_rows:
            for factor in json.loads(row["factors_json"]):
                bucket = top_signals.setdefault(factor["signal"], {"signal": factor["signal"], "count": 0, "impact": 0})
                bucket["count"] += 1
                bucket["impact"] += factor["impact"]
        signals = sorted(top_signals.values(), key=lambda item: (item["count"], item["impact"]), reverse=True)[:6]
        recent = self.list_cases(tenant_id=tenant_id, limit=8)
        return {
            "metrics": [
                {"label": "Scored events", "value": str(total), "tone": "neutral"},
                {"label": "Blocked", "value": str(blocked), "tone": "danger" if blocked else "neutral"},
                {"label": "Challenged", "value": str(challenged), "tone": "warn" if challenged else "neutral"},
                {"label": "Open cases", "value": str(open_cases), "tone": "warn" if open_cases else "good"},
                {"label": "Queued webhooks", "value": str(queued), "tone": "warn" if queued else "good"},
                {"label": "Feedback labels", "value": str(feedback), "tone": "good" if feedback else "neutral"},
            ],
            "recent_cases": recent,
            "top_signals": signals,
        }

    def get_idempotent_response(self, tenant_id: str, route: str, idempotency_key: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute("SELECT response_json FROM idempotency_keys WHERE tenant_id = ? AND route = ? AND idempotency_key = ?", (tenant_id, route, idempotency_key)).fetchone()
        return None if row is None else json.loads(row["response_json"])

    def save_idempotent_response(self, tenant_id: str, route: str, idempotency_key: str, response_payload: dict[str, Any]) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO idempotency_keys (tenant_id, route, idempotency_key, response_json, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(tenant_id, route, idempotency_key) DO UPDATE SET response_json = excluded.response_json, created_at = excluded.created_at",
                (tenant_id, route, idempotency_key, json.dumps(response_payload), now),
            )
            connection.commit()

    def create_webhook_endpoint(self, tenant_id: str, event_type: str, url: str, secret: str | None) -> dict[str, Any]:
        webhook_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute("INSERT INTO webhook_endpoints (tenant_id, webhook_id, event_type, url, secret, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)", (tenant_id, webhook_id, event_type, url, secret, now))
            connection.commit()
        return {"webhook_id": webhook_id, "event_type": event_type, "url": url, "is_active": True, "created_at": datetime.fromisoformat(now)}

    def list_webhook_endpoints(self, tenant_id: str) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute("SELECT * FROM webhook_endpoints WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
        return [{"webhook_id": row["webhook_id"], "event_type": row["event_type"], "url": row["url"], "is_active": bool(row["is_active"]), "created_at": datetime.fromisoformat(row["created_at"])} for row in rows]

    def enqueue_webhook_deliveries(self, tenant_id: str, event_type: str, request_id: str, payload: dict[str, Any]) -> None:
        attempted_at = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            endpoints = connection.execute("SELECT webhook_id FROM webhook_endpoints WHERE tenant_id = ? AND event_type = ? AND is_active = 1", (tenant_id, event_type)).fetchall()
            for endpoint in endpoints:
                connection.execute("INSERT INTO webhook_deliveries (tenant_id, delivery_id, webhook_id, event_type, request_id, status, payload_json, attempted_at, error_message) VALUES (?, ?, ?, ?, ?, 'QUEUED', ?, ?, NULL)", (tenant_id, str(uuid4()), endpoint["webhook_id"], event_type, request_id, json.dumps(payload), attempted_at))
            connection.commit()

    def list_webhook_deliveries(self, tenant_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute("SELECT * FROM webhook_deliveries WHERE tenant_id = ? ORDER BY attempted_at DESC LIMIT ?", (tenant_id, limit)).fetchall()
        return [{"delivery_id": row["delivery_id"], "webhook_id": row["webhook_id"], "event_type": row["event_type"], "request_id": row["request_id"], "status": row["status"], "attempted_at": datetime.fromisoformat(row["attempted_at"]), "error_message": row["error_message"]} for row in rows]

    def list_queued_webhook_deliveries(self, tenant_id: str, limit: int = 25) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute(
                """
                SELECT d.*, e.url, e.secret
                FROM webhook_deliveries d
                JOIN webhook_endpoints e ON e.tenant_id = d.tenant_id AND e.webhook_id = d.webhook_id
                WHERE d.tenant_id = ? AND d.status = 'QUEUED' AND e.is_active = 1
                ORDER BY d.attempted_at ASC LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_webhook_delivery(self, tenant_id: str, delivery_id: str, status: str, error_message: str | None = None) -> None:
        attempted_at = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute("UPDATE webhook_deliveries SET status = ?, attempted_at = ?, error_message = ? WHERE tenant_id = ? AND delivery_id = ?", (status, attempted_at, error_message, tenant_id, delivery_id))
            connection.commit()

    def get_tenant(self, tenant_id: str, key_name: str) -> dict[str, Any]:
        with get_connection() as connection:
            row = connection.execute("SELECT tenant_id, name, status FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return {"tenant_id": row["tenant_id"], "name": row["name"], "status": row["status"], "key_name": key_name}

    def create_api_key(self, tenant_id: str, key_name: str) -> dict[str, Any]:
        raw_key = f"fg_{uuid4().hex}_{uuid4().hex[:12]}"
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        key_prefix = raw_key[:12]
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute("INSERT INTO api_keys (key_hash, tenant_id, key_name, is_active, created_at) VALUES (?, ?, ?, 1, ?)", (key_hash, tenant_id, key_name, now))
            connection.commit()
        return {"raw_key": raw_key, "key_name": key_name, "key_prefix": key_prefix, "is_active": True, "created_at": datetime.fromisoformat(now), "last_used_at": None}

    def list_api_keys(self, tenant_id: str) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute("SELECT key_name, key_hash, is_active, created_at, last_used_at FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
        return [{"key_name": row["key_name"], "key_prefix": row["key_hash"][:12], "is_active": bool(row["is_active"]), "created_at": datetime.fromisoformat(row["created_at"]), "last_used_at": datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None} for row in rows]

    def save_model_version(self, tenant_id: str, model_name: str, version_id: str, artifact_path: str, metrics: dict[str, float]) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO model_versions (tenant_id, model_name, version_id, artifact_path, metrics_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (tenant_id, model_name, version_id, artifact_path, json.dumps(metrics), now),
            )
            connection.commit()

    def list_model_versions(self, tenant_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute(
                "SELECT model_name, version_id, artifact_path, metrics_json, created_at FROM model_versions WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [
            {
                "model_name": row["model_name"],
                "version_id": row["version_id"],
                "artifact_path": row["artifact_path"],
                "metrics": json.loads(row["metrics_json"]),
                "created_at": datetime.fromisoformat(row["created_at"]),
            }
            for row in rows
        ]

    def _audit_row_to_dict(self, row: Any) -> dict[str, Any]:
        return {
            "request_id": row["request_id"],
            "route": row["route"],
            "user_id": row["user_id"],
            "fraud_score": row["fraud_score"],
            "action": row["action"],
            "reasons": json.loads(row["reasons_json"]),
            "factors": json.loads(row["factors_json"]),
            "request_payload": json.loads(row["request_json"]),
            "created_at": datetime.fromisoformat(row["created_at"]),
            "feedback_label": row["feedback_label"],
            "feedback_notes": row["feedback_notes"],
            "case_status": row["case_status"],
            "assigned_to": row["assigned_to"],
        }


repository = FraudRepository()
