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
        self.write_case_activity(tenant_id, request_id, "case.created", user_id, {"route": route, "fraud_score": fraud_score, "action": action, "reasons": reasons[:3]})

    def write_case_activity(self, tenant_id: str, request_id: str, event_type: str, actor_id: str | None, details: dict[str, Any]) -> dict[str, Any]:
        activity_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO case_activity (tenant_id, activity_id, request_id, event_type, actor_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, activity_id, request_id, event_type, actor_id, json.dumps(details), now),
            )
            connection.commit()
        return {
            "activity_id": activity_id,
            "request_id": request_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "details": details,
            "created_at": datetime.fromisoformat(now),
        }

    def list_case_activity(self, tenant_id: str, request_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute(
                "SELECT activity_id, request_id, event_type, actor_id, details_json, created_at FROM case_activity WHERE tenant_id = ? AND request_id = ? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, request_id, limit),
            ).fetchall()
        return [
            {
                "activity_id": row["activity_id"],
                "request_id": row["request_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "details": json.loads(row["details_json"]),
                "created_at": datetime.fromisoformat(row["created_at"]),
            }
            for row in rows
        ]

    def get_audit_event(self, tenant_id: str, request_id: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT a.*, f.label AS feedback_label, f.notes AS feedback_notes FROM audit_events a LEFT JOIN feedback f ON f.tenant_id = a.tenant_id AND f.request_id = a.request_id WHERE a.tenant_id = ? AND a.request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
        return None if row is None else self._audit_row_to_dict(row)

    def list_cases(self, tenant_id: str, limit: int = 20, action: str | None = None, case_status: str | None = None, search: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT a.*, f.label AS feedback_label, f.notes AS feedback_notes FROM audit_events a LEFT JOIN feedback f ON f.tenant_id = a.tenant_id AND f.request_id = a.request_id WHERE a.tenant_id = ?"
        params: list[Any] = [tenant_id]
        if action:
            query += " AND a.action = ?"
            params.append(action)
        if case_status:
            query += " AND a.case_status = ?"
            params.append(case_status)
        if search:
            query += " AND (a.request_id LIKE ? OR COALESCE(a.user_id, '') LIKE ?)"
            needle = f"%{search}%"
            params.extend([needle, needle])
        query += " ORDER BY a.created_at DESC LIMIT ?"
        params.append(limit)
        with get_connection() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._audit_row_to_dict(row) for row in rows]

    def find_linked_cases(self, tenant_id: str, request_id: str, limit: int = 5) -> list[dict[str, Any]]:
        current = self.get_audit_event(tenant_id, request_id)
        if current is None:
            return []

        payload = current["request_payload"]
        current_device = payload.get("device_id") or payload.get("device", {}).get("device_id")
        current_payee = payload.get("payee_vpa")
        current_phone = payload.get("phone_hash")
        current_pan = payload.get("pan_hash")
        current_user = current.get("user_id")

        with get_connection() as connection:
            rows = connection.execute(
                "SELECT a.*, f.label AS feedback_label, f.notes AS feedback_notes FROM audit_events a LEFT JOIN feedback f ON f.tenant_id = a.tenant_id AND f.request_id = a.request_id WHERE a.tenant_id = ? AND a.request_id != ? ORDER BY a.created_at DESC LIMIT 200",
                (tenant_id, request_id),
            ).fetchall()

        linked: list[dict[str, Any]] = []
        for row in rows:
            item = self._audit_row_to_dict(row)
            candidate_payload = item["request_payload"]
            candidate_device = candidate_payload.get("device_id") or candidate_payload.get("device", {}).get("device_id")
            matched_signals: list[str] = []

            if current_user and item.get("user_id") == current_user:
                matched_signals.append("shared_user")
            if current_device and candidate_device == current_device:
                matched_signals.append("shared_device")
            if current_payee and candidate_payload.get("payee_vpa") == current_payee:
                matched_signals.append("shared_payee")
            if current_phone and candidate_payload.get("phone_hash") == current_phone:
                matched_signals.append("shared_phone")
            if current_pan and candidate_payload.get("pan_hash") == current_pan:
                matched_signals.append("shared_pan")

            if matched_signals:
                linked.append({
                    "request_id": item["request_id"],
                    "route": item["route"],
                    "action": item["action"],
                    "fraud_score": item["fraud_score"],
                    "case_status": item["case_status"],
                    "assigned_to": item.get("assigned_to"),
                    "created_at": item["created_at"],
                    "matched_signals": matched_signals,
                })

        linked.sort(key=lambda item: (len(item["matched_signals"]), item["fraud_score"]), reverse=True)
        return linked[:limit]

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
        self.write_case_activity(tenant_id, request_id, "case.feedback", reported_by, {"label": label, "notes": notes})
        return {"request_id": request_id, "label": label, "notes": notes, "reported_by": reported_by}

    def update_case_status(self, tenant_id: str, request_id: str, case_status: str, assigned_to: str | None) -> dict[str, Any] | None:
        with get_connection() as connection:
            exists = connection.execute("SELECT request_id FROM audit_events WHERE tenant_id = ? AND request_id = ?", (tenant_id, request_id)).fetchone()
            if exists is None:
                return None
            connection.execute("UPDATE audit_events SET case_status = ?, assigned_to = ? WHERE tenant_id = ? AND request_id = ?", (case_status, assigned_to, tenant_id, request_id))
            connection.commit()
        self.write_case_activity(tenant_id, request_id, "case.status_updated", assigned_to, {"case_status": case_status, "assigned_to": assigned_to})
        return {"request_id": request_id, "case_status": case_status, "assigned_to": assigned_to}

    def bulk_update_case_status(self, tenant_id: str, request_ids: list[str], case_status: str, assigned_to: str | None) -> dict[str, Any]:
        updated_ids: list[str] = []
        with get_connection() as connection:
            for request_id in request_ids:
                exists = connection.execute("SELECT request_id FROM audit_events WHERE tenant_id = ? AND request_id = ?", (tenant_id, request_id)).fetchone()
                if exists is None:
                    continue
                connection.execute("UPDATE audit_events SET case_status = ?, assigned_to = ? WHERE tenant_id = ? AND request_id = ?", (case_status, assigned_to, tenant_id, request_id))
                updated_ids.append(request_id)
            connection.commit()
        for request_id in updated_ids:
            self.write_case_activity(tenant_id, request_id, "case.status_bulk_updated", assigned_to, {"case_status": case_status, "assigned_to": assigned_to, "bulk": True})
        return {"updated": len(updated_ids), "request_ids": updated_ids, "case_status": case_status, "assigned_to": assigned_to}

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
        return {"webhook_id": webhook_id, "event_type": event_type, "url": url, "has_secret": bool(secret), "is_active": True, "created_at": datetime.fromisoformat(now)}

    def update_webhook_secret(self, tenant_id: str, webhook_id: str, secret: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT event_type, url, is_active, created_at FROM webhook_endpoints WHERE tenant_id = ? AND webhook_id = ?",
                (tenant_id, webhook_id),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE webhook_endpoints SET secret = ? WHERE tenant_id = ? AND webhook_id = ?",
                (secret, tenant_id, webhook_id),
            )
            connection.commit()
        return {"webhook_id": webhook_id, "event_type": row["event_type"], "url": row["url"], "has_secret": True, "is_active": bool(row["is_active"]), "created_at": datetime.fromisoformat(row["created_at"])}

    def list_webhook_endpoints(self, tenant_id: str) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute("SELECT * FROM webhook_endpoints WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
        return [{"webhook_id": row["webhook_id"], "event_type": row["event_type"], "url": row["url"], "has_secret": bool(row["secret"]), "is_active": bool(row["is_active"]), "created_at": datetime.fromisoformat(row["created_at"])} for row in rows]

    def enqueue_webhook_deliveries(self, tenant_id: str, event_type: str, request_id: str, payload: dict[str, Any]) -> None:
        attempted_at = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            endpoints = connection.execute("SELECT webhook_id FROM webhook_endpoints WHERE tenant_id = ? AND event_type = ? AND is_active = 1", (tenant_id, event_type)).fetchall()
            for endpoint in endpoints:
                connection.execute(
                    "INSERT INTO webhook_deliveries (tenant_id, delivery_id, webhook_id, event_type, request_id, status, payload_json, attempted_at, retry_count, max_attempts, next_attempt_at, last_http_status, error_message) VALUES (?, ?, ?, ?, ?, 'QUEUED', ?, ?, 0, 3, ?, NULL, NULL)",
                    (tenant_id, str(uuid4()), endpoint["webhook_id"], event_type, request_id, json.dumps(payload), attempted_at, attempted_at),
                )
            connection.commit()

    def list_webhook_deliveries(self, tenant_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute("SELECT * FROM webhook_deliveries WHERE tenant_id = ? ORDER BY attempted_at DESC LIMIT ?", (tenant_id, limit)).fetchall()
        return [
            {
                "delivery_id": row["delivery_id"],
                "webhook_id": row["webhook_id"],
                "event_type": row["event_type"],
                "request_id": row["request_id"],
                "status": row["status"],
                "attempted_at": datetime.fromisoformat(row["attempted_at"]),
                "retry_count": int(row["retry_count"] or 0),
                "max_attempts": int(row["max_attempts"] or 3),
                "next_attempt_at": datetime.fromisoformat(row["next_attempt_at"]) if row["next_attempt_at"] else None,
                "last_http_status": row["last_http_status"],
                "error_message": row["error_message"],
            }
            for row in rows
        ]

    def list_queued_webhook_deliveries(self, tenant_id: str, limit: int = 25) -> list[dict[str, Any]]:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            rows = connection.execute(
                """
                SELECT d.*, e.url, e.secret
                FROM webhook_deliveries d
                JOIN webhook_endpoints e ON e.tenant_id = d.tenant_id AND e.webhook_id = d.webhook_id
                WHERE d.tenant_id = ? AND d.status = 'QUEUED' AND e.is_active = 1 AND COALESCE(d.next_attempt_at, d.attempted_at) <= ?
                ORDER BY COALESCE(d.next_attempt_at, d.attempted_at) ASC LIMIT ?
                """,
                (tenant_id, now, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_webhook_delivery(self, tenant_id: str, delivery_id: str, status: str, error_message: str | None = None) -> None:
        attempted_at = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute("UPDATE webhook_deliveries SET status = ?, attempted_at = ?, error_message = ? WHERE tenant_id = ? AND delivery_id = ?", (status, attempted_at, error_message, tenant_id, delivery_id))
            connection.commit()

    def mark_webhook_delivery_success(self, tenant_id: str, delivery_id: str, http_status: int) -> None:
        attempted_at = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "UPDATE webhook_deliveries SET status = 'DELIVERED', attempted_at = ?, next_attempt_at = NULL, last_http_status = ?, error_message = NULL WHERE tenant_id = ? AND delivery_id = ?",
                (attempted_at, http_status, tenant_id, delivery_id),
            )
            connection.commit()

    def mark_webhook_delivery_failure(self, tenant_id: str, delivery_id: str, error_message: str, http_status: int | None = None) -> dict[str, Any] | None:
        attempted_at_dt = datetime.now(UTC)
        attempted_at = attempted_at_dt.isoformat()
        with get_connection() as connection:
            row = connection.execute(
                "SELECT retry_count, max_attempts FROM webhook_deliveries WHERE tenant_id = ? AND delivery_id = ?",
                (tenant_id, delivery_id),
            ).fetchone()
            if row is None:
                return None
            retry_count = int(row["retry_count"] or 0) + 1
            max_attempts = int(row["max_attempts"] or 3)
            if retry_count >= max_attempts:
                status = 'DEAD_LETTER'
                next_attempt_at = None
            else:
                status = 'QUEUED'
                next_attempt_at = (attempted_at_dt + timedelta(minutes=2 ** retry_count)).isoformat()
            connection.execute(
                "UPDATE webhook_deliveries SET status = ?, attempted_at = ?, retry_count = ?, next_attempt_at = ?, last_http_status = ?, error_message = ? WHERE tenant_id = ? AND delivery_id = ?",
                (status, attempted_at, retry_count, next_attempt_at, http_status, error_message[:500], tenant_id, delivery_id),
            )
            connection.commit()
        return {"status": status, "retry_count": retry_count, "max_attempts": max_attempts}

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

    def save_model_version(self, tenant_id: str, model_name: str, version_id: str, artifact_path: str, metrics: dict[str, float], stage: str = "candidate", is_active: bool = False, training_job_id: str | None = None) -> None:
        now = datetime.now(UTC).isoformat()
        promoted_at = now if is_active else None
        with get_connection() as connection:
            if is_active:
                connection.execute("UPDATE model_versions SET is_active = 0 WHERE tenant_id = ? AND model_name = ?", (tenant_id, model_name))
            connection.execute(
                "INSERT INTO model_versions (tenant_id, model_name, version_id, artifact_path, metrics_json, stage, is_active, training_job_id, promoted_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, model_name, version_id, artifact_path, json.dumps(metrics), stage, int(is_active), training_job_id, promoted_at, now),
            )
            connection.commit()

    def activate_model_version(self, tenant_id: str, model_name: str, version_id: str, stage: str = "production") -> dict[str, Any] | None:
        promoted_at = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            row = connection.execute(
                "SELECT tenant_id, model_name, version_id FROM model_versions WHERE tenant_id = ? AND model_name = ? AND version_id = ?",
                (tenant_id, model_name, version_id),
            ).fetchone()
            if row is None:
                return None
            connection.execute("UPDATE model_versions SET is_active = 0 WHERE tenant_id = ? AND model_name = ?", (tenant_id, model_name))
            connection.execute(
                "UPDATE model_versions SET is_active = 1, stage = ?, promoted_at = ? WHERE tenant_id = ? AND model_name = ? AND version_id = ?",
                (stage, promoted_at, tenant_id, model_name, version_id),
            )
            connection.commit()
        return {"model_name": model_name, "version_id": version_id, "stage": stage, "is_active": True, "promoted_at": datetime.fromisoformat(promoted_at)}

    def get_active_model_version(self, tenant_id: str, model_name: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT model_name, version_id, artifact_path, metrics_json, stage, is_active, training_job_id, promoted_at, created_at FROM model_versions WHERE tenant_id = ? AND model_name = ? AND is_active = 1 ORDER BY promoted_at DESC, created_at DESC LIMIT 1",
                (tenant_id, model_name),
            ).fetchone()
        if row is None:
            return None
        return {
            "model_name": row["model_name"],
            "version_id": row["version_id"],
            "artifact_path": row["artifact_path"],
            "metrics": json.loads(row["metrics_json"]),
            "stage": row["stage"],
            "is_active": bool(row["is_active"]),
            "training_job_id": row["training_job_id"],
            "promoted_at": datetime.fromisoformat(row["promoted_at"]) if row["promoted_at"] else None,
            "created_at": datetime.fromisoformat(row["created_at"]),
        }

    def list_model_versions(self, tenant_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute(
                "SELECT model_name, version_id, artifact_path, metrics_json, stage, is_active, training_job_id, promoted_at, created_at FROM model_versions WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [
            {
                "model_name": row["model_name"],
                "version_id": row["version_id"],
                "artifact_path": row["artifact_path"],
                "metrics": json.loads(row["metrics_json"]),
                "stage": row["stage"],
                "is_active": bool(row["is_active"]),
                "training_job_id": row["training_job_id"],
                "promoted_at": datetime.fromisoformat(row["promoted_at"]) if row["promoted_at"] else None,
                "created_at": datetime.fromisoformat(row["created_at"]),
            }
            for row in rows
        ]

    def count_analyst_users(self, tenant_id: str) -> int:
        with get_connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM analyst_users WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return int(row["count"])

    def create_analyst_user(self, tenant_id: str, email: str, full_name: str, role: str, password_hash: str, password_salt: str, created_by: str | None) -> dict[str, Any]:
        analyst_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO analyst_users (tenant_id, analyst_id, email, full_name, role, password_hash, password_salt, is_active, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (tenant_id, analyst_id, email.lower(), full_name, role, password_hash, password_salt, created_by, now),
            )
            connection.commit()
        return {"analyst_id": analyst_id, "email": email.lower(), "full_name": full_name, "role": role, "is_active": True, "created_at": datetime.fromisoformat(now), "last_login_at": None}

    def get_analyst_by_email(self, tenant_id: str, email: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT * FROM analyst_users WHERE tenant_id = ? AND email = ?",
                (tenant_id, email.lower()),
            ).fetchone()
        return dict(row) if row else None

    def get_analyst_by_id(self, tenant_id: str, analyst_id: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT analyst_id, email, full_name, role, is_active, created_at, last_login_at FROM analyst_users WHERE tenant_id = ? AND analyst_id = ?",
                (tenant_id, analyst_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "analyst_id": row["analyst_id"],
            "email": row["email"],
            "full_name": row["full_name"],
            "role": row["role"],
            "is_active": bool(row["is_active"]),
            "created_at": datetime.fromisoformat(row["created_at"]),
            "last_login_at": datetime.fromisoformat(row["last_login_at"]) if row["last_login_at"] else None,
        }

    def list_analyst_users(self, tenant_id: str) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute(
                "SELECT analyst_id, email, full_name, role, is_active, created_at, last_login_at FROM analyst_users WHERE tenant_id = ? ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        return [
            {
                "analyst_id": row["analyst_id"],
                "email": row["email"],
                "full_name": row["full_name"],
                "role": row["role"],
                "is_active": bool(row["is_active"]),
                "created_at": datetime.fromisoformat(row["created_at"]),
                "last_login_at": datetime.fromisoformat(row["last_login_at"]) if row["last_login_at"] else None,
            }
            for row in rows
        ]

    def touch_analyst_login(self, tenant_id: str, analyst_id: str) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "UPDATE analyst_users SET last_login_at = ? WHERE tenant_id = ? AND analyst_id = ?",
                (now, tenant_id, analyst_id),
            )
            connection.commit()

    def update_analyst_status(self, tenant_id: str, analyst_id: str, is_active: bool) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM analyst_users WHERE tenant_id = ? AND analyst_id = ?",
                (tenant_id, analyst_id),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE analyst_users SET is_active = ? WHERE tenant_id = ? AND analyst_id = ?",
                (int(is_active), tenant_id, analyst_id),
            )
            connection.commit()
        return self.get_analyst_by_id(tenant_id, analyst_id)

    def write_security_audit_event(self, tenant_id: str, event_type: str, actor_id: str | None, actor_role: str | None, details: dict[str, Any]) -> dict[str, Any]:
        event_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO security_audit_events (tenant_id, event_id, event_type, actor_id, actor_role, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, event_id, event_type, actor_id, actor_role, json.dumps(details), now),
            )
            connection.commit()
        return {"event_id": event_id, "event_type": event_type, "actor_id": actor_id, "actor_role": actor_role, "details": details, "created_at": datetime.fromisoformat(now)}

    def list_security_audit_events(self, tenant_id: str, limit: int = 100, event_type: str | None = None, actor_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT event_id, event_type, actor_id, actor_role, details_json, created_at FROM security_audit_events WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if actor_id:
            query += " AND actor_id = ?"
            params.append(actor_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with get_connection() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "actor_role": row["actor_role"],
                "details": json.loads(row["details_json"]),
                "created_at": datetime.fromisoformat(row["created_at"]),
            }
            for row in rows
        ]

    def enqueue_job(self, tenant_id: str, job_type: str, payload: dict[str, Any], created_by: str | None, priority: int = 100, max_attempts: int = 3, run_after: datetime | None = None) -> dict[str, Any]:
        job_id = str(uuid4())
        now_dt = datetime.now(UTC)
        run_after_dt = run_after or now_dt
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO jobs (tenant_id, job_id, job_type, status, payload_json, priority, attempts, max_attempts, run_after, created_by, created_at) VALUES (?, ?, ?, 'QUEUED', ?, ?, 0, ?, ?, ?, ?)",
                (tenant_id, job_id, job_type, json.dumps(payload), priority, max_attempts, run_after_dt.isoformat(), created_by, now_dt.isoformat()),
            )
            connection.commit()
        return {"job_id": job_id, "job_type": job_type, "status": "QUEUED", "payload": payload, "result": None, "priority": priority, "attempts": 0, "max_attempts": max_attempts, "run_after": run_after_dt, "created_by": created_by, "error_message": None, "created_at": now_dt, "started_at": None, "completed_at": None}

    def list_jobs(self, tenant_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute(
                "SELECT job_id, job_type, status, payload_json, result_json, priority, attempts, max_attempts, run_after, created_by, error_message, created_at, started_at, completed_at FROM jobs WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [
            {
                "job_id": row["job_id"],
                "job_type": row["job_type"],
                "status": row["status"],
                "payload": json.loads(row["payload_json"]),
                "result": json.loads(row["result_json"]) if row["result_json"] else None,
                "priority": int(row["priority"]),
                "attempts": int(row["attempts"]),
                "max_attempts": int(row["max_attempts"]),
                "run_after": datetime.fromisoformat(row["run_after"]),
                "created_by": row["created_by"],
                "error_message": row["error_message"],
                "created_at": datetime.fromisoformat(row["created_at"]),
                "started_at": datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
                "completed_at": datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            }
            for row in rows
        ]

    def claim_jobs(self, worker_id: str, limit: int = 10, lease_seconds: int = 300) -> list[dict[str, Any]]:
        now_dt = datetime.now(UTC)
        now = now_dt.isoformat()
        lease_expires = (now_dt + timedelta(seconds=lease_seconds)).isoformat()
        claimed: list[dict[str, Any]] = []
        with get_connection() as connection:
            rows = connection.execute(
                "SELECT tenant_id, job_id, job_type, payload_json, priority, attempts, max_attempts, created_by, created_at FROM jobs WHERE status IN ('QUEUED', 'RETRYING') AND run_after <= ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?) ORDER BY priority DESC, created_at ASC LIMIT ?",
                (now, now, limit),
            ).fetchall()
            for row in rows:
                connection.execute(
                    "UPDATE jobs SET status = 'RUNNING', attempts = attempts + 1, started_at = COALESCE(started_at, ?), lease_expires_at = ?, error_message = NULL WHERE tenant_id = ? AND job_id = ?",
                    (now, lease_expires, row["tenant_id"], row["job_id"]),
                )
                claimed.append({
                    "tenant_id": row["tenant_id"],
                    "job_id": row["job_id"],
                    "job_type": row["job_type"],
                    "payload": json.loads(row["payload_json"]),
                    "priority": int(row["priority"]),
                    "attempts": int(row["attempts"]) + 1,
                    "max_attempts": int(row["max_attempts"]),
                    "created_by": row["created_by"],
                    "created_at": row["created_at"],
                    "worker_id": worker_id,
                })
            connection.commit()
        return claimed

    def complete_job(self, tenant_id: str, job_id: str, result: dict[str, Any]) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "UPDATE jobs SET status = 'SUCCEEDED', result_json = ?, completed_at = ?, lease_expires_at = NULL, error_message = NULL WHERE tenant_id = ? AND job_id = ?",
                (json.dumps(result), now, tenant_id, job_id),
            )
            connection.commit()

    def fail_job(self, tenant_id: str, job_id: str, error_message: str, retry_delay_seconds: int = 60) -> dict[str, Any] | None:
        now_dt = datetime.now(UTC)
        with get_connection() as connection:
            row = connection.execute(
                "SELECT attempts, max_attempts FROM jobs WHERE tenant_id = ? AND job_id = ?",
                (tenant_id, job_id),
            ).fetchone()
            if row is None:
                return None
            attempts = int(row["attempts"])
            max_attempts = int(row["max_attempts"])
            if attempts >= max_attempts:
                status = 'FAILED'
                completed_at = now_dt.isoformat()
                run_after = now_dt.isoformat()
            else:
                status = 'RETRYING'
                completed_at = None
                run_after = (now_dt + timedelta(seconds=retry_delay_seconds)).isoformat()
            connection.execute(
                "UPDATE jobs SET status = ?, run_after = ?, completed_at = ?, lease_expires_at = NULL, error_message = ? WHERE tenant_id = ? AND job_id = ?",
                (status, run_after, completed_at, error_message[:500], tenant_id, job_id),
            )
            connection.commit()
        return {"status": status, "attempts": attempts, "max_attempts": max_attempts}

    def feedback_training_summary(self, tenant_id: str) -> dict[str, Any]:
        with get_connection() as connection:
            total = connection.execute(
                "SELECT COUNT(*) AS count FROM feedback WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()["count"]
            rows = connection.execute(
                "SELECT label, COUNT(*) AS count FROM feedback WHERE tenant_id = ? GROUP BY label ORDER BY count DESC, label ASC",
                (tenant_id,),
            ).fetchall()
        by_label = {row["label"]: int(row["count"]) for row in rows}
        return {
            "total_feedback_labels": int(total),
            "by_label": by_label,
            "confirmed_fraud_labels": by_label.get("CONFIRMED_FRAUD", 0),
            "false_positive_labels": by_label.get("FALSE_POSITIVE", 0),
            "suspicious_but_allowed_labels": by_label.get("SUSPICIOUS_BUT_ALLOWED", 0),
        }

    def monitoring_snapshot(self, tenant_id: str) -> dict[str, Any]:
        with get_connection() as connection:
            queued_jobs = connection.execute("SELECT COUNT(*) AS count FROM jobs WHERE tenant_id = ? AND status IN ('QUEUED', 'RETRYING')", (tenant_id,)).fetchone()["count"]
            running_jobs = connection.execute("SELECT COUNT(*) AS count FROM jobs WHERE tenant_id = ? AND status = 'RUNNING'", (tenant_id,)).fetchone()["count"]
            failed_jobs = connection.execute("SELECT COUNT(*) AS count FROM jobs WHERE tenant_id = ? AND status = 'FAILED'", (tenant_id,)).fetchone()["count"]
            dead_letter_webhooks = connection.execute("SELECT COUNT(*) AS count FROM webhook_deliveries WHERE tenant_id = ? AND status = 'DEAD_LETTER'", (tenant_id,)).fetchone()["count"]
            queued_webhooks = connection.execute("SELECT COUNT(*) AS count FROM webhook_deliveries WHERE tenant_id = ? AND status = 'QUEUED'", (tenant_id,)).fetchone()["count"]
            api_keys_active = connection.execute("SELECT COUNT(*) AS count FROM api_keys WHERE tenant_id = ? AND is_active = 1", (tenant_id,)).fetchone()["count"]
            analysts_active = connection.execute("SELECT COUNT(*) AS count FROM analyst_users WHERE tenant_id = ? AND is_active = 1", (tenant_id,)).fetchone()["count"]
            model_versions = connection.execute("SELECT COUNT(*) AS count FROM model_versions WHERE tenant_id = ?", (tenant_id,)).fetchone()["count"]
        now = datetime.now(UTC)
        return {"generated_at": now, "queued_jobs": int(queued_jobs), "running_jobs": int(running_jobs), "failed_jobs": int(failed_jobs), "dead_letter_webhooks": int(dead_letter_webhooks), "queued_webhooks": int(queued_webhooks), "api_keys_active": int(api_keys_active), "analysts_active": int(analysts_active), "model_versions": int(model_versions)}

    def create_connector_config(self, tenant_id: str, connector_type: str, route: str, source_path: str, config: dict[str, Any], created_by: str | None) -> dict[str, Any]:
        connector_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO connector_configs (tenant_id, connector_id, connector_type, route, source_path, config_json, is_active, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (tenant_id, connector_id, connector_type, route, source_path, json.dumps(config), created_by, now),
            )
            connection.commit()
        return {"connector_id": connector_id, "connector_type": connector_type, "route": route, "source_path": source_path, "config": config, "is_active": True, "created_by": created_by, "created_at": datetime.fromisoformat(now), "last_run_at": None}

    def list_connector_configs(self, tenant_id: str) -> list[dict[str, Any]]:
        with get_connection() as connection:
            rows = connection.execute(
                "SELECT connector_id, connector_type, route, source_path, config_json, is_active, created_by, created_at, last_run_at FROM connector_configs WHERE tenant_id = ? ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        return [
            {"connector_id": row["connector_id"], "connector_type": row["connector_type"], "route": row["route"], "source_path": row["source_path"], "config": json.loads(row["config_json"]), "is_active": bool(row["is_active"]), "created_by": row["created_by"], "created_at": datetime.fromisoformat(row["created_at"]), "last_run_at": datetime.fromisoformat(row["last_run_at"]) if row["last_run_at"] else None}
            for row in rows
        ]

    def get_connector_config(self, tenant_id: str, connector_id: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT connector_id, connector_type, route, source_path, config_json, is_active, created_by, created_at, last_run_at FROM connector_configs WHERE tenant_id = ? AND connector_id = ?",
                (tenant_id, connector_id),
            ).fetchone()
        if row is None:
            return None
        return {"connector_id": row["connector_id"], "connector_type": row["connector_type"], "route": row["route"], "source_path": row["source_path"], "config": json.loads(row["config_json"]), "is_active": bool(row["is_active"]), "created_by": row["created_by"], "created_at": datetime.fromisoformat(row["created_at"]), "last_run_at": datetime.fromisoformat(row["last_run_at"]) if row["last_run_at"] else None}

    def write_shadow_decision(
        self,
        tenant_id: str,
        request_id: str,
        route: str,
        challenger_version: str,
        production_score: int,
        production_action: str,
        shadow_score: int,
        shadow_action: str,
        shadow_reasons: list[str],
    ) -> None:
        now = datetime.now(UTC).isoformat()
        delta_score = int(shadow_score) - int(production_score)
        diverged = int(production_action != shadow_action)
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO shadow_decisions (
                    tenant_id, request_id, route, challenger_version, production_score, production_action,
                    shadow_score, shadow_action, delta_score, diverged, shadow_reasons_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, request_id) DO UPDATE SET
                    route = excluded.route,
                    challenger_version = excluded.challenger_version,
                    production_score = excluded.production_score,
                    production_action = excluded.production_action,
                    shadow_score = excluded.shadow_score,
                    shadow_action = excluded.shadow_action,
                    delta_score = excluded.delta_score,
                    diverged = excluded.diverged,
                    shadow_reasons_json = excluded.shadow_reasons_json,
                    created_at = excluded.created_at
                """,
                (
                    tenant_id,
                    request_id,
                    route,
                    challenger_version,
                    production_score,
                    production_action,
                    shadow_score,
                    shadow_action,
                    delta_score,
                    diverged,
                    json.dumps(shadow_reasons),
                    now,
                ),
            )
            connection.commit()

    def list_shadow_decisions(self, tenant_id: str, limit: int = 20, route: str | None = None, diverged_only: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM shadow_decisions WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if route:
            query += " AND route = ?"
            params.append(route)
        if diverged_only:
            query += " AND diverged = 1"
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with get_connection() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._shadow_row_to_dict(row) for row in rows]

    def get_shadow_decision(self, tenant_id: str, request_id: str) -> dict[str, Any] | None:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT * FROM shadow_decisions WHERE tenant_id = ? AND request_id = ?",
                (tenant_id, request_id),
            ).fetchone()
        return None if row is None else self._shadow_row_to_dict(row)

    def shadow_summary(self, tenant_id: str, limit: int = 20) -> dict[str, Any]:
        with get_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM shadow_decisions WHERE tenant_id = ? ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        if not rows:
            return {
                "challenger_version": "challenger_v1",
                "total": 0,
                "diverged": 0,
                "divergence_rate": 0.0,
                "route_breakdown": [],
                "recent_drifts": [],
            }

        route_buckets: dict[str, dict[str, float]] = {}
        diverged = 0
        for row in rows:
            bucket = route_buckets.setdefault(row["route"], {"route": row["route"], "total": 0, "diverged": 0, "delta_sum": 0.0})
            bucket["total"] += 1
            bucket["delta_sum"] += float(row["delta_score"])
            if int(row["diverged"]):
                bucket["diverged"] += 1
                diverged += 1
        route_breakdown = [
            {
                "route": bucket["route"],
                "total": int(bucket["total"]),
                "diverged": int(bucket["diverged"]),
                "divergence_rate": round(float(bucket["diverged"]) / max(float(bucket["total"]), 1.0), 4),
                "avg_score_delta": round(float(bucket["delta_sum"]) / max(float(bucket["total"]), 1.0), 1),
            }
            for bucket in route_buckets.values()
        ]
        route_breakdown.sort(key=lambda item: (item["diverged"], item["total"]), reverse=True)
        recent_drifts = [self._shadow_row_to_dict(row) for row in rows if int(row["diverged"])]
        return {
            "challenger_version": rows[0]["challenger_version"],
            "total": len(rows),
            "diverged": diverged,
            "divergence_rate": round(diverged / max(len(rows), 1), 4),
            "route_breakdown": route_breakdown,
            "recent_drifts": recent_drifts[:limit],
        }

    def pilot_report(self, tenant_id: str, limit: int = 10) -> dict[str, Any]:
        summary = self.shadow_summary(tenant_id, limit)
        with get_connection() as connection:
            open_cases = connection.execute(
                "SELECT COUNT(*) AS count FROM audit_events WHERE tenant_id = ? AND case_status != 'RESOLVED'",
                (tenant_id,),
            ).fetchone()["count"]
            labeled_cases = connection.execute(
                "SELECT COUNT(*) AS count FROM feedback WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()["count"]
            production_blocks = connection.execute(
                "SELECT COUNT(*) AS count FROM shadow_decisions WHERE tenant_id = ? AND production_action = 'BLOCK'",
                (tenant_id,),
            ).fetchone()["count"]
            challenger_blocks = connection.execute(
                "SELECT COUNT(*) AS count FROM shadow_decisions WHERE tenant_id = ? AND shadow_action = 'BLOCK'",
                (tenant_id,),
            ).fetchone()["count"]
        incremental_blocks = int(challenger_blocks) - int(production_blocks)
        notes = [
            f"Shadow challenger reviewed {summary['total']} events against production decisions.",
            f"Divergence rate is {round(summary['divergence_rate'] * 100, 2)}% across monitored routes.",
            f"Challenger would add {incremental_blocks} extra blocks versus production in the current sample.",
        ]
        return {
            "generated_at": datetime.now(UTC),
            "challenger_version": summary["challenger_version"],
            "compared_events": summary["total"],
            "divergence_rate": summary["divergence_rate"],
            "production_blocks": int(production_blocks),
            "challenger_blocks": int(challenger_blocks),
            "incremental_blocks": incremental_blocks,
            "open_cases": int(open_cases),
            "labeled_cases": int(labeled_cases),
            "notes": notes,
            "recent_drifts": summary["recent_drifts"][:limit],
        }

    def mark_connector_run(self, tenant_id: str, connector_id: str) -> None:
        now = datetime.now(UTC).isoformat()
        with get_connection() as connection:
            connection.execute(
                "UPDATE connector_configs SET last_run_at = ? WHERE tenant_id = ? AND connector_id = ?",
                (now, tenant_id, connector_id),
            )
            connection.commit()
    def _shadow_row_to_dict(self, row: Any) -> dict[str, Any]:
        return {
            "request_id": row["request_id"],
            "route": row["route"],
            "challenger_version": row["challenger_version"],
            "production_score": int(row["production_score"]),
            "production_action": row["production_action"],
            "shadow_score": int(row["shadow_score"]),
            "shadow_action": row["shadow_action"],
            "delta_score": int(row["delta_score"]),
            "diverged": bool(row["diverged"]),
            "shadow_reasons": json.loads(row["shadow_reasons_json"]),
            "created_at": datetime.fromisoformat(row["created_at"]),
        }

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
            "activity": [],
        }


repository = FraudRepository()








