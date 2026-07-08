from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass
class UserState:
    known_devices: set[str] = field(default_factory=set)
    last_login_at: datetime | None = None
    last_ip_country: str = "IN"
    transaction_times: list[datetime] = field(default_factory=list)
    payees: set[str] = field(default_factory=set)
    total_transactions: int = 0
    clean_streak_days: int = 0


class RuntimeStore:
    def __init__(self) -> None:
        self.users: dict[str, UserState] = {}
        self.device_links: dict[str, set[str]] = {}
        self.phone_links: dict[str, set[str]] = {}
        self.pan_links: dict[str, set[str]] = {}
        self.audit_index: dict[str, dict] = {}

    def get_user(self, user_id: str) -> UserState:
        if user_id not in self.users:
            self.users[user_id] = UserState()
        return self.users[user_id]

    def remember_device(self, user_id: str, device_id: str) -> None:
        user = self.get_user(user_id)
        user.known_devices.add(device_id)
        self.device_links.setdefault(device_id, set()).add(user_id)

    def register_identity(self, user_id: str, device_id: str, phone_hash: str, pan_hash: str) -> None:
        self.remember_device(user_id, device_id)
        self.phone_links.setdefault(phone_hash, set()).add(user_id)
        self.pan_links.setdefault(pan_hash, set()).add(user_id)

    def record_login(self, user_id: str, ip_country: str) -> None:
        user = self.get_user(user_id)
        user.last_login_at = datetime.now(UTC)
        user.last_ip_country = ip_country

    def record_transaction(self, user_id: str, payee_vpa: str) -> int:
        user = self.get_user(user_id)
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=5)
        user.transaction_times = [ts for ts in user.transaction_times if ts >= window_start]
        user.transaction_times.append(now)
        user.payees.add(payee_vpa)
        user.total_transactions += 1
        return len(user.transaction_times)


store = RuntimeStore()
