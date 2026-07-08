from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class BehavioralFeatures:
    keystroke_interval_deviation: float
    is_new_device: int
    hour_of_day_anomaly_score: float
    session_duration_zscore: float
    ip_country_change: int
    txn_velocity_5min: int
    days_since_last_login: float


def login_hour_anomaly(hour_of_day: int) -> float:
    return 1.0 if hour_of_day < 5 or hour_of_day > 23 else 0.15


def duration_zscore(duration_s: float, baseline_s: float = 90.0) -> float:
    if baseline_s <= 0:
        return 0.0
    return abs(duration_s - baseline_s) / baseline_s


def days_since(timestamp: datetime | None) -> float:
    if timestamp is None:
        return 30.0
    delta = datetime.now(UTC) - timestamp
    return max(0.0, delta.total_seconds() / 86400)
