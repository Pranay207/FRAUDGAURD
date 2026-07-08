from __future__ import annotations

from collections import Counter
from threading import Lock

from app.services.queue import job_bus
from app.services.repository import repository


class MonitoringService:
    def __init__(self) -> None:
        self._lock = Lock()
        self._score_actions = Counter()
        self._route_hits = Counter()
        self._latency_ms: list[float] = []

    def record_score(self, route: str, action: str, latency_ms: float) -> None:
        with self._lock:
            self._route_hits[route] += 1
            self._score_actions[action] += 1
            self._latency_ms.append(latency_ms)
            if len(self._latency_ms) > 5000:
                self._latency_ms = self._latency_ms[-2000:]

    def prometheus(self, tenant_id: str) -> str:
        snapshot = repository.monitoring_snapshot(tenant_id)
        redis_state = 1 if job_bus.redis_status() == "ready" else 0
        with self._lock:
            total_latency = sum(self._latency_ms)
            count_latency = len(self._latency_ms)
            lines = [
                "# HELP fraudguard_queued_jobs Queued or retrying background jobs",
                "# TYPE fraudguard_queued_jobs gauge",
                f"fraudguard_queued_jobs {snapshot['queued_jobs']}",
                "# HELP fraudguard_running_jobs Running background jobs",
                "# TYPE fraudguard_running_jobs gauge",
                f"fraudguard_running_jobs {snapshot['running_jobs']}",
                "# HELP fraudguard_failed_jobs Failed background jobs",
                "# TYPE fraudguard_failed_jobs gauge",
                f"fraudguard_failed_jobs {snapshot['failed_jobs']}",
                "# HELP fraudguard_dead_letter_webhooks Webhook dead letters",
                "# TYPE fraudguard_dead_letter_webhooks gauge",
                f"fraudguard_dead_letter_webhooks {snapshot['dead_letter_webhooks']}",
                "# HELP fraudguard_redis_ready Redis health status",
                "# TYPE fraudguard_redis_ready gauge",
                f"fraudguard_redis_ready {redis_state}",
                "# HELP fraudguard_score_actions_total Fraud decisions by action",
                "# TYPE fraudguard_score_actions_total counter",
            ]
            for action, count in sorted(self._score_actions.items()):
                lines.append(f'fraudguard_score_actions_total{{action="{action}"}} {count}')
            lines.extend([
                "# HELP fraudguard_route_hits_total Route hit counts",
                "# TYPE fraudguard_route_hits_total counter",
            ])
            for route, count in sorted(self._route_hits.items()):
                lines.append(f'fraudguard_route_hits_total{{route="{route}"}} {count}')
            lines.extend([
                "# HELP fraudguard_scoring_latency_ms_sum Total scoring latency in ms",
                "# TYPE fraudguard_scoring_latency_ms_sum counter",
                f"fraudguard_scoring_latency_ms_sum {total_latency}",
                "# HELP fraudguard_scoring_latency_ms_count Number of scoring requests",
                "# TYPE fraudguard_scoring_latency_ms_count counter",
                f"fraudguard_scoring_latency_ms_count {count_latency}",
            ])
        return "\n".join(lines) + "\n"


monitoring = MonitoringService()
