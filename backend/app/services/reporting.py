from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from app.config import get_settings


def pilot_report_output_path(tenant_id: str) -> Path:
    settings = get_settings()
    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"pilot_report_{tenant_id}.md"


def render_pilot_report_markdown(tenant_id: str, payload: dict) -> str:
    lines = [
        "# FraudGuard Pilot Report",
        "",
        f"- Tenant: `{tenant_id}`",
        f"- Generated at: `{datetime.now(UTC).isoformat()}`",
        f"- Challenger version: `{payload['challenger_version']}`",
        "",
        "## Executive Summary",
        "",
        f"- Compared events: `{payload['compared_events']}`",
        f"- Divergence rate: `{round(payload['divergence_rate'] * 100, 2)}%`",
        f"- Production blocks: `{payload['production_blocks']}`",
        f"- Challenger blocks: `{payload['challenger_blocks']}`",
        f"- Incremental challenger blocks: `{payload['incremental_blocks']}`",
        f"- Open cases: `{payload['open_cases']}`",
        f"- Labeled cases: `{payload['labeled_cases']}`",
        "",
        "## Pilot Notes",
        "",
    ]
    for note in payload.get("notes", []):
        lines.append(f"- {note}")

    lines.extend(["", "## Recent Drift Events", ""])
    recent = payload.get("recent_drifts", [])
    if not recent:
        lines.append("- No recent drift events were recorded.")
    else:
        for item in recent:
            lines.extend(
                [
                    f"### {item['request_id']}",
                    f"- Route: `{item['route']}`",
                    f"- Production: `{item['production_action']}` at `{item['production_score']}`",
                    f"- Challenger: `{item['shadow_action']}` at `{item['shadow_score']}`",
                    f"- Delta score: `{item['delta_score']}`",
                    f"- Diverged: `{item['diverged']}`",
                    "- Challenger reasons:",
                ]
            )
            for reason in item.get("shadow_reasons", []):
                lines.append(f"  - {reason}")
            lines.append("")

    return "\n".join(lines).strip() + "\n"


def write_pilot_report_markdown(tenant_id: str, payload: dict) -> Path:
    output_path = pilot_report_output_path(tenant_id)
    output_path.write_text(render_pilot_report_markdown(tenant_id, payload), encoding="utf-8")
    return output_path


def case_report_output_path(tenant_id: str, request_id: str) -> Path:
    settings = get_settings()
    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"case_report_{tenant_id}_{request_id}.md"


def render_case_report_markdown(tenant_id: str, payload: dict) -> str:
    lines = [
        "# FraudGuard Case Report",
        "",
        f"- Tenant: `{tenant_id}`",
        f"- Request ID: `{payload['request_id']}`",
        f"- Route: `{payload['route']}`",
        f"- Created at: `{payload['created_at']}`",
        f"- User ID: `{payload.get('user_id') or 'unknown'}`",
        "",
        "## Decision",
        "",
        f"- Production action: `{payload['action']}`",
        f"- Fraud score: `{payload['fraud_score']}`",
        f"- Case status: `{payload['case_status']}`",
        f"- Assigned to: `{payload.get('assigned_to') or 'unassigned'}`",
        "",
        "## Reasons",
        "",
    ]
    for reason in payload.get("reasons", []):
        lines.append(f"- {reason}")

    lines.extend(["", "## Contributing Factors", ""])
    for factor in payload.get("factors", []):
        lines.extend([
            f"- `{factor['signal']}` ({factor['impact']})",
            f"  - {factor['summary']}",
        ])

    shadow = payload.get("shadow_comparison")
    lines.extend(["", "## Shadow Comparison", ""])
    if not shadow:
        lines.append("- No shadow comparison recorded for this case.")
    else:
        lines.extend([
            f"- Challenger version: `{shadow.get('challenger_version') or 'challenger'}`",
            f"- Challenger action: `{shadow['shadow_action']}`",
            f"- Challenger score: `{shadow['shadow_score']}`",
            f"- Diverged: `{shadow['diverged']}`",
            f"- Delta score: `{shadow['delta_score']}`",
            "- Challenger reasons:",
        ])
        for reason in shadow.get("shadow_reasons", []):
            lines.append(f"  - {reason}")

    lines.extend(["", "## Model Evidence", ""])
    model_evidence = payload.get("model_evidence", [])
    if not model_evidence:
        lines.append("- No model evidence recorded for this case.")
    else:
        for item in model_evidence:
            lines.extend([
                f"- Component: `{item.get('component')}`",
                f"  - Model: `{item.get('model_name')}`",
                f"  - Source: `{item.get('source')}`",
                f"  - Version: `{item.get('version_id') or 'none'}`",
                f"  - Artifact: `{item.get('artifact_path') or 'none'}`",
                f"  - Used model output: `{item.get('model_used')}` | heuristic `{item.get('heuristic_score')}` | output `{item.get('output_score')}`",
            ])

    lines.extend(["", "## Feedback", ""])
    if payload.get("feedback_label"):
        lines.append(f"- Label: `{payload['feedback_label']}`")
        lines.append(f"- Notes: {payload.get('feedback_notes') or 'none'}")
    else:
        lines.append("- No analyst feedback recorded.")

    lines.extend([
        "",
        "## Request Payload",
        "",
        "```json",
        json.dumps(payload.get("request_payload", {}), indent=2),
        "```",
        "",
    ])
    return "\n".join(lines).strip() + "\n"


def write_case_report_markdown(tenant_id: str, payload: dict) -> Path:
    output_path = case_report_output_path(tenant_id, payload["request_id"])
    output_path.write_text(render_case_report_markdown(tenant_id, payload), encoding="utf-8")
    return output_path


def shadow_decision_export_output_path(tenant_id: str) -> Path:
    settings = get_settings()
    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"shadow_decisions_{tenant_id}.csv"


def write_shadow_decision_csv(tenant_id: str, items: list[dict]) -> Path:
    output_path = shadow_decision_export_output_path(tenant_id)
    fieldnames = [
        "request_id",
        "route",
        "challenger_version",
        "production_score",
        "production_action",
        "shadow_score",
        "shadow_action",
        "delta_score",
        "diverged",
        "shadow_reasons",
        "created_at",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in items:
            writer.writerow({
                "request_id": item.get("request_id"),
                "route": item.get("route"),
                "challenger_version": item.get("challenger_version"),
                "production_score": item.get("production_score"),
                "production_action": item.get("production_action"),
                "shadow_score": item.get("shadow_score"),
                "shadow_action": item.get("shadow_action"),
                "delta_score": item.get("delta_score"),
                "diverged": item.get("diverged"),
                "shadow_reasons": " | ".join(item.get("shadow_reasons", [])),
                "created_at": item.get("created_at"),
            })
    return output_path


def case_activity_export_output_path(tenant_id: str, request_id: str) -> Path:
    settings = get_settings()
    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"case_activity_{tenant_id}_{request_id}.csv"


def write_case_activity_csv(tenant_id: str, request_id: str, items: list[dict]) -> Path:
    output_path = case_activity_export_output_path(tenant_id, request_id)
    fieldnames = ["activity_id", "request_id", "event_type", "actor_id", "details", "created_at"]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in items:
            writer.writerow({
                "activity_id": item.get("activity_id"),
                "request_id": item.get("request_id"),
                "event_type": item.get("event_type"),
                "actor_id": item.get("actor_id"),
                "details": json.dumps(item.get("details", {}), ensure_ascii=True),
                "created_at": item.get("created_at"),
            })
    return output_path


def case_queue_export_output_path(tenant_id: str) -> Path:
    settings = get_settings()
    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"case_queue_{tenant_id}.csv"


def write_case_queue_csv(tenant_id: str, items: list[dict]) -> Path:
    output_path = case_queue_export_output_path(tenant_id)
    fieldnames = [
        "request_id",
        "route",
        "user_id",
        "fraud_score",
        "action",
        "case_status",
        "assigned_to",
        "feedback_label",
        "feedback_notes",
        "shadow_diverged",
        "shadow_action",
        "shadow_score",
        "shadow_delta_score",
        "reasons",
        "created_at",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in items:
            shadow = item.get("shadow_comparison") or {}
            writer.writerow({
                "request_id": item.get("request_id"),
                "route": item.get("route"),
                "user_id": item.get("user_id"),
                "fraud_score": item.get("fraud_score"),
                "action": item.get("action"),
                "case_status": item.get("case_status"),
                "assigned_to": item.get("assigned_to"),
                "feedback_label": item.get("feedback_label"),
                "feedback_notes": item.get("feedback_notes"),
                "shadow_diverged": shadow.get("diverged"),
                "shadow_action": shadow.get("shadow_action"),
                "shadow_score": shadow.get("shadow_score"),
                "shadow_delta_score": shadow.get("delta_score"),
                "reasons": " | ".join(item.get("reasons", [])),
                "created_at": item.get("created_at"),
            })
    return output_path



def security_audit_export_output_path(tenant_id: str) -> Path:
    settings = get_settings()
    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"security_audit_{tenant_id}.csv"


def write_security_audit_csv(tenant_id: str, items: list[dict]) -> Path:
    output_path = security_audit_export_output_path(tenant_id)
    fieldnames = ["event_id", "event_type", "actor_id", "actor_role", "details", "created_at"]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in items:
            writer.writerow({
                "event_id": item.get("event_id"),
                "event_type": item.get("event_type"),
                "actor_id": item.get("actor_id"),
                "actor_role": item.get("actor_role"),
                "details": json.dumps(item.get("details", {}), ensure_ascii=True),
                "created_at": item.get("created_at"),
            })
    return output_path
