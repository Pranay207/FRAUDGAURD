from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


Action = Literal["ALLOW", "CHALLENGE", "BLOCK"]
FeedbackLabel = Literal["CONFIRMED_FRAUD", "FALSE_POSITIVE", "SAFE"]
CaseStatus = Literal["OPEN", "INVESTIGATING", "RESOLVED"]


class DeviceFingerprint(BaseModel):
    device_id: str
    os: str | None = None
    screen_res: str | None = None
    is_rooted: bool = False
    sim_count: int = 1


class SessionScoreRequest(BaseModel):
    user_id: str
    session_id: str
    device_id: str
    keystroke_mean_ms: float = Field(ge=0, default=140)
    session_duration_s: float = Field(ge=0, default=90)
    hour_of_day: int = Field(ge=0, le=23, default=12)
    ip_country: str = "IN"


class TransactionScoreRequest(BaseModel):
    user_id: str
    amount_paise: int = Field(gt=0)
    payee_vpa: str
    upi_remark: str = ""
    session_id: str
    device_id: str
    ip_country: str = "IN"
    transaction_type: str = "TRANSFER"
    source_balance_paise: int | None = Field(default=None, ge=0)
    destination_balance_paise: int | None = Field(default=None, ge=0)


class PhishingScoreRequest(BaseModel):
    url: str | None = None
    source: str = "manual"
    having_ip_address: int
    url_length: int
    shortening_service: int
    having_at_symbol: int
    double_slash_redirecting: int
    prefix_suffix: int
    having_sub_domain: int
    sslfinal_state: int
    domain_registration_length: int
    favicon: int
    port: int
    https_token: int
    request_url: int
    url_of_anchor: int
    links_in_tags: int
    sfh: int
    submitting_to_email: int
    abnormal_url: int
    redirect: int
    on_mouseover: int
    rightclick: int
    popup_window: int
    iframe: int
    age_of_domain: int
    dnsrecord: int
    web_traffic: int
    page_rank: int
    google_index: int
    links_pointing_to_page: int
    statistical_report: int


class OnboardRequest(BaseModel):
    user_id: str
    pan_hash: str = Field(min_length=64, max_length=64)
    phone_hash: str = Field(min_length=64, max_length=64)
    aadhaar_last4: str = Field(min_length=4, max_length=4)
    email_hash: str | None = None
    device: DeviceFingerprint
    selfie_check_score: float = Field(ge=0, le=1, default=0.0)
    kyc_name_match_score: float = Field(ge=0, le=1, default=1.0)


class ScoreResponse(BaseModel):
    request_id: str
    fraud_score: int
    action: Action
    reasons: list[str]
    latency_ms: float


class ExplainFactor(BaseModel):
    signal: str
    impact: int
    summary: str


class ExplainResponse(BaseModel):
    request_id: str
    fraud_score: int
    action: Action
    route: str
    reasons: list[str]
    factors: list[ExplainFactor]
    created_at: datetime


class HealthResponse(BaseModel):
    status: str
    database: str
    tenant_seeded: bool


class TenantResponse(BaseModel):
    tenant_id: str
    name: str
    status: str
    key_name: str


class CaseSummary(BaseModel):
    request_id: str
    route: str
    user_id: str | None = None
    fraud_score: int
    action: Action
    created_at: datetime
    reasons: list[str]
    feedback_label: FeedbackLabel | None = None
    case_status: CaseStatus = "OPEN"
    assigned_to: str | None = None


class CaseListResponse(BaseModel):
    items: list[CaseSummary]


class CaseDetailResponse(BaseModel):
    request_id: str
    route: str
    user_id: str | None = None
    fraud_score: int
    action: Action
    created_at: datetime
    reasons: list[str]
    factors: list[ExplainFactor]
    request_payload: dict
    feedback_label: FeedbackLabel | None = None
    feedback_notes: str | None = None
    case_status: CaseStatus = "OPEN"
    assigned_to: str | None = None


class FeedbackRequest(BaseModel):
    label: FeedbackLabel
    notes: str | None = None
    reported_by: str = "analyst"


class FeedbackResponse(BaseModel):
    request_id: str
    label: FeedbackLabel
    notes: str | None = None
    reported_by: str


class CaseStatusRequest(BaseModel):
    case_status: CaseStatus
    assigned_to: str | None = None


class CaseStatusResponse(BaseModel):
    request_id: str
    case_status: CaseStatus
    assigned_to: str | None = None


class MetricCard(BaseModel):
    label: str
    value: str
    tone: Literal["neutral", "good", "warn", "danger"] = "neutral"


class DashboardSummary(BaseModel):
    metrics: list[MetricCard]
    recent_cases: list[CaseSummary]
    top_signals: list[dict]


class SeedResponse(BaseModel):
    status: str
    generated_cases: int


class ModelVersionResponse(BaseModel):
    model_name: str
    version_id: str
    artifact_path: str
    metrics: dict[str, float]
    created_at: datetime


class DatasetStatusResponse(BaseModel):
    dataset_name: str
    kind: str
    path: str
    present: bool
    size_bytes: int | None = None
    record_count: int | None = None
    linked_models: list[str]


class GraphEntityResponse(BaseModel):
    entity_type: str
    entity_id: str
    risk_flags: list[str]
    stats: dict[str, int]


class TrainModelsResponse(BaseModel):
    status: str
    artifacts: dict[str, str]
    metrics: dict[str, dict[str, float]]


class ApiKeyCreateRequest(BaseModel):
    key_name: str


class ApiKeyResponse(BaseModel):
    key_name: str
    key_prefix: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None


class ApiKeyCreateResponse(ApiKeyResponse):
    raw_key: str


class WebhookEndpointCreateRequest(BaseModel):
    event_type: str
    url: str
    secret: str | None = None


class WebhookEndpointResponse(BaseModel):
    webhook_id: str
    event_type: str
    url: str
    is_active: bool
    created_at: datetime


class WebhookDeliveryResponse(BaseModel):
    delivery_id: str
    webhook_id: str
    event_type: str
    request_id: str
    status: str
    attempted_at: datetime
    error_message: str | None = None


class WebhookDispatchResponse(BaseModel):
    dispatched: int
    failed: int
    queued_remaining: int
