from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


Action = Literal["ALLOW", "CHALLENGE", "BLOCK"]
FeedbackLabel = Literal["CONFIRMED_FRAUD", "FALSE_POSITIVE", "SAFE"]
CaseStatus = Literal["OPEN", "INVESTIGATING", "RESOLVED"]
UserRole = Literal["admin", "analyst", "viewer", "service"]
JobStatus = Literal["QUEUED", "RUNNING", "RETRYING", "SUCCEEDED", "FAILED"]


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
    redis: str | None = None
    worker_queue: str | None = None


class TenantResponse(BaseModel):
    tenant_id: str
    name: str
    status: str
    key_name: str
    actor_id: str | None = None
    role: UserRole | None = None


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


class CaseActivityRecord(BaseModel):
    activity_id: str
    request_id: str
    event_type: str
    actor_id: str | None = None
    details: dict
    created_at: datetime


class CaseActivityListResponse(BaseModel):
    items: list[CaseActivityRecord]


class LinkedCaseRecord(BaseModel):
    request_id: str
    route: str
    action: Action
    fraud_score: int
    case_status: CaseStatus
    assigned_to: str | None = None
    created_at: datetime
    matched_signals: list[str] = Field(default_factory=list)


class ModelEvidenceRecord(BaseModel):
    component: str
    model_name: str
    model_used: bool
    source: str
    version_id: str | None = None
    artifact_path: str | None = None
    heuristic_score: int
    output_score: int


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
    shadow_comparison: ShadowDecisionRecord | None = None
    activity: list[CaseActivityRecord] = Field(default_factory=list)
    linked_cases: list[LinkedCaseRecord] = Field(default_factory=list)
    model_evidence: list[ModelEvidenceRecord] = Field(default_factory=list)


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


class BulkCaseStatusRequest(BaseModel):
    request_ids: list[str] = Field(min_length=1)
    case_status: CaseStatus
    assigned_to: str | None = None


class BulkCaseStatusResponse(BaseModel):
    updated: int
    request_ids: list[str]
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


class ShadowDecisionRecord(BaseModel):
    request_id: str
    route: str
    challenger_version: str | None = None
    production_score: int
    production_action: Action
    shadow_score: int
    shadow_action: Action
    delta_score: int
    diverged: bool
    shadow_reasons: list[str]
    created_at: datetime


class ShadowDecisionListResponse(BaseModel):
    items: list[ShadowDecisionRecord]


class ShadowRouteSummary(BaseModel):
    route: str
    total: int
    diverged: int
    divergence_rate: float
    avg_score_delta: float


class ShadowSummaryResponse(BaseModel):
    challenger_version: str
    total: int
    diverged: int
    divergence_rate: float
    route_breakdown: list[ShadowRouteSummary]
    recent_drifts: list[ShadowDecisionRecord]


class PilotReportResponse(BaseModel):
    generated_at: datetime
    challenger_version: str
    compared_events: int
    divergence_rate: float
    production_blocks: int
    challenger_blocks: int
    incremental_blocks: int
    open_cases: int
    labeled_cases: int
    notes: list[str]
    recent_drifts: list[ShadowDecisionRecord]


class SeedResponse(BaseModel):
    status: str
    generated_cases: int


class ModelVersionResponse(BaseModel):
    model_name: str
    version_id: str
    artifact_path: str
    metrics: dict[str, float]
    stage: str = "candidate"
    is_active: bool = False
    training_job_id: str | None = None
    promoted_at: datetime | None = None
    created_at: datetime


class ModelActivationRequest(BaseModel):
    stage: str = "production"


class ModelActivationResponse(BaseModel):
    model_name: str
    version_id: str
    stage: str
    is_active: bool
    promoted_at: datetime


class ModelEvaluationRecord(BaseModel):
    version_id: str
    artifact_path: str
    metrics: dict[str, float]


class ModelEvaluationSummaryResponse(BaseModel):
    generated_at: datetime
    models: dict[str, ModelEvaluationRecord]

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


class BulkItemFailure(BaseModel):
    index: int
    error: str


class BulkScoreResponse(BaseModel):
    route: str
    accepted: int
    rejected: int
    results: list[ScoreResponse]
    failures: list[BulkItemFailure]


class SessionBatchRequest(BaseModel):
    events: list[SessionScoreRequest] = Field(min_length=1, max_length=1000)


class TransactionBatchRequest(BaseModel):
    events: list[TransactionScoreRequest] = Field(min_length=1, max_length=1000)


class OnboardBatchRequest(BaseModel):
    events: list[OnboardRequest] = Field(min_length=1, max_length=1000)


class PhishingBatchRequest(BaseModel):
    events: list[PhishingScoreRequest] = Field(min_length=1, max_length=1000)


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


class WebhookSecretRotateRequest(BaseModel):
    secret: str = Field(min_length=8)


class WebhookEndpointResponse(BaseModel):
    webhook_id: str
    event_type: str
    url: str
    has_secret: bool = False
    is_active: bool
    created_at: datetime


class WebhookDeliveryResponse(BaseModel):
    delivery_id: str
    webhook_id: str
    event_type: str
    request_id: str
    status: str
    attempted_at: datetime
    retry_count: int = 0
    max_attempts: int = 3
    next_attempt_at: datetime | None = None
    last_http_status: int | None = None
    error_message: str | None = None


class WebhookDispatchResponse(BaseModel):
    dispatched: int
    failed: int
    retried: int = 0
    dead_lettered: int = 0
    queued_remaining: int


class AuthBootstrapRequest(BaseModel):
    email: str
    password: str = Field(min_length=12)
    full_name: str = Field(min_length=2)


class LoginRequest(BaseModel):
    email: str
    password: str


class AnalystCreateRequest(BaseModel):
    email: str
    password: str = Field(min_length=12)
    full_name: str = Field(min_length=2)
    role: Literal["admin", "analyst", "viewer"]


class AnalystStatusUpdateRequest(BaseModel):
    is_active: bool


class AnalystUserResponse(BaseModel):
    analyst_id: str
    email: str
    full_name: str
    role: Literal["admin", "analyst", "viewer"]
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    tenant_id: str
    role: Literal["admin", "analyst", "viewer"]
    analyst: AnalystUserResponse


class CurrentUserResponse(BaseModel):
    tenant_id: str
    tenant_name: str
    actor_id: str
    actor_type: str
    role: UserRole
    email: str | None = None
    key_name: str
    auth_method: str


class JobResponse(BaseModel):
    job_id: str
    job_type: str
    status: JobStatus
    payload: dict
    result: dict | None = None
    priority: int
    attempts: int
    max_attempts: int
    run_after: datetime
    created_by: str | None = None
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class RetrainRequest(BaseModel):
    promote_stage: str = "candidate"
    activate_after_training: bool = False
    use_feedback_labels: bool = True
    minimum_feedback_labels: int = Field(default=1, ge=0, le=100000)


class ConnectorCreateRequest(BaseModel):
    connector_type: Literal["file_drop"] = "file_drop"
    route: Literal["session", "onboard", "transaction", "phishing"]
    source_path: str
    config: dict = Field(default_factory=dict)


class ConnectorResponse(BaseModel):
    connector_id: str
    connector_type: str
    route: str
    source_path: str
    config: dict
    is_active: bool
    created_by: str | None = None
    created_at: datetime
    last_run_at: datetime | None = None


class ConnectorRunResponse(BaseModel):
    connector_id: str
    job_id: str
    status: str


class MonitoringSnapshotResponse(BaseModel):
    generated_at: datetime
    queued_jobs: int
    running_jobs: int
    failed_jobs: int
    dead_letter_webhooks: int
    queued_webhooks: int
    api_keys_active: int
    analysts_active: int
    model_versions: int


class SecurityPostureFinding(BaseModel):
    id: str
    severity: str
    message: str


class SecurityPostureResponse(BaseModel):
    status: str
    highest_severity: str
    findings: list[SecurityPostureFinding]


class SecurityAuditEventResponse(BaseModel):
    event_id: str
    event_type: str
    actor_id: str | None = None
    actor_role: str | None = None
    details: dict
    created_at: datetime



