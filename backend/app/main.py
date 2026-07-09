import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.db import get_connection, init_db
from app.schemas import (
    AnalystCreateRequest,
    AnalystStatusUpdateRequest,
    AnalystUserResponse,
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyResponse,
    AuthBootstrapRequest,
    AuthTokenResponse,
    BulkScoreResponse,
    BulkCaseStatusRequest,
    BulkCaseStatusResponse,
    CaseActivityListResponse,
    CaseDetailResponse,
    CaseListResponse,
    CaseStatusRequest,
    CaseStatusResponse,
    ConnectorCreateRequest,
    ConnectorResponse,
    ConnectorRunResponse,
    CurrentUserResponse,
    DashboardSummary,
    DatasetStatusResponse,
    ExplainResponse,
    FeedbackRequest,
    FeedbackResponse,
    GraphEntityResponse,
    HealthResponse,
    JobResponse,
    LoginRequest,
    ModelActivationRequest,
    ModelActivationResponse,
    ModelEvaluationSummaryResponse,
    ModelVersionResponse,
    MonitoringSnapshotResponse,
    OnboardBatchRequest,
    OnboardRequest,
    PhishingBatchRequest,
    PhishingScoreRequest,
    PilotReportResponse,
    RetrainRequest,
    ScoreResponse,
    SeedResponse,
    SecurityAuditEventResponse,
    SecurityPostureResponse,
    SessionBatchRequest,
    SessionScoreRequest,
    ShadowDecisionListResponse,
    ShadowDecisionRecord,
    ShadowSummaryResponse,
    TenantResponse,
    TrainModelsResponse,
    TransactionBatchRequest,
    TransactionScoreRequest,
    WebhookDeliveryResponse,
    WebhookDispatchResponse,
    WebhookEndpointCreateRequest,
    WebhookSecretRotateRequest,
    WebhookEndpointResponse,
)
from app.security import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_SERVICE,
    ROLE_VIEWER,
    TenantContext,
    hash_password,
    issue_access_token,
    require_roles,
    verify_password,
    verify_principal,
    verify_service_or_admin,
)
from app.services.monitoring import monitoring
from app.services.queue import job_bus
from app.services.reporting import write_case_activity_csv, write_case_queue_csv, write_case_report_markdown, write_pilot_report_markdown, write_security_audit_csv, write_shadow_decision_csv
from app.services.repository import repository
from app.services.scoring import engine
from app.services.training import get_dataset_inventory, train_baseline_models
from app.services.webhooks import dispatcher


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="FraudGuard API", version="1.1.0", lifespan=lifespan)
frontend_dir = Path(__file__).parent / "frontend"
assets_dir = frontend_dir / "assets"
app.mount("/dashboard/assets", StaticFiles(directory=assets_dir), name="dashboard-assets")

OPS_ROLES = require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER, ROLE_SERVICE)
MUTATION_ROLES = require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_SERVICE)


def _idempotent_response(tenant: TenantContext, route: str, key: str | None) -> dict | None:
    if not key:
        return None
    return repository.get_idempotent_response(tenant.tenant_id, route, key)


def _store_idempotent_response(tenant: TenantContext, route: str, key: str | None, payload: ScoreResponse) -> None:
    if key:
        repository.save_idempotent_response(tenant.tenant_id, route, key, payload.model_dump(mode="json"))


def _record_score(route: str, response: ScoreResponse) -> None:
    monitoring.record_score(route, response.action, response.latency_ms)


def _record_bulk_scores(route: str, payload: BulkScoreResponse) -> None:
    for item in payload.results:
        monitoring.record_score(route, item.action, item.latency_ms)


def _schedule_webhook_dispatch(background_tasks: BackgroundTasks, tenant: TenantContext, response: ScoreResponse) -> None:
    if response.action in {"CHALLENGE", "BLOCK"}:
        background_tasks.add_task(job_bus.enqueue_webhook_dispatch, tenant.tenant_id, tenant.actor_id, 25)


def _principal_view(principal: TenantContext) -> CurrentUserResponse:
    return CurrentUserResponse(
        tenant_id=principal.tenant_id,
        tenant_name=principal.tenant_name,
        actor_id=principal.actor_id,
        actor_type=principal.actor_type,
        role=principal.role,
        email=principal.email,
        key_name=principal.key_name,
        auth_method=principal.auth_method,
    )


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    with get_connection() as connection:
        connection.execute("SELECT 1")
    return HealthResponse(status="ok", database="ready", tenant_seeded=True, redis=job_bus.redis_status(), worker_queue="ready")


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics(principal: TenantContext = Depends(verify_service_or_admin)) -> PlainTextResponse:
    return PlainTextResponse(monitoring.prometheus(principal.tenant_id), media_type="text/plain; version=0.0.4")


@app.get("/", include_in_schema=False)
async def root() -> FileResponse:
    return FileResponse(frontend_dir / "index.html")


@app.get("/dashboard", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(frontend_dir / "index.html")


@app.post("/v1/auth/bootstrap", response_model=AnalystUserResponse)
async def bootstrap_admin(req: AuthBootstrapRequest, principal: TenantContext = Depends(verify_service_or_admin)) -> AnalystUserResponse:
    if repository.count_analyst_users(principal.tenant_id) > 0:
        raise HTTPException(status_code=409, detail="Bootstrap already completed")
    password_hash, password_salt = hash_password(req.password)
    analyst = repository.create_analyst_user(principal.tenant_id, req.email, req.full_name, ROLE_ADMIN, password_hash, password_salt, principal.actor_id)
    repository.write_security_audit_event(principal.tenant_id, "auth.bootstrap", principal.actor_id, principal.role, {"email": req.email, "analyst_id": analyst["analyst_id"]})
    return AnalystUserResponse(**analyst)


@app.post("/v1/auth/login", response_model=AuthTokenResponse)
async def login(req: LoginRequest, x_tenant_id: str = Header(default="demo-tenant", alias="X-Tenant-Id")) -> AuthTokenResponse:
    analyst = repository.get_analyst_by_email(x_tenant_id, req.email)
    if analyst is None or not bool(analyst["is_active"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(req.password, analyst["password_hash"], analyst["password_salt"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    tenant = repository.get_tenant(x_tenant_id, "analyst-session")
    repository.touch_analyst_login(x_tenant_id, analyst["analyst_id"])
    repository.write_security_audit_event(x_tenant_id, "auth.login", analyst["analyst_id"], analyst["role"], {"email": analyst["email"]})
    token = issue_access_token(
        type("AnalystRecord", (), {
            "tenant_id": x_tenant_id,
            "analyst_id": analyst["analyst_id"],
            "email": analyst["email"],
            "full_name": analyst["full_name"],
            "role": analyst["role"],
            "password_hash": analyst["password_hash"],
            "password_salt": analyst["password_salt"],
            "is_active": bool(analyst["is_active"]),
        })(),
        tenant["name"],
    )
    analyst_view = AnalystUserResponse(
        analyst_id=analyst["analyst_id"],
        email=analyst["email"],
        full_name=analyst["full_name"],
        role=analyst["role"],
        is_active=bool(analyst["is_active"]),
        created_at=analyst["created_at"],
        last_login_at=repository.get_analyst_by_email(x_tenant_id, req.email)["last_login_at"],
    )
    return AuthTokenResponse(access_token=token, expires_in_seconds=get_settings().access_token_ttl_minutes * 60, tenant_id=x_tenant_id, role=analyst["role"], analyst=analyst_view)


@app.get("/v1/auth/me", response_model=CurrentUserResponse)
async def auth_me(principal: TenantContext = Depends(verify_principal)) -> CurrentUserResponse:
    return _principal_view(principal)


@app.get("/v1/tenant", response_model=TenantResponse)
async def tenant_info(principal: TenantContext = Depends(verify_principal)) -> TenantResponse:
    tenant = repository.get_tenant(principal.tenant_id, principal.key_name)
    return TenantResponse(**tenant, actor_id=principal.actor_id, role=principal.role)


@app.get("/v1/ops/analysts", response_model=list[AnalystUserResponse])
async def list_analysts(principal: TenantContext = Depends(OPS_ROLES)) -> list[AnalystUserResponse]:
    return [AnalystUserResponse(**item) for item in repository.list_analyst_users(principal.tenant_id)]


@app.post("/v1/ops/analysts", response_model=AnalystUserResponse)
async def create_analyst(req: AnalystCreateRequest, principal: TenantContext = Depends(verify_service_or_admin)) -> AnalystUserResponse:
    password_hash, password_salt = hash_password(req.password)
    analyst = repository.create_analyst_user(principal.tenant_id, req.email, req.full_name, req.role, password_hash, password_salt, principal.actor_id)
    repository.write_security_audit_event(principal.tenant_id, "analyst.created", principal.actor_id, principal.role, {"email": req.email, "role": req.role})
    return AnalystUserResponse(**analyst)


@app.patch("/v1/ops/analysts/{analyst_id}/status", response_model=AnalystUserResponse)
async def update_analyst_status(analyst_id: str, req: AnalystStatusUpdateRequest, principal: TenantContext = Depends(verify_service_or_admin)) -> AnalystUserResponse:
    if principal.actor_type == "analyst" and principal.actor_id == analyst_id and not req.is_active:
        raise HTTPException(status_code=400, detail="cannot deactivate current analyst session")
    analyst = repository.update_analyst_status(principal.tenant_id, analyst_id, req.is_active)
    if analyst is None:
        raise HTTPException(status_code=404, detail="analyst not found")
    repository.write_security_audit_event(principal.tenant_id, "analyst.status_updated", principal.actor_id, principal.role, {"analyst_id": analyst_id, "is_active": req.is_active})
    return AnalystUserResponse(**analyst)


@app.get("/v1/ops/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(principal: TenantContext = Depends(verify_service_or_admin)) -> list[ApiKeyResponse]:
    return [ApiKeyResponse(**item) for item in repository.list_api_keys(principal.tenant_id)]


@app.post("/v1/ops/api-keys", response_model=ApiKeyCreateResponse)
async def create_api_key(req: ApiKeyCreateRequest, principal: TenantContext = Depends(verify_service_or_admin)) -> ApiKeyCreateResponse:
    payload = repository.create_api_key(principal.tenant_id, req.key_name)
    repository.write_security_audit_event(principal.tenant_id, "api_key.created", principal.actor_id, principal.role, {"key_name": req.key_name})
    return ApiKeyCreateResponse(**payload)


@app.get("/v1/ops/models", response_model=list[ModelVersionResponse])
async def list_models(limit: int = Query(default=20, ge=1, le=100), principal: TenantContext = Depends(OPS_ROLES)) -> list[ModelVersionResponse]:
    return [ModelVersionResponse(**item) for item in repository.list_model_versions(principal.tenant_id, limit)]


@app.post("/v1/ops/models/{model_name}/{version_id}/activate", response_model=ModelActivationResponse)
async def activate_model(model_name: str, version_id: str, req: ModelActivationRequest, principal: TenantContext = Depends(verify_service_or_admin)) -> ModelActivationResponse:
    payload = repository.activate_model_version(principal.tenant_id, model_name, version_id, req.stage)
    if payload is None:
        raise HTTPException(status_code=404, detail="model version not found")
    repository.write_security_audit_event(principal.tenant_id, "model.activated", principal.actor_id, principal.role, {"model_name": model_name, "version_id": version_id, "stage": req.stage})
    return ModelActivationResponse(**payload)


@app.get("/v1/ops/model-evaluation-summary", response_model=ModelEvaluationSummaryResponse)
async def model_evaluation_summary(principal: TenantContext = Depends(OPS_ROLES)) -> ModelEvaluationSummaryResponse:
    report_path = Path(__file__).resolve().parents[2] / "MODEL_EVALUATION_SUMMARY.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="model evaluation summary not found")
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    return ModelEvaluationSummaryResponse(**payload)

@app.get("/v1/ops/datasets", response_model=list[DatasetStatusResponse])
async def list_datasets(_: TenantContext = Depends(OPS_ROLES)) -> list[DatasetStatusResponse]:
    return [DatasetStatusResponse(**item) for item in get_dataset_inventory()]


@app.get("/v1/ops/graph/{entity_type}/{entity_id}", response_model=GraphEntityResponse)
async def graph_entity(entity_type: str, entity_id: str, principal: TenantContext = Depends(verify_principal)) -> GraphEntityResponse:
    payload = await engine.graph_entity(principal, entity_type, entity_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="graph entity not found")
    return GraphEntityResponse(**payload)


@app.post("/v1/score/session", response_model=ScoreResponse)
async def score_session(
    req: SessionScoreRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: TenantContext = Depends(verify_principal),
) -> ScoreResponse:
    cached = _idempotent_response(principal, "session", idempotency_key)
    if cached:
        return ScoreResponse(**cached)
    result = await engine.score_session(principal, req)
    _store_idempotent_response(principal, "session", idempotency_key, result)
    _record_score("session", result)
    _schedule_webhook_dispatch(background_tasks, principal, result)
    return result


@app.post("/v1/score/onboard", response_model=ScoreResponse)
async def score_onboard(
    req: OnboardRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: TenantContext = Depends(verify_principal),
) -> ScoreResponse:
    cached = _idempotent_response(principal, "onboard", idempotency_key)
    if cached:
        return ScoreResponse(**cached)
    result = await engine.score_onboard(principal, req)
    _store_idempotent_response(principal, "onboard", idempotency_key, result)
    _record_score("onboard", result)
    _schedule_webhook_dispatch(background_tasks, principal, result)
    return result


@app.post("/v1/score/transaction", response_model=ScoreResponse)
async def score_transaction(
    req: TransactionScoreRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: TenantContext = Depends(verify_principal),
) -> ScoreResponse:
    cached = _idempotent_response(principal, "transaction", idempotency_key)
    if cached:
        return ScoreResponse(**cached)
    result = await engine.score_transaction(principal, req)
    _store_idempotent_response(principal, "transaction", idempotency_key, result)
    _record_score("transaction", result)
    _schedule_webhook_dispatch(background_tasks, principal, result)
    return result


@app.post("/v1/score/phishing", response_model=ScoreResponse)
async def score_phishing(
    req: PhishingScoreRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: TenantContext = Depends(verify_principal),
) -> ScoreResponse:
    cached = _idempotent_response(principal, "phishing", idempotency_key)
    if cached:
        return ScoreResponse(**cached)
    result = await engine.score_phishing(principal, req)
    _store_idempotent_response(principal, "phishing", idempotency_key, result)
    _record_score("phishing", result)
    _schedule_webhook_dispatch(background_tasks, principal, result)
    return result


@app.post("/v1/ingest/session", response_model=BulkScoreResponse)
async def ingest_sessions(req: SessionBatchRequest, principal: TenantContext = Depends(verify_principal)) -> BulkScoreResponse:
    payload = await engine.score_session_batch(principal, req.events)
    _record_bulk_scores("session", payload)
    return payload


@app.post("/v1/ingest/onboard", response_model=BulkScoreResponse)
async def ingest_onboards(req: OnboardBatchRequest, principal: TenantContext = Depends(verify_principal)) -> BulkScoreResponse:
    payload = await engine.score_onboard_batch(principal, req.events)
    _record_bulk_scores("onboard", payload)
    return payload


@app.post("/v1/ingest/transaction", response_model=BulkScoreResponse)
async def ingest_transactions(req: TransactionBatchRequest, principal: TenantContext = Depends(verify_principal)) -> BulkScoreResponse:
    payload = await engine.score_transaction_batch(principal, req.events)
    _record_bulk_scores("transaction", payload)
    return payload


@app.post("/v1/ingest/phishing", response_model=BulkScoreResponse)
async def ingest_phishing(req: PhishingBatchRequest, principal: TenantContext = Depends(verify_principal)) -> BulkScoreResponse:
    payload = await engine.score_phishing_batch(principal, req.events)
    _record_bulk_scores("phishing", payload)
    return payload


@app.get("/v1/explain/{request_id}", response_model=ExplainResponse)
async def explain(request_id: str, principal: TenantContext = Depends(verify_principal)) -> ExplainResponse:
    payload = await engine.explain(principal, request_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="request_id not found")
    return ExplainResponse(**payload)


@app.get("/v1/ops/summary", response_model=DashboardSummary)
async def ops_summary(principal: TenantContext = Depends(OPS_ROLES)) -> DashboardSummary:
    return DashboardSummary(**await engine.dashboard_summary(principal))


@app.get("/v1/ops/shadow-decisions", response_model=ShadowDecisionListResponse)
async def ops_shadow_decisions(limit: int = Query(default=20, ge=1, le=100), route: str | None = Query(default=None), diverged_only: bool = Query(default=False), principal: TenantContext = Depends(OPS_ROLES)) -> ShadowDecisionListResponse:
    items = await engine.list_shadow_decisions(principal, limit, route, diverged_only)
    return ShadowDecisionListResponse(items=[ShadowDecisionRecord(**item) for item in items])


@app.get("/v1/ops/shadow-decisions/export")
async def export_shadow_decisions(limit: int = Query(default=100, ge=1, le=1000), route: str | None = Query(default=None), diverged_only: bool = Query(default=False), principal: TenantContext = Depends(OPS_ROLES)) -> FileResponse:
    items = await engine.list_shadow_decisions(principal, limit, route, diverged_only)
    output_path = write_shadow_decision_csv(principal.tenant_id, items)
    return FileResponse(output_path, media_type="text/csv; charset=utf-8", filename=output_path.name)


@app.get("/v1/ops/shadow-decisions/{request_id}", response_model=ShadowDecisionRecord)
async def ops_shadow_decision_detail(request_id: str, principal: TenantContext = Depends(OPS_ROLES)) -> ShadowDecisionRecord:
    payload = await engine.get_shadow_decision(principal, request_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="shadow decision not found")
    return ShadowDecisionRecord(**payload)


@app.get("/v1/ops/shadow-summary", response_model=ShadowSummaryResponse)
async def ops_shadow_summary(limit: int = Query(default=20, ge=1, le=100), principal: TenantContext = Depends(OPS_ROLES)) -> ShadowSummaryResponse:
    return ShadowSummaryResponse(**await engine.shadow_summary(principal, limit))


@app.get("/v1/ops/pilot-report", response_model=PilotReportResponse)
async def ops_pilot_report(limit: int = Query(default=10, ge=1, le=50), principal: TenantContext = Depends(OPS_ROLES)) -> PilotReportResponse:
    return PilotReportResponse(**await engine.pilot_report(principal, limit))


@app.get("/v1/ops/pilot-report/export")
async def export_pilot_report(limit: int = Query(default=10, ge=1, le=50), principal: TenantContext = Depends(OPS_ROLES)) -> FileResponse:
    payload = await engine.pilot_report(principal, limit)
    output_path = write_pilot_report_markdown(principal.tenant_id, payload)
    return FileResponse(output_path, media_type="text/markdown; charset=utf-8", filename=output_path.name)

@app.get("/v1/ops/cases", response_model=CaseListResponse)
async def list_cases(limit: int = Query(default=20, ge=1, le=100), action: str | None = Query(default=None), case_status: str | None = Query(default=None), search: str | None = Query(default=None), principal: TenantContext = Depends(OPS_ROLES)) -> CaseListResponse:
    cases = await engine.list_cases(principal, limit=limit, action=action, case_status=case_status, search=search)
    return CaseListResponse(items=cases)


@app.get("/v1/ops/cases/export")
async def export_case_queue(limit: int = Query(default=100, ge=1, le=1000), action: str | None = Query(default=None), case_status: str | None = Query(default=None), search: str | None = Query(default=None), principal: TenantContext = Depends(OPS_ROLES)) -> FileResponse:
    cases = await engine.list_cases(principal, limit=limit, action=action, case_status=case_status, search=search)
    for item in cases:
        item["shadow_comparison"] = repository.get_shadow_decision(principal.tenant_id, item["request_id"])
    output_path = write_case_queue_csv(principal.tenant_id, cases)
    return FileResponse(output_path, media_type="text/csv; charset=utf-8", filename=output_path.name)

@app.get("/v1/ops/cases/{request_id}/activity", response_model=CaseActivityListResponse)
async def case_activity(request_id: str, limit: int = Query(default=50, ge=1, le=200), principal: TenantContext = Depends(OPS_ROLES)) -> CaseActivityListResponse:
    items = await engine.list_case_activity(principal, request_id, limit)
    return CaseActivityListResponse(items=items)


@app.get("/v1/ops/cases/{request_id}/activity/export")
async def export_case_activity(request_id: str, limit: int = Query(default=200, ge=1, le=1000), principal: TenantContext = Depends(OPS_ROLES)) -> FileResponse:
    items = await engine.list_case_activity(principal, request_id, limit)
    output_path = write_case_activity_csv(principal.tenant_id, request_id, items)
    return FileResponse(output_path, media_type="text/csv; charset=utf-8", filename=output_path.name)

@app.get("/v1/ops/cases/{request_id}/export")
async def export_case_report(request_id: str, principal: TenantContext = Depends(OPS_ROLES)) -> FileResponse:
    case = await engine.get_case(principal, request_id)
    if case is None:
        raise HTTPException(status_code=404, detail="request_id not found")
    output_path = write_case_report_markdown(principal.tenant_id, case)
    return FileResponse(output_path, media_type="text/markdown; charset=utf-8", filename=output_path.name)

@app.post("/v1/ops/cases/bulk-status", response_model=BulkCaseStatusResponse)
async def bulk_update_case_status(req: BulkCaseStatusRequest, principal: TenantContext = Depends(MUTATION_ROLES)) -> BulkCaseStatusResponse:
    payload = await engine.bulk_update_case_status(principal, req.request_ids, req.case_status, req.assigned_to)
    return BulkCaseStatusResponse(**payload)


@app.get("/v1/ops/cases/{request_id}", response_model=CaseDetailResponse)
async def case_detail(request_id: str, principal: TenantContext = Depends(OPS_ROLES)) -> CaseDetailResponse:
    case = await engine.get_case(principal, request_id)
    if case is None:
        raise HTTPException(status_code=404, detail="request_id not found")
    return CaseDetailResponse(**case)


@app.post("/v1/ops/cases/{request_id}/feedback", response_model=FeedbackResponse)
async def submit_feedback(request_id: str, req: FeedbackRequest, principal: TenantContext = Depends(MUTATION_ROLES)) -> FeedbackResponse:
    payload = await engine.submit_feedback(principal, request_id, req.label, req.notes, req.reported_by)
    if payload is None:
        raise HTTPException(status_code=404, detail="request_id not found")
    return FeedbackResponse(**payload)


@app.patch("/v1/ops/cases/{request_id}/status", response_model=CaseStatusResponse)
async def update_case_status(request_id: str, req: CaseStatusRequest, principal: TenantContext = Depends(MUTATION_ROLES)) -> CaseStatusResponse:
    payload = await engine.update_case_status(principal, request_id, req.case_status, req.assigned_to)
    if payload is None:
        raise HTTPException(status_code=404, detail="request_id not found")
    return CaseStatusResponse(**payload)


@app.post("/v1/ops/webhooks", response_model=WebhookEndpointResponse)
async def create_webhook(req: WebhookEndpointCreateRequest, principal: TenantContext = Depends(MUTATION_ROLES)) -> WebhookEndpointResponse:
    payload = await engine.create_webhook_endpoint(principal, req.event_type, req.url, req.secret)
    repository.write_security_audit_event(principal.tenant_id, "webhook.created", principal.actor_id, principal.role, {"event_type": req.event_type, "url": req.url})
    return WebhookEndpointResponse(**payload)


@app.get("/v1/ops/webhooks", response_model=list[WebhookEndpointResponse])
async def list_webhooks(principal: TenantContext = Depends(OPS_ROLES)) -> list[WebhookEndpointResponse]:
    return [WebhookEndpointResponse(**item) for item in await engine.list_webhook_endpoints(principal)]


@app.patch("/v1/ops/webhooks/{webhook_id}/secret", response_model=WebhookEndpointResponse)
async def rotate_webhook_secret(webhook_id: str, req: WebhookSecretRotateRequest, principal: TenantContext = Depends(verify_service_or_admin)) -> WebhookEndpointResponse:
    payload = await engine.rotate_webhook_secret(principal, webhook_id, req.secret)
    if payload is None:
        raise HTTPException(status_code=404, detail="webhook not found")
    repository.write_security_audit_event(principal.tenant_id, "webhook.secret_rotated", principal.actor_id, principal.role, {"webhook_id": webhook_id})
    return WebhookEndpointResponse(**payload)


@app.get("/v1/ops/webhook-deliveries", response_model=list[WebhookDeliveryResponse])
async def list_webhook_deliveries(limit: int = Query(default=20, ge=1, le=100), principal: TenantContext = Depends(OPS_ROLES)) -> list[WebhookDeliveryResponse]:
    return [WebhookDeliveryResponse(**item) for item in await engine.list_webhook_deliveries(principal, limit)]


@app.post("/v1/ops/webhook-deliveries/dispatch", response_model=WebhookDispatchResponse)
async def dispatch_webhooks(limit: int = Query(default=25, ge=1, le=100), principal: TenantContext = Depends(MUTATION_ROLES)) -> WebhookDispatchResponse:
    result = await dispatcher.dispatch_pending(principal, limit)
    return WebhookDispatchResponse(**result)


@app.get("/v1/ops/jobs", response_model=list[JobResponse])
async def list_jobs(limit: int = Query(default=50, ge=1, le=100), principal: TenantContext = Depends(OPS_ROLES)) -> list[JobResponse]:
    return [JobResponse(**item) for item in repository.list_jobs(principal.tenant_id, limit)]


@app.get("/v1/ops/monitoring", response_model=MonitoringSnapshotResponse)
async def monitoring_snapshot(principal: TenantContext = Depends(OPS_ROLES)) -> MonitoringSnapshotResponse:
    return MonitoringSnapshotResponse(**repository.monitoring_snapshot(principal.tenant_id))


@app.get("/v1/ops/security-posture", response_model=SecurityPostureResponse)
async def security_posture(principal: TenantContext = Depends(verify_service_or_admin)) -> SecurityPostureResponse:
    return SecurityPostureResponse(**get_settings().security_posture())


@app.get("/v1/ops/security-audit", response_model=list[SecurityAuditEventResponse])
async def security_audit(limit: int = Query(default=100, ge=1, le=200), event_type: str | None = Query(default=None), actor_id: str | None = Query(default=None), principal: TenantContext = Depends(verify_service_or_admin)) -> list[SecurityAuditEventResponse]:
    return [SecurityAuditEventResponse(**item) for item in repository.list_security_audit_events(principal.tenant_id, limit, event_type=event_type, actor_id=actor_id)]


@app.get("/v1/ops/security-audit/export")
async def export_security_audit(limit: int = Query(default=200, ge=1, le=1000), event_type: str | None = Query(default=None), actor_id: str | None = Query(default=None), principal: TenantContext = Depends(verify_service_or_admin)) -> FileResponse:
    items = repository.list_security_audit_events(principal.tenant_id, limit, event_type=event_type, actor_id=actor_id)
    output_path = write_security_audit_csv(principal.tenant_id, items)
    return FileResponse(output_path, media_type="text/csv; charset=utf-8", filename=output_path.name)


@app.get("/v1/ops/connectors", response_model=list[ConnectorResponse])
async def list_connectors(principal: TenantContext = Depends(OPS_ROLES)) -> list[ConnectorResponse]:
    return [ConnectorResponse(**item) for item in repository.list_connector_configs(principal.tenant_id)]


@app.post("/v1/ops/connectors", response_model=ConnectorResponse)
async def create_connector(req: ConnectorCreateRequest, principal: TenantContext = Depends(verify_service_or_admin)) -> ConnectorResponse:
    payload = repository.create_connector_config(principal.tenant_id, req.connector_type, req.route, req.source_path, req.config, principal.actor_id)
    repository.write_security_audit_event(principal.tenant_id, "connector.created", principal.actor_id, principal.role, {"route": req.route, "source_path": req.source_path})
    return ConnectorResponse(**payload)


@app.post("/v1/ops/connectors/{connector_id}/run", response_model=ConnectorRunResponse)
async def run_connector(connector_id: str, principal: TenantContext = Depends(verify_service_or_admin)) -> ConnectorRunResponse:
    connector = repository.get_connector_config(principal.tenant_id, connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="connector not found")
    job = job_bus.enqueue_connector_sync(principal.tenant_id, connector_id, principal.actor_id)
    return ConnectorRunResponse(connector_id=connector_id, job_id=job["job_id"], status=job["status"])


@app.post("/v1/dev/train-models", response_model=TrainModelsResponse)
async def train_models(principal: TenantContext = Depends(verify_service_or_admin)) -> TrainModelsResponse:
    training_result = train_baseline_models()
    artifacts = {name: info["artifact_path"] for name, info in training_result.items()}
    metrics = {name: info["metrics"] for name, info in training_result.items()}
    training_job_id = f"sync-train-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
    for name, info in training_result.items():
        repository.save_model_version(
            principal.tenant_id,
            name,
            info["version_id"],
            info["artifact_path"],
            info["metrics"],
            stage="candidate",
            is_active=False,
            training_job_id=training_job_id,
        )
    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "MODEL_EVALUATION_SUMMARY.json"
    evaluation_payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "training_manifest": {
            "training_job_id": training_job_id,
            "tenant_id": principal.tenant_id,
            "mode": "sync",
            "promote_stage": "candidate",
            "activate_after_training": False,
        },
        "models": {
            model_name: {
                "version_id": info["version_id"],
                "artifact_path": info["artifact_path"],
                "metrics": info["metrics"],
            }
            for model_name, info in sorted(training_result.items())
        },
    }
    report_path.write_text(json.dumps(evaluation_payload, indent=2), encoding="utf-8")
    repository.write_security_audit_event(principal.tenant_id, "models.trained.sync", principal.actor_id, principal.role, {"models": list(training_result), "training_job_id": training_job_id})
    return TrainModelsResponse(status="ok", artifacts=artifacts, metrics=metrics)


@app.post("/v1/dev/retraining-jobs", response_model=JobResponse)
async def enqueue_retraining(req: RetrainRequest, principal: TenantContext = Depends(verify_service_or_admin)) -> JobResponse:
    job = job_bus.enqueue_retraining(
        principal.tenant_id,
        principal.actor_id,
        req.promote_stage,
        req.activate_after_training,
        req.use_feedback_labels,
        req.minimum_feedback_labels,
    )
    repository.write_security_audit_event(principal.tenant_id, "models.retraining.enqueued", principal.actor_id, principal.role, {"job_id": job["job_id"], "promote_stage": req.promote_stage, "activate_after_training": req.activate_after_training, "use_feedback_labels": req.use_feedback_labels, "minimum_feedback_labels": req.minimum_feedback_labels})
    return JobResponse(**job)


@app.post("/v1/dev/seed", response_model=SeedResponse)
async def seed_demo(principal: TenantContext = Depends(verify_service_or_admin)) -> SeedResponse:
    generated = await engine.seed_demo_data(principal)
    return SeedResponse(status="ok", generated_cases=generated)







