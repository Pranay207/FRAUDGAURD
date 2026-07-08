from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.db import init_db
from app.schemas import (
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyResponse,
    CaseDetailResponse,
    CaseListResponse,
    CaseStatusRequest,
    CaseStatusResponse,
    DashboardSummary,
    DatasetStatusResponse,
    ExplainResponse,
    FeedbackRequest,
    FeedbackResponse,
    GraphEntityResponse,
    HealthResponse,
    ModelVersionResponse,
    OnboardRequest,
    PhishingScoreRequest,
    ScoreResponse,
    SeedResponse,
    SessionScoreRequest,
    TenantResponse,
    TrainModelsResponse,
    TransactionScoreRequest,
    WebhookDeliveryResponse,
    WebhookDispatchResponse,
    WebhookEndpointCreateRequest,
    WebhookEndpointResponse,
)
from app.security import TenantContext, verify_api_key
from app.services.repository import repository
from app.services.scoring import engine
from app.services.training import get_dataset_inventory, train_baseline_models
from app.services.webhooks import dispatcher


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="FraudGuard API", version="0.8.0", lifespan=lifespan)
frontend_dir = Path(__file__).parent / "frontend"
assets_dir = frontend_dir / "assets"
app.mount("/dashboard/assets", StaticFiles(directory=assets_dir), name="dashboard-assets")


def _idempotent_response(tenant: TenantContext, route: str, key: str | None) -> dict | None:
    if not key:
        return None
    return repository.get_idempotent_response(tenant.tenant_id, route, key)


def _store_idempotent_response(tenant: TenantContext, route: str, key: str | None, payload: ScoreResponse) -> None:
    if key:
        repository.save_idempotent_response(tenant.tenant_id, route, key, payload.model_dump(mode="json"))


def _schedule_webhook_dispatch(background_tasks: BackgroundTasks, tenant: TenantContext, response: ScoreResponse) -> None:
    if response.action in {"CHALLENGE", "BLOCK"}:
        background_tasks.add_task(dispatcher.dispatch_pending, tenant, 25)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", database="ready", tenant_seeded=True)


@app.get("/", include_in_schema=False)
async def root() -> FileResponse:
    return FileResponse(frontend_dir / "index.html")


@app.get("/dashboard", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(frontend_dir / "index.html")


@app.get("/v1/tenant", response_model=TenantResponse)
async def tenant_info(tenant: TenantContext = Depends(verify_api_key)) -> TenantResponse:
    return TenantResponse(**repository.get_tenant(tenant.tenant_id, tenant.key_name))


@app.get("/v1/ops/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(tenant: TenantContext = Depends(verify_api_key)) -> list[ApiKeyResponse]:
    return [ApiKeyResponse(**item) for item in repository.list_api_keys(tenant.tenant_id)]


@app.post("/v1/ops/api-keys", response_model=ApiKeyCreateResponse)
async def create_api_key(req: ApiKeyCreateRequest, tenant: TenantContext = Depends(verify_api_key)) -> ApiKeyCreateResponse:
    return ApiKeyCreateResponse(**repository.create_api_key(tenant.tenant_id, req.key_name))


@app.get("/v1/ops/models", response_model=list[ModelVersionResponse])
async def list_models(limit: int = Query(default=20, ge=1, le=100), tenant: TenantContext = Depends(verify_api_key)) -> list[ModelVersionResponse]:
    return [ModelVersionResponse(**item) for item in repository.list_model_versions(tenant.tenant_id, limit)]


@app.get("/v1/ops/datasets", response_model=list[DatasetStatusResponse])
async def list_datasets(_: TenantContext = Depends(verify_api_key)) -> list[DatasetStatusResponse]:
    return [DatasetStatusResponse(**item) for item in get_dataset_inventory()]


@app.get("/v1/ops/graph/{entity_type}/{entity_id}", response_model=GraphEntityResponse)
async def graph_entity(entity_type: str, entity_id: str, tenant: TenantContext = Depends(verify_api_key)) -> GraphEntityResponse:
    payload = await engine.graph_entity(tenant, entity_type, entity_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="graph entity not found")
    return GraphEntityResponse(**payload)


@app.post("/v1/score/session", response_model=ScoreResponse)
async def score_session(
    req: SessionScoreRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    tenant: TenantContext = Depends(verify_api_key),
) -> ScoreResponse:
    cached = _idempotent_response(tenant, "session", idempotency_key)
    if cached:
        return ScoreResponse(**cached)
    result = await engine.score_session(tenant, req)
    _store_idempotent_response(tenant, "session", idempotency_key, result)
    _schedule_webhook_dispatch(background_tasks, tenant, result)
    return result


@app.post("/v1/score/onboard", response_model=ScoreResponse)
async def score_onboard(
    req: OnboardRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    tenant: TenantContext = Depends(verify_api_key),
) -> ScoreResponse:
    cached = _idempotent_response(tenant, "onboard", idempotency_key)
    if cached:
        return ScoreResponse(**cached)
    result = await engine.score_onboard(tenant, req)
    _store_idempotent_response(tenant, "onboard", idempotency_key, result)
    _schedule_webhook_dispatch(background_tasks, tenant, result)
    return result


@app.post("/v1/score/transaction", response_model=ScoreResponse)
async def score_transaction(
    req: TransactionScoreRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    tenant: TenantContext = Depends(verify_api_key),
) -> ScoreResponse:
    cached = _idempotent_response(tenant, "transaction", idempotency_key)
    if cached:
        return ScoreResponse(**cached)
    result = await engine.score_transaction(tenant, req)
    _store_idempotent_response(tenant, "transaction", idempotency_key, result)
    _schedule_webhook_dispatch(background_tasks, tenant, result)
    return result


@app.post("/v1/score/phishing", response_model=ScoreResponse)
async def score_phishing(
    req: PhishingScoreRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    tenant: TenantContext = Depends(verify_api_key),
) -> ScoreResponse:
    cached = _idempotent_response(tenant, "phishing", idempotency_key)
    if cached:
        return ScoreResponse(**cached)
    result = await engine.score_phishing(tenant, req)
    _store_idempotent_response(tenant, "phishing", idempotency_key, result)
    _schedule_webhook_dispatch(background_tasks, tenant, result)
    return result


@app.get("/v1/explain/{request_id}", response_model=ExplainResponse)
async def explain(request_id: str, tenant: TenantContext = Depends(verify_api_key)) -> ExplainResponse:
    payload = await engine.explain(tenant, request_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="request_id not found")
    return ExplainResponse(**payload)


@app.get("/v1/ops/summary", response_model=DashboardSummary)
async def ops_summary(tenant: TenantContext = Depends(verify_api_key)) -> DashboardSummary:
    return DashboardSummary(**await engine.dashboard_summary(tenant))


@app.get("/v1/ops/cases", response_model=CaseListResponse)
async def list_cases(limit: int = Query(default=20, ge=1, le=100), action: str | None = Query(default=None), case_status: str | None = Query(default=None), tenant: TenantContext = Depends(verify_api_key)) -> CaseListResponse:
    cases = await engine.list_cases(tenant, limit=limit, action=action, case_status=case_status)
    return CaseListResponse(items=cases)


@app.get("/v1/ops/cases/{request_id}", response_model=CaseDetailResponse)
async def case_detail(request_id: str, tenant: TenantContext = Depends(verify_api_key)) -> CaseDetailResponse:
    case = await engine.get_case(tenant, request_id)
    if case is None:
        raise HTTPException(status_code=404, detail="request_id not found")
    return CaseDetailResponse(**case)


@app.post("/v1/ops/cases/{request_id}/feedback", response_model=FeedbackResponse)
async def submit_feedback(request_id: str, req: FeedbackRequest, tenant: TenantContext = Depends(verify_api_key)) -> FeedbackResponse:
    payload = await engine.submit_feedback(tenant, request_id, req.label, req.notes, req.reported_by)
    if payload is None:
        raise HTTPException(status_code=404, detail="request_id not found")
    return FeedbackResponse(**payload)


@app.patch("/v1/ops/cases/{request_id}/status", response_model=CaseStatusResponse)
async def update_case_status(request_id: str, req: CaseStatusRequest, tenant: TenantContext = Depends(verify_api_key)) -> CaseStatusResponse:
    payload = await engine.update_case_status(tenant, request_id, req.case_status, req.assigned_to)
    if payload is None:
        raise HTTPException(status_code=404, detail="request_id not found")
    return CaseStatusResponse(**payload)


@app.post("/v1/ops/webhooks", response_model=WebhookEndpointResponse)
async def create_webhook(req: WebhookEndpointCreateRequest, tenant: TenantContext = Depends(verify_api_key)) -> WebhookEndpointResponse:
    return WebhookEndpointResponse(**await engine.create_webhook_endpoint(tenant, req.event_type, req.url, req.secret))


@app.get("/v1/ops/webhooks", response_model=list[WebhookEndpointResponse])
async def list_webhooks(tenant: TenantContext = Depends(verify_api_key)) -> list[WebhookEndpointResponse]:
    return [WebhookEndpointResponse(**item) for item in await engine.list_webhook_endpoints(tenant)]


@app.get("/v1/ops/webhook-deliveries", response_model=list[WebhookDeliveryResponse])
async def list_webhook_deliveries(limit: int = Query(default=20, ge=1, le=100), tenant: TenantContext = Depends(verify_api_key)) -> list[WebhookDeliveryResponse]:
    return [WebhookDeliveryResponse(**item) for item in await engine.list_webhook_deliveries(tenant, limit)]


@app.post("/v1/ops/webhook-deliveries/dispatch", response_model=WebhookDispatchResponse)
async def dispatch_webhooks(limit: int = Query(default=25, ge=1, le=100), tenant: TenantContext = Depends(verify_api_key)) -> WebhookDispatchResponse:
    result = await dispatcher.dispatch_pending(tenant, limit)
    return WebhookDispatchResponse(**result)


@app.post("/v1/dev/train-models", response_model=TrainModelsResponse)
async def train_models(tenant: TenantContext = Depends(verify_api_key)) -> TrainModelsResponse:
    training_result = train_baseline_models()
    artifacts = {name: info["artifact_path"] for name, info in training_result.items()}
    metrics = {name: info["metrics"] for name, info in training_result.items()}
    for name, info in training_result.items():
        repository.save_model_version(tenant.tenant_id, name, info["version_id"], info["artifact_path"], info["metrics"])
    return TrainModelsResponse(status="ok", artifacts=artifacts, metrics=metrics)


@app.post("/v1/dev/seed", response_model=SeedResponse)
async def seed_demo(tenant: TenantContext = Depends(verify_api_key)) -> SeedResponse:
    generated = await engine.seed_demo_data(tenant)
    return SeedResponse(status="ok", generated_cases=generated)
