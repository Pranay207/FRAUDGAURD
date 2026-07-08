from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from uuid import uuid4

from app.engine.ensemble import LayerScores, combine_scores
from app.engine.features import BehavioralFeatures, days_since, duration_zscore, login_hour_anomaly
from app.engine.rules import SOCIAL_ENGINEERING_TERMS, clamp
from app.schemas import OnboardRequest, PhishingScoreRequest, ScoreResponse, SessionScoreRequest, TransactionScoreRequest
from app.security import TenantContext
from app.services.models import model_registry
from app.services.repository import repository

PHISHING_FEATURE_FIELDS = [
    "having_ip_address",
    "url_length",
    "shortening_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "sslfinal_state",
    "domain_registration_length",
    "favicon",
    "port",
    "https_token",
    "request_url",
    "url_of_anchor",
    "links_in_tags",
    "sfh",
    "submitting_to_email",
    "abnormal_url",
    "redirect",
    "on_mouseover",
    "rightclick",
    "popup_window",
    "iframe",
    "age_of_domain",
    "dnsrecord",
    "web_traffic",
    "page_rank",
    "google_index",
    "links_pointing_to_page",
    "statistical_report",
]


class FraudEngine:
    async def score_session(self, tenant: TenantContext, req: SessionScoreRequest) -> ScoreResponse:
        start = time.perf_counter()
        profile = repository.get_user_profile(tenant.tenant_id, req.user_id)
        features = BehavioralFeatures(
            keystroke_interval_deviation=abs(req.keystroke_mean_ms - 140.0),
            is_new_device=int(req.device_id not in profile["known_devices"]),
            hour_of_day_anomaly_score=login_hour_anomaly(req.hour_of_day),
            session_duration_zscore=duration_zscore(req.session_duration_s),
            ip_country_change=int(profile["last_ip_country"] != req.ip_country),
            txn_velocity_5min=repository.transaction_velocity(tenant.tenant_id, req.user_id),
            days_since_last_login=days_since(self._parse_dt(profile["last_login_at"])),
        )
        behavioral_score, reasons, factors = self._behavioral_score(features)
        action = self._action_for_score(behavioral_score)

        repository.upsert_user_identity(tenant.tenant_id, req.user_id, None, None, None, None)
        repository.link_user_device(tenant.tenant_id, req.user_id, req.device_id)
        repository.update_login(tenant.tenant_id, req.user_id, req.ip_country)
        repository.create_session(tenant.tenant_id, req.session_id, req.user_id, req.device_id, behavioral_score, action, req.ip_country)

        request_id = str(uuid4())
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        response = ScoreResponse(request_id=request_id, fraud_score=behavioral_score, action=action, reasons=reasons, latency_ms=latency_ms)
        repository.write_audit_event(tenant.tenant_id, request_id, "session", req.user_id, response.fraud_score, response.action, response.reasons, factors, req.model_dump())
        self._queue_case_webhooks(tenant.tenant_id, response, "session")
        return response

    async def score_onboard(self, tenant: TenantContext, req: OnboardRequest) -> ScoreResponse:
        start = time.perf_counter()
        links = repository.get_device_link_counts(tenant.tenant_id, req.device.device_id, req.phone_hash, req.pan_hash)
        identity_score, reasons, factors = self._identity_score(req, links)
        action = self._action_for_score(identity_score)

        repository.upsert_user_identity(tenant.tenant_id, req.user_id, req.pan_hash, req.phone_hash, req.aadhaar_last4, req.email_hash)
        repository.upsert_device(tenant.tenant_id, req.device.model_dump())
        repository.link_user_device(tenant.tenant_id, req.user_id, req.device.device_id)

        request_id = str(uuid4())
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        response = ScoreResponse(request_id=request_id, fraud_score=identity_score, action=action, reasons=reasons, latency_ms=latency_ms)
        repository.write_audit_event(tenant.tenant_id, request_id, "onboard", req.user_id, response.fraud_score, response.action, response.reasons, factors, req.model_dump())
        self._queue_case_webhooks(tenant.tenant_id, response, "onboard")
        return response

    async def score_transaction(self, tenant: TenantContext, req: TransactionScoreRequest) -> ScoreResponse:
        start = time.perf_counter()
        profile = repository.get_user_profile(tenant.tenant_id, req.user_id)
        first_time_payee = req.payee_vpa not in profile["payees"]
        current_velocity = repository.transaction_velocity(tenant.tenant_id, req.user_id)
        payee_graph = repository.get_payee_graph_counts(tenant.tenant_id, req.payee_vpa)

        behavioral_task = self._behavioral_for_transaction(profile, req.device_id, req.ip_country, current_velocity)
        transaction_task = self._transaction_score(
            req.amount_paise,
            first_time_payee,
            current_velocity + 1,
            profile["clean_streak_days"],
            req.transaction_type,
            req.source_balance_paise,
            req.destination_balance_paise,
            payee_graph,
        )
        remark_task = self._remark_score(req.upi_remark, req.payee_vpa, req.amount_paise, first_time_payee)
        behavioral, transaction, remark = await asyncio.gather(behavioral_task, transaction_task, remark_task)

        final_score, action = combine_scores(LayerScores(behavioral=behavioral["score"], identity=0, transaction=transaction["score"], remark=remark["score"]))

        repository.upsert_user_identity(tenant.tenant_id, req.user_id, None, None, None, None)
        repository.link_user_device(tenant.tenant_id, req.user_id, req.device_id)
        repository.update_login(tenant.tenant_id, req.user_id, req.ip_country)

        request_id = str(uuid4())
        repository.create_transaction(tenant.tenant_id, request_id, req.user_id, req.amount_paise, req.payee_vpa, req.session_id, req.device_id, req.upi_remark, final_score, action)

        reasons = [*behavioral["reasons"], *transaction["reasons"], *remark["reasons"]]
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        response = ScoreResponse(request_id=request_id, fraud_score=final_score, action=action, reasons=reasons[:5], latency_ms=latency_ms)
        repository.write_audit_event(tenant.tenant_id, request_id, "transaction", req.user_id, response.fraud_score, response.action, response.reasons, [*behavioral["factors"], *transaction["factors"], *remark["factors"]], req.model_dump())
        self._queue_case_webhooks(tenant.tenant_id, response, "transaction")
        return response

    async def score_phishing(self, tenant: TenantContext, req: PhishingScoreRequest) -> ScoreResponse:
        start = time.perf_counter()
        score, reasons, factors = self._phishing_score(req)
        action = self._action_for_score(score)

        request_id = str(uuid4())
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        response = ScoreResponse(request_id=request_id, fraud_score=score, action=action, reasons=reasons, latency_ms=latency_ms)
        repository.write_audit_event(tenant.tenant_id, request_id, "phishing", None, response.fraud_score, response.action, response.reasons, factors, req.model_dump())
        self._queue_case_webhooks(tenant.tenant_id, response, "phishing")
        return response

    async def explain(self, tenant: TenantContext, request_id: str) -> dict | None:
        payload = repository.get_audit_event(tenant.tenant_id, request_id)
        if not payload:
            return None
        factors = sorted(payload["factors"], key=lambda item: item["impact"], reverse=True)[:5]
        return {
            "request_id": request_id,
            "fraud_score": payload["fraud_score"],
            "action": payload["action"],
            "route": payload["route"],
            "reasons": payload["reasons"],
            "factors": factors,
            "created_at": payload["created_at"],
        }

    async def get_case(self, tenant: TenantContext, request_id: str) -> dict | None:
        return repository.get_audit_event(tenant.tenant_id, request_id)

    async def list_cases(self, tenant: TenantContext, limit: int = 20, action: str | None = None, case_status: str | None = None) -> list[dict]:
        return repository.list_cases(tenant.tenant_id, limit=limit, action=action, case_status=case_status)

    async def submit_feedback(self, tenant: TenantContext, request_id: str, label: str, notes: str | None, reported_by: str) -> dict | None:
        return repository.submit_feedback(tenant.tenant_id, request_id, label, notes, reported_by)

    async def update_case_status(self, tenant: TenantContext, request_id: str, case_status: str, assigned_to: str | None) -> dict | None:
        return repository.update_case_status(tenant.tenant_id, request_id, case_status, assigned_to)

    async def dashboard_summary(self, tenant: TenantContext) -> dict:
        return repository.dashboard_summary(tenant.tenant_id)

    async def graph_entity(self, tenant: TenantContext, entity_type: str, entity_id: str) -> dict | None:
        return repository.get_graph_entity_summary(tenant.tenant_id, entity_type, entity_id)

    async def seed_demo_data(self, tenant: TenantContext) -> int:
        generated = 0
        for index in range(1, 6):
            await self.score_onboard(
                tenant,
                OnboardRequest(
                    user_id=f"seed-user-{index}",
                    pan_hash=(str(index) * 64)[:64],
                    phone_hash=(str(index + 1) * 64)[:64],
                    aadhaar_last4=f"{1000 + index}"[-4:],
                    email_hash=None,
                    device={
                        "device_id": "shared-seed-device" if index > 3 else f"seed-device-{index}",
                        "os": "Android",
                        "screen_res": "1080x2400",
                        "is_rooted": index == 5,
                        "sim_count": 3 if index >= 4 else 1,
                    },
                    selfie_check_score=0.8 if index >= 4 else 0.1,
                    kyc_name_match_score=0.55 if index == 5 else 0.95,
                ),
            )
            await self.score_session(
                tenant,
                SessionScoreRequest(
                    user_id=f"seed-user-{index}",
                    session_id=f"seed-session-{index}",
                    device_id="shared-seed-device" if index > 3 else f"seed-device-{index}",
                    keystroke_mean_ms=280 if index >= 4 else 145,
                    session_duration_s=18 if index >= 4 else 95,
                    hour_of_day=2 if index >= 4 else 14,
                    ip_country="AE" if index == 5 else "IN",
                ),
            )
            await self.score_transaction(
                tenant,
                TransactionScoreRequest(
                    user_id=f"seed-user-{index}",
                    amount_paise=180000 if index >= 4 else 24000,
                    payee_vpa="urgent-clearance@upi" if index >= 4 else "merchant@upi",
                    upi_remark="Government clearance payment" if index >= 4 else "Groceries",
                    session_id=f"seed-session-{index}",
                    device_id="shared-seed-device" if index > 3 else f"seed-device-{index}",
                    ip_country="AE" if index == 5 else "IN",
                    transaction_type="TRANSFER",
                    source_balance_paise=210000 if index >= 4 else 55000,
                    destination_balance_paise=0,
                ),
            )
            generated += 3
        return generated

    async def create_webhook_endpoint(self, tenant: TenantContext, event_type: str, url: str, secret: str | None) -> dict:
        return repository.create_webhook_endpoint(tenant.tenant_id, event_type, url, secret)

    async def list_webhook_endpoints(self, tenant: TenantContext) -> list[dict]:
        return repository.list_webhook_endpoints(tenant.tenant_id)

    async def list_webhook_deliveries(self, tenant: TenantContext, limit: int = 20) -> list[dict]:
        return repository.list_webhook_deliveries(tenant.tenant_id, limit)

    def _queue_case_webhooks(self, tenant_id: str, response: ScoreResponse, route: str) -> None:
        if response.action in {"CHALLENGE", "BLOCK"}:
            repository.enqueue_webhook_deliveries(tenant_id, "fraud.case.created", response.request_id, {"route": route, **response.model_dump()})
        if response.action == "BLOCK":
            repository.enqueue_webhook_deliveries(tenant_id, "fraud.case.blocked", response.request_id, {"route": route, **response.model_dump()})

    def _behavioral_score(self, features: BehavioralFeatures) -> tuple[int, list[str], list[dict]]:
        parts = []
        reasons = []
        if features.is_new_device:
            parts.append(("new_device", 260, "Login from a device not seen before"))
            reasons.append("New device detected")
        if features.hour_of_day_anomaly_score > 0.8:
            parts.append(("odd_hour_activity", 170, "Login time is outside the user's normal pattern"))
            reasons.append("Odd-hour activity")
        if features.ip_country_change:
            parts.append(("ip_country_change", 180, "IP geography changed since the last login"))
            reasons.append("IP country changed")
        if features.keystroke_interval_deviation > 90:
            parts.append(("typing_pattern_shift", 140, "Typing rhythm shifted sharply from baseline"))
            reasons.append("Typing pattern anomaly")
        if features.days_since_last_login > 14:
            parts.append(("long_inactivity", 70, "Dormant account suddenly became active"))
            reasons.append("Dormant account reactivated")
        if features.session_duration_zscore > 0.7:
            parts.append(("session_duration_shift", 80, "Session duration is materially different from the norm"))
            reasons.append("Session duration anomaly")
        heuristic_score = clamp(sum(impact for _, impact, _ in parts))
        model_prediction = model_registry.behavioral_score(features, heuristic_score)
        score = model_prediction.score
        factors = [{"signal": signal, "impact": impact, "summary": summary} for signal, impact, summary in parts]
        if model_prediction.model_used:
            factors.append({"signal": "model:behavioral", "impact": max(1, score // 4), "summary": "Behavioral baseline model scored this session from trained artifacts"})
            if score >= 350 and "Behavioral model consensus risk" not in reasons:
                reasons.append("Behavioral model consensus risk")
        return score, reasons or ["No major behavioral anomalies"], factors

    async def _behavioral_for_transaction(self, profile: dict, device_id: str, ip_country: str, velocity: int) -> dict:
        features = BehavioralFeatures(
            keystroke_interval_deviation=0.0,
            is_new_device=int(device_id not in profile["known_devices"]),
            hour_of_day_anomaly_score=login_hour_anomaly(datetime.now(UTC).hour),
            session_duration_zscore=0.0,
            ip_country_change=int(profile["last_ip_country"] != ip_country),
            txn_velocity_5min=velocity,
            days_since_last_login=days_since(self._parse_dt(profile["last_login_at"])),
        )
        score, reasons, factors = self._behavioral_score(features)
        return {"score": score, "reasons": reasons, "factors": factors}

    async def _transaction_score(
        self,
        amount_paise: int,
        first_time_payee: bool,
        velocity: int,
        clean_streak_days: int,
        transaction_type: str = "TRANSFER",
        source_balance_paise: int | None = None,
        destination_balance_paise: int | None = None,
        payee_graph: dict[str, int] | None = None,
    ) -> dict:
        parts = []
        reasons = []
        transaction_type_upper = transaction_type.upper()
        drain_ratio = min(2.0, amount_paise / max(source_balance_paise, 1)) if source_balance_paise and source_balance_paise > 0 else (2.0 if source_balance_paise == 0 else 0.0)

        if amount_paise >= 100_000:
            parts.append(("high_value", 600, "Transaction value is high for the account context"))
            reasons.append("High-value payment")
        if first_time_payee:
            parts.append(("first_time_payee", 400, "Funds are being sent to a new payee"))
            reasons.append("First-time payee")
        if velocity >= 3:
            parts.append(("velocity_spike", 700, "Multiple transactions occurred in a short window"))
            reasons.append("Velocity spike")
        if clean_streak_days >= 90 and amount_paise >= 75_000:
            parts.append(("bust_out_signature", 500, "Long clean streak followed by sudden large utilization"))
            reasons.append("Possible bust-out pattern")
        if transaction_type_upper in {"TRANSFER", "CASH_OUT"}:
            parts.append(("transfer_rail", 180, "Transfer and cash-out rails have elevated fraud exposure"))
            reasons.append("High-risk transaction rail")
        if drain_ratio >= 0.85:
            parts.append(("balance_drain", 320, "Transaction consumes most of the available source balance"))
            reasons.append("Balance drain pattern")
        if destination_balance_paise == 0 and first_time_payee and amount_paise >= 50_000:
            parts.append(("empty_destination_context", 180, "A large first-time transfer is heading to a low-context destination"))
            reasons.append("Low-context destination account")
        if payee_graph and payee_graph["payee_users"] >= 2:
            parts.append(("shared_payee_graph", 240, "This payee is already receiving funds from multiple users"))
            reasons.append("Payee linked across multiple users")
        if payee_graph and payee_graph["blocked_transactions"] >= 1:
            parts.append(("blocked_payee_history", 320, "The payee has prior blocked transaction history"))
            reasons.append("Payee has blocked-history exposure")

        heuristic_score = clamp(sum(impact for _, impact, _ in parts))
        feature_values = [
            float(amount_paise),
            float(int(first_time_payee)),
            float(velocity),
            float(clean_streak_days),
            float(int(transaction_type_upper in {"TRANSFER", "CASH_OUT"})),
            float(source_balance_paise or 0),
            float(destination_balance_paise or 0),
            float(drain_ratio),
        ]
        model_prediction = model_registry.transaction_score(feature_values, heuristic_score)
        score = model_prediction.score
        factors = [{"signal": signal, "impact": impact, "summary": summary} for signal, impact, summary in parts]
        if model_prediction.model_used:
            factors.append({"signal": "model:transaction", "impact": max(1, score // 4), "summary": "Transaction baseline model scored this payment from trained artifacts"})
            if score >= 350 and "Transaction model consensus risk" not in reasons:
                reasons.append("Transaction model consensus risk")
        return {"score": score, "reasons": reasons or ["No major transaction anomalies"], "factors": factors}

    async def _remark_score(self, upi_remark: str, payee_vpa: str, amount_paise: int, first_time_payee: bool) -> dict:
        text = f"{upi_remark} {payee_vpa}".lower()
        parts = []
        reasons = []
        for term, impact in SOCIAL_ENGINEERING_TERMS.items():
            if term in text:
                parts.append((f"remark:{term}", impact, f"Remark contains scam-linked phrase '{term}'"))
        if first_time_payee and amount_paise >= 50_000 and parts:
            parts.append(("pressure_payment_combo", 360, "Suspicious language plus a first-time payee increases risk"))
            reasons.append("Suspicious language to a new payee")
        if parts:
            reasons.append("Remark resembles social-engineering language")
        heuristic_score = clamp(sum(impact for _, impact, _ in parts))
        model_prediction = model_registry.remark_score(text, heuristic_score)
        score = model_prediction.score
        factors = [{"signal": signal, "impact": impact, "summary": summary} for signal, impact, summary in parts]
        if model_prediction.model_used:
            factors.append({"signal": "model:remark", "impact": max(1, score // 4), "summary": "Remark classifier model scored this payment context from trained artifacts"})
            if score >= 350 and "Remark classifier consensus risk" not in reasons:
                reasons.append("Remark classifier consensus risk")
        return {"score": score, "reasons": reasons or ["Remark is low risk"], "factors": factors}

    def _phishing_score(self, req: PhishingScoreRequest) -> tuple[int, list[str], list[dict]]:
        feature_values = [float(getattr(req, name)) for name in PHISHING_FEATURE_FIELDS]
        activated_flags = sum(1 for value in feature_values if value != 0)
        heuristic_score = clamp(activated_flags * 18)
        model_prediction = model_registry.phishing_feature_score(feature_values, heuristic_score)
        score = model_prediction.score

        factors = [
            {
                "signal": "url:feature_vector",
                "impact": max(60, min(420, activated_flags * 14)),
                "summary": "URL and page-structure indicators were evaluated against the phishing feature model",
            }
        ]
        if req.url:
            factors.append({
                "signal": "url:submitted",
                "impact": 40,
                "summary": f"Submitted URL: {req.url[:120]}",
            })
        if model_prediction.model_used:
            factors.append({
                "signal": "model:phishing_feature",
                "impact": max(1, score // 4),
                "summary": "Phishing feature classifier scored the submitted webpage feature vector",
            })

        if score >= 700:
            reasons = ["Phishing feature model indicates a high-risk webpage", "URL feature vector matches known phishing patterns"]
        elif score >= 350:
            reasons = ["URL feature vector appears suspicious", "Feature model recommends additional challenge or review"]
        else:
            reasons = ["URL feature vector is low risk"]
        return score, reasons, factors

    def _identity_score(self, req: OnboardRequest, links: dict[str, int]) -> tuple[int, list[str], list[dict]]:
        parts = []
        reasons = []
        if links["device_users"] >= 1:
            impact = 320 + min(260, links["device_users"] * 70)
            parts.append(("shared_device", impact, "Device is already linked to another identity"))
            reasons.append("Device shared across identities")
        if links["phone_users"] >= 1:
            parts.append(("shared_phone", 300, "Phone hash already appears in another onboarding"))
            reasons.append("Phone hash reused")
        if links["pan_users"] >= 1:
            parts.append(("pan_reuse", 350, "PAN hash reuse suggests synthetic identity activity"))
            reasons.append("PAN hash reused")
        if req.selfie_check_score >= 0.7:
            parts.append(("selfie_deepfake_risk", 300, "Selfie integrity check indicates manipulation risk"))
            reasons.append("Selfie integrity risk")
        if req.kyc_name_match_score <= 0.6:
            parts.append(("kyc_mismatch", 220, "KYC attributes do not align strongly"))
            reasons.append("KYC consistency issue")
        if req.device.is_rooted:
            parts.append(("rooted_device", 120, "Rooted device increases onboarding risk"))
            reasons.append("Rooted device")
        if req.device.sim_count >= 3:
            parts.append(("multi_sim_device", 90, "High SIM count can indicate shared mule infrastructure"))
            reasons.append("Unusual SIM profile")
        if links["device_users"] + links["phone_users"] + links["pan_users"] >= 3:
            parts.append(("identity_cluster", 210, "Multiple graph links indicate clustered identity reuse"))
            reasons.append("Clustered identity graph exposure")

        heuristic_score = clamp(sum(impact for _, impact, _ in parts))
        feature_values = [
            float(links["device_users"]),
            float(links["phone_users"]),
            float(links["pan_users"]),
            float(req.selfie_check_score),
            float(1.0 - req.kyc_name_match_score),
            float(int(req.device.is_rooted or req.device.sim_count >= 3)),
        ]
        model_prediction = model_registry.identity_score(feature_values, heuristic_score)
        score = model_prediction.score
        factors = [{"signal": signal, "impact": impact, "summary": summary} for signal, impact, summary in parts]
        if model_prediction.model_used:
            factors.append({"signal": "model:identity", "impact": max(1, score // 4), "summary": "Identity baseline model scored this onboarding from trained artifacts"})
            if score >= 350 and "Identity model consensus risk" not in reasons:
                reasons.append("Identity model consensus risk")
        return score, reasons or ["No major onboarding anomalies"], factors

    def _action_for_score(self, score: int) -> str:
        if score <= 300:
            return "ALLOW"
        if score <= 700:
            return "CHALLENGE"
        return "BLOCK"

    def _parse_dt(self, value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.fromisoformat(value)


engine = FraudEngine()
