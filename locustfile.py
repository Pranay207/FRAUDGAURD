from locust import HttpUser, between, task


class FraudGuardUser(HttpUser):
    wait_time = between(0.1, 0.5)

    @task
    def score_transaction(self) -> None:
        self.client.post(
            "/v1/score/transaction",
            json={
                "user_id": "load-test-user",
                "amount_paise": 85000,
                "payee_vpa": "merchant@upi",
                "upi_remark": "rent payment",
                "session_id": "sess-load",
                "device_id": "device-load",
                "ip_country": "IN",
            },
            headers={"Authorization": "Bearer test_key"},
        )
