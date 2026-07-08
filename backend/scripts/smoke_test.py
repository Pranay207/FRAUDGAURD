from __future__ import annotations

import sys
from pprint import pprint

import httpx

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
API_KEY = sys.argv[2] if len(sys.argv) > 2 else "test_key"
HEADERS = {"Authorization": f"Bearer {API_KEY}"}


def ensure(response: httpx.Response, label: str) -> dict | str:
    if response.status_code >= 400:
        raise SystemExit(f"{label} failed: {response.status_code}\n{response.text}")
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        return response.json()
    return response.text


def main() -> None:
    with httpx.Client(base_url=BASE_URL, timeout=20.0) as client:
        health = ensure(client.get("/health"), "health")
        dashboard = ensure(client.get("/dashboard"), "dashboard")
        tenant = ensure(client.get("/v1/tenant", headers=HEADERS), "tenant")
        seed = ensure(client.post("/v1/dev/seed", headers=HEADERS), "seed")
        summary = ensure(client.get("/v1/ops/summary", headers=HEADERS), "summary")
        datasets = ensure(client.get("/v1/ops/datasets", headers=HEADERS), "datasets")
        cases = ensure(client.get("/v1/ops/cases", headers=HEADERS), "cases")

        print("Smoke test passed")
        print(f"Base URL: {BASE_URL}")
        print(f"Dashboard loaded: {'FraudGuard Console' in dashboard}")
        print(f"Tenant: {tenant['tenant_id']} ({tenant['name']})")
        print(f"Seeded cases: {seed['generated_cases']}")
        print(f"Recent cases: {len(cases['items'])}")
        print(f"Metrics: {len(summary['metrics'])}")
        print("Datasets:")
        pprint([{item['dataset_name']: item['present']} for item in datasets])

        if cases["items"]:
            first_case_id = cases["items"][0]["request_id"]
            detail = ensure(client.get(f"/v1/ops/cases/{first_case_id}", headers=HEADERS), "case detail")
            print(f"First case route: {detail['route']}")
            print(f"First case action: {detail['action']}")


if __name__ == "__main__":
    main()
