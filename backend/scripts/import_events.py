from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
API_KEY = sys.argv[2] if len(sys.argv) > 2 else "test_key"
ROUTE = sys.argv[3] if len(sys.argv) > 3 else "transaction"
INPUT_FILE = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("sample_events.json")

ROUTE_TO_ENDPOINT = {
    "session": "/v1/ingest/session",
    "onboard": "/v1/ingest/onboard",
    "transaction": "/v1/ingest/transaction",
    "phishing": "/v1/ingest/phishing",
}


def load_events(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "events" in payload:
        events = payload["events"]
    elif isinstance(payload, list):
        events = payload
    else:
        raise SystemExit("Input file must be a JSON array or an object with an 'events' field.")
    if not isinstance(events, list) or not events:
        raise SystemExit("Input file must contain at least one event.")
    return events


def main() -> None:
    if ROUTE not in ROUTE_TO_ENDPOINT:
        raise SystemExit(f"Unsupported route '{ROUTE}'. Use one of: {', '.join(sorted(ROUTE_TO_ENDPOINT))}")
    if not INPUT_FILE.exists():
        raise SystemExit(f"Input file not found: {INPUT_FILE}")

    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    body = {"events": load_events(INPUT_FILE)}

    with httpx.Client(base_url=BASE_URL, timeout=60.0) as client:
        response = client.post(ROUTE_TO_ENDPOINT[ROUTE], headers=headers, json=body)
        if response.status_code >= 400:
            raise SystemExit(f"Import failed: {response.status_code}\n{response.text}")
        payload = response.json()

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
