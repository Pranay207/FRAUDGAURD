# FraudGuard

FraudGuard is a real-time fraud detection and investigation platform for digital financial products. It helps teams score risky activity across onboarding, sessions, payments, phishing signals, and linked entity graphs, then review those events in an analyst console with stored case workflow and model evaluation outputs.

## Problem

Modern fraud operations move faster than static rules. Fintech apps, lenders, wallets, and digital platforms face a mix of:

- synthetic identity abuse during onboarding
- account takeover during login and session activity
- high-risk or scam-linked payment behavior
- phishing and social-engineering attempts
- shared-device, shared-phone, and shared-identifier fraud rings

FraudGuard is built to detect those patterns in real time, explain why something looks risky, and give operators a single place to investigate and act.

## What FraudGuard Does

- scores onboarding, session, transaction, and phishing events
- explains fraud decisions with factor-level reasoning
- tracks linked graph exposure across users, devices, payees, phone hashes, and PAN hashes
- stores cases, feedback, assignees, and status changes
- registers and dispatches fraud webhooks
- trains baseline ML models from local datasets
- exports consolidated model evaluation metrics into a single project file

## Core Capabilities

### Scoring APIs

- `POST /v1/score/onboard`
- `POST /v1/score/session`
- `POST /v1/score/transaction`
- `POST /v1/score/phishing`
- `GET /v1/explain/{request_id}`

### Operations APIs

- `GET /v1/tenant`
- `GET /v1/ops/summary`
- `GET /v1/ops/cases`
- `GET /v1/ops/cases/{request_id}`
- `PATCH /v1/ops/cases/{request_id}/status`
- `POST /v1/ops/cases/{request_id}/feedback`
- `GET /v1/ops/datasets`
- `GET /v1/ops/graph/{entity_type}/{entity_id}`
- `GET /v1/ops/api-keys`
- `POST /v1/ops/api-keys`
- `GET /v1/ops/webhooks`
- `POST /v1/ops/webhooks`
- `GET /v1/ops/webhook-deliveries`
- `POST /v1/ops/webhook-deliveries/dispatch`
- `GET /v1/ops/models`
- `POST /v1/dev/train-models`
- `POST /v1/dev/seed`

## Project Structure

```text
FraudGaurd/
+-- backend/
¦   +-- app/                  # FastAPI app, scoring engine, services, frontend
¦   +-- data/                 # Raw datasets, trained artifacts, generated metrics
¦   +-- migrations/           # SQL migrations
¦   +-- scripts/              # Utility scripts for training, smoke tests, export
¦   +-- tests/                # API, graph, and training tests
+-- infra/                    # SQL/bootstrap artifacts
+-- sdk/                      # Minimal JS SDK
+-- MODEL_EVALUATION_SUMMARY.json
+-- README.md
```

## Dashboard

FraudGuard includes a browser-based analyst console at:

- `http://127.0.0.1:8000/dashboard`

The dashboard includes:

- recent fraud cases
- signal heatmap
- dataset inventory
- phishing quick screen
- case detail, feedback, and assignment flow
- graph lookup for users, devices, payees, phone hashes, and PAN hashes

## Model Evaluation Output

The consolidated model evaluation file is stored at:

- [MODEL_EVALUATION_SUMMARY.json](/C:/Users/Shiva/Downloads/FraudGaurd/MODEL_EVALUATION_SUMMARY.json)

This file contains, for every trained model:

- `version_id`
- `artifact_path`
- `auc`
- `precision`
- `recall`
- `f1`
- `accuracy`
- `true_negatives`
- `false_positives`
- `false_negatives`
- `true_positives`
- `negative_support`
- `positive_support`
- `total_test_samples`

## Local Setup

### 1. Create the environment

```powershell
cd C:\Users\Shiva\Downloads\FraudGaurd\backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .[dev]
```

### 2. Start the API

```powershell
cd C:\Users\Shiva\Downloads\FraudGaurd\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

### 3. Open the app

- API docs: `http://127.0.0.1:8000/docs`
- Dashboard: `http://127.0.0.1:8000/dashboard`

Default API key:

- `test_key`

## Verification

### Run tests

```powershell
cd C:\Users\Shiva\Downloads\FraudGaurd\backend
.\.venv\Scripts\python.exe -m pytest
```

### Run live smoke test

```powershell
cd C:\Users\Shiva\Downloads\FraudGaurd\backend
.\.venv\Scripts\python.exe scripts\smoke_test.py
```

## Training and Metrics Export

### Train baseline models

```powershell
cd C:\Users\Shiva\Downloads\FraudGaurd\backend
.\.venv\Scripts\python.exe scripts\train_baseline_models.py
```

### Export the consolidated metrics file

```powershell
cd C:\Users\Shiva\Downloads\FraudGaurd\backend
.\.venv\Scripts\python.exe scripts\export_model_metrics.py
```

This refreshes:

- [MODEL_EVALUATION_SUMMARY.json](/C:/Users/Shiva/Downloads/FraudGaurd/MODEL_EVALUATION_SUMMARY.json)

## Data Sources Used in This Build

The current local build is wired around datasets placed under `backend/data/raw/`, including support for:

- credit card fraud CSV data
- phishing website feature data in ARFF format
- SMS spam / scam text data
- PaySim transaction fraud data
- AMLSim and Elliptic graph datasets for future graph expansion

## Current State

FraudGuard is a strong local MVP and engineering foundation. It is functional end-to-end for development, demos, and experimentation, but it is not yet a bank-grade production deployment.

## Recommended Next Steps

- add dashboard-native model evaluation views
- add stronger onboarding, transaction, and session input forms
- add retry and dead-letter handling for webhook delivery
- add RBAC and analyst authentication
- add production deployment, observability, and secret management
- expand training and evaluation with larger labeled datasets and reporting
