# TrustShield

TrustShield is an explainable, multi-stage message threat detection prototype.

## Current structure

```text
trustshield/
  gateway/                 # validate/encode destinations; never direct-redirects
  api/                     # FastAPI URL scan endpoint and evidence retrieval
frontend/                  # React/Vite secure scan page
  models/schemas.py       # Indicator, AnalysisContext, stage/result contracts
  stages/                 # ingestion, preprocessing, and text analysis
  reasoners/              # OpenRouter interface and validated fallback
  storage/                # SQLAlchemy SQLite result store
  engine/                 # pipeline orchestration, ML baseline, risk fusion
  cli.py                  # local demo command
tests/                    # Phase 1 tests
```

Every stage receives an `AnalysisContext` and returns a typed `StageResult`.
Indicators have stable IDs so explanations can cite their supporting evidence.
The current prototype includes a generated-in-code synthetic
TF-IDF/logistic-regression baseline, consent gate, PII masking, URL safety
checks, static-only file checks, sender trust context, and SQLite persistence.
The OpenRouter reasoner is real when `OPENROUTER_API_KEY` is configured, but is
advisory: rule-based detections cannot be downgraded by it. Requests contain
only masked text and non-sensitive indicator summaries.

## Run

```powershell
python -m pip install -e ".[test]"
python -m pytest
python -m trustshield.cli --consent --text "Urgent: verify your bank password immediately."
```

The API, UI, correlation, audit, feedback, and real sandbox integrations are
planned for later phases. URL reputation is currently local/blocklist-based;
browser inspection, WHOIS, DNS/TLS intelligence, and file behavioral monitoring
are simulated/not yet implemented. The OpenRouter key is read only from
`OPENROUTER_API_KEY`. Use `python scripts/refresh_models.py` to refresh the
free-model list.

## Secure URL gateway

`SecureURLGateway` accepts HTTPS destinations, rejects dangerous protocols,
embedded credentials, private/internal/loopback targets, and malformed URLs,
then returns an encoded `/scan?url=...` route. It never performs a network
request or direct redirect. The destination must be analyzed before a later
component permits navigation.

## URL API

Run the API with:

```powershell
uvicorn trustshield.api.app:app --reload
```

`POST /api/analyze/url` validates a destination, performs offline URL analysis,
stores the scan in SQLite, and returns a scan ID plus evidence. `GET
/api/scan/{scan_id}` retrieves the result and `GET
/api/scan/{scan_id}/evidence` returns the explainable evidence view. These
endpoints never fetch or redirect to the submitted destination.

## Secure scan page

Run the backend and frontend separately:

```powershell
uvicorn trustshield.api.app:app --reload
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173/scan?url=https%3A%2F%2Fexample.com`.
The page submits the URL to TrustShield first and only exposes a continue
action after a completed result. Critical findings have no continue button.
