# SentinelX Complete Documentation

## 1) Overview
SentinelX is an AI-powered network defense platform that combines:
- live packet monitoring,
- ML-based threat detection,
- API + dashboard observability,
- persistent storage,
- and a mini DSL for operational queries.

This document is the single onboarding and operations reference for running and maintaining the project like a production-style software system.

---

## 2) Core Capabilities
- Real-time packet capture (with graceful fallback when sniffing is unavailable).
- Feature extraction and ML inference for `NORMAL` / `ATTACK` style outcomes.
- Risk/confidence post-processing and validation checks.
- REST APIs for health, predictions, and traffic metrics.
- Streamlit dashboard for live visibility.
- DSL query interface for security-oriented data retrieval.
- SQLAlchemy + Alembic persistence and migration workflow.

---

## 3) Tech Stack
- **Language:** Python 3.8+
- **Backend:** FastAPI + Uvicorn
- **Frontend:** Streamlit (with React path noted in project scope)
- **ML:** scikit-learn, XGBoost, NumPy, Pandas, joblib
- **Network Capture:** Scapy
- **Database:** SQLite (default) or PostgreSQL
- **ORM & Migrations:** SQLAlchemy + Alembic

---

## 4) Repository Structure
```text
Backend/
  api/        FastAPI app and traffic analysis service
  compiler/   DSL lexer/parser/executor + CLI
  db/         SQLAlchemy models, DB session, admin CLI, Alembic migrations
  ML/         Feature aggregation/validation utilities and model artifacts usage
  network/    Dashboard/data integration layer
Frontend/
  app.py      Streamlit app entrypoint
docs/
  SRS.md, TEST_PLAN.md, DB_ERD.md, UI_WIREFRAMES.md, PROJECT_PROPOSAL.md
  COMPLETE_DOCUMENTATION.md (this file)
test/
  test_api.py API tests
```

---

## 5) Environment Setup
### 5.1 Prerequisites
- Python 3.8+
- `pip`
- Optional: elevated privileges for live packet capture (OS dependent)

### 5.2 Install Dependencies
```bash
pip install -r requirements.txt
```

### 5.3 Optional Test Dependency
```bash
pip install pytest
```

---

## 6) Configuration
### 6.1 Database URL
Default:
```bash
sqlite:///./sentinelx.db
```

Override example (PostgreSQL):
```bash
export DATABASE_URL="postgresql+psycopg2://<user>:<password>@<host>:5432/sentinelx"
```

PowerShell:
```powershell
$env:DATABASE_URL = "postgresql+psycopg2://<user>:<password>@<host>:5432/sentinelx"
```

### 6.2 API Base for DSL Fallback
If DB reads are unavailable, DSL falls back to API base:
- default: `http://127.0.0.1:8000`
- override via CLI: `--api-base`

---

## 7) Runbook (Local Development)
### 7.1 Start Backend API
```bash
cd Backend/api
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### 7.2 Start Streamlit Dashboard
```bash
streamlit run Frontend/app.py
```

### 7.3 Use DSL (one-shot)
```bash
python Backend/compiler/cli.py "show threats limit 10"
```

### 7.4 Use DSL (interactive REPL)
```bash
python Backend/compiler/cli.py
```

---

## 8) API Reference
Base URL (local): `http://127.0.0.1:8000`

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Service metadata and endpoint list |
| GET | `/health` | Health + capture status |
| GET | `/predict` | Latest live prediction |
| POST | `/predict` | Predict from feature payload or latest fallback |
| GET | `/traffic_stats` | Aggregated traffic + recent predictions |
| GET | `/recent_predictions?limit=20` | Recent prediction list |
| POST | `/capture/start` | Start packet capture thread |
| POST | `/capture/stop` | Stop packet capture and return session stats |

### Error Handling Highlights
- `GET /predict` returns **404** when no prediction exists yet.
- `POST /predict` returns **400** when feature payload validation fails.
- Startup is resilient: API can still boot if live capture permissions are unavailable.

---

## 9) Data Layer
### 9.1 Main Tables
- `predictions`
  - source/destination IP, protocol/service, label, probabilities, confidence, severity, packet summary
- `traffic_stats`
  - total predictions, attacks, normal, uncertain, uptime snapshots

### 9.2 Migration Commands
```bash
alembic -c alembic.ini upgrade head
alembic -c alembic.ini revision --autogenerate -m "describe change"
alembic -c alembic.ini check
```

### 9.3 DB Admin CLI
```bash
python Backend/db/cli.py init-db
python Backend/db/cli.py migrate
python Backend/db/cli.py list-predictions --limit 20
python Backend/db/cli.py show-stats --limit 10
```

---

## 10) DSL Layer
Supported examples:
```text
SHOW_THREATS
SHOW_TRAFFIC
SHOW_IPS
SHOW_PROTOCOLS
COUNT_PACKETS
COUNT_THREATS
COUNT_IPS
SHOW_HIGH_RISK
SHOW_MEDIUM_RISK
SHOW_LOW_RISK
SHOW_TCP
SHOW_UDP
SHOW_ICMP
LATEST_THREATS
LATEST_PACKETS
TOP_ATTACKERS
HELP
VERSION
STATUS
```

Also supports natural-style forms from the guide, e.g.:
- `SHOW THREATS LIMIT 10`
- `SHOW TRAFFIC LIMIT 5`
- `SHOW STATS`

Reference: `Backend/compiler/DSL_GUIDE.md`

---

## 11) Testing and Quality
### 11.1 Current Test Entry
```bash
python -m pytest -q
```

### 11.2 CI Migration Guard
GitHub Actions workflow `.github/workflows/db-migrations.yml` validates:
1. `alembic -c alembic.ini upgrade head`
2. `alembic -c alembic.ini check`

with SQLite DB URL in CI.

---

## 12) Operational Notes
- Live packet sniffing may require admin/root privileges.
- If sniffing is blocked, API still runs in degraded mode.
- Prediction persistence runs via background DB worker queue in traffic service.
- Ensure model artifacts exist under ML model directory before inference runtime.

---

## 13) Troubleshooting
### API starts but no live predictions
- Check network capture permissions.
- Call `/health` and inspect `live_capture_enabled` and `last_error`.

### `GET /predict` gives 404
- No packet-derived prediction exists yet; generate traffic or use `POST /predict` payload.

### Migration issues
- Verify `DATABASE_URL` is correct.
- Run `alembic -c alembic.ini upgrade head` before `alembic check`.

### Dashboard cannot reach backend
- Confirm API process is running at expected host/port.
- Verify firewall/port conflicts.

---

## 14) Extended Documentation Map
- Requirements: `docs/SRS.md`
- Test Strategy: `docs/TEST_PLAN.md`
- Database ERD: `docs/DB_ERD.md`
- UI Wireframes: `docs/UI_WIREFRAMES.md`
- Project Proposal: `docs/PROJECT_PROPOSAL.md`
- Learning/Flow guides: `docs/Learning/*`

---

## 15) Contribution Workflow (Recommended)
1. Pull latest code.
2. Create/update feature branch.
3. Implement focused changes.
4. Run tests and migration checks.
5. Update docs if behavior/config/interfaces changed.
6. Open PR with clear summary and validation output.

---

## 16) License
MIT (see `LICENSE`).
