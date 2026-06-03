# SentinelX Test Plan Document

## 1. Testing Scope

### In Scope
- Backend API endpoints (`/health`, `/predict`, `/traffic_stats`, `/recent_predictions`)
- Packet capture and feature extraction workflow
- ML inference pipeline and output validation
- Database persistence and migration integrity
- DSL query parsing and execution paths
- Frontend dashboard integration with backend APIs

### Out of Scope
- Production cloud cost/performance optimization
- Third-party service internal reliability guarantees
- OS-level network permission policy validation beyond application handling

## 2. Testing Types
- **Unit Testing:** Core functions in packet processing, feature validation, model utilities, and DSL parsing.
- **Integration Testing:** Backend ↔ database, backend ↔ ML model artifacts, dashboard ↔ API, DSL ↔ DB/API fallback.
- **API Testing:** Request/response contract checks, status codes, schema validation, error handling.
- **Database Testing:** Migration checks, schema consistency, data insert/retrieval integrity.
- **System Testing:** End-to-end user flows from traffic ingestion to dashboard visibility.
- **Regression Testing:** Critical-path rechecks after fixes/releases to prevent behavior breakage.
- **Non-Functional Testing:** Basic response-time monitoring, reliability checks under normal/edge traffic conditions.

## 3. Test Strategy
1. **Shift-left validation** with unit tests and migration checks before integration runs.
2. **Risk-based prioritization** for high-impact flows:
   - prediction generation,
   - threat visibility,
   - persistence and retrieval,
   - DSL query correctness.
3. **Layered execution order:** Unit → Integration → API/DB checks → End-to-end scenario validation.
4. **Environment approach:**
   - Local dev environment for quick verification.
   - CI environment for repeatable migration and backend safety checks.
5. **Defect lifecycle:**
   - Log issue with scenario, expected vs actual result, and reproducible steps.
   - Re-test fixes and include regression checks for related modules.
6. **Exit criteria:**
   - No critical open defects in in-scope modules.
   - Core scenarios pass.
   - Migration check passes without pending diffs.

## 4. Tools Used
- **Pytest** (recommended): Python unit and integration testing framework.
- **FastAPI TestClient / HTTP clients:** API contract and endpoint validation.
- **Alembic:** Migration upgrade/check validation.
- **SQLite/PostgreSQL:** Database behavior verification.
- **GitHub Actions:** Automated CI checks (DB migration workflow).
- **Manual validation via Streamlit + CLI:** Dashboard and DSL behavior confirmation.

## 5. Test Case Designing

### 5.1 Test Scenarios
1. System health and startup behavior.
2. Prediction API behavior (GET/POST) for valid and invalid inputs.
3. Traffic statistics and recent prediction retrieval.
4. Data persistence after prediction generation.
5. DSL command execution (valid/invalid commands and fallback behavior).
6. Dashboard data loading and failure-state messaging.
7. Migration consistency across schema changes.

### 5.2 Test Cases

| TC ID | Test Scenario | Test Case Description | Precondition | Steps | Expected Result |
|---|---|---|---|---|---|
| TC-01 | Health Check | Validate `/health` returns service status | Backend running | Send GET `/health` | 200 response with healthy status payload |
| TC-02 | Predict GET | Validate GET `/predict` with sample/derived data path | Backend running, model loaded | Send GET `/predict` | 200 response with class/confidence fields |
| TC-03 | Predict POST Valid | Validate POST `/predict` for valid feature payload | Backend running | Send valid JSON payload to POST `/predict` | 200 response with prediction output and valid schema |
| TC-04 | Predict POST Invalid | Validate input validation for malformed payload | Backend running | Send incomplete/invalid JSON to POST `/predict` | 4xx response with clear validation error |
| TC-05 | Traffic Stats | Validate `/traffic_stats` data shape and values | Traffic/prediction data exists | Send GET `/traffic_stats` | 200 response with non-negative counters and expected keys |
| TC-06 | Recent Predictions | Validate `/recent_predictions` returns latest data | DB has records | Send GET `/recent_predictions` | 200 response with ordered recent prediction list |
| TC-07 | Persistence | Validate prediction data is stored correctly | Backend + DB configured | Trigger prediction, then query DB/API history | Stored record contains timestamp, class, confidence |
| TC-08 | DSL Valid Query | Validate supported DSL query returns result | DB/API available | Run `show threats limit 5` via DSL | Human-readable output with requested threat entries |
| TC-09 | DSL Invalid Query | Validate DSL handles unsupported command safely | DSL engine running | Run invalid DSL command | Controlled error message without crash |
| TC-10 | Migration Check | Validate schema is up to date | Alembic configured | Run `alembic upgrade head` then `alembic check` | Upgrade succeeds and check reports no pending diffs |
| TC-11 | Dashboard Connectivity | Validate dashboard shows backend health state | Backend running | Open Streamlit app and load dashboard | Health indicator shows connected/healthy |
| TC-12 | Dashboard Degraded Mode | Validate user feedback when backend unreachable | Backend stopped | Open/refresh dashboard | Clear warning/error state shown without UI crash |

## 6. Traceability (High-Level)
- FR-1, FR-11, FR-13 → TC-01, TC-02, TC-03, TC-04
- FR-12, FR-16 → TC-05, TC-06, TC-07
- FR-20, FR-21, FR-22 → TC-08, TC-09
- FR-15 → TC-10
- FR-17, FR-18, FR-19 → TC-11, TC-12

