# Software Requirements Specification (SRS)
## Project: SentinelX

## 1. Introduction

### 1.1 Purpose
This document defines the complete software requirements for SentinelX, an intelligent AI-driven network defense platform. It establishes functional and non-functional requirements, interfaces, constraints, and acceptance criteria to guide development, testing, deployment, and maintenance.

### 1.2 Scope
SentinelX provides real-time network traffic monitoring, ML-based intrusion detection, API access, dashboard visualization, and DSL-based querying. The system is intended for operational monitoring, threat detection, analytics, and educational/research use.

### 1.3 Definitions and Acronyms
- **SRS:** Software Requirements Specification
- **ML:** Machine Learning
- **API:** Application Programming Interface
- **DSL:** Domain-Specific Language
- **SOC:** Security Operations Center
- **NFR:** Non-Functional Requirement

### 1.4 References
- Repository README
- DSL Guide
- Internal architecture and learning flow documentation under `docs/Learning`

## 2. Overall Description

### 2.1 Product Perspective
SentinelX is a modular platform composed of:
- packet capture and feature extraction,
- ML inference and validation,
- persistent data storage,
- FastAPI backend,
- Streamlit/React frontend,
- and DSL query interface.

### 2.2 Product Functions
- Capture network packets from available interfaces.
- Transform traffic into model-ready features.
- Predict threat class/confidence using trained ML models.
- Expose prediction and statistics through REST APIs.
- Display live and historical insights in dashboard views.
- Execute DSL commands for threat/traffic/stats retrieval.

### 2.3 User Classes
1. **Security Analyst:** monitors threats and reviews predictions.
2. **Administrator/DevOps Engineer:** deploys and maintains services.
3. **Research/Student User:** evaluates model behavior and workflows.

### 2.4 Operating Environment
- Python 3.8+
- Backend via FastAPI/uvicorn
- Frontend via Streamlit (and/or React)
- SQLite or PostgreSQL database
- Linux/macOS/Windows (with interface/permission differences for sniffing)

### 2.5 Constraints
- Live packet capture may require elevated privileges.
- Model quality depends on training data coverage and freshness.
- Performance depends on host resources and traffic volume.
- Some environments may restrict raw socket/network interface access.

### 2.6 Assumptions and Dependencies
- Required Python packages are installed.
- Model artifacts exist and are accessible.
- Database is initialized/migrated.
- Network interface is accessible for live monitoring mode.

## 3. External Interface Requirements

### 3.1 User Interfaces
- Web dashboard shall show system health, recent predictions, and traffic statistics.
- Dashboard shall provide controls for viewing trends and querying DSL commands.

### 3.2 Hardware Interfaces
- Access to network interface card(s) for packet sniffing when enabled.

### 3.3 Software Interfaces
- Database interface via SQLAlchemy-compatible backend.
- API endpoints over HTTP/JSON.
- Model files loaded from local filesystem.

### 3.4 Communication Interfaces
- REST communication over HTTP.
- Optional cloud/container network interfaces for deployment.

## 4. Functional Requirements

### 4.1 System Initialization
- **FR-1:** System shall expose a health endpoint to report service availability.
- **FR-2:** System shall initialize data/storage components on startup.
- **FR-3:** System shall start even if live sniffing is unavailable, with degraded capture mode.

### 4.2 Packet Capture and Feature Processing
- **FR-4:** System shall capture network traffic packets from configured interface(s).
- **FR-5:** System shall aggregate packet data into structured features for inference.
- **FR-6:** System shall validate extracted features before model prediction.

### 4.3 ML Inference and Validation
- **FR-7:** System shall load trained model and preprocessing artifacts.
- **FR-8:** System shall generate predictions for incoming feature windows.
- **FR-9:** System shall compute prediction confidence/probability outputs.
- **FR-10:** System shall support post-processing thresholds for alert quality control.

### 4.4 API Services
- **FR-11:** System shall provide GET and POST prediction endpoints.
- **FR-12:** System shall provide traffic statistics and recent prediction endpoints.
- **FR-13:** API responses shall be JSON formatted with relevant fields and status codes.

### 4.5 Data Persistence
- **FR-14:** System shall store prediction records with timestamp and metadata.
- **FR-15:** System shall support schema migration through Alembic.
- **FR-16:** System shall allow retrieval of historical prediction and statistics data.

### 4.6 Dashboard and Visualization
- **FR-17:** Dashboard shall display backend connectivity/health status.
- **FR-18:** Dashboard shall show recent threats and traffic summaries.
- **FR-19:** Dashboard shall visualize trends (e.g., attacks over time, class distribution).

### 4.7 DSL Query Layer
- **FR-20:** System shall accept supported DSL commands for threat/traffic/stat queries.
- **FR-21:** DSL engine shall prefer DB-backed retrieval and fallback to API when needed.
- **FR-22:** System shall return human-readable results and error messages for invalid queries.

### 4.8 Security and Access
- **FR-23:** System shall validate and sanitize API/DSL inputs.
- **FR-24:** System shall avoid exposing sensitive runtime details in user-facing errors.
- **FR-25:** System shall support secure deployment configuration through environment variables.

### 4.9 Logging and Monitoring
- **FR-26:** System shall log startup, prediction, and failure events.
- **FR-27:** System shall provide enough diagnostics to troubleshoot capture/model/API issues.

## 5. Non-Functional Requirements

### 5.1 Performance
- **NFR-1:** API health responses should be near real-time under normal load.
- **NFR-2:** Prediction endpoints should respond within acceptable operational latency for monitoring workflows.
- **NFR-3:** System should process packet windows continuously without frequent service interruption.

### 5.2 Reliability and Availability
- **NFR-4:** System should remain operational when packet capture is unavailable, with partial functionality.
- **NFR-5:** Service should recover gracefully from transient data/model loading errors where possible.

### 5.3 Scalability
- **NFR-6:** Architecture should support horizontal or distributed processing enhancements.
- **NFR-7:** Database and API layers should support growth in stored prediction volume.

### 5.4 Security
- **NFR-8:** Inputs shall be validated to reduce injection and malformed-request risks.
- **NFR-9:** Secrets/configuration values shall be managed via environment/config files, not hardcoded.

### 5.5 Maintainability
- **NFR-10:** Codebase shall remain modular across capture, ML, API, dashboard, and DSL layers.
- **NFR-11:** Database schema evolution shall be managed through versioned migrations.
- **NFR-12:** Documentation shall be kept synchronized with endpoint and workflow changes.

### 5.6 Portability
- **NFR-13:** Core services shall run in standard Python environments and containerized setups.

## 6. Data Requirements
- Prediction entity shall include at minimum: timestamp, predicted class, confidence/probability, and relevant feature/traffic metadata.
- Traffic statistics entity shall include aggregated packet/flow metrics over defined intervals.
- Historical retention strategy shall support dashboard and DSL query use cases.

## 7. Use Cases

### UC-1: View System Health
- **Actor:** Analyst/Admin
- **Precondition:** Backend running
- **Flow:** User requests health status via API or dashboard.
- **Postcondition:** Current service state is displayed.

### UC-2: Analyze Traffic and Receive Prediction
- **Actor:** Analyst
- **Precondition:** Feature pipeline and model loaded
- **Flow:** Traffic is captured -> features built -> model predicts -> result stored/displayed.
- **Postcondition:** Threat classification and confidence become available.

### UC-3: Query Recent Threats Using DSL
- **Actor:** Analyst/Research User
- **Precondition:** DSL component available
- **Flow:** User submits DSL query -> parser validates -> data fetched -> formatted result returned.
- **Postcondition:** User receives query output for decision-making.

## 8. Acceptance Criteria
1. API endpoints (`/health`, `/predict`, `/traffic_stats`, `/recent_predictions`) are operational and documented.
2. Dashboard displays backend status and recent analytical views.
3. ML inference executes with loaded artifacts and returns predictions.
4. Database records are created and retrievable.
5. DSL commands for key query categories execute successfully.
6. System supports startup in restricted sniffing environments without total failure.

## 9. Verification and Validation Strategy
- Unit-level validation for feature and inference logic where available.
- Integration validation across capture -> inference -> storage -> API -> dashboard.
- Data validation checks for malformed/edge-case feature windows.
- Manual/automated smoke checks for deployment and runtime health.

## 10. Future Enhancements (Non-Blocking)
- Advanced alert correlation and incident scoring.
- Role-based access controls and authentication hardening.
- Extended distributed analytics integration.
- Automated model retraining pipelines and drift monitoring.

---
**Document Version:** 1.0  
**Prepared For:** SentinelX Project  
**Status:** Baseline Complete SRS
