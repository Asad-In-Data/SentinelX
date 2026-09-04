# SentinelX
**Intelligent AI DevOps & Network Defense Platform**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-red.svg)](https://pytorch.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-green.svg)](https://streamlit.io/)

⚠️ License & Usage

© 2026 Asad Ali — All Rights Reserved

This repository is publicly available for viewing and portfolio purposes.

The source code, architecture, documentation, and original implementations are the intellectual property of the author.

No permission is granted to copy, modify, redistribute, reproduce, or use this project or its source code for personal, academic, commercial, or derivative projects without explicit written permission from the author.

Tech stack

- Language: Python
- Backend: FastAPI
- Frontend: Streamlit / React
- Database: PostgreSQL
- Distributed: Spark
- Cloud: AWS
- Container: Docker

Ek aisa system banana jo:
1. Live network traffic monitor kare
2. AI se attack detect kare
3. Distributed system pe process kare
4. Cloud pe deploy ho
5.Apni mini programming language support kare
6. Proper QA lifecycle follow kare
7. Production-level documentation ho

Aur ye sab ek integrated ecosystem ho.

## Documentation Hub

- Complete Project Documentation: [docs/COMPLETE_DOCUMENTATION.md](docs/COMPLETE_DOCUMENTATION.md)
- Software Requirements (SRS): [docs/SRS.md](docs/SRS.md)
- Test Plan: [docs/TEST_PLAN.md](docs/TEST_PLAN.md)
- Database ERD: [docs/DB_ERD.md](docs/DB_ERD.md)
- UI Wireframes: [docs/UI_WIREFRAMES.md](docs/UI_WIREFRAMES.md)
- Project Proposal: [docs/PROJECT_PROPOSAL.md](docs/PROJECT_PROPOSAL.md)
- DSL Guide: [Backend/compiler/DSL_GUIDE.md](Backend/compiler/DSL_GUIDE.md)

```
[Network Traffic]
        ↓
[Packet Sniffer Module]
        ↓
[Log Storage]
        ↓
[Distributed Processing Engine]
        ↓
[ML Anomaly Detection]
        ↓
[API Layer]
        ↓
[Web Dashboard + Custom Query Language]
        ↓
[Cloud Deployment + Monitoring]

```

💣 Real Impact Areas
Machine Learning:
AI-based intrusion detection (real dataset + live data)

**Networks:**
Real packet capturing & protocol analysis

**Distributed:**
Parallel vs sequential benchmark graphs

**Cloud:**
AWS deployment + Docker + CI/CD

**SQA:**
Industry-grade SRS + testing automation

Compiler:
Mini DSL (Domain Specific Language)

Part 1: Architecture

Part 2: ML System

Part 3: Distributed Benchmark

Part 4: Cloud Deployment

Part 5: Custom Language

Final: Full Demo Video

## Run the Live Stack

Backend API:

```bash
cd Backend/api
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Streamlit dashboard:

```bash
streamlit run Frontend/app.py
```

Useful endpoints:

- `GET /health`
- `GET /predict`
- `POST /predict`
- `GET /traffic_stats`
- `GET /recent_predictions`

The API starts the live packet capture in the background when it can access the network interface. If packet sniffing is blocked on your machine, the API still starts and the dashboard will show the backend status.

## Database Migrations (Alembic)

Default database URL is SQLite:

```bash
sqlite:///./sentinelx.db
```

Set custom DB URL (example PostgreSQL):

```bash
export DATABASE_URL="postgresql+psycopg2://USER:PASSWORD@HOST:5432/sentinelx"
```

On Windows PowerShell:

```powershell
$env:DATABASE_URL = "postgresql+psycopg2://USER:PASSWORD@HOST:5432/sentinelx"
```

Run migrations:

```bash
alembic -c alembic.ini upgrade head
```

Create a new migration from model changes (autogenerate):

```bash
alembic -c alembic.ini revision --autogenerate -m "describe change"
```

Check if there are pending schema diffs:

```bash
alembic -c alembic.ini check
```

Simple DB admin CLI:

```bash
python Backend/db/cli.py init-db
python Backend/db/cli.py migrate
python Backend/db/cli.py list-predictions --limit 20
python Backend/db/cli.py show-stats --limit 10
```

## Mini DSL

The DSL reads from the database first and falls back to the API when needed.

Examples:

```bash
python Backend/compiler/cli.py "show threats limit 10"
python Backend/compiler/cli.py "show traffic limit 5"
python Backend/compiler/cli.py "show stats"
python Backend/compiler/cli.py "show latest"
```

Dashboard support:

- Open the Streamlit dashboard and use the `Mini DSL` section.

Guide:

- [Backend/compiler/DSL_GUIDE.md](Backend/compiler/DSL_GUIDE.md)

## CLI-First DSL Mode

If you want to use the DSL without the web dashboard, run:

```bash
python Backend/compiler/cli.py
```

Useful commands:

```bash
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
