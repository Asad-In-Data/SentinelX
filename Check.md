🛡️ SentinelX
Intelligent AI-Powered Network Defense Platform

SentinelX is an AI-powered network security project designed to monitor network traffic, analyze suspicious activity, detect potential threats using machine learning, and present security insights through an interactive dashboard.

The project combines network monitoring, machine learning, backend APIs, distributed processing, database management, DevOps practices, and a custom Domain-Specific Language (DSL) into a single integrated system.

🎓 Academic Project: Developed as a 6th-semester university project to explore the integration of AI, cybersecurity, networking, distributed systems, and software engineering.

✨ Features
🔍 Network Traffic Monitoring — Capture and analyze network traffic and protocols.
🤖 ML-Based Threat Detection — Identify suspicious or anomalous network activity.
📊 Interactive Dashboard — Visualize traffic statistics, predictions, and security information.
⚡ FastAPI Backend — REST API for predictions, traffic statistics, and system health.
🗄️ Database Integration — Store network traffic and prediction results.
🧩 Custom DSL — Query SentinelX data using a small domain-specific language.
🚀 Distributed Processing — Support for experimenting with parallel and distributed processing.
🐳 Docker Support — Containerized deployment workflow.
☁️ Cloud Ready — Designed with AWS deployment in mind.
🧪 Testing & QA — Includes automated tests and project-level testing documentation.
📚 Project Documentation — SRS, architecture, ERD, test plan, wireframes, and DSL documentation.
🏗️ System Architecture
┌──────────────────────┐
│   Network Traffic    │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│   Packet Sniffer     │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│    Data Storage      │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Distributed / Data   │
│     Processing       │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ ML Threat Detection  │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│    FastAPI Backend   │
└──────────┬───────────┘
           ↓
      ┌────┴─────┐
      ↓          ↓
┌──────────┐ ┌──────────────┐
│Dashboard │ │  SentinelX   │
│          │ │     DSL      │
└──────────┘ └──────────────┘


🧰 Tech Stack
Area	Technology
Programming Language	Python
Backend	FastAPI
Frontend / Dashboard	Streamlit / React
Database	SQLite / PostgreSQL
Database Migrations	Alembic
Distributed Processing	Apache Spark
Containerization	Docker
Cloud	AWS
Testing	Pytest
CI/CD	GitHub Actions
Machine Learning	Python ML ecosystem



📂 Project Structure
SentinelX/
│
├── Backend/
│   ├── api/              # FastAPI backend
│   ├── compiler/         # SentinelX DSL
│   └── db/               # Database layer and CLI
│
├── Frontend/
│   └── app.py            # Streamlit dashboard
│
├── docs/
│   ├── COMPLETE_DOCUMENTATION.md
│   ├── SRS.md
│   ├── TEST_PLAN.md
│   ├── DB_ERD.md
│   ├── UI_WIREFRAMES.md
│   └── PROJECT_PROPOSAL.md
│
├── test/                 # Automated tests
│
├── Architecture.png      # System architecture
├── ERD.PNG               # Database ERD
├── network_traffic.csv   # Network traffic dataset
├── requirements.txt      # Python dependencies
├── alembic.ini           # Alembic configuration
└── README.md

🚀 Getting Started
1. Clone the Repository
git clone https://github.com/Asad-In-Data/SentinelX.git
cd SentinelX

2. Create a Virtual Environment
python -m venv venv


Activate it:

Windows

venv\Scripts\activate


Linux / macOS

source venv/bin/activate

3. Install Dependencies
pip install -r requirements.txt

▶️ Running SentinelX
Start the FastAPI Backend
cd Backend/api
uvicorn main:app --reload --host 127.0.0.1 --port 8000


The API will be available at:

http://127.0.0.1:8000

Start the Streamlit Dashboard

From the project root:

streamlit run Frontend/app.py

🔌 API Endpoints

Some of the available API endpoints include:

Endpoint	Method	Purpose
/health	GET	Check backend health
/predict	GET	Get prediction information
/predict	POST	Submit data for prediction
/traffic_stats	GET	Retrieve traffic statistics
/recent_predictions	GET	Retrieve recent predictions

Packet capture is started in the background when the environment allows access to the required network interface.

🗄️ Database

SentinelX uses SQLite by default:

sqlite:///./sentinelx.db


PostgreSQL can also be configured using the DATABASE_URL environment variable.

Example
export DATABASE_URL="postgresql+psycopg2://USER:PASSWORD@HOST:5432/sentinelx"


Windows PowerShell:

$env:DATABASE_URL = "postgresql+psycopg2://USER:PASSWORD@HOST:5432/sentinelx"

Run migrations
alembic -c alembic.ini upgrade head

Check migration status
alembic -c alembic.ini check

🧩 SentinelX DSL

One of the distinctive components of SentinelX is its custom Domain-Specific Language (DSL).

The DSL provides a simple command-based interface for querying network and threat information.

Example
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

Run the DSL
python Backend/compiler/cli.py


Or execute a command directly:

python Backend/compiler/cli.py "show threats limit 10"


Additional examples:

python Backend/compiler/cli.py "show traffic limit 5"
python Backend/compiler/cli.py "show stats"
python Backend/compiler/cli.py "show latest"


📖 Detailed DSL documentation:

Backend/compiler/DSL_GUIDE.md

📊 Database & Data Management

SentinelX includes a small database administration CLI.

python Backend/db/cli.py init-db
python Backend/db/cli.py migrate
python Backend/db/cli.py list-predictions --limit 20
python Backend/db/cli.py show-stats --limit 10

🧪 Testing

The project includes automated tests and a dedicated testing plan.

Test files are located in:

test/


Project testing documentation:

docs/TEST_PLAN.md

📚 Documentation

Detailed project documentation is available in the docs/ directory.

📘 Complete Documentation
📋 Software Requirements Specification
🧪 Test Plan
🗄️ Database ERD
🎨 UI Wireframes
📝 Project Proposal
🧩 DSL Guide
🖼️ Project Resources
Architecture

Database ERD

Add dashboard screenshots or a short demo GIF here as the project UI evolves.

🎯 Project Goals

SentinelX was developed to explore how multiple areas of computer science can work together in a single security-oriented system:

Artificial Intelligence & Machine Learning
Computer Networks
Cybersecurity
Distributed Systems
Backend Development
Database Engineering
Compiler / DSL Design
Software Quality Assurance
DevOps & Cloud Computing

The main goal was not just to build an ML model, but to understand how a complete system can connect data collection → processing → detection → API → visualization → querying.

🔮 Future Improvements

Potential future improvements include:

More advanced ML models and anomaly-detection techniques
Improved real-time threat alerting
More network protocols and traffic features
Enhanced dashboard visualizations
More expressive DSL commands
Improved distributed-processing scalability
Production-grade cloud deployment
Authentication and role-based access control
More comprehensive automated testing
👨‍💻 Author

Asad Ali

GitHub: @Asad-In-Data

📄 License

© 2026 Asad Ali. All Rights Reserved.

This repository is publicly available for viewing and portfolio purposes. The source code, architecture, documentation, and original implementations are the intellectual property of the author.

Unauthorized copying, modification, redistribution, reproduction, or use of this project or its source code is not permitted without explicit written permission from the author.
