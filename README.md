# ThreatPulse 🛡️ — AI-Powered Cyber Defense Platform

<div align="center">

![ThreatPulse Banner](docs/banner.png)

**Enterprise-grade SOC platform — ML threat detection, SOAR automation, MITRE ATT&CK, and real-time attack visualization**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-success?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-blue?style=flat-square&logo=react)](https://react.dev)
[![LightGBM](https://img.shields.io/badge/LightGBM-ML_Engine-orange?style=flat-square)](https://lightgbm.readthedocs.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## 🚀 What Is ThreatPulse?

ThreatPulse is a full-stack, autonomous AI cyber defense platform designed to:

- **Detect** anomalous events in real time using a multi-layer ML pipeline
- **Classify** attack types using LightGBM (98%+ precision) across 5 attack classes
- **Enrich** every event with live AbuseIPDB threat intelligence data
- **Respond** automatically via SOAR actions (block IP, disable account, rate limit)
- **Visualize** attack kill chains as a D3.js force-directed graph
- **Explain** ML decisions using SHAP feature importance
- **Map** every attack to the MITRE ATT&CK framework

It resembles real-world platforms used by **Splunk**, **CrowdStrike**, and **Palo Alto Networks**.

---

## 🏗️ Architecture

```
Real Logs / CSV Upload / Traffic Simulator
              ↓
   Log Ingestion Service (Watchdog)
              ↓
   TF Autoencoder + Rule Engine ←→ LightGBM ML Classifier
              ↓                          ↓
   Risk Scoring Engine          Attack Type Classification
              ↓
   AbuseIPDB Threat Intelligence Lookup
              ↓
   SQLite / PostgreSQL Database
              ↓
   SOAR Auto-Response Engine (risk > 90)
              ↓                    ↓
   FastAPI REST + WebSocket    WhatsApp Alerts (Twilio)
              ↓
   React/Vite 8-Page SOC Dashboard
```

---

## ✨ Key Features

| Feature | Technology | Details |
|---|---|---|
| **ML Detection** | LightGBM + TF Autoencoder | 98.2% precision, 5 attack classes |
| **Threat Intel** | AbuseIPDB API | IP reputation, country, abuse score |
| **SOAR Automation** | Custom engine | IP block, account lock, rate limit, firewall rule |
| **Attack Graph** | NetworkX + D3.js | Kill chain visualization with zoom/pan |
| **MITRE ATT&CK** | Local lookup map | Technique IDs (T1110, T1190…) + tactic mapping |
| **SHAP Explainability** | SHAP TreeExplainer | Feature importance visualization |
| **AI Summaries** | OpenRouter (StepFun Step 3.5 Flash) | SOC-grade incident analysis |
| **Real-Time Feed** | WebSockets | New events pushed live to dashboard |
| **Geo Distribution** | AbuseIPDB + flag emojis | Attack origin country breakdown |
| **CSV Ingestion** | FastAPI + Watchdog | Upload any real security dataset |

---

## � Project Structure

```
ThreatPulse/
├── src/
│   ├── ml_engine.py         ← LightGBM attack classifier
│   ├── threat_intel.py      ← AbuseIPDB lookup + cache
│   ├── response_engine.py   ← SOAR automation (IP block, lock account…)
│   ├── attack_graph.py      ← NetworkX kill chain builder
│   ├── mitre_mapping.py     ← MITRE ATT&CK technique database
│   ├── explainability_shap.py ← SHAP feature importance
│   ├── threat_predictor.py  ← Next-attack scenario prediction
│   └── database.py          ← SQLAlchemy ORM (SQLite/PostgreSQL)
├── api/
│   └── main.py              ← FastAPI backend (20+ endpoints + WebSocket)
├── frontend/
│   └── src/
│       ├── pages/           ← 8 React pages (Dashboard, Incidents, MITRE…)
│       ├── components/      ← LiveFeed, AttackTimeline, Badges, Sidebar…
│       └── api/client.js    ← Axios API client
├── utils/
│   ├── train_ml_engine.py   ← ML training script
│   ├── simulate_live_traffic.py ← Realistic attack traffic generator
│   ├── gemini_client.py     ← OpenRouter AI summaries
│   └── alerting.py          ← Twilio WhatsApp alerts
├── start_enterprise.ps1     ← One-command startup (all 4 services)
└── reset_data.ps1           ← Demo reset script
```

---

## ⚡ Quick Start

### 1. Prerequisites

- Python 3.10+
- Node.js 18+ (for React frontend)
- Git

### 2. Install Dependencies

```powershell
# Python dependencies
pip install -r requirements.txt

# Train the ML model (one-time)
python utils/train_ml_engine.py

# Install frontend dependencies
cd frontend; npm install; cd ..
```

### 3. Configure Environment

Copy `.env.example` to `.env` and fill in your API keys:

```ini
# Required for AI-powered incident summaries
OPENROUTER_API_KEY=your_openrouter_key_here

# Required for live threat intelligence
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# Optional: for WhatsApp critical alerts
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
TO_WHATSAPP=whatsapp:+1234567890
```

### 4. Launch Everything

```powershell
powershell -ExecutionPolicy Bypass -File start_enterprise.ps1
```

This starts **4 services in parallel**:
- 🧠 **Ingestion Service** — watches `logs_ingest/` for new events
- 🚦 **Traffic Simulator** — generates realistic attack data
- 🔗 **FastAPI Backend** — REST + WebSocket on port 8000
- 🖥️ **React Dashboard** — SOC UI on port 5173

Then open: **http://localhost:5173** → Login: `admin` / `threatpulse`

---

## � API Reference

Base URL: `http://localhost:8000`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | KPI summary (events, incidents, risk) |
| `GET` | `/api/events` | Paginated log events with filters |
| `GET` | `/api/incidents` | All incidents with status filter |
| `GET` | `/api/incidents/{id}` | Single incident with log event |
| `POST` | `/api/incidents/{id}/status` | Update incident status |
| `GET` | `/api/attack-graph` | D3-compatible nodes/edges JSON |
| `GET` | `/api/attack-chains` | Detected kill chains |
| `GET` | `/api/ml-metrics` | Model accuracy, F1, confusion matrix |
| `GET` | `/api/mitre/mapping` | MITRE ATT&CK technique for attack type |
| `GET` | `/api/threat-intel/{ip}` | AbuseIPDB reputation lookup |
| `GET` | `/api/geo-distribution` | Attack origin country counts |
| `GET` | `/api/explainability` | SHAP feature importance |
| `GET` | `/api/timeline/{id}` | Attack timeline for an incident |
| `POST` | `/api/response/{id}` | Trigger SOAR automated response |
| `POST` | `/api/ingest/csv` | Upload real CSV log file |
| `POST` | `/api/ingest/json` | POST JSON events for ingestion |
| `WS`  | `/ws/live-feed` | WebSocket real-time event stream |

Full interactive docs: **http://localhost:8000/docs**

---

## 📊 ML Model Details

| Metric | Score |
|---|---|
| **Accuracy** | 98.2% |
| **Precision** | 98.2% |
| **Recall** | 98.2% |
| **F1 Score** | 98.2% |

**Attack Classes Detected:**
- `brute_force` → MITRE T1110 (Credential Access)
- `sql_injection` → MITRE T1190 (Initial Access)
- `data_exfiltration` → MITRE T1041 (Exfiltration)
- `port_scan` → MITRE T1046 (Discovery)
- `normal` → Benign traffic

**Training Data:** Synthetic balanced dataset (5,000 events).  
**Production Datasets:** Pipeline is compatible with [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — replace `data/labeled_logs.csv` and retrain.

---

## � Ingest Real Data

Upload a CSV with columns: `timestamp, user, ip, action, status, resource`

```bash
# Via API
curl -F "file=@my_logs.csv" http://localhost:8000/api/ingest/csv

# Via Dashboard
# Click the "📤 UPLOAD LOGS (CSV)" button on the Dashboard page
```

---

## 🔢 MITRE ATT&CK Coverage

| Attack Type | Technique ID | Tactic |
|---|---|---|
| Brute Force | T1110 | Credential Access |
| SQL Injection | T1190 | Initial Access |
| Data Exfiltration | T1041 | Exfiltration |
| Port Scan | T1046 | Discovery |
| Malware Execution | T1059 | Execution |
| Privilege Escalation | T1068 | Privilege Escalation |
| Lateral Movement | T1021 | Lateral Movement |

---

## 🛣️ Roadmap

- [ ] **Neo4j integration** — scalable attack graph database for enterprise deployments
- [ ] **Kafka stream ingestion** — real-time log streaming at scale
- [ ] **STIX/TAXII feeds** — live threat intelligence from MITRE/ISAC
- [ ] **Role-based access control** — multi-analyst SOC workflows
- [ ] **PDF report export** — executive incident summary reports

---

## 🤝 Contributing

Contributions welcome! Please open an issue or pull request.

---

## 📝 License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">
Built with ❤️ for autonomous cyber defense
</div>
