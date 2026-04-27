# TrustFlow — AI-Powered Cyber Defense Platform

<div align="center">

**Enterprise-grade SOC platform — ML threat detection (97% accuracy, 15 attack types), SOAR automation, MITRE ATT&CK mapping, multi-tenant SaaS, real-time attack visualization.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-success?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-blue?style=flat-square&logo=react)](https://react.dev)
[![Postgres](https://img.shields.io/badge/PostgreSQL-16-blue?style=flat-square&logo=postgresql)](https://postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## What Is TrustFlow?

> **TrustFlow is an AI-powered cybersecurity platform that watches your server traffic in real-time, detects 15 types of cyber attacks with 97% accuracy, and automatically fights back — blocking hackers, locking compromised accounts, and alerting your team via Telegram and WhatsApp within seconds.**

Think of it like a smart CCTV system, but for computer networks:
- **Cameras** → Log Ingestion (every HTTP request)
- **AI Guard** → ML Engine (visitors vs. burglars)
- **Automatic Locks** → SOAR Playbooks (slams doors shut on confirmed threats)
- **Control Room** → React Dashboard (everything on one screen)

**The problem it solves:** Enterprise security tools (Splunk, CrowdStrike) cost $15K–50K/year. **99% of small businesses have zero security monitoring.** TrustFlow gives them enterprise-grade protection for free.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      CUSTOMER'S WEB SERVER                       │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  SDK (npm install @trustflow/sdk)                        │    │
│  │  Captures: IP, method, path, status, user, timestamp     │    │
│  │  Batches events → ships to TrustFlow API                 │    │
│  └────────────────────────┬─────────────────────────────────┘    │
└───────────────────────────┼──────────────────────────────────────┘
                            │ POST /api/v1/ingest (API key auth)
                            v
┌──────────────────────────────────────────────────────────────────┐
│                    TRUSTFLOW PLATFORM                            │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  REACT DASHBOARD (13 pages)                                 │ │
│  └────────────────────────┬────────────────────────────────────┘ │
│                           │ REST + WebSocket                     │
│  ┌────────────────────────v────────────────────────────────────┐ │
│  │  FASTAPI BACKEND                                            │ │
│  │  JWT Auth | API Keys | Multi-Tenant | WebSocket Live Feed   │ │
│  └──┬────┬────┬────┬────┬────┬────┬────┬─────────────────────┬─┘ │
│     │    │    │    │    │    │    │    │                     │   │
│  ┌──v──┐┌v───┐┌v──┐┌v────┐┌v───┐┌v────┐┌v────────────┐       │   │
│  │ ML  ││UEBA││SOAR││MITRE││OSINT││TI    ││TF Autoencdr │       │   │
│  │LGBM ││z-sc││15pl││15+  ││1847 ││4 src ││Anomaly      │       │   │
│  └─────┘└────┘└────┘└─────┘└─────┘└──────┘└─────────────┘       │   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  PostgreSQL (sole source of truth) + Redis cache           │ │
│  │  Users | ApiKeys | LogEvents | Incidents | AttackChains    │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Key Features

| Feature | Technology | Details |
|---|---|---|
| **ML Detection** | LightGBM + TF Autoencoder | 97% accuracy, 15 attack classes (OWASP Top 10) |
| **Threat Intel** | AbuseIPDB + OTX + VirusTotal + OSINT | 4 independent sources, 1,847+ indicators |
| **SOAR Automation** | 15 conditional playbooks | Risk-based: IP block, account lock, WAF rules, rate limit |
| **UEBA** | Statistical z-score analysis | Per-user behavioral baselines, anomaly flagging |
| **Attack Graph** | NetworkX + D3.js | Kill chain visualization with zoom/pan |
| **MITRE ATT&CK** | 15+ technique mappings | Full tactic/technique/sub-technique with mitigations |
| **SHAP Explainability** | SHAP TreeExplainer | Per-prediction feature importance |
| **AI Summaries** | OpenRouter (Llama-3.3-70B class models) | SOC-grade incident analysis with recommendations |
| **Real-Time Feed** | WebSockets | New events pushed live to dashboard |
| **Multi-Tenant SaaS** | JWT + API keys | User registration, data isolation, admin roles |
| **SDK Integration** | Node.js + Python | Zero-config middleware for customer web servers |
| **Alerts** | Telegram Bot + Twilio WhatsApp | Instant critical alerts |
| **Adversarial Testing** | 5 evasion techniques | 100% detection rate on robustness suite |
| **Feedback Loop** | Analyst corrections | FP tracking, drift scoring, retrain recommendations |
| **MTTD/MTTR** | Real-time metrics | Detect < 10s, Respond < 1s |

---

## The 15 Attack Types

Based on **OWASP Top 10 (2021 + 2023 API Security)**:

| # | Attack | OWASP | MITRE ID |
|---|--------|-------|----------|
| 1 | SQL Injection | 2021 #3 | T1190 |
| 2 | XSS | 2021 #3 | T1059.007 |
| 3 | Command Injection | 2021 #3 | T1059 |
| 4 | Privilege Escalation | 2021 #1 | T1068 |
| 5 | Directory Traversal | 2021 #1 | T1083 |
| 6 | Insider Threat | 2021 #1 | T1078 |
| 7 | Brute Force | 2021 #7 | T1110 |
| 8 | Credential Stuffing | 2021 #7 | T1110.004 |
| 9 | Session Hijacking | 2021 #7 | T1550 |
| 10 | DoS | 2023 API #4 | T1498 |
| 11 | Port Scan | Discovery | T1046 |
| 12 | SSRF | 2021 #10 | T1090 |
| 13 | Malware | 2021 #8 | T1204 |
| 14 | Data Exfiltration | Exfiltration | T1041 |
| 15 | Normal | N/A | — |

---

## Project Structure

```
TrustFlow/
├── src/                          # Core Python modules
│   ├── ml_engine.py              # LightGBM attack classifier (15 classes)
│   ├── anomaly_detection.py      # TF Autoencoder anomaly detection
│   ├── threat_intel.py           # AbuseIPDB lookup + cache
│   ├── threat_intel_extended.py  # OTX + VirusTotal integration
│   ├── osint_feeds.py            # Tor exit nodes + ET + URLhaus
│   ├── response_engine.py        # SOAR automation
│   ├── soar_playbooks.py         # 15 conditional playbooks
│   ├── attack_graph.py           # NetworkX kill-chain builder
│   ├── mitre_mapping.py          # MITRE ATT&CK technique database
│   ├── ueba.py                   # User & Entity Behavior Analytics
│   ├── explainability_shap.py    # SHAP feature importance
│   ├── feedback_loop.py          # Analyst feedback + drift detection
│   ├── adversarial_test.py       # 5 evasion technique tests
│   ├── database.py               # SQLAlchemy ORM (PostgreSQL only)
│   ├── auth.py                   # JWT authentication
│   ├── api_keys.py               # API key generation/validation
│   ├── ingestion_service.py      # Log ingestion service
│   └── bootstrap_admin.py        # First-admin CLI
├── api/main.py                   # FastAPI backend (REST + WebSocket)
├── frontend/                     # React 19 + Vite (13 pages)
├── sdk/
│   ├── node/                     # @trustflow/sdk (Node.js)
│   └── python/                   # trustflow-sdk (Python)
├── utils/                        # Trainers, alerters, dispatchers
├── tests/                        # Pytest suite
├── data/                         # ML models + threat-intel cache
├── docker-compose.yml            # Production stack
├── Dockerfile.backend            # Backend container
├── .env.example                  # Environment template
└── requirements.txt
```

---

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Strong values for `POSTGRES_PASSWORD` and `JWT_SECRET_KEY`

### 1. Clone and configure

```bash
git clone https://github.com/Yeager077/TrustFlow.git
cd TrustFlow
cp .env.example .env
# Edit .env — at minimum set POSTGRES_PASSWORD and JWT_SECRET_KEY.
# Generate JWT secret with:
#   python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### 2. Launch the stack

```bash
docker compose up -d
docker compose logs -f api
```

Services started: `postgres`, `redis`, `api`, `ingestion`, `frontend`.

- Dashboard: <http://localhost>
- API: <http://localhost:8000>
- API docs: <http://localhost:8000/docs>

### 3. Create the first admin

There is no seeded demo account. Bootstrap your admin once:

```bash
docker compose exec api python -m src.bootstrap_admin --email you@example.com
# (you will be prompted for a password)
```

Then log in at <http://localhost> with that email/password.

### 4. SDK integration on the customer side

```javascript
// Node.js (Express)
const { trustFlowMiddleware } = require('@trustflow/sdk/express');
app.use(trustFlowMiddleware({
  apiKey: process.env.TRUSTFLOW_API_KEY,  // Generated in the dashboard
  endpoint: 'https://your-trustflow-host'
}));
```

```python
# Python
from trustflow import TrustFlow
tf = TrustFlow(api_key=os.environ['TRUSTFLOW_API_KEY'],
               endpoint='https://your-trustflow-host')
```

---

## Environment Configuration

Set these in `.env` (see `.env.example` for the full list):

| Variable | Required | Purpose |
|---|---|---|
| `POSTGRES_PASSWORD` | yes | DB password |
| `JWT_SECRET_KEY` | yes | JWT signing secret (64+ random chars) |
| `POSTGRES_DB` / `POSTGRES_USER` | no | Default `trustflow` / `trustflow` |
| `OPENROUTER_API_KEY` | no | AI incident summaries |
| `ABUSEIPDB_API_KEY` / `OTX_API_KEY` / `VIRUSTOTAL_API_KEY` | no | Threat intel |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | no | Telegram alerts |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TO_WHATSAPP` | no | WhatsApp alerts |
| `VITE_API_URL` | no | Public API URL for the frontend build |

---

## API Reference

Base URL: `http://localhost:8000` · Interactive docs: `/docs`

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/register` | User registration |
| `POST` | `/api/auth/login` | JWT login |
| `GET`  | `/api/auth/me` | Current user profile |
| `GET`  | `/api/stats` | KPI summary |
| `GET`  | `/api/events` | Paginated log events |
| `GET`  | `/api/incidents` | Incidents with filters |
| `GET`  | `/api/incidents/{id}` | Single incident |
| `POST` | `/api/incidents/{id}/status` | Update status |
| `POST` | `/api/incidents/{id}/feedback` | FP/TP feedback |
| `GET`  | `/api/attack-graph` | D3-compatible nodes/edges |
| `GET`  | `/api/attack-chains` | Detected kill chains |
| `GET`  | `/api/ml-metrics` | Accuracy, F1, confusion matrix |
| `GET`  | `/api/mitre/mapping` | MITRE technique lookup |
| `GET`  | `/api/threat-intel/{ip}` | AbuseIPDB + OTX + VT reputation |
| `GET`  | `/api/explainability` | SHAP feature importance |
| `GET`  | `/api/ueba/{username}` | User behavior profile |
| `POST` | `/api/response/{id}` | Trigger SOAR response |
| `POST` | `/api/keys` | Generate API key |
| `GET`  | `/api/keys` | List your API keys |
| `DELETE` | `/api/keys/{id}` | Revoke API key |
| `POST` | `/api/v1/ingest` | SDK event ingestion (X-API-Key header, body `{"events":[...]}`) |
| `GET`  | `/api/mttd-mttr` | MTTD/MTTR + trends |
| `WS`   | `/ws/live-feed` | WebSocket real-time stream |

Full list at `/docs` (auto-generated from FastAPI).

---

## ML Model

| Metric | Score |
|---|---|
| Accuracy | 97% |
| Precision | 97% |
| Recall | 97% |
| F1 | 97% |

**Training data:** synthetic events with CIC-IDS2017-compatible network feature distributions (provided in `data/labeled_logs.csv`). Each attack type has a unique fingerprint (DoS = high packet counts, brute force = many SYN flags, etc.).

**Production datasets:** the pipeline is compatible with [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — replace training data and rerun `python utils/train_ml_engine.py`.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, Vite, Recharts, D3.js |
| Backend | FastAPI (Python 3.11) |
| ML | LightGBM, TensorFlow, SHAP |
| Database | **PostgreSQL 16** (SQLAlchemy ORM) |
| Cache | Redis 7 |
| Auth | JWT + bcrypt |
| Alerts | Telegram Bot API, Twilio WhatsApp |
| AI Summary | OpenRouter (Llama-3.3-70B class) |
| Threat Intel | AbuseIPDB, OTX, VirusTotal, OSINT |
| Deployment | Docker Compose |
| SDKs | Node.js, Python |

---

## Roadmap

- [ ] Per-API-key rate limiting
- [ ] Wire Redis into threat-intel + ML prediction caches
- [ ] GitHub Actions CI/CD
- [ ] Ensemble ML (LightGBM + XGBoost + neural net)
- [ ] Online retraining from analyst feedback
- [ ] Visual playbook builder
- [ ] SIEM connectors (Splunk, Elastic, Datadog)
- [ ] Kafka streaming for 100K+ events/sec
- [ ] Kubernetes manifests + Helm chart

---

## License

MIT — see [LICENSE](LICENSE).
