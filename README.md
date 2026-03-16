# ThreatPulse - AI-Powered Cyber Defense Platform

<div align="center">

![ThreatPulse Banner](docs/banner.png)

**Enterprise-grade SOC platform - ML threat detection (97% accuracy, 15 attack types), SOAR automation, MITRE ATT&CK mapping, multi-tenant SaaS, real-time attack visualization, and live DVWA attack lab**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-success?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-blue?style=flat-square&logo=react)](https://react.dev)
[![LightGBM](https://img.shields.io/badge/LightGBM-ML_Engine-orange?style=flat-square)](https://lightgbm.readthedocs.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## What Is ThreatPulse?

> **ThreatPulse is an AI-powered cybersecurity platform that watches your server traffic in real-time, detects 15 types of cyber attacks with 97% accuracy, and automatically fights back — blocking hackers, locking compromised accounts, and alerting your team via Telegram and WhatsApp within seconds.**

Think of it like a **smart CCTV system**, but for computer networks:
- **Cameras** = Log Ingestion (watches every HTTP request)
- **AI Guard** = ML Engine (tells visitors from burglars)
- **Automatic Locks** = SOAR Playbooks (slams doors shut when burglars are detected)
- **Control Room** = React Dashboard (everything on one screen)

**The problem it solves:** Enterprise security tools (Splunk, CrowdStrike) cost $15K-50K/year. **99% of small businesses have zero security monitoring.** ThreatPulse gives them enterprise-grade protection for free.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      CUSTOMER'S WEB SERVER                       │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  SDK (npm install @threatpulse/sdk)                      │    │
│  │  Captures: IP, method, path, status, user, timestamp     │    │
│  │  Batches events -> ships to ThreatPulse API              │    │
│  └────────────────────────┬─────────────────────────────────┘    │
└───────────────────────────┼──────────────────────────────────────┘
                            │ POST /api/v1/ingest (API Key auth)
                            v
┌──────────────────────────────────────────────────────────────────┐
│                    THREATPULSE PLATFORM                           │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  REACT DASHBOARD (13 pages)                                 │ │
│  │  Landing -> Login -> Dashboard -> Incidents -> Investigation │ │
│  │  -> Attack Graph -> ML Metrics -> Threat Intel -> SOAR      │ │
│  │  -> Playbooks -> API Keys -> Integration Guide              │ │
│  └────────────────────────┬────────────────────────────────────┘ │
│                           │ REST API (55 endpoints)              │
│  ┌────────────────────────v────────────────────────────────────┐ │
│  │  FASTAPI BACKEND                                            │ │
│  │  JWT Auth | API Keys | Multi-Tenant | WebSocket Live Feed   │ │
│  └──┬────┬────┬────┬────┬────┬────┬────┬────┬────┬───────────┘ │
│     │    │    │    │    │    │    │    │    │    │               │
│  ┌──v──┐ ┌───v─┐ ┌─v──┐ ┌──v──┐ ┌───v──┐ ┌──v───────────┐   │
│  │ ML  │ │UEBA │ │SOAR│ │MITRE│ │OSINT │ │Threat Intel  │   │
│  │97%  │ │z-scr│ │15  │ │15+  │ │1847  │ │AbuseIPDB     │   │
│  │LGB  │ │base │ │play│ │tech │ │indic │ │OTX+VT        │   │
│  └─────┘ └─────┘ └────┘ └─────┘ └──────┘ └──────────────┘   │
│                                                                  │
│  ┌──────────┐ ┌──────┐   ┌─────────┐ ┌────────────┐           │
│  │TensorFlow│ │Attack│   │Feedback │ │Alert       │           │
│  │Autoencdr │ │Graph │   │Loop+    │ │Dispatch    │           │
│  │Anomaly   │ │D3.js │   │Drift    │ │Telegram    │           │
│  └──────────┘ └──────┘   └─────────┘ │WhatsApp    │           │
│                                       └────────────┘           │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  DATABASE (SQLite/PostgreSQL + SQLAlchemy ORM)            │ │
│  │  Users | ApiKeys | LogEvents | Incidents | AttackChains   │ │
│  └───────────────────────────────────────────────────────────┘ │
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
| **SHAP Explainability** | SHAP TreeExplainer | Feature importance visualization per prediction |
| **AI Summaries** | Google Gemini (via OpenRouter) | SOC-grade incident analysis with recommendations |
| **Real-Time Feed** | WebSockets | New events pushed live to dashboard |
| **Multi-Tenant SaaS** | JWT + API Keys | User registration, data isolation, admin roles |
| **SDK Integration** | Node.js + Python | Zero-config middleware for customer web servers |
| **Alerts** | Telegram Bot + Twilio WhatsApp | Instant critical alerts with action buttons |
| **Adversarial Testing** | 5 evasion techniques | 100% detection rate — model verified as ROBUST |
| **Feedback Loop** | Analyst corrections | FP tracking, drift scoring, retrain recommendations |
| **MTTD/MTTR** | Real-time metrics | Detect < 10s, Respond < 1s (industry avg: 197 days / 69 days) |

---

## The 15 Attack Types We Detect

Based on **OWASP Top 10 (2021 + 2023 API Security)**:

| # | Attack | OWASP | MITRE ID | What Happens |
|---|--------|-------|----------|-------------|
| 1 | SQL Injection | 2021 #3 | T1190 | Attacker steals database via login form |
| 2 | XSS | 2021 #3 | T1059.007 | Hidden script steals user cookies |
| 3 | Command Injection | 2021 #3 | T1059 | OS commands via web input |
| 4 | Privilege Escalation | 2021 #1 | T1068 | User gains admin access |
| 5 | Directory Traversal | 2021 #1 | T1083 | Reading files via `../../` paths |
| 6 | Insider Threat | 2021 #1 | T1078 | Employee steals data |
| 7 | Brute Force | 2021 #7 | T1110 | Trying thousands of passwords |
| 8 | Credential Stuffing | 2021 #7 | T1110.004 | Using leaked passwords |
| 9 | Session Hijacking | 2021 #7 | T1550 | Stealing login sessions |
| 10 | DoS Attack | 2023 API #4 | T1498 | Flooding server with requests |
| 11 | Port Scan | Discovery | T1046 | Scanning for open doors |
| 12 | SSRF | 2021 #10 | T1090 | Tricking server to attack itself |
| 13 | Malware | 2021 #8 | T1204 | Uploading virus/backdoor |
| 14 | Data Exfiltration | Exfiltration | T1041 | Stealing data to external server |
| 15 | Normal | N/A | — | Not an attack |

---

## DVWA Attack Lab

ThreatPulse includes a live attack lab powered by **DVWA (Damn Vulnerable Web Application)**. It runs 12 real attack modules in Docker, each spoofing geo-realistic IPs via `X-Forwarded-For` headers, and ships the nginx logs into ThreatPulse for real-time detection.

```
attack-runner (sets X-Forwarded-For per module)
    |
    v
nginx (logs $remote_addr + $http_x_forwarded_for)
    |
    v
log-shipper (extracts XFF IP, ships to ThreatPulse /api/v1/ingest)
    |
    v
ThreatPulse Dashboard (diverse IPs, countries, geo heatmap)
```

**12 Attack Modules:**

| Module | Country | Attack Type |
|---|---|---|
| Brute Force | RU | Dictionary attack with 25 passwords |
| SQL Injection | CN | UNION, OR 1=1, comment bypass |
| Blind SQLi | CN | Boolean-based extraction |
| Reflected XSS | EU | Script tags, event handlers |
| Stored XSS | EU | Guestbook payload injection |
| DOM XSS | EU | Query param manipulation |
| Command Injection | RU | `;cat`, `| whoami`, `&& rm` |
| File Inclusion | KR | LFI with `../../`, `file://` |
| File Upload | JP | PHP shell, MIME spoofing |
| CSRF | BR | Forged password change |
| Weak Session IDs | ZA | Predictable token harvest |
| Normal Traffic | US | Benign employee browsing |

Each module cycles through DVWA security levels (low, medium, high) with rotating IPs per cycle.

```powershell
# Start the DVWA lab separately
cd dvwa-stack
docker compose up --build -d

# Check attack logs
docker logs dvwa-attack-runner --tail 20
docker logs dvwa-shipper --tail 20
```

---

## Project Structure

```
ThreatPulse/
├── src/                              # Core Python modules (25 files)
│   ├── ml_engine.py                  # LightGBM attack classifier (15 classes)
│   ├── anomaly_detection.py          # TF Autoencoder anomaly detection
│   ├── model_tf.py                   # TensorFlow model definitions
│   ├── threat_intel.py               # AbuseIPDB lookup + cache
│   ├── threat_intel_extended.py      # OTX + VirusTotal integration
│   ├── osint_feeds.py                # Tor exit nodes + ET + URLhaus
│   ├── response_engine.py            # SOAR automation (IP block, lock account)
│   ├── soar_playbooks.py             # 15 conditional playbooks
│   ├── attack_graph.py               # NetworkX kill chain builder
│   ├── mitre_mapping.py              # MITRE ATT&CK technique database
│   ├── ueba.py                       # User & Entity Behavior Analytics
│   ├── explainability_shap.py        # SHAP feature importance
│   ├── feedback_loop.py              # Analyst feedback + drift detection
│   ├── threat_predictor.py           # Next-attack scenario prediction
│   ├── risk_scoring.py               # Risk scoring engine
│   ├── adversarial_test.py           # 5 evasion technique tests
│   ├── database.py                   # SQLAlchemy ORM (SQLite/PostgreSQL)
│   ├── auth.py                       # JWT authentication
│   ├── api_keys.py                   # API key generation/validation
│   ├── ingestion_service.py          # Log ingestion service
│   ├── context_analysis.py           # Context analysis engine
│   └── log_parser.py                 # Log parsing utilities
├── api/
│   └── main.py                       # FastAPI backend (55 endpoints + WebSocket)
├── frontend/
│   └── src/
│       ├── pages/                    # 13 React pages
│       │   ├── LandingPage.jsx       # Marketing page with hex grid animation
│       │   ├── LoginPage.jsx         # Matrix rain effect, boot sequence
│       │   ├── RegisterPage.jsx      # Email + password signup
│       │   ├── DashboardPage.jsx     # Threat gauge, KPIs, charts, live feed
│       │   ├── IncidentsPage.jsx     # Grid/table view, search, MITRE tags
│       │   ├── InvestigationPage.jsx # 4-tab deep dive (Details, Timeline, MITRE, SOAR)
│       │   ├── AttackGraphPage.jsx   # D3.js force-directed visualization
│       │   ├── MLMetricsPage.jsx     # Accuracy, confusion matrix, SHAP, drift
│       │   ├── ThreatIntelPage.jsx   # IP/domain lookup (AbuseIPDB + OTX + VT)
│       │   ├── PlaybooksPage.jsx     # Visual step flow with risk slider
│       │   ├── ApiKeysPage.jsx       # Generate, list, revoke API keys
│       │   └── IntegrationGuidePage.jsx # SDK install instructions
│       ├── components/               # LiveFeed, AttackTimeline, Sidebar, etc.
│       └── api/client.js             # Axios API client
├── sdk/
│   ├── node/                         # Node.js SDK (@threatpulse/sdk)
│   └── python/                       # Python SDK (threatpulse)
├── utils/
│   ├── train_ml_engine.py            # ML model training
│   ├── simulate_live_traffic.py      # Realistic attack traffic generator
│   ├── telegram_bot.py               # Telegram bot integration
│   ├── telegram_alerter.py           # Telegram alert dispatch
│   ├── alert_dispatcher.py           # Multi-channel alert dispatcher
│   ├── gemini_client.py              # OpenRouter AI summaries (Gemini)
│   ├── seed_demo_account.py          # Demo account seeding
│   └── verify_integrations.py        # Integration verification
├── dvwa-stack/                       # DVWA Attack Lab (Docker)
│   ├── docker-compose.yml            # 5 containers: db, dvwa, nginx, attacker, shipper
│   ├── attack-runner/                # 12 attack modules with geo-IP spoofing
│   │   ├── runner.py                 # Main orchestration loop
│   │   ├── ip_pools.py              # Per-module IP ranges (aligned with API)
│   │   ├── dvwa_session.py          # Session wrapper with XFF + CSRF handling
│   │   └── modules/                 # brute_force, sqli, xss, cmd_injection, etc.
│   ├── shipper/log_shipper.py       # Tails nginx logs, ships to /api/v1/ingest
│   └── nginx/nginx.conf             # Custom log format with XFF field
├── tests/                            # Pytest test suite
├── data/                             # Threat intel cache, blocked IPs, etc.
├── docker-compose.yml                # 6-service Docker deployment
├── Dockerfile.backend                # Backend container
├── start_all.ps1                     # One-command startup (ALL services + DVWA lab)
├── start_enterprise.ps1              # Startup without DVWA lab
├── .env.example                      # Environment template
└── requirements.txt                  # Python dependencies
```

---

## Quick Start

### Option A: Full Stack Launch (Recommended)

```powershell
# 1. Clone the repo
git clone https://github.com/Yeager077/Threat-Pulse.git
cd Threat-Pulse

# 2. Install dependencies
pip install -r requirements.txt
cd frontend && npm install && cd ..

# 3. Configure environment
# Copy .env.example to .env and fill in your API keys

# 4. Train the ML model (first time only)
python utils/train_ml_engine.py

# 5. Launch everything (API + Frontend + DVWA Attack Lab)
powershell -ExecutionPolicy Bypass -File start_all.ps1
```

This starts all services in one command:
- **Ingestion Service** - watches `logs_ingest/` for new events
- **Traffic Simulator** - generates realistic attack data
- **FastAPI Backend** - REST + WebSocket on port 8000
- **React Dashboard** - SOC UI on port 5173
- **DVWA Attack Lab** - 12 real attack modules via Docker (port 8080)
- **Log Shipper** - sends DVWA attack logs to ThreatPulse in real-time

Then open: **http://localhost:5173**

> To start without the DVWA lab, use `start_enterprise.ps1` instead.

### Option B: Docker (Production)

```bash
# 1. Clone and configure
git clone https://github.com/Yeager077/Threat-Pulse.git
cd Threat-Pulse
cp .env.example .env  # Edit with your credentials

# 2. Launch all services
docker-compose up -d

# Services: PostgreSQL, Redis, API, Ingestion, Simulator, Frontend
# Dashboard: http://localhost (port 80)
# API: http://localhost:8000
```

### Option C: SDK Integration (Customer's Website)

```javascript
// Node.js (Express)
const { threatPulseMiddleware } = require('@threatpulse/sdk/express');
app.use(threatPulseMiddleware({
  apiKey: process.env.THREATPULSE_API_KEY  // Generated from dashboard
}));
// Every HTTP request is now monitored by ThreatPulse
```

```python
# Python (Flask/Django)
from threatpulse import ThreatPulse
tp = ThreatPulse(api_key=os.environ['THREATPULSE_API_KEY'])
# Auto-captures and ships request logs
```

### Default Login

- **Email:** `demo@threatpulse.com`
- **Password:** `ThreatPulse2025`
- **Role:** Admin (sees all data)

---

## Environment Configuration

Copy `.env.example` to `.env` and fill in your API keys:

```ini
# Required for AI-powered incident summaries
OPENROUTER_API_KEY=your_openrouter_key_here

# Required for live threat intelligence
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# Telegram alerts
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id

# Optional: AlienVault OTX
OTX_API_KEY=your_otx_key_here

# Optional: VirusTotal
VIRUSTOTAL_API_KEY=your_vt_key_here

# Optional: WhatsApp alerts (Twilio)
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
TO_WHATSAPP=whatsapp:+1234567890
```

---

## API Reference

Base URL: `http://localhost:8000` | Interactive docs: `http://localhost:8000/docs`

**55 endpoints** including:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/register` | User registration |
| `POST` | `/api/v1/auth/login` | JWT login |
| `GET` | `/api/stats` | KPI summary (events, incidents, risk) |
| `GET` | `/api/events` | Paginated log events with filters |
| `GET` | `/api/incidents` | All incidents with status filter |
| `GET` | `/api/incidents/{id}` | Single incident with full details |
| `POST` | `/api/incidents/{id}/status` | Update incident status |
| `POST` | `/api/incidents/{id}/feedback` | Analyst feedback (FP/TP) |
| `GET` | `/api/attack-graph` | D3-compatible nodes/edges JSON |
| `GET` | `/api/attack-chains` | Detected kill chains |
| `GET` | `/api/ml-metrics` | Model accuracy, F1, confusion matrix |
| `GET` | `/api/mitre/mapping` | MITRE ATT&CK technique lookup |
| `GET` | `/api/threat-intel/{ip}` | AbuseIPDB + OTX + VT reputation |
| `GET` | `/api/osint/stats` | OSINT feed statistics |
| `GET` | `/api/geo-distribution` | Attack origin country counts |
| `GET` | `/api/explainability` | SHAP feature importance |
| `GET` | `/api/ueba/{username}` | User behavior profile |
| `GET` | `/api/timeline/{id}` | Attack timeline for an incident |
| `POST` | `/api/response/{id}` | Trigger SOAR automated response |
| `GET` | `/api/playbooks` | List all SOAR playbooks |
| `GET` | `/api/soar/actions` | SOAR action log |
| `POST` | `/api/api-keys` | Generate new API key |
| `GET` | `/api/api-keys` | List user's API keys |
| `DELETE` | `/api/api-keys/{id}` | Revoke an API key |
| `POST` | `/api/v1/ingest` | SDK event ingestion (API key auth) |
| `POST` | `/api/ingest/csv` | Upload CSV log file |
| `POST` | `/api/ingest/json` | POST JSON events |
| `GET` | `/api/mttd-mttr` | MTTD/MTTR metrics + trends |
| `GET` | `/api/adversarial/results` | Adversarial robustness test results |
| `GET` | `/api/feedback/stats` | Feedback loop + drift metrics |
| `WS` | `/ws/live-feed` | WebSocket real-time event stream |

---

## ML Model Details

| Metric | Score |
|---|---|
| **Accuracy** | 97% |
| **Precision** | 97% |
| **Recall** | 97% |
| **F1 Score** | 97% |

**Training data:** 10,000 synthetic events generated with CIC-IDS2017 compatible network feature distributions. Each attack type has a unique network fingerprint (e.g., DoS attacks have extremely high packet counts, brute force has many SYN flags).

**21 features analyzed per request:**
- **Who**: username, role (admin/user/guest)
- **What**: action (login, download, api_call), resource accessed
- **When**: hour of day (3 AM login = suspicious)
- **Where**: IP address, country
- **Network fingerprint**: 15 CIC-IDS2017 features (packet sizes, flow duration, flag counts)

**Production datasets:** Pipeline is compatible with [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — replace training data and retrain.

---

## MITRE ATT&CK Coverage

| Attack Type | Technique ID | Tactic |
|---|---|---|
| SQL Injection | T1190 | Initial Access |
| XSS | T1059.007 | Execution |
| Command Injection | T1059 | Execution |
| Privilege Escalation | T1068 | Privilege Escalation |
| Directory Traversal | T1083 | Discovery |
| Insider Threat | T1078 | Defense Evasion |
| Brute Force | T1110 | Credential Access |
| Credential Stuffing | T1110.004 | Credential Access |
| Session Hijacking | T1550 | Lateral Movement |
| DoS Attack | T1498 | Impact |
| Port Scan | T1046 | Discovery |
| SSRF | T1090 | Command & Control |
| Malware | T1204 | Execution |
| Data Exfiltration | T1041 | Exfiltration |

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Frontend | React 19 + Vite + Recharts + D3.js | Fast, interactive, beautiful |
| Backend | FastAPI (Python) | Fastest Python framework, auto-docs |
| ML Model | LightGBM + TensorFlow Autoencoder | Best accuracy for tabular data |
| Database | SQLite/PostgreSQL + SQLAlchemy | Flexible, works anywhere |
| Auth | JWT + bcrypt | Industry standard |
| Alerts | Telegram Bot API + Twilio WhatsApp | Free, instant, mobile |
| AI Summary | Google Gemini (via OpenRouter) | Best free AI for analysis |
| Threat Intel | AbuseIPDB + OTX + VirusTotal + OSINT | 4 independent sources |
| Deployment | Docker Compose (6 services) | One-command deployment |
| SDKs | Node.js + Python packages | Zero dependencies |

---

## Numbers That Matter

| Metric | Value |
|--------|-------|
| Attack types detected | **15** (OWASP Top 10 mapped) |
| ML model accuracy | **97%** |
| API endpoints | **55** |
| SOAR playbooks | **15** (conditional, risk-based) |
| MITRE techniques mapped | **15+** |
| OSINT indicators | **1,847+** |
| Threat intel sources | **4** (AbuseIPDB, OTX, VirusTotal, OSINT) |
| Frontend pages | **13** |
| Response time (SOAR) | **< 1 second** |
| Adversarial robustness | **100%** detection |
| Python modules | **43** |
| Total functions | **167** |
| Docker services | **6** |
| SDK languages | **2** (Node.js + Python) |

---

## Competitive Advantage

| Feature | ThreatPulse | Splunk | CrowdStrike |
|---------|-------------|--------|-------------|
| Price | **Free** | $15K+/year | $25K+/year |
| Attack types | 15 (OWASP) | Custom rules | Agent-based |
| ML accuracy | 97% | No built-in ML | Proprietary |
| Auto-response | 15 SOAR playbooks | Manual | Limited |
| MITRE mapping | Built-in | Plugin | Built-in |
| Setup time | 5 minutes | Weeks | Days |
| Multi-tenant | Yes (SaaS) | Enterprise only | Enterprise only |
| SDK integration | Node.js + Python | Heavy forwarder | Agent install |
| Open source | Yes | No | No |
| Alerts | Telegram + WhatsApp | Email only | Email/Slack |

---

## Roadmap

### Phase 1: Production Hardening
- [ ] PostgreSQL migration for production scale
- [ ] Redis caching for threat intel lookups and ML predictions
- [ ] Per-API-key rate limiting (1000 events/min)
- [ ] GitHub Actions CI/CD pipeline

### Phase 2: Advanced ML
- [ ] Ensemble models (LightGBM + XGBoost + Neural Network)
- [ ] Online retraining from analyst feedback (weekly)
- [ ] Transformer-based sequence anomaly detection
- [ ] Zero-day detection via unsupervised clustering

### Phase 3: Platform Features
- [ ] Stripe billing integration for paid plans
- [ ] Visual drag-and-drop playbook builder
- [ ] SIEM connector (Splunk, Elastic, Datadog export)
- [ ] SOC 2 / ISO 27001 compliance report generation
- [ ] React Native mobile companion app

### Phase 4: Scale
- [ ] Kafka streaming for 100K+ events/sec
- [ ] Neo4j graph DB for attack graph scaling
- [ ] Kubernetes auto-scaling deployment
- [ ] STIX/TAXII standardized threat intel feeds

---

## Contributing

Contributions welcome! Please open an issue or pull request.

---

## License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">
Built for autonomous cyber defense
</div>
