# TrustFlow — AI-Powered Cyber Defense Platform

<div align="center">

**Enterprise-grade multi-tenant SOC platform. ML ensemble threat detection (97.2 % accuracy, 15 attack types), SOAR automation, MITRE ATT&CK mapping, real-time attack graph, Kafka streaming, and SOC 2 / ISO 27001 compliance reports — all in one open-source platform.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-success?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-blue?style=flat-square&logo=react)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?style=flat-square&logo=postgresql)](https://postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-red?style=flat-square&logo=redis)](https://redis.io)
[![CI](https://img.shields.io/github/actions/workflow/status/Muzzu077/Threat-Detection-and-Risk-Scoring/ci.yml?style=flat-square&label=CI)](https://github.com/Muzzu077/Threat-Detection-and-Risk-Scoring/actions)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## What Is TrustFlow?

TrustFlow is an AI-powered cybersecurity operations platform that ingests your server logs in real time, classifies threats with a LightGBM + XGBoost ensemble, and automatically responds — blocking IPs, disabling accounts, forwarding to your SIEM, and alerting your team on Telegram, WhatsApp, or Email within seconds.

It is designed as a proper multi-tenant SaaS: every tenant registers their **Applications**, generates **API keys** per application, and the entire data model — events, incidents, playbooks, alerts — is isolated by `tenant_id` + `application_id`.

**The gap it fills:** Commercial SOC platforms (Splunk, CrowdStrike) cost $15 K–50 K/year. TrustFlow delivers comparable detection and automation at zero licensing cost.

---

## Platform Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                      CUSTOMER WEB SERVER                          │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  TrustFlow SDK  (npm / pip)                                 │  │
│  │  Captures: IP · method · path · status · user · timestamp   │  │
│  │  Batches & ships → POST /api/v1/ingest  (X-API-Key)         │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
└─────────────────────────────┼─────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────┐
│                      TRUSTFLOW PLATFORM                           │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │  REACT 19 DASHBOARD  (20 pages, role-based nav)            │   │
│  │  Operations · Developer · Admin · ML Lab · Compliance      │   │
│  └───────────────────────────┬────────────────────────────────┘   │
│                              │  REST + WebSocket                  │
│  ┌───────────────────────────▼────────────────────────────────┐   │
│  │  FASTAPI BACKEND                                           │   │
│  │  JWT Auth · API Keys · Rate Limiting · Multi-Tenant        │   │
│  └──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬─────────────┘   │
│     │  │  │  │  │  │  │  │  │  │  │  │  │  │  │                 │
│  ┌──▼─┐┌▼─┐┌▼──┐┌▼───┐┌▼──┐┌▼───┐┌▼────┐┌▼───┐┌▼──┐┌▼──┐        │
│  │ ML ││UE││SOA││MITR││TI ││SIEM││Kafka││STIX││Neo││Cmp│        │
│  │Ens ││BA││ R ││ E  ││4sr││conn││strm ││TAXI││4j ││ ply│        │
│  └────┘└──┘└───┘└────┘└───┘└────┘└─────┘└────┘└───┘└───┘        │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │  PostgreSQL 16 (single source of truth) + Redis 7 cache   │   │
│  │  Users · Tenants · Applications · ApiKeys · Events        │   │
│  │  Incidents · AttackChains · Playbooks · NotifPrefs        │   │
│  └────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

---

## Feature Matrix

| Capability | Technology | Details |
|---|---|---|
| **ML Ensemble** | LightGBM + XGBoost | Averaged probabilities → **97.2 % accuracy**, 15 attack classes |
| **Sequence Anomaly** | Keras MultiHeadAttention Transformer | Session-level user-behaviour anomaly; heuristic fallback |
| **Zero-Day Clustering** | DBSCAN (HDBSCAN) | Novelty detection on residual "normal" traffic with risk > 25 |
| **UEBA** | Statistical z-score baselines | Per-user hourly / action / failure-rate profiling |
| **Threat Intel** | AbuseIPDB · OTX · VirusTotal · OSINT | 4 independent sources; STIX/TAXII private feed layer |
| **SOAR — Built-in** | 15 conditional playbooks | Risk-based: IP block, account lock, WAF, rate limit |
| **SOAR — Custom** | Visual playbook builder | 7 step types, drag-to-reorder, dry-run, live execution |
| **SIEM Export** | Splunk HEC · Elastic · Datadog · Webhook | CEF format; per-tenant configuration |
| **Attack Graph** | NetworkX + D3.js / Neo4j (opt-in) | Kill-chain visualisation; Neo4j scales beyond single worker |
| **MITRE ATT&CK** | 15+ technique mappings | Tactic / technique / sub-technique / mitigations |
| **Compliance Reports** | SOC 2 Type II · ISO 27001 | 15 controls, 5 evidence sections, browser-print PDF |
| **SHAP Explainability** | SHAP TreeExplainer | Per-prediction feature importance |
| **AI Summaries** | OpenRouter (Llama-3.3-70B) | SOC-grade incident analysis + recommendations |
| **Real-Time Feed** | WebSocket | New events pushed live; React dashboard updates instantly |
| **Multi-Tenant SaaS** | JWT · bcrypt · API keys | Data fully isolated by `tenant_id + application_id` |
| **Applications** | First-class entity | Register apps, generate per-app keys, SDK code snippets |
| **Per-User Alerts** | Telegram · WhatsApp · Email | Per-tenant routing, severity threshold, channel toggles |
| **Kafka Streaming** | aiokafka (opt-in) | Every ingested event → `trustflow.events` topic; fail-open |
| **STIX/TAXII Feed** | taxii2-client (opt-in) | Private IOC feed; Redis 6 h cache; fast IP/domain lookup |
| **Rate Limiting** | Redis sliding window | 1 000 req / 60 s per API key (configurable) |
| **SDK** | Node.js · Python | Zero-config Express middleware + Python client |
| **CI/CD** | GitHub Actions | ruff lint · pytest · frontend build · Docker smoke build |
| **Adversarial Testing** | 5 evasion techniques | 100 % detection rate on robustness suite |
| **Feedback Loop** | Analyst corrections | FP/TP tracking, drift scoring, retrain recommendations |

---

## The 15 Attack Classes

| # | Attack Type | OWASP | MITRE ATT&CK |
|---|---|---|---|
| 1 | SQL Injection | 2021 #3 | T1190 |
| 2 | XSS | 2021 #3 | T1059.007 |
| 3 | Command Injection | 2021 #3 | T1059 |
| 4 | Privilege Escalation | 2021 #1 | T1068 |
| 5 | Directory Traversal | 2021 #1 | T1083 |
| 6 | Insider Threat | 2021 #1 | T1078 |
| 7 | Brute Force | 2021 #7 | T1110 |
| 8 | Credential Stuffing | 2021 #7 | T1110.004 |
| 9 | Session Hijacking | 2021 #7 | T1550 |
| 10 | DoS Attack | API 2023 #4 | T1498 |
| 11 | Port Scan | Discovery | T1046 |
| 12 | SSRF | 2021 #10 | T1090 |
| 13 | Malware | 2021 #8 | T1204 |
| 14 | Data Exfiltration | Exfiltration | T1041 |
| 15 | Normal | — | — |

---

## ML Model Performance

| Model | Accuracy | F1 |
|---|---|---|
| LightGBM | 97.0 % | 97.0 % |
| XGBoost | 96.7 % | 96.7 % |
| **Ensemble (avg prob)** | **97.2 %** | **97.2 %** |

Evaluated on 2 000-sample held-out test set. Training data: synthetic events with CIC-IDS2017-compatible feature distributions (`data/labeled_logs.csv`). Compatible with [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — replace CSVs and rerun `python utils/train_ml_engine.py`.

---

## Project Structure

```
TrustFlow/
├── api/
│   └── main.py                    # FastAPI app — all REST + WebSocket routes
│
├── src/                           # Core Python modules
│   ├── database.py                # SQLAlchemy ORM (PostgreSQL); all models + migrations
│   ├── auth.py                    # JWT auth; require_admin() dependency
│   ├── api_keys.py                # tf_live_* key generation, sha256 hash, validation
│   ├── redis_cache.py             # Redis helpers + sliding-window rate limiter
│   ├── ingestion_service.py       # Background log ingestion worker
│   ├── bootstrap_admin.py         # First-admin CLI (interactive)
│   │
│   ├── ml_engine.py               # LightGBM attack classifier
│   ├── ensemble_engine.py         # XGBoost training + LGBM/XGB ensemble
│   ├── zero_day_detector.py       # DBSCAN zero-day clustering
│   ├── sequence_anomaly.py        # Transformer sequence anomaly (Keras)
│   ├── anomaly_detection.py       # TF Autoencoder anomaly detection
│   ├── model_tf.py                # TF model helpers
│   ├── threat_predictor.py        # Unified prediction pipeline
│   │
│   ├── threat_intel.py            # AbuseIPDB lookup + Redis cache
│   ├── threat_intel_extended.py   # OTX + VirusTotal integration
│   ├── osint_feeds.py             # Tor exit nodes, ET rules, URLhaus
│   ├── stix_taxii.py              # STIX 2.1 / TAXII 2.1 feed (opt-in)
│   │
│   ├── response_engine.py         # SOAR built-in automation
│   ├── soar_playbooks.py          # 15 conditional playbooks
│   ├── playbook_runner.py         # Custom playbook executor (7 step types)
│   │
│   ├── attack_graph.py            # NetworkX kill-chain builder
│   ├── attack_graph_neo4j.py      # Neo4j backend (opt-in)
│   ├── mitre_mapping.py           # MITRE ATT&CK technique database
│   ├── ueba.py                    # User & Entity Behavior Analytics
│   │
│   ├── siem_export.py             # SIEM connector (Splunk/Elastic/Datadog/Webhook)
│   ├── compliance_report.py       # SOC 2 / ISO 27001 evidence generator
│   ├── kafka_stream.py            # Kafka streaming producer (opt-in)
│   │
│   ├── explainability.py          # Feature importance pipeline
│   ├── explainability_shap.py     # SHAP TreeExplainer
│   ├── context_analysis.py        # Contextual risk analysis
│   ├── feedback_loop.py           # Analyst feedback + drift detection
│   ├── adversarial_test.py        # 5 evasion technique tests
│   ├── risk_scoring.py            # Risk score calculation
│   └── log_parser.py              # Raw log → structured event
│
├── frontend/                      # React 19 + Vite
│   └── src/
│       ├── pages/
│       │   ├── DashboardPage.jsx          # KPIs, live feed, charts
│       │   ├── ApplicationsPage.jsx       # App grid + Create modal
│       │   ├── ApplicationDetailPage.jsx  # Stats, API keys, SDK snippets
│       │   ├── IncidentsPage.jsx          # Incident list + detail
│       │   ├── AttackGraphPage.jsx        # D3 kill-chain graph
│       │   ├── ThreatIntelPage.jsx        # IP / domain reputation lookup
│       │   ├── ApiKeysPage.jsx            # API key management
│       │   ├── IntegrationGuidePage.jsx   # SDK setup guide
│       │   ├── NotificationsPage.jsx      # Alert channels + SIEM config
│       │   ├── PlaybookBuilderPage.jsx    # Visual custom playbook editor
│       │   ├── PlaybooksPage.jsx          # Built-in SOAR playbooks
│       │   ├── MLLabPage.jsx              # Ensemble + zero-day + sequence UI
│       │   ├── MLMetricsPage.jsx          # Model accuracy / confusion matrix
│       │   ├── ResponsePage.jsx           # Manual SOAR trigger
│       │   ├── InvestigationPage.jsx      # Deep incident investigation
│       │   ├── CompliancePage.jsx         # SOC 2 / ISO 27001 report viewer
│       │   ├── AdminUsersPage.jsx         # User promote/demote (admin only)
│       │   ├── LandingPage.jsx            # Public marketing page
│       │   ├── LoginPage.jsx
│       │   └── RegisterPage.jsx
│       └── components/
│           ├── Sidebar.jsx                # Role-based nav (Operations/Dev/Admin)
│           ├── AttackTimeline.jsx
│           ├── LiveFeed.jsx
│           ├── PredictionWidget.jsx
│           └── Badges.jsx
│
├── sdk/
│   ├── node/                      # @trustflow/sdk — Express middleware
│   └── python/                    # trustflow — Python HTTP client
│
├── utils/
│   ├── alert_dispatcher.py        # Multi-channel alert dispatch
│   ├── train_ml_engine.py         # LightGBM training script
│   └── ...
│
├── tests/                         # Pytest test suite
├── data/                          # ML models, threat-intel cache, logs
├── .github/workflows/ci.yml       # GitHub Actions CI
├── docker-compose.yml             # Production 5-service stack
├── Dockerfile.backend             # API + ingestion container
├── requirements.txt
└── .env.example                   # Environment variable template
```

---

## Quick Start

### Prerequisites

- Docker ≥ 24 and Docker Compose V2
- `POSTGRES_PASSWORD` and `JWT_SECRET_KEY` — see step 1

### 1. Clone and configure

```bash
git clone https://github.com/Muzzu077/Threat-Detection-and-Risk-Scoring.git
cd Threat-Detection-and-Risk-Scoring
cp .env.example .env
```

Open `.env` and set at minimum:

```env
POSTGRES_PASSWORD=<strong-random-password>
JWT_SECRET_KEY=<64-char-random-string>
# Generate the secret with:
# python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### 2. Start the stack

```bash
docker compose up -d
docker compose logs -f api        # watch until "Application startup complete"
```

Five containers start: `postgres`, `redis`, `api`, `ingestion`, `frontend`.

| Service | URL |
|---|---|
| Dashboard | http://localhost |
| REST API | http://localhost:8000 |
| Interactive API docs | http://localhost:8000/docs |

### 3. Create the first admin account

There is no seeded demo account. Run the bootstrap CLI once:

```bash
docker compose exec api python -m src.bootstrap_admin --email you@example.com
# You will be prompted for a password interactively.
```

Log in at http://localhost with that email/password. You will land on the Admin dashboard with full access to all pages.

### 4. Register an Application and generate an API key

1. **Applications → New Application** — give it a name and environment (`production` / `staging` / `development`).
2. **Application Detail → API Keys → Generate** — copy the `tf_live_...` key shown once.
3. Use the key to ship events from your web server (see SDK section below).

---

## SDK Integration

### Node.js (Express)

```bash
cd sdk/node && npm install
```

```javascript
const { trustFlowMiddleware } = require('./sdk/node/express');

app.use(trustFlowMiddleware({
  apiKey:   process.env.TRUSTFLOW_API_KEY,   // tf_live_... key from the dashboard
  endpoint: 'http://localhost:8000',          // or your production host
}));
```

Every incoming HTTP request is captured and forwarded automatically.

### Python

```bash
pip install -e sdk/python
```

```python
from trustflow import TrustFlow

tf = TrustFlow(
    api_key  = os.environ['TRUSTFLOW_API_KEY'],
    endpoint = 'http://localhost:8000',
)

# Log a single event manually:
tf.log(user='alice', ip='1.2.3.4', action='GET /admin', status=403)
```

### Raw HTTP

```bash
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "X-API-Key: tf_live_..." \
  -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "user": "alice",
      "ip":   "1.2.3.4",
      "action": "GET /admin",
      "status": 403,
      "timestamp": "2026-04-28T10:00:00Z"
    }]
  }'
```

---

## Environment Variables

Copy `.env.example` to `.env`. Full reference:

| Variable | Required | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | **yes** | Database password |
| `JWT_SECRET_KEY` | **yes** | JWT signing secret (64+ random chars) |
| `POSTGRES_DB` / `POSTGRES_USER` | no | Default `trustflow` / `trustflow` |
| `REDIS_URL` | no | Default `redis://localhost:6379/0` |
| `OPENROUTER_API_KEY` | no | AI-generated incident summaries |
| `ABUSEIPDB_API_KEY` | no | IP reputation (AbuseIPDB) |
| `OTX_API_KEY` | no | Threat feed (AlienVault OTX) |
| `VIRUSTOTAL_API_KEY` | no | File/URL/IP reputation |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | no | Global Telegram alerts |
| `TWILIO_ACCOUNT_SID` + `TWILIO_AUTH_TOKEN` + `TO_WHATSAPP` | no | Global WhatsApp alerts |
| `ENABLE_TELEGRAM` / `ENABLE_WHATSAPP` / `ENABLE_EMAIL` | no | Channel toggles (default `false`) |
| `SMTP_HOST` + `SMTP_PORT` + `SMTP_USER` + `SMTP_PASS` | no | Email alert SMTP config |
| `SLACK_WEBHOOK_URL` | no | Slack alerts |
| `ALERT_WEBHOOK_URL` | no | Generic webhook alerts |
| `VITE_API_URL` | no | Frontend build-time API origin |
| `KAFKA_BROKERS` | no | Enable Kafka streaming (e.g. `broker:9092`) |
| `KAFKA_EVENTS_TOPIC` | no | Default `trustflow.events` |
| `NEO4J_URI` + `NEO4J_USER` + `NEO4J_PASSWORD` | no | Enable Neo4j attack-graph backend |
| `TAXII_SERVER_URL` + `TAXII_USERNAME` + `TAXII_PASSWORD` | no | Enable STIX/TAXII feed |
| `TAXII_COLLECTIONS` | no | Comma-separated collection IDs to pull |
| `API_KEY_RATE_LIMIT_REQUESTS` | no | Requests per window (default `1000`) |
| `API_KEY_RATE_LIMIT_WINDOW` | no | Window in seconds (default `60`) |

---

## API Reference

Base URL: `http://localhost:8000` · Swagger UI: `/docs`

### Auth

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Register a new tenant user |
| `POST` | `/api/auth/login` | JWT login — returns `access_token` |
| `GET` | `/api/auth/me` | Current user profile |

### Events & Incidents

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/ingest` | Ingest events from SDK (`X-API-Key` header) |
| `GET` | `/api/events` | Paginated log events (tenant-scoped) |
| `GET` | `/api/stats` | KPI summary (total events, incidents, risk avg) |
| `GET` | `/api/incidents` | Incident list with filters |
| `GET` | `/api/incidents/{id}` | Single incident |
| `POST` | `/api/incidents/{id}/status` | Update incident status |
| `POST` | `/api/incidents/{id}/feedback` | Analyst FP/TP feedback |
| `GET` | `/api/mttd-mttr` | MTTD / MTTR metrics and trends |
| `WS` | `/ws/live-feed` | WebSocket — real-time event stream |

### Applications

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/applications` | List your applications |
| `POST` | `/api/applications` | Create an application |
| `GET` | `/api/applications/{id}` | Application detail + stats |
| `PUT` | `/api/applications/{id}` | Update application |
| `DELETE` | `/api/applications/{id}` | Archive application |

### API Keys

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/keys` | List API keys |
| `POST` | `/api/keys` | Generate a new API key |
| `DELETE` | `/api/keys/{id}` | Revoke an API key |

### Threat Intelligence

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/threat-intel/{ip}` | AbuseIPDB + OTX + VirusTotal reputation |
| `GET` | `/api/stix/indicators` | Cached STIX IOC set |
| `POST` | `/api/stix/pull` | Pull fresh indicators from TAXII server |

### ML & Analytics

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/ml-metrics` | Accuracy, F1, confusion matrix |
| `GET` | `/api/ml/ensemble` | Latest ensemble metrics comparison |
| `POST` | `/api/ml/ensemble/train` | Trigger XGBoost training + ensemble eval |
| `POST` | `/api/ml/zero-day` | Run DBSCAN zero-day clustering |
| `POST` | `/api/ml/sequence-anomaly` | Score user sessions (transformer) |
| `POST` | `/api/ml/sequence-anomaly/train` | Re-train sequence model |
| `GET` | `/api/explainability` | SHAP feature importance |
| `GET` | `/api/ueba/{username}` | User behaviour profile |

### Attack Graph

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/attack-graph` | NetworkX graph (nodes + links) |
| `GET` | `/api/attack-graph/neo4j` | Neo4j graph (when configured) |
| `GET` | `/api/attack-chains` | Detected kill chains |
| `GET` | `/api/mitre/mapping` | MITRE ATT&CK technique lookup |

### SOAR & Playbooks

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/response/{id}` | Trigger built-in SOAR response |
| `GET` | `/api/playbooks/custom` | List custom playbooks |
| `POST` | `/api/playbooks/custom` | Create a custom playbook |
| `PUT` | `/api/playbooks/custom/{id}` | Update a custom playbook |
| `DELETE` | `/api/playbooks/custom/{id}` | Delete a custom playbook |
| `POST` | `/api/playbooks/custom/{id}/dry-run` | Dry-run against a sample event |

### Notifications & SIEM

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/notifications/preferences` | Your alert channel config |
| `PUT` | `/api/notifications/preferences` | Update channels / SIEM settings |
| `POST` | `/api/notifications/test` | Send a test alert |
| `POST` | `/api/siem/test` | Test SIEM connectivity |

### Compliance

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/compliance/report` | Generate SOC 2 or ISO 27001 evidence report |

Query params: `framework=soc2\|iso27001`, `days=30\|60\|90`.

### Admin (admin role required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/users` | List all tenant users |
| `POST` | `/api/admin/users/{id}/role` | Promote / demote user role |

---

## Role-Based Access Control

| Page / Feature | Normal User | Admin |
|---|---|---|
| Dashboard, Incidents, Attack Graph | ✅ | ✅ |
| Threat Intel, API Keys, Integration | ✅ | ✅ |
| Applications | ✅ | ✅ |
| Notifications, Custom Playbooks | ✅ | ✅ |
| ML Engine, ML Lab | — | ✅ |
| SOAR (built-in playbooks) | — | ✅ |
| Compliance Reports | — | ✅ |
| Admin Users page | — | ✅ |

---

## CI / CD

GitHub Actions runs on every push to `main` and on every pull request:

```
.github/workflows/ci.yml
├── backend   — ruff lint + pytest (in-memory SQLite, no Docker needed)
├── frontend  — npm ci + vite build + artifact upload
└── docker    — docker buildx smoke build (GHA layer cache)
```

All three jobs must pass before a PR can merge.

---

## Deployment (Dokploy / Docker)

TrustFlow ships as a standard Docker Compose stack. Any platform that can run Compose works (Dokploy, Coolify, Portainer, plain VPS).

### Dokploy (recommended)

1. **Create three App services** in Dokploy pointing at this repo:
   - `api` → build context `.`, Dockerfile `Dockerfile.backend`, start command `uvicorn api.main:app --host 0.0.0.0 --port 8000`
   - `ingestion` → same image, start command `python -m src.ingestion_service`
   - `frontend` → build context `./frontend`, Dockerfile `frontend/Dockerfile.frontend`
2. **Add managed PostgreSQL** (Dokploy built-in) and set `DATABASE_URL`.
3. **Add managed Redis** and set `REDIS_URL`.
4. **Set environment variables** from `.env.example` in each service's env panel.
5. Deploy. Dokploy handles SSL via Let's Encrypt automatically.

### Plain VPS

```bash
git clone https://github.com/Muzzu077/Threat-Detection-and-Risk-Scoring.git
cd Threat-Detection-and-Risk-Scoring
cp .env.example .env          # fill in POSTGRES_PASSWORD + JWT_SECRET_KEY
docker compose up -d --build
docker compose exec api python -m src.bootstrap_admin --email admin@example.com
```

---

## Optional Scale-Out (Phase 4)

All Phase 4 integrations are opt-in — the default 5-container stack keeps running unchanged when these env vars are blank.

### Kafka Streaming

Set `KAFKA_BROKERS=broker1:9092,broker2:9092`. Every ingested event is published to the `trustflow.events` topic (partitioned by `tenant_id`). Consumer groups can be attached for downstream analytics, data lakes, or sibling SOC platforms.

### Neo4j Attack Graph

Set `NEO4J_URI=bolt://host:7687` + `NEO4J_USER` + `NEO4J_PASSWORD`. Events with `risk_score ≥ 30` are mirrored to Neo4j. The `/api/attack-graph/neo4j` endpoint serves the graph database; NetworkX keeps serving as fallback when unset.

### STIX / TAXII Threat Feed

Set `TAXII_SERVER_URL` (and optionally `TAXII_USERNAME` / `TAXII_PASSWORD` / `TAXII_COLLECTIONS`). The platform pulls indicator bundles, parses IPv4, IPv6, domain, URL, and file-hash IOCs, and caches them in Redis for 6 hours. The IP-reputation lookup path consults this cache before hitting AbuseIPDB / OTX / VirusTotal, saving API quota and adding a private feed layer.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite, Recharts, D3.js |
| Backend | FastAPI (Python 3.11), Uvicorn |
| ML | LightGBM, XGBoost, TensorFlow / Keras, SHAP, HDBSCAN |
| Database | PostgreSQL 16 (SQLAlchemy ORM) |
| Cache / Rate-limit | Redis 7 |
| Auth | JWT (PyJWT) + bcrypt |
| Alerts | Telegram Bot API, Twilio WhatsApp, SMTP, Slack Webhook |
| AI Summaries | OpenRouter (Llama-3.3-70B class) |
| Threat Intel | AbuseIPDB, AlienVault OTX, VirusTotal, OSINT feeds |
| SIEM | Splunk HEC, Elasticsearch, Datadog, Generic Webhook (CEF) |
| Streaming | Apache Kafka (aiokafka) |
| Graph DB | Neo4j 5 (optional) + NetworkX (default) |
| Threat Feed | STIX 2.1 / TAXII 2.1 (taxii2-client) |
| CI/CD | GitHub Actions |
| Deployment | Docker Compose, Dokploy |
| SDK | Node.js (Express middleware), Python |

---

## License

MIT — see [LICENSE](LICENSE).
