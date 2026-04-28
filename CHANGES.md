# TrustFlow — Complete Change Log

> Comprehensive record of every change made to the project across all sessions —
> code, infrastructure, deployment, and operational fixes.
>
> Project: **Threat-Detection-and-Risk-Scoring** (rebranded from ThreatPulse → TrustFlow)
> Repository: <https://github.com/Muzzu077/Threat-Detection-and-Risk-Scoring>
> Owner: Muzzu077
> Time period: **2026-04-27 → 2026-04-28**

---

## Table of Contents

1. [High-Level Summary](#1-high-level-summary)
2. [Phase 1–4 SaaS Roadmap (60fea96)](#2-phase-14-saas-roadmap-60fea96)
3. [Bootstrap Admin CLI (d742989)](#3-bootstrap-admin-cli-d742989)
4. [Python SDK Rename (c199179)](#4-python-sdk-rename-c199179)
5. [README Rewrite (a8e287c)](#5-readme-rewrite-a8e287c)
6. [Dokploy Compose File (50b2001)](#6-dokploy-compose-file-50b2001)
7. [Container Startup Script (fecb86f)](#7-container-startup-script-fecb86f)
8. [Node SDK npm Publish (228758e)](#8-node-sdk-npm-publish-228758e)
9. [Frontend nginx Crash Fix (9c1a404)](#9-frontend-nginx-crash-fix-9c1a404)
10. [CORS + Imports + CI Test Fix (efd3bce)](#10-cors--imports--ci-test-fix-efd3bce)
11. [**SERVER / DOKPLOY DEPLOYMENT — full record**](#11-server--dokploy-deployment--full-record)
12. [Production URLs & Credentials](#12-production-urls--credentials)
13. [Verification Commands](#13-verification-commands)
14. [Outstanding / Optional Next Steps](#14-outstanding--optional-next-steps)

---

## 1. High-Level Summary

| Area | Change | Status |
|------|--------|--------|
| **SaaS Roadmap (Phases 1–4)** | Multi-tenant Applications, RBAC, ML ensemble (97.2%), zero-day clustering, SOAR playbooks, SIEM export, compliance, Kafka, STIX/TAXII, Neo4j | ✅ Shipped |
| **GitHub Actions CI** | Backend lint+tests, Frontend build, Docker smoke build | ✅ Green after `efd3bce` |
| **Node SDK** | `trustflow-sdk@1.0.0` published to npm registry (Automation Token bypass for 2FA) | ✅ Live |
| **Python SDK** | Renamed `threatpulse → trustflow`, untracked package files committed | ✅ Importable |
| **Documentation** | Full README rewrite covering all four phases | ✅ Merged |
| **Dokploy Deployment** | 5 services deployed via tRPC API: API, Ingestion, Frontend, Postgres, Redis | ✅ Live |
| **Bootstrap admin pattern** | `startup.sh` + ADMIN_EMAIL/ADMIN_PASSWORD env-driven admin promotion on first boot | ✅ Live |
| **CORS + lint + CI test failure** | Allow-list now env-driven; imports cleaned; `httpx` added to CI deps | ✅ Pushed |

Total commits authored: **9** (across 2 days)
Total files touched: **40+**
Live services: **5** (API + Ingestion + Frontend + Postgres + Redis)
External integrations: **npm registry**, **Dokploy panel**, **GitHub Actions**, **Traefik (Let's Encrypt → custom none)**

---

## 2. Phase 1–4 SaaS Roadmap (60fea96)

> Single largest commit. Implemented the full SaaS feature set across the backend, frontend, and ML pipeline.

### Phase 1 — Multi-Tenant Applications + RBAC

**Backend (`src/database.py`, `api/main.py`, `src/auth.py`)**
- New `Application` model with tenant scoping; events + API keys stamped with `application_id`.
- `_apply_tenant_filter()` helper enforces tenant isolation on every query.
- Full CRUD endpoints under `/api/applications/*` (list / detail / archive / regenerate key).
- New `require_admin()` dependency for admin-only endpoints.
- `Role` enum: `user` / `admin` (with implicit `developer` mapping handled in UI).

**Frontend (`frontend/src/pages/`)**
- `ApplicationsPage.jsx` — list view, create dialog, archive.
- `ApplicationDetailPage.jsx` — detail view, SDK install snippets (Python/Node), API key reveal, revoke.
- `AdminUsersPage.jsx` — promote/demote roles.
- `Sidebar.jsx` — three groups (Operations / Developer / Admin), `<AdminOnly>` wrapper hides admin links.

### Phase 2 — ML Ensemble + Zero-Day Detection

- `src/ensemble_engine.py` — XGBoost + LightGBM averaging ensemble (97.2% accuracy on benchmark).
- `src/zero_day_detector.py` — DBSCAN clustering on residual normal events with risk > 25.
- `src/sequence_anomaly.py` — Keras MultiHeadAttention transformer with heuristic fallback when TF unavailable.
- `MLLabPage.jsx` — train / score buttons, drift display, residual cluster table.
- `data/ml_ensemble_metrics.json` — checked-in benchmark snapshot.

### Phase 3 — SOAR + Compliance + SIEM

**SIEM Export** (`src/siem_export.py`)
- Splunk HEC, Elasticsearch `_bulk`, Datadog logs, generic webhook (CEF format).

**Visual Playbook Builder** (`PlaybookBuilderPage.jsx`, `src/playbook_runner.py`)
- 7 step types: `block_ip`, `disable_account`, `notify_telegram`, `notify_email`, `tag_incident`, `ml_score`, `webhook`.
- Drag-to-reorder, dry-run mode, live execution wired into ingestion path.

**Compliance** (`src/compliance_report.py`, `CompliancePage.jsx`)
- SOC 2 + ISO 27001 evidence report; 15 controls; browser-print → PDF.

**Per-User Notifications** (`utils/alert_dispatcher.py`, `src/database.py`)
- `NotificationPreference` model with Telegram / WhatsApp / Email / SIEM fields.
- Env-override dispatch pattern → multi-tenant routing without rewriting channel functions.
- Severity threshold gating; `/api/notifications/test` endpoint.

### Phase 4 — Scale-Out (opt-in via env)

- `src/kafka_stream.py` — aiokafka singleton, fire-and-forget, fail-open.
- `src/stix_taxii.py` — STIX 2.1 / TAXII 2.1 feed, Redis 6h cache.
- `src/attack_graph_neo4j.py` — Neo4j backend with NetworkX fallback.

### CI/CD (`.github/workflows/ci.yml`)

Three jobs:
1. **Backend (lint + tests)** — ruff + pytest with SQLite in-memory DB.
2. **Frontend (build)** — Node 20, vite build, artifact upload (`frontend-dist`).
3. **Docker images (smoke build)** — gated on the first two passing.

---

## 3. Bootstrap Admin CLI (d742989)

**File:** `src/bootstrap_admin.py`

CLI tool to create the first admin user without committing creds to repo.
- Prompts for password interactively (with confirmation) by default.
- Accepts `--password` for non-interactive use (used by `startup.sh`).
- `--force` flag promotes an existing user to admin.
- Idempotent.

**Runtime usage (in container):**
```bash
docker compose exec api python -m src.bootstrap_admin --email you@example.com
```

This replaced the deleted `seed_demo_account.py` pattern — credentials are no longer committed anywhere in the repo.

---

## 4. Python SDK Rename (c199179)

**Background:** The earlier rebrand from `threatpulse → trustflow` deleted `sdk/python/threatpulse/` but the new `sdk/python/trustflow/` files were left **untracked**. A clean checkout broke `from trustflow import TrustFlow`.

**Fix:** Committed:
- `sdk/python/trustflow/__init__.py`
- `sdk/python/trustflow/client.py` (115 lines)
- `sdk/python/trustflow/middleware.py` (73 lines)

---

## 5. README Rewrite (a8e287c)

**Before:** Old hackathon-pitch description; 190 lines.
**After:** 655 lines documenting:
- Architecture diagram + data flow
- Feature matrix across all four phases
- 15 attack classes table
- ML performance breakdown (97.2% ensemble)
- Full API reference (50+ endpoints)
- RBAC role table
- CI/CD pipeline
- **Dokploy deployment guide**
- Optional Scale-Out section (Kafka, STIX, Neo4j)
- SDK install snippets (`pip install trustflow-sdk`, `npm install trustflow-sdk`)

Companion commit `1642681` removed the obsolete `PROJECT_EXPLANATION.md` (782 lines).

---

## 6. Dokploy Compose File (50b2001)

**File:** `docker-compose.dokploy.yml`

The standard `docker-compose.yml` includes managed `postgres` and `redis` services, which would conflict with Dokploy's already-provisioned managed databases.

The Dokploy variant defines **only** application containers:
- `api` — FastAPI backend on port 8000
- `ingestion` — Worker (`python -m src.ingestion_service`)
- `frontend` — React build on port 3000:80

All three share volumes for `./data`, `./logs_ingest`, `./models`. Postgres + Redis are referenced via env URLs pointing at Dokploy-managed services.

---

## 7. Container Startup Script (fecb86f)

**File:** `startup.sh`

```bash
#!/bin/bash
if [ -n "$ADMIN_EMAIL" ] && [ -n "$ADMIN_PASSWORD" ]; then
    python -m src.bootstrap_admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD" --force
fi
exec uvicorn api.main:app --host 0.0.0.0 --port 8000
```

**Why:** Dokploy doesn't give an interactive shell during build, so the chicken-and-egg of "admin promotion needs an admin" was unsolvable. This:
1. Bootstraps an admin on first boot when `ADMIN_EMAIL` + `ADMIN_PASSWORD` are set.
2. `exec uvicorn` keeps the process as PID 1 — without `exec`, the bash wrapper survives but uvicorn dies on signal forwarding gaps and the container restarts in a loop.

**Dockerfile.backend** updated to:
```dockerfile
COPY startup.sh /app/startup.sh
RUN chmod +x /app/startup.sh
CMD ["/app/startup.sh"]
```

---

## 8. Node SDK npm Publish (228758e)

**File:** `sdk/node/package.json`

Fixed three issues so `npm install trustflow-sdk` works for end users:

| Field | Before | After |
|------|--------|------|
| `repository.url` | `https://github.com/Muzammil-Threat-Detection-and-Risk-Scoring` (malformed) | `git+https://github.com/Muzzu077/Threat-Detection-and-Risk-Scoring.git` |
| `repository.directory` | _missing_ | `sdk/node` |
| `homepage` | _missing_ | `https://github.com/Muzzu077/Threat-Detection-and-Risk-Scoring#readme` |
| `bugs.url` | _missing_ | `https://github.com/Muzzu077/Threat-Detection-and-Risk-Scoring/issues` |

**Publish process (post-commit):**

1. `npm login` — browser-based session via npmjs.com OAuth.
2. **First attempt:** `npm publish --access public` → 403 (2FA required even after login).
3. **OTP attempt:** `npm publish --access public --otp=...` → 403 (newer npm requires automation token, not just OTP, when 2FA is enabled).
4. **Resolution:** Generated an **Automation Token** at <https://www.npmjs.com/settings/muzzu07/tokens>, set it via `npm set //registry.npmjs.org/:_authToken=npm_...`, then `npm publish --access public` succeeded.

**Result:** `trustflow-sdk@1.0.0` is **live** on the npm registry.

```bash
$ npm view trustflow-sdk version
1.0.0
```

---

## 9. Frontend nginx Crash Fix (9c1a404)

**File:** `frontend/nginx.conf`

**Symptom:** Frontend container in Dokploy stuck in `Exited (1)` crash-loop. Domain `trustflow.welocalhost.com` returned **502 Bad Gateway**.

**Root cause:** nginx.conf had:
```nginx
location /api/ {
    proxy_pass http://api:8000;     # <— DNS lookup at startup
}
location /ws/ {
    proxy_pass http://api:8000;
}
```
nginx resolves upstream hostnames at startup (not request time). In **local docker-compose**, the service `api` exists on the bridge network. In **Dokploy/Swarm**, the service is named `app-reboot-wireless-microchip-rqctt8-api` (or similar generated name), so DNS lookup fails and nginx exits 1 immediately.

**Fix:** Removed both `proxy_pass` blocks. The frontend uses `VITE_API_URL` injected at build time, so the browser hits the API domain directly. nginx now only serves static files with SPA fallback.

```nginx
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

---

## 10. CORS + Imports + CI Test Fix (efd3bce)

### Symptom A — Browser register/login failed silently
The deployed frontend (`https://trustflow.welocalhost.com`) couldn't create users. Hitting the API directly with curl worked fine.

**Root cause:** `api/main.py` had a hardcoded CORS allow-list:
```python
allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"]
```
Browser preflight requests from `https://trustflow.welocalhost.com` were blocked.

**Fix:** Allow-list now reads from `CORS_ALLOWED_ORIGINS` env var (comma-separated), with the localhost defaults preserved when unset:
```python
_cors_default = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"
_cors_env = os.getenv("CORS_ALLOWED_ORIGINS", _cors_default)
_cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
```
Dokploy's API service env was extended with:
```
CORS_ALLOWED_ORIGINS=https://trustflow.welocalhost.com,http://trustflow.welocalhost.com,http://localhost:5173,http://localhost:3000
```

### Symptom B — CI Backend job failing with exit code 2
GitHub Actions Backend job consistently red on every push.

**Root cause:** `tests/test_api_endpoints.py` collection error:
```
RuntimeError: The starlette.testclient module requires the httpx package to be installed.
```
`httpx` wasn't in `requirements.txt` or in CI's explicit test deps.

**Fix:** Appended `httpx` to the CI test install line in `.github/workflows/ci.yml`:
```yaml
pip install ruff pytest pytest-cov httpx
```

### Symptom C — ruff lint annotations red across the run
9 errors in `api/main.py`:
- `E402` — module imports below `sys.path.append` and `load_dotenv` calls.
- `F401` — `JSONResponse`, `EmailStr`, `get_current_user_optional`, `datetime.timezone` imported but unused.
- `F821` — `LogEvent` referenced in ML metrics endpoint but **never imported** (a real runtime bug — would 500 on `/api/ml/metrics`).
- 3× E402 from mid-file `_re` / `_random` / `_url_decode` imports near line 791.

**Fix:** Reorganized imports cleanly:
1. `sys` + `os` first.
2. `sys.path.append()` to expose project root.
3. `load_dotenv()`.
4. Stdlib + 3rd-party imports (`asyncio`, `json`, `re`, `random`, `urllib.parse.unquote`, `pandas`, `fastapi`, `pydantic`).
5. Project imports (`src.*`, `utils.*`) with `# noqa: E402` since they require `sys.path.append` to have run.
6. Removed unused: `EmailStr`, `JSONResponse`, `get_current_user_optional`.
7. **Added missing `LogEvent` import** to fix the F821 (and the runtime bug).

Also dropped unused `import pytest` from `tests/test_sdk_python.py`.

**Result:** `ruff check api/main.py` now reports **All checks passed!** locally.

---

## 11. SERVER / DOKPLOY DEPLOYMENT — full record

> **This is the section the user asked to be most detailed.** Every change made to the live server, in chronological order, including the failures and recoveries.

### 11.1 Environment Snapshot

| Item | Value |
|------|-------|
| **Dokploy panel** | <https://dokploy.welocalhost.com/dashboard/projects> |
| **Server IP** | `178.16.137.247` |
| **Dokploy version** | v0.28.8 |
| **Auth provider** | better-auth (session cookie: `better-auth.session_token`) |
| **API style** | tRPC at `/api/trpc/*` |
| **Reverse proxy** | Traefik (rules in `/etc/dokploy/traefik/dynamic/`) |
| **TLS** | Let's Encrypt (initially) → switched to `none` (Traefik default cert) for IP-based testing prior to DNS |
| **Dokploy login** | `muzzammilmuzzu860@gmail.com` / `Muzzu6373M` |

### 11.2 Project + Services Created

A single Dokploy **Project** named `TrustFlow` with description "AI-Powered Cyber Defense Platform" — `projectId: 6k3IBjqPyGOsK85AJIPV-`.

Five services were created in the `production` environment (`environmentId: AT38HJj-O_DGqTOpqR4GB`):

| Service | Type | Service ID | Domain | Internal Port |
|---------|------|-----------|--------|---------------|
| `TrustFlow-API` | Application (Dockerfile) | `0uQF8n40oB5J2_980szDb` | `trustflowapi.welocalhost.com` | 8000 |
| `TrustFlow-Ingestion` | Application (Dockerfile) | `FKKdAP_ibHS0BfD3NBisU` | _(none — worker)_ | n/a |
| `TrustFlow-Frontend` | Application (Dockerfile) | `xiYpkpMKGJAq-jR4ZaQtn` | `trustflow.welocalhost.com` | 80 (after fix) |
| `TrustFlow-Postgres` | Managed Postgres | `mCrP6E4FCk65xVvTJ1KXr` | _(internal)_ | 5432 |
| `TrustFlow-Redis` | Managed Redis | `clRsS1431x8NIoFSK8xHe` | _(internal)_ | 6379 |

### 11.3 Database & Redis (managed by Dokploy)

**Postgres:**
- Internal hostname: `datapulse-datapulse-ieqn6d`
- Database: `trustflow`
- User: `Muzammil`
- Password: `Muzzu6373M`
- Connection URL (used in API env): `postgresql://Muzammil:Muzzu6373M@datapulse-datapulse-ieqn6d:5432/trustflow`

**Redis:**
- Internal hostname: `redis-parse-solid-state-application-ik9dxo`
- Connection URL: `redis://redis-parse-solid-state-application-ik9dxo:6379/0`

### 11.4 GitHub Source Configuration

All three application services use:
- **Source:** GitHub
- **Repository:** `Muzzu077/Threat-Detection-and-Risk-Scoring`
- **Branch:** `main`
- **Build type:** `dockerfile`
- **GitHub provider ID:** `2UbSJrY09CtI6C3qqRtqV` (had to be set explicitly on the second/third app — was None initially, blocking GitHub access)

| Service | Dockerfile path | Context |
|---------|-----------------|---------|
| API | `Dockerfile.backend` | `.` (repo root) |
| Ingestion | `Dockerfile.backend` | `.` (repo root) |
| Frontend | `frontend/Dockerfile.frontend` | `frontend` |

### 11.5 Environment Variables Set on Each Service

**TrustFlow-API + TrustFlow-Ingestion:**
```
DATABASE_URL=postgresql://Muzammil:Muzzu6373M@datapulse-datapulse-ieqn6d:5432/trustflow
REDIS_URL=redis://redis-parse-solid-state-application-ik9dxo:6379/0
JWT_SECRET_KEY=BU0xf3e3JfOio0pUiF0AfeI5B1RthiTdtKtz7VhzKEXd5Tscbfkk8K5ljoh98YZoGCdwcvFTc-HpEPABI8eVYQ
POSTGRES_PASSWORD=Muzzu6373M
ADMIN_EMAIL=admin@trustflow.com
ADMIN_PASSWORD=TrustFlow2026!
OPENROUTER_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
VIRUSTOTAL_API_KEY=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
ENABLE_TELEGRAM=false
ENABLE_WHATSAPP=false
ENABLE_EMAIL=false
KAFKA_BROKERS=
NEO4J_URI=
CORS_ALLOWED_ORIGINS=https://trustflow.welocalhost.com,http://trustflow.welocalhost.com,http://localhost:5173,http://localhost:3000   # ← added in last fix
```

**TrustFlow-Frontend:**
```
VITE_API_URL=https://trustflowapi.welocalhost.com
```
(originally was set to `https://dokploy.welocalhost.com` by mistake — corrected to the real API domain.)

### 11.6 Traefik Routing

Dokploy auto-generated `/etc/dokploy/traefik/dynamic/app-reboot-wireless-microchip-rqctt8.yml` (frontend) and a corresponding file for the API. Sample (frontend, **after the port fix**):

```yaml
http:
  routers:
    app-reboot-wireless-microchip-rqctt8-router-127:
      rule: Host(`trustflow.welocalhost.com`)
      service: app-reboot-wireless-microchip-rqctt8-service-127
      middlewares:
        - redirect-to-https
      entryPoints: [web]
    app-reboot-wireless-microchip-rqctt8-router-websecure-127:
      rule: Host(`trustflow.welocalhost.com`)
      service: app-reboot-wireless-microchip-rqctt8-service-127
      entryPoints: [websecure]
  services:
    app-reboot-wireless-microchip-rqctt8-service-127:
      loadBalancer:
        servers:
          - url: http://app-reboot-wireless-microchip-rqctt8:80   # ← was :3000 before fix
        passHostHeader: true
```

### 11.7 Domain Changes

| Old | New | Reason |
|-----|-----|--------|
| `api.welocalhost.com` (initial draft) | `trustflowapi.welocalhost.com` | User requested explicit project naming in subdomain. |
| `api.dokploy.welocalhost.com` | `trustflowapi.welocalhost.com` | Same — avoid the dokploy admin subdomain prefix. |
| Frontend domain port `3000` | `80` | Container's nginx EXPOSE is 80; the original Dokploy default of 3000 was wrong, causing Traefik 502. |
| `certificateType: letsencrypt` | `certificateType: none` | Traefik couldn't issue certs against IP-based testing yet. Switched to none for IP-host-header testing. |

### 11.8 Failures Encountered & Fixed

Chronologically, every wrong field name / config error encountered with the Dokploy tRPC API:

| # | Mistake | Symptom | Fix |
|---|---------|---------|-----|
| 1 | Used field name `dockerfilePath` | Dokploy validation rejected payload | Correct field is `dockerfile` |
| 2 | Used field name `startCommand` | Dokploy ignored override | Correct field is `command` |
| 3 | Custom `command` field set on API → caused container to crash on Dokploy redeploy | API responded briefly then 502 cycle | Cleared `command` so Docker uses Dockerfile `CMD` directly (exec form, signal-stable) |
| 4 | Ingestion + Frontend created without `githubId` | `githubId: None` → no GitHub access during build | Set `githubId: 2UbSJrY09CtI6C3qqRtqV` on both |
| 5 | `docker-compose.yml` would conflict with managed Postgres/Redis | Duplicate service names | Created `docker-compose.dokploy.yml` (commit `50b2001`) — used as reference, but Dokploy actually deploys via per-service Dockerfile builds |
| 6 | Bootstrap admin needs an existing admin (chicken-and-egg) | `/api/admin/users/{id}/role` requires admin | `startup.sh` (commit `fecb86f`) bootstraps from `ADMIN_EMAIL`/`ADMIN_PASSWORD` env on first boot |
| 7 | npm publish E403 with OTP | `Two-factor authentication or granular access token with bypass 2fa enabled is required` | Switched to **Automation Token** instead of OTP |
| 8 | Frontend domain mapped to port 3000, but nginx EXPOSEs 80 | 502 Bad Gateway through Traefik | Updated Dokploy domain config: port 3000 → 80 |
| 9 | Frontend nginx config `proxy_pass http://api:8000` | nginx exit code 1 → container crash-loop | Removed `proxy_pass` blocks (commit `9c1a404`); frontend hits API via `VITE_API_URL` directly |
| 10 | Backend CORS allow-list hardcoded to localhost | Browser register/login from `trustflow.welocalhost.com` blocked silently | Made allow-list env-driven; set `CORS_ALLOWED_ORIGINS` in Dokploy (commit `efd3bce`) |
| 11 | CI Backend job failing — `httpx` missing | pytest collection error for `test_api_endpoints.py` | Added `httpx` to CI install line (commit `efd3bce`) |
| 12 | Hidden bug: `LogEvent` referenced but not imported | F821; `/api/ml/metrics` would 500 in prod | Added `LogEvent` to imports (commit `efd3bce`) |

### 11.9 Deployment Method

All five services were created and configured **entirely via the Dokploy tRPC HTTP API** (no UI clicks). Examples:

```bash
# Authenticate (better-auth session)
curl -X POST https://dokploy.welocalhost.com/api/auth/sign-in/email \
  -H "Content-Type: application/json" \
  -d '{"email":"...","password":"..."}'

# Create app
curl https://dokploy.welocalhost.com/api/trpc/application.create?batch=1 \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"0":{"json":{"name":"TrustFlow-API","environmentId":"...","dockerfile":"Dockerfile.backend",...}}}'

# Update env
curl -X POST https://dokploy.welocalhost.com/api/trpc/application.update?batch=1 \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"0":{"json":{"applicationId":"...","env":"KEY=value\n..."}}}'

# Trigger deploy
curl -X POST https://dokploy.welocalhost.com/api/trpc/application.deploy?batch=1 \
  -b cookies.txt \
  -d '{"0":{"json":{"applicationId":"..."}}}'
```

### 11.10 Cleanup of Other Services

User asked to remove all non-TrustFlow services from the panel. Work was done **only on TrustFlow** services — other projects (`acetechwebsite`, `aikyabuilders`, `chatjs`, `datapulse`, `edutou`, `landing`, `localhost-*`, `nstprojects`, `nunukkam-*`, `omshakthy`, `pocketdev`, `portfolio`, `supercampusai`) are visible in `/etc/dokploy/traefik/dynamic/` but were **not deleted** as the user later focused on TrustFlow specifically. Their Traefik configs remain on disk but routing is unaffected.

---

## 12. Production URLs & Credentials

### Public URLs (require DNS or `Host:` header against `178.16.137.247`)

| URL | Purpose |
|-----|---------|
| `https://trustflow.welocalhost.com` | React dashboard (frontend) |
| `https://trustflowapi.welocalhost.com` | FastAPI REST + WebSocket |
| `https://trustflowapi.welocalhost.com/health` | Liveness probe |
| `https://trustflowapi.welocalhost.com/docs` | Swagger UI |
| `https://trustflowapi.welocalhost.com/redoc` | ReDoc |

### Admin User (created on first container boot via `startup.sh`)

| Field | Value |
|-------|-------|
| Email | `admin@trustflow.com` |
| Password | `TrustFlow2026!` |
| Role | `admin` |

### Internal Service Endpoints (only reachable inside the Dokploy network)

| Service | URL |
|---------|-----|
| Postgres | `postgresql://Muzammil:Muzzu6373M@datapulse-datapulse-ieqn6d:5432/trustflow` |
| Redis | `redis://redis-parse-solid-state-application-ik9dxo:6379/0` |

### npm Registry

```bash
$ npm install trustflow-sdk
# trustflow-sdk@1.0.0
```

### JWT Secret (server-side only — never expose to clients)

```
JWT_SECRET_KEY=BU0xf3e3JfOio0pUiF0AfeI5B1RthiTdtKtz7VhzKEXd5Tscbfkk8K5ljoh98YZoGCdwcvFTc-HpEPABI8eVYQ
```

---

## 13. Verification Commands

Each command is what was actually used to confirm the fix in this session.

```bash
# 1. Frontend reachable
curl -sk -H "Host: trustflow.welocalhost.com" https://178.16.137.247/ \
  -o /dev/null -w "HTTP %{http_code}\n"
# → HTTP 200

# 2. API healthy
curl -sk -H "Host: trustflowapi.welocalhost.com" https://178.16.137.247/health
# → {"status":"healthy","timestamp":"2026-04-28T..."}

# 3. Swagger live
curl -sk -H "Host: trustflowapi.welocalhost.com" https://178.16.137.247/docs \
  -o /dev/null -w "HTTP %{http_code}\n"
# → HTTP 200

# 4. CORS preflight from frontend origin
curl -sk -i -H "Host: trustflowapi.welocalhost.com" \
  -H "Origin: https://trustflow.welocalhost.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS https://178.16.137.247/api/auth/login | grep access-control
# → access-control-allow-origin: https://trustflow.welocalhost.com

# 5. Browser-style register
curl -sk -H "Host: trustflowapi.welocalhost.com" \
  -H "Origin: https://trustflow.welocalhost.com" \
  -H "Content-Type: application/json" \
  -X POST https://178.16.137.247/api/auth/register \
  -d '{"email":"x@y.com","password":"Pass1234!","fullName":"X"}'
# → {"user":{...},"access_token":"...","refresh_token":"..."}

# 6. Admin login
curl -sk -H "Host: trustflowapi.welocalhost.com" \
  -H "Content-Type: application/json" \
  -X POST https://178.16.137.247/api/auth/login \
  -d '{"email":"admin@trustflow.com","password":"TrustFlow2026!"}'
# → {"user":{"role":"admin",...},"access_token":"..."}

# 7. npm SDK availability
npm view trustflow-sdk version
# → 1.0.0

# 8. Lint clean
~/.local/bin/ruff check api/main.py
# → All checks passed!
```

---

## 14. Outstanding / Optional Next Steps

These were called out during the session but were **not** the user's immediate priority.

| Item | What it unlocks | How to do it |
|------|-----------------|--------------|
| **DNS A records** for `trustflow.welocalhost.com` and `trustflowapi.welocalhost.com` → `178.16.137.247` | Public access without `Host:` header trick; lets Let's Encrypt issue real TLS certs | Add records with the `welocalhost.com` registrar; flip `certificateType` back to `letsencrypt` in Dokploy |
| Re-issue Let's Encrypt certificates | Browsers stop showing self-signed warnings | After DNS propagates: redeploy the API + Frontend in Dokploy with `certificateType: letsencrypt` |
| Clean up other Dokploy projects | Free server resources | User-driven; left alone since user only mentioned TrustFlow specifically |
| Remove `continue-on-error: true` from CI lint | Fail builds on style regressions | Once the existing 111 ruff warnings across the repo are addressed |
| `npm publish` automation in CI | One-click SDK releases | Store the npm Automation Token as a GH Actions secret; add a `release` workflow on tag push |

---

## 15. File-Level Diff Summary

| Commit | Files Added | Files Modified | Files Deleted |
|--------|-------------|----------------|---------------|
| `60fea96` | 18 | 10 | 0 |
| `c199179` | 3 | 0 | 0 |
| `1642681` | 0 | 0 | 1 |
| `d742989` | 1 | 0 | 0 |
| `a8e287c` | 0 | 1 | 0 |
| `50b2001` | 1 | 0 | 0 |
| `fecb86f` | 1 | 1 | 0 |
| `228758e` | 0 | 1 | 0 |
| `9c1a404` | 0 | 1 | 0 |
| `efd3bce` | 0 | 3 | 0 |
| **Total** | **24** | **17** | **1** |

---

## 16. Commit Quick-Reference

```
efd3bce 2026-04-28  fix(api): CORS allow-list from env + clean up imports
9c1a404 2026-04-28  fix: remove nginx upstream proxy blocks that break in Dokploy
228758e 2026-04-28  fix: correct repository URL and add homepage/bugs fields in Node SDK package.json
fecb86f 2026-04-28  feat: add startup.sh with optional admin bootstrap on first boot
50b2001 2026-04-28  feat: add Dokploy-specific compose file (no managed postgres/redis)
a8e287c 2026-04-28  docs: rewrite README with complete feature coverage
60fea96 2026-04-28  feat: complete SaaS roadmap — Phases 1-4
c199179 2026-04-27  fix: add renamed Python SDK package (sdk/python/trustflow/)
1642681 2026-04-27  chore: drop PROJECT_EXPLANATION.md hackathon-pitch doc
d742989 2026-04-27  feat: add bootstrap admin CLI
```

---

_Last updated: 2026-04-28_
_Maintainer: Muzammil ([@Muzzu077](https://github.com/Muzzu077))_
