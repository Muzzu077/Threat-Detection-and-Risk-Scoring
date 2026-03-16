"""
ThreatPulse FastAPI Backend
REST + WebSocket API for the React frontend dashboard.
Multi-tenant SaaS with JWT auth and API key support.
"""
import sys
import os
import json
import asyncio
from datetime import datetime
from typing import Optional, List
from contextlib import asynccontextmanager

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, UploadFile, File, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
import pandas as pd
import io
import time

from src.database import db, User, ApiKey
from src.auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    get_current_user, get_current_user_optional,
    revoke_refresh_token, validate_refresh_token,
)
from src.api_keys import generate_api_key, get_api_key_user
from src.attack_graph import build_graph, graph_to_json, get_attack_chains
from src.ml_engine import get_ml_metrics
from src.threat_intel import check_ip, get_known_bad_ips
from src.response_engine import execute_response, get_response_log, get_blocked_ips, get_disabled_accounts
from src.mitre_mapping import get_mitre_mapping, get_all_techniques
from src.explainability_shap import load_cached_shap, get_static_feature_importance
from src.threat_predictor import get_prediction_from_db_events
from src.ueba import analyze_event_ueba, get_user_profile, get_all_profiles
from src.soar_playbooks import get_all_playbooks, evaluate_playbook, execute_playbook
from src.osint_feeds import get_feed_summary, check_ip_osint, fetch_urlhaus_recent
from src.feedback_loop import record_feedback, get_feedback_stats, get_drift_metrics
from src.adversarial_test import run_adversarial_tests, get_cached_results
from src.threat_intel_extended import extended_check_ip, check_domain_virustotal
from utils.telegram_alerter import send_system_status, get_bot_info
from utils.log_parsers import parse_log_file
from utils.telegram_bot import start_polling_thread as start_telegram_bot

# ─── Helpers: tenant scoping ────────────────────────────────────────────────

def _tenant_args(user: User) -> dict:
    """Return tenant_id and user_role kwargs for DB queries."""
    if user is None:
        return {"tenant_id": None, "user_role": "admin"}
    return {"tenant_id": user.id, "user_role": user.role}

# ─── WebSocket Connection Manager ────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections[:]:
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# ─── Background Task: Event Broadcaster ──────────────────────────────────────

_last_broadcast_event_id = 0

async def broadcast_live_events():
    """Poll DB for new events and push to WebSocket clients."""
    global _last_broadcast_event_id
    while True:
        try:
            events, _ = db.fetch_events_paginated(page=1, limit=10, min_risk=0)
            new_events = []
            for e in events:
                if e.id > _last_broadcast_event_id:
                    new_events.append(e)
                    if e.id > _last_broadcast_event_id:
                        _last_broadcast_event_id = e.id

            for event in reversed(new_events):
                await manager.broadcast({
                    "type": "new_event",
                    "data": {
                        "id": event.id,
                        "timestamp": event.timestamp.isoformat(),
                        "user": event.user,
                        "action": event.action,
                        "ip": event.ip,
                        "risk_score": event.risk_score,
                        "attack_type": event.attack_type or "unknown",
                        "country": event.country or "UNKNOWN",
                        "status": event.status,
                        "resource": event.resource
                    }
                })
        except Exception:
            pass
        await asyncio.sleep(2)

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(broadcast_live_events())
    start_telegram_bot()
    yield
    task.cancel()

# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ThreatPulse API",
    description="AI-Powered Threat Detection and Risk Scoring Platform",
    version="3.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Pydantic Schemas ─────────────────────────────────────────────────────────

class StatusUpdate(BaseModel):
    status: str
    owner: Optional[str] = "Admin"

class ResponseTrigger(BaseModel):
    force: Optional[bool] = False

class LogEventSchema(BaseModel):
    timestamp: str
    user: str
    ip: str
    action: str
    status: str
    resource: str

class LogBatchSchema(BaseModel):
    events: List[LogEventSchema]

class RegisterRequest(BaseModel):
    email: str
    password: str
    display_name: Optional[str] = ""

class LoginRequest(BaseModel):
    email: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class LogoutRequest(BaseModel):
    refresh_token: str

class CreateApiKeyRequest(BaseModel):
    name: Optional[str] = "Default"

class IngestEvent(BaseModel):
    timestamp: str
    user: str
    ip: str
    action: str
    status: str
    resource: str

class IngestBatch(BaseModel):
    events: List[IngestEvent]

# ─── Helper: serialize ORM event ─────────────────────────────────────────────

def serialize_event(e) -> dict:
    return {
        "id": e.id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "user": e.user,
        "role": e.role,
        "ip": e.ip,
        "action": e.action,
        "status": e.status,
        "resource": e.resource,
        "risk_score": round(e.risk_score or 0, 1),
        "anomaly_score": round(e.anomaly_score or 0, 2),
        "attack_type": e.attack_type or "unknown",
        "ml_confidence": round(e.ml_confidence or 0, 1),
        "country": e.country or "UNKNOWN",
        "threat_intel_score": e.threat_intel_score or 0,
        "explanation": e.explanation or "",
    }

def serialize_incident(inc) -> dict:
    return {
        "id": inc.id,
        "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
        "status": inc.status,
        "owner": inc.owner,
        "note": inc.note or "",
        "risk_score": round(inc.risk_score or 0, 1),
        "user": inc.user,
        "action": inc.action,
        "attack_type": inc.attack_type or "unknown",
        "response_actions": inc.response_actions or "",
        "log_event_id": inc.log_event_id
    }

def serialize_user(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }

# ─── Auth Routes ─────────────────────────────────────────────────────────────

@app.post("/api/auth/register")
def auth_register(body: RegisterRequest):
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    existing = db.get_user_by_email(body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    pw_hash = hash_password(body.password)
    user = db.create_user(
        email=body.email,
        password_hash=pw_hash,
        display_name=body.display_name or body.email.split("@")[0],
    )
    access_token = create_access_token(user.id, user.email)
    refresh_token = create_refresh_token(user.id)
    return {
        "user": serialize_user(user),
        "access_token": access_token,
        "refresh_token": refresh_token,
    }

@app.post("/api/auth/login")
def auth_login(body: LoginRequest):
    user = db.get_user_by_email(body.email)
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    access_token = create_access_token(user.id, user.email)
    refresh_token = create_refresh_token(user.id)
    return {
        "user": serialize_user(user),
        "access_token": access_token,
        "refresh_token": refresh_token,
    }

@app.post("/api/auth/refresh")
def auth_refresh(body: RefreshRequest):
    user_id = validate_refresh_token(body.refresh_token)
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # Revoke old, issue new
    revoke_refresh_token(body.refresh_token)
    access_token = create_access_token(user.id, user.email)
    new_refresh = create_refresh_token(user.id)
    return {"access_token": access_token, "refresh_token": new_refresh}

@app.post("/api/auth/logout")
def auth_logout(body: LogoutRequest):
    revoke_refresh_token(body.refresh_token)
    return {"success": True}

@app.get("/api/auth/me")
def auth_me(current_user: User = Depends(get_current_user)):
    return {"user": serialize_user(current_user)}

# ─── API Key Routes ──────────────────────────────────────────────────────────

@app.post("/api/keys")
def create_api_key_endpoint(body: CreateApiKeyRequest, current_user: User = Depends(get_current_user)):
    full_key, prefix, key_hash = generate_api_key()
    session = db.Session()
    try:
        ak = ApiKey(
            user_id=current_user.id,
            name=body.name,
            prefix=prefix,
            key_hash=key_hash,
        )
        session.add(ak)
        session.commit()
        session.refresh(ak)
        return {
            "key": full_key,
            "prefix": prefix,
            "name": ak.name,
            "id": ak.id,
            "created_at": ak.created_at.isoformat() if ak.created_at else None,
        }
    finally:
        session.close()

@app.get("/api/keys")
def list_api_keys(current_user: User = Depends(get_current_user)):
    session = db.Session()
    try:
        keys = session.query(ApiKey).filter(
            ApiKey.user_id == current_user.id
        ).order_by(ApiKey.created_at.desc()).all()
        return {
            "data": [
                {
                    "id": k.id,
                    "name": k.name,
                    "prefix": k.prefix,
                    "created_at": k.created_at.isoformat() if k.created_at else None,
                    "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                    "is_active": k.is_active,
                }
                for k in keys
            ]
        }
    finally:
        session.close()

@app.delete("/api/keys/{key_id}")
def revoke_api_key(key_id: int, current_user: User = Depends(get_current_user)):
    session = db.Session()
    try:
        ak = session.query(ApiKey).filter(
            ApiKey.id == key_id,
            ApiKey.user_id == current_user.id,
        ).first()
        if not ak:
            raise HTTPException(status_code=404, detail="API key not found")
        ak.is_active = False
        session.commit()
        return {"success": True}
    finally:
        session.close()

# ─── SDK Ingest Endpoint ─────────────────────────────────────────────────────

def _parse_sdk_timestamp(ts_str: str):
    """Parse an ISO timestamp string into a datetime. Tolerates Z suffix and various formats."""
    if not ts_str:
        return datetime.utcnow()
    ts_str = ts_str.replace("Z", "+00:00")
    try:
        from datetime import timezone
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo:
            dt = dt.replace(tzinfo=None)  # store as naive UTC
        return dt
    except Exception:
        return datetime.utcnow()


def _map_http_status(status_str: str) -> str:
    """Normalize status values from SDK."""
    s = str(status_str).lower().strip()
    if s in ("success", "ok", "200", "201", "204", "301", "302"):
        return "success"
    if s in ("failure", "error", "fail", "denied"):
        return "failure"
    # If it looks like a numeric status code
    try:
        code = int(s)
        return "success" if 200 <= code < 400 else "failure"
    except ValueError:
        return s


import re as _re

# Patterns for lightweight threat detection on SDK-ingested events
_THREAT_PATTERNS = {
    "sql_injection": {
        "patterns": [r"['\"].*OR.*['\"]", r"UNION\s+SELECT", r"--\s*$", r"1\s*=\s*1", r"DROP\s+TABLE", r";\s*DELETE", r";\s*INSERT", r"SLEEP\(", r"BENCHMARK\("],
        "risk": 88, "confidence": 0.85,
    },
    "xss": {
        "patterns": [r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=", r"alert\(", r"document\.cookie", r"<img\s+src.*onerror"],
        "risk": 82, "confidence": 0.80,
    },
    "directory_traversal": {
        "patterns": [r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow", r"\.\.%2[fF]", r"/proc/self"],
        "risk": 78, "confidence": 0.82,
    },
    "command_injection": {
        "patterns": [r";\s*ls\b", r"\|\s*cat\b", r"&&\s*rm\b", r"`whoami`", r"\$\(id\)", r"\|\s*nc\s", r";\s*wget\s"],
        "risk": 90, "confidence": 0.88,
    },
    "port_scan": {
        "patterns": [r"/robots\.txt", r"/\.env", r"/\.git", r"/wp-admin", r"/phpinfo", r"/actuator", r"/\.htaccess", r"/server-status", r"/api-docs", r"/swagger", r"/wp-login", r"/xmlrpc"],
        "risk": 45, "confidence": 0.60,
    },
    "data_exfiltration": {
        "patterns": [r"/export/all", r"/download/dump", r"/api/dump", r"/backup", r"/api/export.*all", r"/db/export"],
        "risk": 82, "confidence": 0.78,
    },
    "privilege_escalation": {
        "patterns": [r"/admin/config", r"/api/users/role", r"/api/admin", r"/admin/settings", r"/sudo", r"/api/permissions"],
        "risk": 75, "confidence": 0.72,
    },
    "malware_upload": {
        "patterns": [r"\.php$", r"\.jsp$", r"\.asp$", r"\.exe$", r"\.sh$", r"webshell", r"c99\.php", r"r57\.php"],
        "risk": 92, "confidence": 0.90,
    },
    "ssrf": {
        "patterns": [r"url=http", r"redirect=http", r"@169\.254", r"@127\.0\.0\.1", r"localhost%3A", r"url=file://"],
        "risk": 80, "confidence": 0.75,
    },
}

_COMPILED_PATTERNS = {}
for _atype, _cfg in _THREAT_PATTERNS.items():
    _COMPILED_PATTERNS[_atype] = {
        "regexes": [_re.compile(p, _re.IGNORECASE) for p in _cfg["patterns"]],
        "risk": _cfg["risk"],
        "confidence": _cfg["confidence"],
    }


def _analyze_sdk_event(action: str, status: str, resource: str, ip: str) -> dict:
    """Lightweight threat detection for SDK events. Returns risk_score, attack_type, explanation, confidence."""
    resource_lower = (resource or "").lower()
    action_upper = (action or "").upper()
    is_failure = status == "failure"

    # Check resource against threat patterns
    for attack_type, cfg in _COMPILED_PATTERNS.items():
        for regex in cfg["regexes"]:
            if regex.search(resource_lower):
                risk = cfg["risk"]
                if is_failure:
                    risk = min(risk + 8, 100)
                return {
                    "risk_score": float(risk),
                    "attack_type": attack_type,
                    "ml_confidence": cfg["confidence"],
                    "explanation": f"Suspicious pattern detected in {action_upper} {resource} from {ip} — possible {attack_type.replace('_', ' ')}",
                }

    # Brute force heuristic: failed POST to auth endpoints
    auth_paths = ("/login", "/signin", "/auth", "/api/auth", "/oauth", "/token")
    if is_failure and action_upper == "POST" and any(p in resource_lower for p in auth_paths):
        return {
            "risk_score": 65.0,
            "attack_type": "brute_force",
            "ml_confidence": 0.60,
            "explanation": f"Failed authentication attempt from {ip} — {action_upper} {resource}",
        }

    # Normal traffic baseline
    base = 12.0 if is_failure else 5.0
    if action_upper in ("DELETE", "PUT", "PATCH"):
        base += 10.0
    if action_upper == "POST":
        base += 5.0

    return {
        "risk_score": min(base, 100.0),
        "attack_type": "normal",
        "ml_confidence": 0.0,
        "explanation": f"SDK event from {ip} — {action_upper} {resource}",
    }


@app.post("/api/v1/ingest")
def sdk_ingest(batch: IngestBatch, api_user: User = Depends(get_api_key_user)):
    """SDK ingestion endpoint — saves events DIRECTLY to database for instant visibility.
    Includes lightweight pattern-based threat detection.
    Auth via X-API-Key header.
    """
    if not batch.events or len(batch.events) == 0:
        raise HTTPException(status_code=400, detail="Empty event batch")
    if len(batch.events) > 1000:
        raise HTTPException(status_code=400, detail="Max 1000 events per batch")

    inserted = 0
    incidents_created = 0
    for ev in batch.events:
        status_normalized = _map_http_status(ev.status)
        analysis = _analyze_sdk_event(ev.action, status_normalized, ev.resource, ev.ip)

        event_dict = {
            "timestamp": _parse_sdk_timestamp(ev.timestamp),
            "user": ev.user or "anonymous",
            "role": "sdk",
            "ip": ev.ip or "unknown",
            "action": ev.action or "unknown",
            "status": status_normalized,
            "resource": ev.resource or "/",
            "anomaly_score": 0.0,
            "risk_score": analysis["risk_score"],
            "time_risk": 0.0,
            "role_risk": 0.0,
            "resource_risk": 0.0,
            "explanation": analysis["explanation"],
            "attack_type": analysis["attack_type"],
            "ml_confidence": analysis["ml_confidence"],
            "country": "UNKNOWN",
            "threat_intel_score": 0.0,
            "threat_intel_reason": "",
            "response_actions": "",
            "tenant_id": api_user.id,
        }

        event_id, incident_id = db.insert_event(event_dict)
        if event_id:
            inserted += 1
        if incident_id:
            incidents_created += 1

    return {
        "accepted": inserted,
        "total": len(batch.events),
        "incidents_created": incidents_created,
        "stored": True,
    }

# ─── Public Routes ───────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "online", "service": "ThreatPulse API v3.0"}

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ─── Protected Data Routes ───────────────────────────────────────────────────

# Events
@app.get("/api/events")
def get_events(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    min_risk: float = Query(0, ge=0, le=100),
    current_user: User = Depends(get_current_user),
):
    ta = _tenant_args(current_user)
    events, total = db.fetch_events_paginated(page=page, limit=limit, min_risk=min_risk, **ta)
    return {
        "data": [serialize_event(e) for e in events],
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit
    }

# Real-world Data Ingestion
@app.post("/api/ingest/csv")
async def ingest_csv(file: UploadFile = File(...), current_user: User = Depends(get_current_user)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")

    content = await file.read()
    try:
        df = pd.read_csv(io.StringIO(content.decode('utf-8')))
        required_cols = {'timestamp', 'user', 'ip', 'action', 'status', 'resource'}
        if not required_cols.issubset(set(df.columns)):
            raise HTTPException(status_code=400, detail=f"CSV must contain columns: {required_cols}")

        df['_tenant_id'] = current_user.id
        save_dir = os.path.join(os.path.dirname(__file__), '..', 'logs_ingest')
        os.makedirs(save_dir, exist_ok=True)
        filename = f"real_data_{int(time.time())}.csv"
        filepath = os.path.join(save_dir, filename)
        df.to_csv(filepath, index=False)

        return {"message": "CSV uploaded and queued for ingestion.", "events_count": len(df), "file": filename}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process CSV: {str(e)}")

@app.post("/api/ingest/json")
def ingest_json(batch: LogBatchSchema, current_user: User = Depends(get_current_user)):
    if not batch.events:
        raise HTTPException(status_code=400, detail="Empty event batch.")

    df = pd.DataFrame([e.dict() for e in batch.events])
    df['_tenant_id'] = current_user.id

    save_dir = os.path.join(os.path.dirname(__file__), '..', 'logs_ingest')
    os.makedirs(save_dir, exist_ok=True)
    filename = f"real_data_{int(time.time())}.csv"
    filepath = os.path.join(save_dir, filename)
    df.to_csv(filepath, index=False)

    return {"message": "Logs uploaded and queued for ingestion.", "events_count": len(df), "file": filename}

# Stats / KPIs
@app.get("/api/stats")
def get_stats(current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    return db.get_stats(**ta)

@app.get("/api/metrics/mttd-mttr")
def get_mttd_mttr(current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    return db.get_mttd_mttr_stats(**ta)

# Incidents
@app.get("/api/incidents")
def get_incidents(status: Optional[str] = None, current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    incidents = db.fetch_incidents(status=status, **ta)
    return {"data": [serialize_incident(i) for i in incidents]}

@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int, current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    incident, log_event = db.get_incident_details(incident_id, **ta)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = serialize_incident(incident)
    if log_event:
        result["log_event"] = serialize_event(log_event)
    return result

@app.post("/api/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, body: StatusUpdate, current_user: User = Depends(get_current_user)):
    valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    ta = _tenant_args(current_user)
    db.update_incident_status(incident_id, body.status, body.owner, **ta)
    return {"success": True, "incident_id": incident_id, "new_status": body.status}

# SOAR Response
@app.post("/api/response/{incident_id}")
def trigger_response(incident_id: int, body: ResponseTrigger, current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    incident, log_event = db.get_incident_details(incident_id, **ta)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not body.force and incident.response_actions:
        return {"message": "Response already executed", "actions": json.loads(incident.response_actions or "[]")}

    event_dict = {
        "user": incident.user,
        "action": incident.action,
        "ip": log_event.ip if log_event else "unknown",
        "risk_score": incident.risk_score,
        "explanation": log_event.explanation if log_event else "",
        "attack_type": incident.attack_type or "unknown"
    }
    response = execute_response(event_dict, incident_id)
    db.update_incident_response(incident_id, json.dumps(response.get("actions_taken", [])))
    return response

@app.get("/api/response/log")
def get_response_log_endpoint(limit: int = Query(50, ge=1, le=200), current_user: User = Depends(get_current_user)):
    return {"data": get_response_log(limit=limit)}

@app.get("/api/response/blocked-ips")
def get_blocked_ips_endpoint(current_user: User = Depends(get_current_user)):
    return {"data": get_blocked_ips()}

@app.get("/api/response/disabled-accounts")
def get_disabled_accounts_endpoint(current_user: User = Depends(get_current_user)):
    return {"data": get_disabled_accounts()}

# Attack Graph
@app.get("/api/attack-graph")
def get_attack_graph(current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    events = db.get_recent_events_for_graph(limit=200, **ta)
    if not events:
        return {"nodes": [], "links": [], "node_count": 0, "link_count": 0}
    G = build_graph(events)
    return graph_to_json(G)

@app.get("/api/attack-chains")
def get_attack_chains_endpoint(current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    events = db.get_recent_events_for_graph(limit=300, **ta)
    chains = get_attack_chains(events, window_minutes=15)
    return {"data": chains, "count": len(chains)}

# ML Metrics
@app.get("/api/ml-metrics")
def get_ml_metrics_endpoint(current_user: User = Depends(get_current_user)):
    metrics = get_ml_metrics()
    if not metrics:
        return {"message": "No ML metrics found. Run utils/train_ml_engine.py first."}
    return metrics

# Threat Intelligence
@app.get("/api/threat-intel/known-bad")
def get_known_bad(current_user: User = Depends(get_current_user)):
    return {"data": get_known_bad_ips()}

@app.get("/api/threat-intel/{ip}")
def get_threat_intel(ip: str, current_user: User = Depends(get_current_user)):
    return check_ip(ip)

# Country Distribution
@app.get("/api/geo-distribution")
def get_geo_distribution(current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    events, _ = db.fetch_events_paginated(page=1, limit=500, min_risk=50, **ta)
    country_counts = {}
    for e in events:
        country = e.country or "UNKNOWN"
        if country not in ("UNKNOWN", "LOCAL"):
            country_counts[country] = country_counts.get(country, 0) + 1
    return {
        "data": [
            {"country": k, "count": v}
            for k, v in sorted(country_counts.items(), key=lambda x: -x[1])
        ]
    }

# MITRE ATT&CK
@app.get("/api/mitre/mapping")
def get_mitre_for_event(
    attack_type: str = Query("unknown"),
    action: str = Query(""),
    current_user: User = Depends(get_current_user),
):
    return get_mitre_mapping(attack_type, action)

@app.get("/api/mitre/techniques")
def list_mitre_techniques(current_user: User = Depends(get_current_user)):
    return {"data": get_all_techniques()}

@app.get("/api/mitre/event/{event_id}")
def get_event_mitre(event_id: int, current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    events, _ = db.fetch_events_paginated(page=1, limit=1000, **ta)
    event = next((e for e in events if e.id == event_id), None)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    mapping = get_mitre_mapping(event.attack_type or "", event.action or "")
    return {
        "event_id": event_id,
        "attack_type": event.attack_type,
        "action": event.action,
        "mitre": mapping
    }

# SHAP / Explainability
@app.get("/api/explainability")
def get_explainability(current_user: User = Depends(get_current_user)):
    cached = load_cached_shap()
    if cached.get("features"):
        return cached
    return get_static_feature_importance()

# Threat Prediction
@app.get("/api/prediction")
def get_threat_prediction(current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    events = db.get_recent_events_for_graph(limit=100, **ta)
    return get_prediction_from_db_events(events)

# Attack Timeline
@app.get("/api/timeline/{incident_id}")
def get_incident_timeline(incident_id: int, current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    incident, log_event = db.get_incident_details(incident_id, **ta)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    all_events, _ = db.fetch_events_paginated(page=1, limit=500, **ta)
    if not log_event:
        return {"timeline": [], "incident_id": incident_id}

    ts = log_event.timestamp
    user = log_event.user or ""
    ip = log_event.ip or ""

    timeline = []
    for e in all_events:
        if not e.timestamp:
            continue
        diff = abs((e.timestamp - ts).total_seconds())
        if diff <= 1800 and (e.user == user or e.ip == ip):
            mitre = get_mitre_mapping(e.attack_type or "", e.action or "")
            timeline.append({
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "user": e.user,
                "ip": e.ip,
                "action": e.action,
                "resource": e.resource,
                "risk_score": round(e.risk_score or 0, 1),
                "attack_type": e.attack_type or "normal",
                "mitre_id": mitre.get("technique_id"),
                "mitre_tactic": mitre.get("tactic"),
                "mitre_name": mitre.get("technique_name"),
                "is_focal": e.id == log_event.id,
            })

    timeline.sort(key=lambda x: x["timestamp"])
    return {
        "incident_id": incident_id,
        "user": user,
        "ip": ip,
        "focal_timestamp": ts.isoformat(),
        "timeline": timeline
    }

# Events with MITRE enrichment
@app.get("/api/events/mitre")
def get_events_with_mitre(
    limit: int = Query(50, ge=1, le=200),
    min_risk: float = Query(50, ge=0, le=100),
    current_user: User = Depends(get_current_user),
):
    ta = _tenant_args(current_user)
    events, total = db.fetch_events_paginated(page=1, limit=limit, min_risk=min_risk, **ta)
    result = []
    for e in events:
        mitre = get_mitre_mapping(e.attack_type or "", e.action or "")
        result.append({
            **serialize_event(e),
            "mitre_id": mitre.get("technique_id"),
            "mitre_tactic": mitre.get("tactic"),
            "mitre_name": mitre.get("technique_name"),
            "mitre_url": mitre.get("url"),
        })
    return {"data": result, "total": total}

# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        events, _ = db.fetch_events_paginated(page=1, limit=10)
        for e in reversed(events):
            await websocket.send_json({
                "type": "history_event",
                "data": serialize_event(e)
            })

        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── UEBA Endpoints ────────────────────────────────────────────────────────────

@app.get("/api/ueba/profiles")
def get_ueba_profiles(current_user: User = Depends(get_current_user)):
    return {"data": get_all_profiles()}

@app.get("/api/ueba/user/{user}")
def get_ueba_user_profile(user: str, current_user: User = Depends(get_current_user)):
    return get_user_profile(user)


# ── Extended Threat Intel ─────────────────────────────────────────────────────

@app.get("/api/threat-intel/extended/{ip}")
def get_extended_threat_intel(ip: str, current_user: User = Depends(get_current_user)):
    return extended_check_ip(ip)

@app.get("/api/threat-intel/domain/{domain}")
def check_domain(domain: str, current_user: User = Depends(get_current_user)):
    return check_domain_virustotal(domain)


# ── Feedback Loop / Online Learning ─────────────────────────────────────────

@app.get("/api/feedback/stats")
def get_feedback_statistics(current_user: User = Depends(get_current_user)):
    return get_feedback_stats()

@app.get("/api/model/drift")
def get_model_drift(current_user: User = Depends(get_current_user)):
    return get_drift_metrics()

@app.post("/api/feedback/{incident_id}")
def submit_feedback(incident_id: int, body: dict, current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    incident, log_event = db.get_incident_details(incident_id, **ta)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    label = body.get("label", "")
    if label not in ("false_positive", "confirmed_threat", "escalated", "benign"):
        raise HTTPException(status_code=400, detail="Invalid label. Use: false_positive, confirmed_threat, escalated, benign")

    event_data = serialize_event(log_event) if log_event else {"attack_type": incident.attack_type}
    entry = record_feedback(
        incident_id=incident_id,
        event_data=event_data,
        analyst_label=label,
        original_prediction=incident.attack_type or "unknown",
        analyst=body.get("analyst", current_user.display_name or current_user.email),
    )

    if label == "false_positive":
        db.update_incident_status(incident_id, "FALSE_POSITIVE", current_user.display_name or current_user.email, **ta)

    return {"success": True, "feedback": entry}


# ── Adversarial Robustness ──────────────────────────────────────────────────

@app.get("/api/adversarial/results")
def get_adversarial_results(current_user: User = Depends(get_current_user)):
    return get_cached_results()

@app.post("/api/adversarial/run")
def run_adversarial(current_user: User = Depends(get_current_user)):
    from src.ml_engine import load_ml_engine
    model, encoders = load_ml_engine()
    if model is None:
        raise HTTPException(status_code=400, detail="ML model not loaded. Train it first.")
    return run_adversarial_tests(model, encoders)


# ── Telegram Bot Endpoints ────────────────────────────────────────────────────

@app.get("/api/telegram/status")
def telegram_status(current_user: User = Depends(get_current_user)):
    info = get_bot_info()
    configured = bool(os.getenv("TELEGRAM_BOT_TOKEN")) and bool(os.getenv("TELEGRAM_CHAT_ID"))
    if info:
        return {"status": "online", "configured": True, "bot_name": f"@{info.get('username', '')}", "name": info.get("first_name", "")}
    return {"status": "offline", "configured": configured, "bot_name": "N/A", "error": "Bot not reachable — check TELEGRAM_BOT_TOKEN"}

@app.post("/api/telegram/test")
def telegram_test_message(current_user: User = Depends(get_current_user)):
    ok = send_system_status(
        "ThreatPulse Telegram integration is working!\n\nThis is a test message from your SOC platform."
    )
    return {"sent": ok}


# ── Real Log File Upload ──────────────────────────────────────────────────────

@app.post("/api/upload/log-file")
async def upload_real_log_file(file: UploadFile = File(...), current_user: User = Depends(get_current_user)):
    content = await file.read()
    tmp_path = os.path.join(os.path.dirname(__file__), '..', 'logs_ingest', f"uploaded_{int(time.time())}_{file.filename}")
    os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
    with open(tmp_path, 'wb') as f_out:
        f_out.write(content)

    try:
        events = parse_log_file(tmp_path)
        if not events:
            return {"message": "File parsed but no events matched known log formats.", "events_count": 0}

        df = pd.DataFrame(events)
        df['_tenant_id'] = current_user.id
        csv_path = tmp_path.replace(file.filename, f"parsed_{int(time.time())}.csv")
        df.to_csv(csv_path, index=False)
        os.remove(tmp_path)
        return {
            "message": f"{file.filename} parsed successfully",
            "events_count": len(events),
            "sample_events": events[:3],
            "log_format": events[0].get('_source', 'unknown') if events else 'unknown',
        }
    except Exception as e:
        return {"error": f"Parse failed: {str(e)}"}


# ── SOAR Playbooks ──────────────────────────────────────────────────────────

@app.get("/api/playbooks")
def list_playbooks(current_user: User = Depends(get_current_user)):
    return {"data": get_all_playbooks()}

@app.get("/api/playbooks/{attack_type}")
def get_playbook_for_type(attack_type: str, risk_score: float = Query(80), current_user: User = Depends(get_current_user)):
    return evaluate_playbook(attack_type, risk_score)

@app.post("/api/playbooks/execute/{incident_id}")
def execute_playbook_endpoint(incident_id: int, current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    incident, log_event = db.get_incident_details(incident_id, **ta)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    event_dict = {
        "user": incident.user,
        "action": incident.action,
        "ip": log_event.ip if log_event else "unknown",
        "risk_score": incident.risk_score,
        "attack_type": incident.attack_type or "unknown",
    }
    result = execute_playbook(event_dict, incident_id)
    db.update_incident_response(incident_id, json.dumps([a.get("action", "") for a in result.get("actions_taken", [])]))
    return result


# ── OSINT Threat Feeds ──────────────────────────────────────────────────────

@app.get("/api/osint/feeds")
def get_osint_feeds(current_user: User = Depends(get_current_user)):
    return get_feed_summary()

@app.get("/api/osint/check/{ip}")
def check_ip_osint_endpoint(ip: str, current_user: User = Depends(get_current_user)):
    return check_ip_osint(ip)

@app.get("/api/osint/urlhaus")
def get_urlhaus(current_user: User = Depends(get_current_user)):
    return {"data": fetch_urlhaus_recent()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
