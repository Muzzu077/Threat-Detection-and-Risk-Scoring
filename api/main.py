"""
TrustFlow FastAPI Backend
REST + WebSocket API for the React frontend dashboard.
Multi-tenant SaaS with JWT auth and API key support.
"""
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

import asyncio  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import random as _random  # noqa: E402
import re as _re  # noqa: E402
import time  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from datetime import datetime, timedelta  # noqa: E402
from typing import List, Optional  # noqa: E402
from urllib.parse import unquote as _url_decode  # noqa: E402

import pandas as pd  # noqa: E402
from fastapi import (  # noqa: E402
    Body,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from src.database import db, User, ApiKey, Application, NotificationPreference, Playbook, LogEvent  # noqa: E402
from src.auth import (  # noqa: E402
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    get_current_user, revoke_refresh_token, validate_refresh_token,
    require_admin,
)
from src.api_keys import generate_api_key, get_api_key_user  # noqa: E402
from src.attack_graph import build_graph, graph_to_json, get_attack_chains  # noqa: E402
from src.ml_engine import get_ml_metrics  # noqa: E402
from src.threat_intel import check_ip, get_known_bad_ips  # noqa: E402
from src.response_engine import execute_response, get_response_log, get_blocked_ips, get_disabled_accounts  # noqa: E402
from src.mitre_mapping import get_mitre_mapping, get_all_techniques  # noqa: E402
from src.explainability_shap import load_cached_shap, get_static_feature_importance  # noqa: E402
from src.threat_predictor import get_prediction_from_db_events  # noqa: E402
from src.ueba import analyze_event_ueba, get_user_profile, get_all_profiles  # noqa: E402
from src.soar_playbooks import get_all_playbooks, evaluate_playbook, execute_playbook  # noqa: E402
from src.osint_feeds import get_feed_summary, check_ip_osint, fetch_urlhaus_recent  # noqa: E402
from src.feedback_loop import record_feedback, get_feedback_stats, get_drift_metrics  # noqa: E402
from src.adversarial_test import run_adversarial_tests, get_cached_results  # noqa: E402
from src.threat_intel_extended import extended_check_ip, check_domain_virustotal  # noqa: E402
from utils.telegram_alerter import send_system_status, get_bot_info  # noqa: E402
from utils.gemini_client import generate_security_summary  # noqa: E402
from utils.alert_dispatcher import dispatch_alert, dispatch_alert_for_user  # noqa: E402
from utils.log_parsers import parse_log_file  # noqa: E402
from utils.telegram_bot import start_polling_thread as start_telegram_bot  # noqa: E402

# ─── Access Token Blacklist (for logout) ─────────────────────────────────────
_revoked_access_tokens: set = set()

# ─── Helpers: tenant scoping ────────────────────────────────────────────────

def _tenant_args(user: User) -> dict:
    """Return tenant_id and user_role kwargs for DB queries."""
    if user is None:
        return {"tenant_id": None, "user_role": "admin"}
    return {"tenant_id": user.id, "user_role": user.role}

# ─── WebSocket Connection Manager ────────────────────────────────────────────

class ConnectionManager:
    """Per-tenant WebSocket fan-out.

    Each connection carries (tenant_id, user_role). Events are routed
    only to connections whose tenant matches the event's tenant_id, or
    to admin connections (which see everything for ops monitoring).
    """
    def __init__(self):
        # connection -> {"tenant_id": int, "user_role": str}
        self.connections: dict = {}

    async def connect(self, websocket: WebSocket, tenant_id: int, user_role: str):
        await websocket.accept()
        self.connections[websocket] = {"tenant_id": tenant_id, "user_role": user_role}

    def disconnect(self, websocket: WebSocket):
        self.connections.pop(websocket, None)

    async def broadcast_to_tenant(self, message: dict, event_tenant_id):
        """Send message to every connection that should see this event."""
        dead = []
        for ws, ctx in list(self.connections.items()):
            # Admins see all tenants' traffic; users see only their own.
            if ctx["user_role"] != "admin" and ctx["tenant_id"] != event_tenant_id:
                continue
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()

# ─── Background Task: Event Broadcaster ──────────────────────────────────────

_last_broadcast_event_id = 0

async def broadcast_live_events():
    """Safety-net poller for the live feed.

    /api/v1/ingest now broadcasts events immediately, so this loop is
    primarily a fallback for events written via paths that don't push
    (legacy ingestion, manual DB seeds, replays). Limit is generous so
    a burst can't slip past the cursor unseen.
    """
    global _last_broadcast_event_id
    while True:
        try:
            # Pull recent events globally, but route them per-tenant below.
            # user_role="admin" bypasses the DB tenant filter so we can see
            # every fresh event and decide who to forward it to.
            events, _ = db.fetch_events_paginated(
                page=1, limit=200, min_risk=0, tenant_id=None, user_role="admin"
            )
            new_events = []
            for e in events:
                if e.id > _last_broadcast_event_id:
                    new_events.append(e)
                    _last_broadcast_event_id = e.id

            for event in reversed(new_events):
                payload = {
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
                }
                await manager.broadcast_to_tenant(payload, event.tenant_id)
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
    title="TrustFlow API",
    description="AI-Powered Threat Detection and Risk Scoring Platform",
    version="3.0.0",
    lifespan=lifespan
)

_cors_default = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"
_cors_env = os.getenv("CORS_ALLOWED_ORIGINS", _cors_default)
_cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
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
    application_id: Optional[int] = None

class CreateApplicationRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    environment: Optional[str] = "production"

class UpdateApplicationRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    environment: Optional[str] = None
    status: Optional[str] = None


class NotificationPrefsRequest(BaseModel):
    telegram_chat_id: Optional[str] = None
    whatsapp_number: Optional[str] = None
    email_address: Optional[str] = None
    enable_telegram: Optional[bool] = None
    enable_whatsapp: Optional[bool] = None
    enable_email: Optional[bool] = None
    min_severity: Optional[str] = None
    # SIEM export (Phase 3)
    siem_type:   Optional[str] = None
    siem_url:    Optional[str] = None
    siem_token:  Optional[str] = None
    siem_index:  Optional[str] = None
    enable_siem: Optional[bool] = None


class NotificationTestRequest(BaseModel):
    channel: str  # "telegram" | "whatsapp" | "email"


class PlaybookStep(BaseModel):
    type: str
    params: Optional[dict] = {}

class CustomPlaybookRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    enabled: Optional[bool] = True
    trigger_attack_types: Optional[str] = ""
    trigger_min_risk: Optional[float] = 70.0
    trigger_application_id: Optional[int] = None
    steps: List[PlaybookStep] = []

class CustomPlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    trigger_attack_types: Optional[str] = None
    trigger_min_risk: Optional[float] = None
    trigger_application_id: Optional[int] = None
    steps: Optional[List[PlaybookStep]] = None

class PlaybookDryRunRequest(BaseModel):
    sample_event: dict

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

def serialize_application(app: Application, stats: dict = None) -> dict:
    return {
        "id": app.id,
        "tenant_id": app.tenant_id,
        "name": app.name,
        "slug": app.slug,
        "description": app.description or "",
        "environment": app.environment,
        "status": app.status,
        "created_at": app.created_at.isoformat() if app.created_at else None,
        "updated_at": app.updated_at.isoformat() if app.updated_at else None,
        "stats": stats or {},
    }


def _slugify(name: str, suffix: int = 0) -> str:
    import re as _re_local
    s = _re_local.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "app"
    return f"{s}-{suffix}" if suffix else s

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
def auth_logout(request: Request, body: LogoutRequest = Body(default=None)):
    # Revoke refresh token if provided
    if body and body.refresh_token:
        revoke_refresh_token(body.refresh_token)
    # Blacklist the access token so it can't be reused
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        _revoked_access_tokens.add(auth_header[7:])
    return {"success": True}

@app.get("/api/auth/me")
def auth_me(current_user: User = Depends(get_current_user)):
    return {"user": serialize_user(current_user)}

# ─── Admin: User Management ──────────────────────────────────────────────────

@app.get("/api/admin/users")
def list_users(current_user: User = Depends(require_admin)):
    session = db.Session()
    try:
        users = session.query(User).order_by(User.created_at.desc()).all()
        out = []
        for u in users:
            apps = session.query(Application).filter(Application.tenant_id == u.id).count()
            out.append({**serialize_user(u), "is_active": u.is_active, "applications_count": apps})
        return {"data": out}
    finally:
        session.close()

# ─── Notification Preferences ────────────────────────────────────────────────

_VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

def serialize_notification_prefs(pref: NotificationPreference) -> dict:
    if pref is None:
        return {
            "telegram_chat_id": "",
            "whatsapp_number": "",
            "email_address": "",
            "enable_telegram": False,
            "enable_whatsapp": False,
            "enable_email": False,
            "min_severity": "HIGH",
            "siem_type": "",
            "siem_url": "",
            "siem_token": "",
            "siem_index": "trustflow",
            "enable_siem": False,
            "configured": False,
        }
    # Mask the SIEM token in API responses — return only a short prefix
    token = pref.siem_token or ""
    masked_token = (token[:6] + "…" + token[-4:]) if len(token) > 12 else ("•" * len(token) if token else "")
    return {
        "telegram_chat_id": pref.telegram_chat_id or "",
        "whatsapp_number": pref.whatsapp_number or "",
        "email_address": pref.email_address or "",
        "enable_telegram": bool(pref.enable_telegram),
        "enable_whatsapp": bool(pref.enable_whatsapp),
        "enable_email": bool(pref.enable_email),
        "min_severity": pref.min_severity or "HIGH",
        "siem_type": pref.siem_type or "",
        "siem_url": pref.siem_url or "",
        "siem_token": masked_token,
        "siem_token_set": bool(token),
        "siem_index": pref.siem_index or "trustflow",
        "enable_siem": bool(pref.enable_siem),
        "configured": True,
        "updated_at": pref.updated_at.isoformat() if pref.updated_at else None,
    }


@app.get("/api/notifications/preferences")
def get_notification_prefs(current_user: User = Depends(get_current_user)):
    pref = db.get_notification_preferences(current_user.id)
    return serialize_notification_prefs(pref)


_VALID_SIEM_TYPES = ("", "splunk", "elastic", "datadog", "webhook")

@app.put("/api/notifications/preferences")
def update_notification_prefs(body: NotificationPrefsRequest, current_user: User = Depends(get_current_user)):
    if body.min_severity is not None and body.min_severity.upper() not in _VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"min_severity must be one of {_VALID_SEVERITIES}")
    if body.siem_type is not None and body.siem_type.lower() not in _VALID_SIEM_TYPES:
        raise HTTPException(status_code=400, detail=f"siem_type must be one of {_VALID_SIEM_TYPES}")

    fields = body.model_dump(exclude_unset=True)
    if "min_severity" in fields and fields["min_severity"]:
        fields["min_severity"] = fields["min_severity"].upper()
    if "siem_type" in fields and fields["siem_type"]:
        fields["siem_type"] = fields["siem_type"].lower()

    # Drop the token field if it looks masked (user re-saved without retyping it)
    token = fields.get("siem_token")
    if token is not None and ("…" in token or all(c == "•" for c in token)):
        fields.pop("siem_token", None)

    pref = db.upsert_notification_preferences(current_user.id, **fields)
    return serialize_notification_prefs(pref)


@app.post("/api/siem/test")
def siem_test_connection(current_user: User = Depends(get_current_user)):
    """Send a heartbeat event to the user's configured SIEM."""
    from src.siem_export import test_connection
    pref = db.get_notification_preferences(current_user.id)
    if not pref or not pref.siem_type:
        raise HTTPException(status_code=400, detail="No SIEM configured")
    return test_connection(pref)


@app.post("/api/notifications/test")
def send_test_notification(body: NotificationTestRequest, current_user: User = Depends(get_current_user)):
    """Send a test alert via the requested channel using the user's saved preferences."""
    from utils.alert_dispatcher import dispatch_alert_for_user

    channel = body.channel.lower()
    if channel not in ("telegram", "whatsapp", "email"):
        raise HTTPException(status_code=400, detail="channel must be telegram, whatsapp, or email")

    pref = db.get_notification_preferences(current_user.id)
    if not pref:
        raise HTTPException(status_code=400, detail="No notification preferences set yet")

    test_event = {
        "user": current_user.email,
        "ip": "test.test.test.test",
        "risk_score": 99.0,
        "attack_type": "test_alert",
        "explanation": f"This is a TrustFlow test alert from your {channel} channel — if you got it, you're wired up.",
    }

    result = dispatch_alert_for_user(
        test_event,
        incident_id=0,
        user=current_user,
        prefs=pref,
        only_channel=channel,
    )
    return {"channel": channel, "delivered": result.get(channel, False), "all": result}

@app.post("/api/admin/users/{user_id}/role")
def set_user_role(user_id: int, body: dict, current_user: User = Depends(require_admin)):
    role = body.get("role", "")
    if role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="role must be 'user' or 'admin'")
    if user_id == current_user.id and role != "admin":
        raise HTTPException(status_code=400, detail="Cannot demote yourself")
    session = db.Session()
    try:
        u = session.query(User).filter(User.id == user_id).first()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        u.role = role
        session.commit()
        return {"success": True, "user_id": user_id, "role": role}
    finally:
        session.close()


@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int, current_user: User = Depends(require_admin)):
    """Hard-delete a user and every record that hangs off them.

    Wipes (in FK-safe order): incidents, attack chains, log events,
    custom playbooks, notification prefs, refresh tokens, api keys,
    applications, and finally the user row. Returns counts so the
    caller can verify what was removed.
    """
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    from src.database import Incident, AttackChain, RefreshToken
    session = db.Session()
    try:
        u = session.query(User).filter(User.id == user_id).first()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        email = u.email

        # Delete in FK-safe order. tenant_id and user_id both reference users.id.
        counts = {
            "incidents":     session.query(Incident).filter(Incident.tenant_id == user_id).delete(synchronize_session=False),
            "attack_chains": session.query(AttackChain).filter(AttackChain.tenant_id == user_id).delete(synchronize_session=False),
            "log_events":    session.query(LogEvent).filter(LogEvent.tenant_id == user_id).delete(synchronize_session=False),
            "playbooks":     session.query(Playbook).filter(Playbook.tenant_id == user_id).delete(synchronize_session=False),
            "notif_prefs":   session.query(NotificationPreference).filter(NotificationPreference.user_id == user_id).delete(synchronize_session=False),
            "refresh_tokens": session.query(RefreshToken).filter(RefreshToken.user_id == user_id).delete(synchronize_session=False),
            "api_keys":      session.query(ApiKey).filter(ApiKey.user_id == user_id).delete(synchronize_session=False),
            "applications":  session.query(Application).filter(Application.tenant_id == user_id).delete(synchronize_session=False),
        }
        session.delete(u)
        session.commit()
        return {"success": True, "user_id": user_id, "email": email, "deleted": counts}
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Delete failed: {e}")
    finally:
        session.close()

# ─── Application Routes ──────────────────────────────────────────────────────

def _ensure_default_application(user: User) -> Application:
    """Get-or-create a Default Application for the given user."""
    apps = db.list_applications(tenant_id=user.id, user_role=user.role)
    own = [a for a in apps if a.tenant_id == user.id]
    if own:
        return own[0]
    return db.create_application(
        tenant_id=user.id,
        name="Default Application",
        slug=_slugify("default", suffix=user.id),
        description="Auto-created default application.",
        environment="production",
    )


@app.get("/api/applications")
def list_applications(current_user: User = Depends(get_current_user)):
    apps = db.list_applications(tenant_id=current_user.id, user_role=current_user.role)
    out = []
    for a in apps:
        stats = db.get_application_stats(a.id, tenant_id=current_user.id, user_role=current_user.role)
        out.append(serialize_application(a, stats))
    return {"data": out}


@app.post("/api/applications")
def create_application(body: CreateApplicationRequest, current_user: User = Depends(get_current_user)):
    if not body.name or not body.name.strip():
        raise HTTPException(status_code=400, detail="Application name is required")
    if body.environment not in ("production", "staging", "development"):
        raise HTTPException(status_code=400, detail="environment must be production, staging, or development")

    # Build a unique slug per-tenant
    base_slug = _slugify(body.name)
    existing_slugs = {a.slug for a in db.list_applications(tenant_id=current_user.id, user_role="user")}
    slug = base_slug
    n = 1
    while slug in existing_slugs:
        n += 1
        slug = f"{base_slug}-{n}"

    app_obj = db.create_application(
        tenant_id=current_user.id,
        name=body.name.strip(),
        slug=slug,
        description=body.description or "",
        environment=body.environment,
    )
    return serialize_application(app_obj, {})


@app.get("/api/applications/{app_id}")
def get_application(app_id: int, current_user: User = Depends(get_current_user)):
    app_obj = db.get_application(app_id, tenant_id=current_user.id, user_role=current_user.role)
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    stats = db.get_application_stats(app_id, tenant_id=current_user.id, user_role=current_user.role)
    return serialize_application(app_obj, stats)


@app.patch("/api/applications/{app_id}")
def update_application(app_id: int, body: UpdateApplicationRequest, current_user: User = Depends(get_current_user)):
    if body.environment is not None and body.environment not in ("production", "staging", "development"):
        raise HTTPException(status_code=400, detail="invalid environment")
    if body.status is not None and body.status not in ("active", "paused", "archived"):
        raise HTTPException(status_code=400, detail="invalid status")

    app_obj = db.update_application(
        app_id,
        tenant_id=current_user.id,
        user_role=current_user.role,
        name=body.name,
        description=body.description,
        environment=body.environment,
        status=body.status,
    )
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    return serialize_application(app_obj, {})


@app.delete("/api/applications/{app_id}")
def delete_application(app_id: int, current_user: User = Depends(get_current_user)):
    app_obj = db.delete_application(app_id, tenant_id=current_user.id, user_role=current_user.role)
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    return {"success": True, "id": app_id, "status": "archived"}


@app.get("/api/applications/{app_id}/stats")
def application_stats(app_id: int, current_user: User = Depends(get_current_user)):
    app_obj = db.get_application(app_id, tenant_id=current_user.id, user_role=current_user.role)
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    return db.get_application_stats(app_id, tenant_id=current_user.id, user_role=current_user.role)


@app.get("/api/applications/{app_id}/keys")
def list_application_keys(app_id: int, current_user: User = Depends(get_current_user)):
    app_obj = db.get_application(app_id, tenant_id=current_user.id, user_role=current_user.role)
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    session = db.Session()
    try:
        keys = session.query(ApiKey).filter(
            ApiKey.application_id == app_id,
        ).order_by(ApiKey.created_at.desc()).all()
        return {
            "data": [
                {
                    "id": k.id,
                    "name": k.name,
                    "prefix": k.prefix,
                    "application_id": k.application_id,
                    "created_at": k.created_at.isoformat() if k.created_at else None,
                    "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                    "is_active": k.is_active,
                }
                for k in keys
            ]
        }
    finally:
        session.close()


# ─── API Key Routes ──────────────────────────────────────────────────────────

@app.post("/api/keys")
def create_api_key_endpoint(body: CreateApiKeyRequest, current_user: User = Depends(get_current_user)):
    # Resolve application_id: explicit or fall back to default app
    if body.application_id is not None:
        app_obj = db.get_application(body.application_id, tenant_id=current_user.id, user_role=current_user.role)
        if not app_obj or app_obj.tenant_id != current_user.id:
            raise HTTPException(status_code=404, detail="Application not found")
        application_id = app_obj.id
    else:
        default_app = _ensure_default_application(current_user)
        application_id = default_app.id

    full_key, prefix, key_hash = generate_api_key()
    session = db.Session()
    try:
        ak = ApiKey(
            user_id=current_user.id,
            application_id=application_id,
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
            "application_id": application_id,
            "created_at": ak.created_at.isoformat() if ak.created_at else None,
        }
    finally:
        session.close()

@app.get("/api/keys")
def list_api_keys(current_user: User = Depends(get_current_user)):
    session = db.Session()
    try:
        # Build a lookup of application names for this tenant
        apps = session.query(Application).filter(Application.tenant_id == current_user.id).all()
        app_names = {a.id: a.name for a in apps}

        keys = session.query(ApiKey).filter(
            ApiKey.user_id == current_user.id
        ).order_by(ApiKey.created_at.desc()).all()
        return {
            "data": [
                {
                    "id": k.id,
                    "name": k.name,
                    "prefix": k.prefix,
                    "application_id": k.application_id,
                    "application_name": app_names.get(k.application_id, "—"),
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


# Patterns for lightweight threat detection on SDK-ingested events
# Severity tiers: LOW (1-30), MEDIUM (31-65), HIGH (66-100)
_THREAT_PATTERNS = {
    # ── HIGH severity (risk 66-100) — critical attacks ────────────────────────
    "sql_injection": {
        "patterns": [r"['\"].*OR.*['\"]", r"UNION\s+SELECT", r"--\s*$", r"1\s*=\s*1", r"DROP\s+TABLE", r";\s*DELETE", r";\s*INSERT", r"SLEEP\(", r"BENCHMARK\("],
        "risk": 78, "confidence": 0.85,
    },
    "command_injection": {
        "patterns": [r";\s*cat\b", r";\s*ls\b", r"\|\s*cat\b", r"&&\s*rm\b", r"`whoami`", r"\$\(id\)", r"\|\s*nc\s", r";\s*wget\s", r";\s*curl\s", r";\s*python", r";\s*bash", r";\s*sh\b", r"\|\s*sh\b", r";\s*id\b"],
        "risk": 80, "confidence": 0.88,
    },
    "malware_upload": {
        "patterns": [r"upload.*\.php", r"\.jsp$", r"\.asp$", r"\.exe$", r"webshell", r"c99\.php", r"r57\.php", r"shell\.(php|jsp|asp)", r"cmd\.(php|jsp)", r"backdoor"],
        "risk": 80, "confidence": 0.90,
    },
    "data_exfiltration": {
        "patterns": [r"/export/all", r"/download/dump", r"/api/dump", r"/backup", r"/api/export.*all", r"/db/export"],
        "risk": 78, "confidence": 0.78,
    },
    "privilege_escalation": {
        "patterns": [r"/admin/config", r"/api/users/role", r"/admin/users/role", r"/api/admin", r"/admin/settings", r"/sudo", r"/api/permissions", r"/admin/promote", r"/api/role", r"/users/role", r"/change.?role", r"/elevate", r"/api/users/admin"],
        "risk": 75, "confidence": 0.78,
    },
    # ── MEDIUM severity (risk 31-65) — moderate threats ───────────────────────
    "xss": {
        "patterns": [r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=", r"alert\(", r"document\.cookie", r"<img\s+src.*onerror"],
        "risk": 48, "confidence": 0.70,
    },
    "directory_traversal": {
        "patterns": [r"\.\./", r"\.\.\\", r"\.\.%2[fF]", r"/proc/self"],
        "risk": 52, "confidence": 0.72,
    },
    "ssrf": {
        "patterns": [r"url=http", r"redirect=http", r"@169\.254", r"@127\.0\.0\.1", r"localhost%3A", r"url=file://"],
        "risk": 55, "confidence": 0.68,
    },
    "port_scan": {
        "patterns": [r"/robots\.txt", r"/\.env", r"/\.git", r"/wp-admin", r"/phpinfo", r"/actuator", r"/\.htaccess", r"/server-status", r"/api-docs", r"/swagger", r"/wp-login", r"/xmlrpc"],
        "risk": 35, "confidence": 0.55,
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
    """Lightweight threat detection for SDK events. Returns risk_score, attack_type, explanation, confidence.
    Each event receives a unique risk score via ±jitter for dashboard diversity.
    """
    # URL-decode resource so patterns match encoded payloads (e.g., %3Cscript → <script)
    resource_lower = _url_decode((resource or "")).lower()
    action_lower = (action or "").lower()
    action_upper = (action or "").upper()
    is_failure = status == "failure"

    # ── Action-based classification (shipper embeds attack type in action field) ──
    # Action format example: "GET sql_injection", "POST xss_stored", etc.
    _ACTION_ATTACK_MAP = {
        "sql_injection": "sql_injection", "sqli": "sql_injection", "sqli_blind": "sql_injection",
        "xss_reflected": "xss", "xss_stored": "xss", "xss_dom": "xss",
        "command_injection": "command_injection",
        "file_inclusion": "directory_traversal",
        "file_upload": "malware_upload",
        "csrf": "xss",  # CSRF mapped to medium tier
        "weak_session": "port_scan",  # Weak session mapped to medium tier
        "brute_force": "brute_force",
    }
    for action_keyword, mapped_type in _ACTION_ATTACK_MAP.items():
        if action_keyword in action_lower:
            cfg = _COMPILED_PATTERNS.get(mapped_type)
            if cfg:
                base_risk = cfg["risk"]
                if base_risk >= 66:
                    jitter = _random.uniform(-10, 10)
                    risk = max(66.0, min(100.0, base_risk + jitter))
                    if is_failure:
                        risk = min(100.0, risk + 5)
                else:
                    jitter = _random.uniform(-8, 8)
                    risk = max(31.0, min(65.0, base_risk + jitter))
                    if is_failure:
                        risk = min(65.0, risk + 4)
                return {
                    "risk_score": round(float(risk), 1),
                    "attack_type": mapped_type,
                    "ml_confidence": round(cfg["confidence"] + _random.uniform(-0.05, 0.05), 2),
                    "explanation": f"Attack detected via action classification: {action} {resource} from {ip} — {mapped_type.replace('_', ' ')}",
                }
            break

    # Check resource against threat patterns (URL-based detection)
    for attack_type, cfg in _COMPILED_PATTERNS.items():
        for regex in cfg["regexes"]:
            if regex.search(resource_lower):
                base_risk = cfg["risk"]
                # Determine tier boundaries for jitter clamping
                if base_risk >= 66:
                    # HIGH tier: jitter within 66-100
                    jitter = _random.uniform(-10, 10)
                    risk = max(66.0, min(100.0, base_risk + jitter))
                    if is_failure:
                        risk = min(100.0, risk + 5)
                else:
                    # MEDIUM tier: jitter within 31-65
                    jitter = _random.uniform(-8, 8)
                    risk = max(31.0, min(65.0, base_risk + jitter))
                    if is_failure:
                        risk = min(65.0, risk + 4)
                return {
                    "risk_score": round(float(risk), 1),
                    "attack_type": attack_type,
                    "ml_confidence": round(cfg["confidence"] + _random.uniform(-0.05, 0.05), 2),
                    "explanation": f"Suspicious pattern detected in {action_upper} {resource} from {ip} — possible {attack_type.replace('_', ' ')}",
                }

    # Privilege escalation heuristic: PUT/PATCH to role/admin/permission endpoints
    priv_paths = ("/role", "/admin", "/permission", "/promote", "/elevate", "/users/role")
    if action_upper in ("PUT", "PATCH", "POST") and any(p in resource_lower for p in priv_paths):
        return {
            "risk_score": round(75.0 + _random.uniform(-8, 10), 1),
            "attack_type": "privilege_escalation",
            "ml_confidence": 0.78,
            "explanation": f"Potential privilege escalation: {action_upper} {resource} from {ip}",
        }

    # Brute force heuristic: failed auth attempt — HIGH tier.
    # Matches both HTTP-method style (action="POST", resource="/login") and
    # semantic style (action="login"/"signin") that SDKs commonly send.
    auth_paths = ("/login", "/signin", "/auth", "/api/auth", "/oauth", "/token")
    _semantic_auth = {"login", "signin", "authenticate", "auth", "password", "logon"}
    is_http_auth_post = action_upper == "POST" and any(p in resource_lower for p in auth_paths)
    is_semantic_auth  = action_lower in _semantic_auth
    if is_failure and (is_http_auth_post or is_semantic_auth):
        return {
            "risk_score": round(70.0 + _random.uniform(-4, 15), 1),
            "attack_type": "brute_force",
            "ml_confidence": 0.60,
            "explanation": f"Failed authentication attempt from {ip} — {action_upper} {resource}",
        }

    # Normal traffic baseline — LOW tier (1-30), unique per event
    base = 12.0 if is_failure else 5.0
    if action_upper in ("DELETE", "PUT", "PATCH"):
        base += 8.0
    if action_upper == "POST":
        base += 4.0
    base += _random.uniform(-3, 8)
    base = max(1.0, min(30.0, base))

    return {
        "risk_score": round(base, 1),
        "attack_type": "normal",
        "ml_confidence": 0.0,
        "explanation": f"SDK event from {ip} — {action_upper} {resource}",
    }


def _ip_to_country(ip: str) -> str:
    """Lightweight IP-to-country mapping using first octet heuristics + known ranges."""
    if not ip or ip in ("unknown", "127.0.0.1", "::1"):
        return "LOCAL"
    parts = ip.split(".")
    if len(parts) != 4:
        return "UNKNOWN"
    try:
        o1, o2 = int(parts[0]), int(parts[1])
    except ValueError:
        return "UNKNOWN"
    # Private ranges
    if o1 == 10 or (o1 == 172 and 16 <= o2 <= 31) or (o1 == 192 and o2 == 168):
        return "LOCAL"
    # Common geo heuristics based on IP allocation blocks
    _GEO_MAP = {
        (1, 50): "US", (51, 80): "EU", (81, 95): "EU", (96, 120): "US",
        (121, 130): "JP", (131, 145): "JP", (146, 160): "US", (161, 175): "US",
        (176, 185): "RU", (186, 190): "BR", (191, 195): "EU", (196, 200): "ZA",
        (201, 210): "CN", (211, 220): "KR", (221, 230): "CN", (231, 240): "US",
    }
    for (lo, hi), country in _GEO_MAP.items():
        if lo <= o1 <= hi:
            return country
    return "US"


@app.post("/api/v1/ingest")
async def sdk_ingest(batch: IngestBatch, api_user: User = Depends(get_api_key_user)):
    """SDK ingestion endpoint — saves events DIRECTLY to database for instant visibility.
    Includes lightweight pattern-based threat detection + UEBA analysis.
    Auth via X-API-Key header.

    Each accepted event is also broadcast immediately to the tenant's
    WebSocket subscribers so the live feed reflects activity in real time
    (no 2-second polling delay, no burst loss).
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
        ts = _parse_sdk_timestamp(ev.timestamp)
        country = _ip_to_country(ev.ip)
        risk = analysis["risk_score"]

        # UEBA analysis — build user profiles and detect anomalies
        try:
            ueba_event = {
                "user": ev.user or "anonymous",
                "ip": ev.ip or "unknown",
                "country": country,
                "action": ev.action or "unknown",
                "resource": ev.resource or "/",
                "hour": ts.hour if ts else 0,
                "timestamp": ts.isoformat() if ts else "",
            }
            ueba_anomalies = analyze_event_ueba(ueba_event)
            for anomaly in ueba_anomalies:
                risk = min(100, risk + anomaly.get("risk_boost", 0))
        except Exception:
            pass

        # Clamp risk to severity tier so UEBA boosts don't cross tier boundaries
        _MEDIUM_ATTACKS = {"xss", "directory_traversal", "ssrf", "port_scan"}
        _HIGH_ATTACKS = {"sql_injection", "command_injection", "malware_upload",
                         "data_exfiltration", "privilege_escalation", "brute_force"}
        atype = analysis["attack_type"]
        if atype == "normal":
            risk = min(risk, 30.0)
        elif atype in _MEDIUM_ATTACKS:
            risk = max(31.0, min(risk, 65.0))
        elif atype in _HIGH_ATTACKS:
            risk = max(66.0, risk)

        event_dict = {
            "timestamp": ts,
            "user": ev.user or "anonymous",
            "role": "sdk",
            "ip": ev.ip or "unknown",
            "action": ev.action or "unknown",
            "status": status_normalized,
            "resource": ev.resource or "/",
            "anomaly_score": 0.0,
            "risk_score": risk,
            "time_risk": 0.0,
            "role_risk": 0.0,
            "resource_risk": 0.0,
            "explanation": analysis["explanation"],
            "attack_type": analysis["attack_type"],
            "ml_confidence": analysis["ml_confidence"],
            "country": country,
            "threat_intel_score": 0.0,
            "threat_intel_reason": "",
            "response_actions": "",
            "tenant_id": api_user.id,
            "application_id": getattr(api_user, "_tf_application_id", None),
        }

        event_id, incident_id = db.insert_event(event_dict)
        if event_id:
            inserted += 1
            # Push to the tenant's live feed *immediately*. Without this,
            # the dashboard would only see events on the next 2s poll tick
            # and would silently drop bursts of >10 events/2s.
            try:
                live_payload = {
                    "type": "new_event",
                    "data": {
                        "id": event_id,
                        "timestamp": ts.isoformat() if ts else datetime.utcnow().isoformat(),
                        "user": event_dict["user"],
                        "action": event_dict["action"],
                        "ip": event_dict["ip"],
                        "risk_score": round(event_dict["risk_score"] or 0, 1),
                        "attack_type": event_dict["attack_type"] or "unknown",
                        "country": event_dict["country"] or "UNKNOWN",
                        "status": event_dict["status"],
                        "resource": event_dict["resource"],
                    },
                }
                global _last_broadcast_event_id
                if event_id > _last_broadcast_event_id:
                    _last_broadcast_event_id = event_id
                await manager.broadcast_to_tenant(live_payload, api_user.id)
            except Exception:
                pass
            # Phase 4: stream to Kafka if KAFKA_BROKERS is configured (no-op otherwise)
            try:
                from src.kafka_stream import publish_event, is_enabled
                if is_enabled():
                    publish_event(event_dict, incident_id or 0)
            except Exception:
                pass
            # Phase 4: mirror to Neo4j if configured
            try:
                from src.attack_graph_neo4j import upsert_event as neo_upsert, is_configured as neo_ready
                if neo_ready() and (event_dict.get("risk_score") or 0) >= 30:
                    neo_upsert(event_dict, tenant_id=api_user.id)
            except Exception:
                pass
        if incident_id:
            incidents_created += 1
            # Generate AI summary for high-risk incidents
            try:
                ai_summary = generate_security_summary(event_dict)
                if ai_summary:
                    db.update_incident_note(incident_id, ai_summary)
            except Exception:
                pass
            # SOAR Auto-Response — sets responded_at for MTTD/MTTR metrics
            response_json = ""
            try:
                from src.soar_playbooks import execute_playbook
                soar_result = execute_playbook(event_dict, incident_id)
                response_json = json.dumps(
                    [a.get("action", "") for a in soar_result.get("actions_taken", [])]
                )
                db.update_incident_response(incident_id, response_json)
            except Exception:
                pass
            # Dispatch alerts to the tenant's configured channels (multi-tenant)
            try:
                prefs = db.get_notification_preferences(api_user.id)
                if prefs:
                    dispatch_alert_for_user(
                        event_dict, incident_id,
                        user=api_user, prefs=prefs,
                        response_actions=response_json,
                    )
                else:
                    # Legacy fallback: global env-based dispatch (admin/system events)
                    dispatch_alert(event_dict, incident_id, response_json)
            except Exception:
                pass
            # SIEM export — push to customer's Splunk/Elastic/Datadog
            try:
                if prefs and prefs.enable_siem:
                    from src.siem_export import export_event
                    export_event(prefs, event_dict, incident_id)
            except Exception:
                pass
            # Custom playbooks — run any tenant-defined SOAR flows that match
            try:
                from src.playbook_runner import run_matching_playbooks
                run_matching_playbooks(
                    event_dict, incident_id,
                    tenant_id=api_user.id,
                    application_id=event_dict.get("application_id"),
                    db=db, prefs=prefs,
                )
            except Exception:
                pass

    return {
        "accepted": inserted,
        "total": len(batch.events),
        "incidents_created": incidents_created,
        "stored": True,
    }

# ─── Public Routes ───────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "online", "service": "TrustFlow API v3.0"}

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
def trigger_response(incident_id: int, body: ResponseTrigger = Body(default=None), current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    incident, log_event = db.get_incident_details(incident_id, **ta)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if body and not body.force and incident.response_actions:
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
def get_response_log_endpoint(limit: int = Query(50, ge=1, le=200), current_user: User = Depends(require_admin)):
    raw = get_response_log(limit=limit)
    # Flatten: each action becomes its own entry with context
    flat = []
    for entry in raw:
        for action_item in entry.get("actions_taken", []):
            flat.append({
                "timestamp": entry.get("timestamp"),
                "incident_id": entry.get("incident_id"),
                "user": entry.get("user"),
                "ip": entry.get("ip"),
                "risk_score": entry.get("risk_score"),
                "action": action_item.get("action", "unknown"),
                "target": action_item.get("ip") or action_item.get("user") or action_item.get("target", ""),
                "status": action_item.get("status", "unknown"),
                "message": action_item.get("message", ""),
            })
    return {"data": flat[:limit]}

@app.get("/api/response/blocked-ips")
def get_blocked_ips_endpoint(current_user: User = Depends(require_admin)):
    return {"data": get_blocked_ips()}

@app.get("/api/response/disabled-accounts")
def get_disabled_accounts_endpoint(current_user: User = Depends(require_admin)):
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

# ML Metrics (admin-only)
@app.get("/api/ml-metrics")
def get_ml_metrics_endpoint(current_user: User = Depends(require_admin)):
    metrics = get_ml_metrics()
    if not metrics:
        return {"message": "No ML metrics found. Run utils/train_ml_engine.py first."}

    # Build live confusion matrix from actual database events
    ta = _tenant_args(current_user)
    session = db.Session()
    try:
        from sqlalchemy import func as sa_func
        q = session.query(
            LogEvent.attack_type,
            sa_func.count(LogEvent.id)
        ).group_by(LogEvent.attack_type)
        q = db._apply_tenant_filter(q, LogEvent, ta.get("tenant_id"), ta.get("user_role"))
        rows = q.all()
        live_counts = {atype: count for atype, count in rows if atype}
        total_live = sum(live_counts.values())

        # Build per-class distribution for live data
        live_classes = sorted(live_counts.keys())
        live_matrix_data = []
        for cls in live_classes:
            live_matrix_data.append({
                "class": cls.replace("_", " "),
                "count": live_counts[cls],
                "pct": round(live_counts[cls] / total_live * 100, 1) if total_live else 0,
            })

        # Compute live accuracy proxies from severity tiers
        normal_count = live_counts.get("normal", 0)
        attack_count = total_live - normal_count

        # Analyst-verified counts (from incidents marked as resolved or false_positive)
        from src.database import Incident
        iq = session.query(Incident)
        iq = db._apply_tenant_filter(iq, Incident, ta.get("tenant_id"), ta.get("user_role"))
        confirmed = iq.filter(Incident.status == "RESOLVED").count()
        false_pos = iq.filter(Incident.status == "FALSE_POSITIVE").count()
        total_reviewed = confirmed + false_pos

        metrics["live_matrix"] = {
            "total_events": total_live,
            "classes": live_matrix_data,
            "normal_count": normal_count,
            "attack_count": attack_count,
            "analyst_confirmed": confirmed,
            "analyst_false_positive": false_pos,
            "analyst_reviewed": total_reviewed,
            "live_fp_rate": round(false_pos / total_reviewed * 100, 1) if total_reviewed else 0,
            "live_precision": round(confirmed / (confirmed + false_pos) * 100, 1) if (confirmed + false_pos) else 0,
        }
    except Exception:
        metrics["live_matrix"] = None
    finally:
        session.close()

    return metrics

# Threat Intelligence
@app.get("/api/threat-intel/known-bad")
def get_known_bad(current_user: User = Depends(require_admin)):
    return {"data": get_known_bad_ips()}

@app.get("/api/threat-intel/{ip}")
def get_threat_intel(ip: str, current_user: User = Depends(get_current_user)):
    return check_ip(ip)

# Hourly Risk Timeline
@app.get("/api/risk-timeline")
def get_risk_timeline(hours: int = Query(24, ge=1, le=168), current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    events, _ = db.fetch_events_paginated(page=1, limit=2000, min_risk=0, **ta)
    from collections import defaultdict
    hourly = defaultdict(lambda: {"count": 0, "total_risk": 0.0, "max_risk": 0.0, "attacks": 0})
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=hours)
    for e in events:
        if e.timestamp and e.timestamp >= cutoff:
            hour_key = e.timestamp.strftime("%Y-%m-%d %H:00")
            hourly[hour_key]["count"] += 1
            hourly[hour_key]["total_risk"] += (e.risk_score or 0)
            hourly[hour_key]["max_risk"] = max(hourly[hour_key]["max_risk"], e.risk_score or 0)
            if (e.attack_type or "normal") != "normal":
                hourly[hour_key]["attacks"] += 1
    result = []
    for hour_key in sorted(hourly.keys()):
        d = hourly[hour_key]
        result.append({
            "hour": hour_key,
            "events": d["count"],
            "avg_risk": round(d["total_risk"] / d["count"], 1) if d["count"] else 0,
            "max_risk": round(d["max_risk"], 1),
            "attacks": d["attacks"],
        })
    return {"data": result, "hours": hours}

# Country Distribution
@app.get("/api/geo-distribution")
def get_geo_distribution(current_user: User = Depends(get_current_user)):
    ta = _tenant_args(current_user)
    events, _ = db.fetch_events_paginated(page=1, limit=500, min_risk=0, **ta)
    country_counts = {}
    for e in events:
        country = e.country or _ip_to_country(e.ip or "")
        if country and country not in ("UNKNOWN",):
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
    attack_type: str = Query(""),
    action: str = Query(""),
    current_user: User = Depends(get_current_user),
):
    # If no attack_type specified, return all mappings
    if not attack_type or attack_type == "all":
        from src.mitre_mapping import MITRE_ATTACK_MAP
        result = []
        for at, mapping in MITRE_ATTACK_MAP.items():
            if mapping.get("technique_id"):
                result.append({"attack_type": at, **mapping})
        return {"data": result, "count": len(result)}
    return get_mitre_mapping(attack_type, action)

@app.get("/api/mitre/techniques")
def list_mitre_techniques(current_user: User = Depends(get_current_user)):
    return {"data": get_all_techniques()}

@app.get("/api/mitre/all-mappings")
def get_all_mitre_mappings(current_user: User = Depends(get_current_user)):
    """Return all attack_type -> MITRE ATT&CK mappings."""
    from src.mitre_mapping import MITRE_ATTACK_MAP
    result = []
    for attack_type, mapping in MITRE_ATTACK_MAP.items():
        if mapping.get("technique_id"):  # skip 'normal'
            result.append({
                "attack_type": attack_type,
                **mapping,
            })
    return {"data": result, "count": len(result)}

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

@app.get("/api/shap")
def get_shap_values(current_user: User = Depends(get_current_user)):
    """Alias for /api/explainability — SHAP feature importance."""
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

# ─── Phase 4: Neo4j Attack-Graph Backend ─────────────────────────────────────

@app.get("/api/attack-graph/neo4j")
def attack_graph_neo4j(current_user: User = Depends(get_current_user)):
    """Neo4j-backed graph (falls back gracefully if NEO4J_URI is not set)."""
    from src.attack_graph_neo4j import get_graph, is_configured
    if not is_configured():
        # Graceful degradation — fall through to NetworkX
        ta = _tenant_args(current_user)
        events = db.get_recent_events_for_graph(limit=200, **ta)
        if not events:
            return {"backend": "networkx", "configured": False, "nodes": [], "links": [], "node_count": 0, "link_count": 0}
        from src.attack_graph import build_graph, graph_to_json
        G = build_graph(events)
        out = graph_to_json(G)
        out["backend"] = "networkx"
        out["configured"] = False
        return out
    tenant_id = current_user.id if current_user.role != "admin" else None
    out = get_graph(tenant_id=tenant_id, limit=200)
    out["backend"] = "neo4j"
    return out


@app.get("/api/attack-graph/neo4j/stats")
def attack_graph_neo4j_stats(current_user: User = Depends(require_admin)):
    from src.attack_graph_neo4j import stats
    return stats()


# ─── Phase 4: STIX/TAXII Threat-Intel Feed ───────────────────────────────────

@app.get("/api/stix/indicators")
def stix_indicators(current_user: User = Depends(get_current_user)):
    """Return the cached STIX indicator bundle (read-only, all users)."""
    from src.stix_taxii import get_cached_indicators, is_configured
    out = get_cached_indicators()
    out["server_configured"] = is_configured()
    return out


@app.post("/api/stix/pull")
def stix_pull(max_indicators: int = Query(1000, ge=1, le=10000),
              current_user: User = Depends(require_admin)):
    """Trigger a fresh pull from the configured TAXII server."""
    from src.stix_taxii import pull_feeds
    return pull_feeds(max_indicators=max_indicators)


# ─── Phase 3: Compliance Reports ─────────────────────────────────────────────

@app.get("/api/compliance/report")
def compliance_report_endpoint(
    framework: str = Query("soc2", pattern="^(soc2|iso27001)$"),
    days: int = Query(90, ge=1, le=730),
    current_user: User = Depends(require_admin),
):
    """SOC 2 / ISO 27001 evidence report covering the trailing N days."""
    from src.compliance_report import generate_report
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    return generate_report(db, framework=framework, period_start=start, period_end=end)


# ─── Phase 3: Custom Playbook Builder ────────────────────────────────────────

_VALID_STEP_TYPES = {
    "block_ip", "disable_account", "dispatch_alert", "run_webhook",
    "set_incident_status", "siem_export", "delay",
}


def serialize_playbook(pb: Playbook) -> dict:
    try:
        steps = json.loads(pb.steps or "[]")
    except Exception:
        steps = []
    return {
        "id": pb.id,
        "tenant_id": pb.tenant_id,
        "name": pb.name,
        "description": pb.description or "",
        "enabled": bool(pb.enabled),
        "trigger_attack_types": pb.trigger_attack_types or "",
        "trigger_min_risk": pb.trigger_min_risk or 0,
        "trigger_application_id": pb.trigger_application_id,
        "steps": steps,
        "step_count": len(steps),
        "created_at": pb.created_at.isoformat() if pb.created_at else None,
        "updated_at": pb.updated_at.isoformat() if pb.updated_at else None,
    }


def _validate_steps(steps: list) -> list:
    """Normalise step list and reject unknown types."""
    out = []
    for s in steps:
        if hasattr(s, "dict"):
            s = s.dict()
        stype = (s.get("type") or "").lower()
        if stype not in _VALID_STEP_TYPES:
            raise HTTPException(status_code=400, detail=f"unknown step type: {s.get('type')}")
        out.append({"type": stype, "params": s.get("params") or {}})
    return out


@app.get("/api/playbooks/custom")
def list_custom_playbooks(current_user: User = Depends(get_current_user)):
    pbs = db.list_playbooks(tenant_id=current_user.id)
    return {"data": [serialize_playbook(p) for p in pbs]}


@app.post("/api/playbooks/custom")
def create_custom_playbook(body: CustomPlaybookRequest, current_user: User = Depends(get_current_user)):
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="name required")
    steps_json = json.dumps(_validate_steps(body.steps))
    pb = db.create_playbook(
        tenant_id=current_user.id,
        name=body.name.strip(),
        description=body.description or "",
        enabled=bool(body.enabled),
        trigger_attack_types=body.trigger_attack_types or "",
        trigger_min_risk=float(body.trigger_min_risk or 70.0),
        trigger_application_id=body.trigger_application_id,
        steps=steps_json,
    )
    return serialize_playbook(pb)


@app.get("/api/playbooks/custom/{pb_id}")
def get_custom_playbook(pb_id: int, current_user: User = Depends(get_current_user)):
    pb = db.get_playbook(pb_id, current_user.id)
    if not pb:
        raise HTTPException(status_code=404, detail="playbook not found")
    return serialize_playbook(pb)


@app.patch("/api/playbooks/custom/{pb_id}")
def update_custom_playbook(pb_id: int, body: CustomPlaybookUpdate, current_user: User = Depends(get_current_user)):
    fields = body.model_dump(exclude_unset=True)
    if "steps" in fields and fields["steps"] is not None:
        fields["steps"] = json.dumps(_validate_steps(fields["steps"]))
    pb = db.update_playbook(pb_id, current_user.id, **fields)
    if not pb:
        raise HTTPException(status_code=404, detail="playbook not found")
    return serialize_playbook(pb)


@app.delete("/api/playbooks/custom/{pb_id}")
def delete_custom_playbook(pb_id: int, current_user: User = Depends(get_current_user)):
    ok = db.delete_playbook(pb_id, current_user.id)
    if not ok:
        raise HTTPException(status_code=404, detail="playbook not found")
    return {"success": True, "id": pb_id}


@app.post("/api/playbooks/custom/{pb_id}/dry-run")
def dry_run_custom_playbook(pb_id: int, body: PlaybookDryRunRequest, current_user: User = Depends(get_current_user)):
    pb = db.get_playbook(pb_id, current_user.id)
    if not pb:
        raise HTTPException(status_code=404, detail="playbook not found")
    from src.playbook_runner import dry_run
    return dry_run(serialize_playbook(pb), body.sample_event)


# ─── Phase 2: Advanced ML ────────────────────────────────────────────────────

@app.get("/api/ml/ensemble")
def ml_ensemble_metrics(current_user: User = Depends(require_admin)):
    """Return saved LGBM vs XGB vs combined-ensemble comparison."""
    from src.ensemble_engine import get_ensemble_metrics, compute_and_save_ensemble_metrics
    cached = get_ensemble_metrics()
    if cached.get("per_model"):
        return cached
    try:
        return compute_and_save_ensemble_metrics()
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/ml/ensemble/train")
def ml_ensemble_train(current_user: User = Depends(require_admin)):
    """Train XGBoost and recompute ensemble metrics."""
    from src.ensemble_engine import train_xgboost, compute_and_save_ensemble_metrics
    xgb_metrics = train_xgboost()
    ensemble = compute_and_save_ensemble_metrics()
    return {"xgb": xgb_metrics, "ensemble": ensemble}


@app.get("/api/ml/zero-day")
def ml_zero_day(current_user: User = Depends(get_current_user)):
    """Cluster recent normal-but-suspicious events to surface candidate zero-days."""
    from src.zero_day_detector import cluster_zero_day_events
    ta = _tenant_args(current_user)
    events = db.get_recent_events_for_graph(limit=1000, **ta)
    # We want all events (including risk < 50) for zero-day analysis,
    # so refetch via fetch_events_paginated which doesn't pre-filter.
    events, _ = db.fetch_events_paginated(page=1, limit=2000, min_risk=0, **ta)
    return cluster_zero_day_events(events)


@app.get("/api/ml/sequence-anomaly")
def ml_sequence_anomaly(top_k: int = Query(10, ge=1, le=50), current_user: User = Depends(get_current_user)):
    """Score user sessions for transformer-based sequence anomaly."""
    from src.sequence_anomaly import score_sessions
    ta = _tenant_args(current_user)
    events, _ = db.fetch_events_paginated(page=1, limit=2000, min_risk=0, **ta)
    return score_sessions(events, top_k=top_k)


@app.post("/api/ml/sequence-anomaly/train")
def ml_sequence_anomaly_train(epochs: int = Query(5, ge=1, le=50), current_user: User = Depends(require_admin)):
    """Train the transformer on the platform's full event history (admin)."""
    from src.sequence_anomaly import train_sequence_transformer
    events, _ = db.fetch_events_paginated(page=1, limit=10000, min_risk=0, tenant_id=None, user_role="admin")
    return train_sequence_transformer(events, epochs=epochs)


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket, token: str = Query(default="")):
    """Live event feed.

    Browsers can't set Authorization headers on WebSockets, so the JWT is
    passed as ?token=... in the URL. The connection is rejected if the
    token is missing/invalid; otherwise it's tagged with the user's
    tenant_id so the broadcaster only forwards that tenant's events.
    """
    # Authenticate before accepting — close with 1008 (policy violation) on failure.
    from src.auth import decode_token
    if not token:
        await websocket.close(code=1008, reason="Missing token")
        return
    if token in _revoked_access_tokens:
        await websocket.close(code=1008, reason="Token revoked")
        return
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            await websocket.close(code=1008, reason="Wrong token type")
            return
        user_id = int(payload["sub"])
    except HTTPException:
        await websocket.close(code=1008, reason="Invalid token")
        return

    session = db.Session()
    try:
        user = session.query(User).filter(User.id == user_id, User.is_active == True).first()  # noqa: E712
        if not user:
            await websocket.close(code=1008, reason="User not found")
            return
        tenant_id, user_role = user.id, user.role
    finally:
        session.close()

    await manager.connect(websocket, tenant_id=tenant_id, user_role=user_role)
    try:
        # Tenant-scoped history: same DB filter as GET /api/events.
        ta = {"tenant_id": None, "user_role": "admin"} if user_role == "admin" \
             else {"tenant_id": tenant_id, "user_role": user_role}
        events, _ = db.fetch_events_paginated(page=1, limit=10, **ta)
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
    except Exception:
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
def get_feedback_statistics(current_user: User = Depends(require_admin)):
    return get_feedback_stats()

@app.get("/api/model/drift")
def get_model_drift(current_user: User = Depends(require_admin)):
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
def get_adversarial_results(current_user: User = Depends(require_admin)):
    cached = get_cached_results()
    if cached.get("tests") and len(cached["tests"]) > 0:
        return cached
    # Auto-run if no cached results exist
    try:
        from src.ml_engine import load_ml_engine
        model, encoders = load_ml_engine()
        if model is not None:
            return run_adversarial_tests(model, encoders)
    except Exception:
        pass
    return cached

@app.post("/api/adversarial/run")
def run_adversarial(current_user: User = Depends(require_admin)):
    from src.ml_engine import load_ml_engine
    model, encoders = load_ml_engine()
    if model is None:
        raise HTTPException(status_code=400, detail="ML model not loaded. Train it first.")
    return run_adversarial_tests(model, encoders)


# ── Telegram Bot Endpoints ────────────────────────────────────────────────────

@app.get("/api/telegram/status")
def telegram_status(current_user: User = Depends(require_admin)):
    info = get_bot_info()
    configured = bool(os.getenv("TELEGRAM_BOT_TOKEN")) and bool(os.getenv("TELEGRAM_CHAT_ID"))
    if info:
        return {"status": "online", "configured": True, "bot_name": f"@{info.get('username', '')}", "name": info.get("first_name", "")}
    return {"status": "offline", "configured": configured, "bot_name": "N/A", "error": "Bot not reachable — check TELEGRAM_BOT_TOKEN"}

@app.post("/api/telegram/test")
def telegram_test_message(current_user: User = Depends(require_admin)):
    ok = send_system_status(
        "TrustFlow Telegram integration is working!\n\nThis is a test message from your SOC platform."
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
        # First: try to detect standard CSV with known columns
        if file.filename.endswith('.csv'):
            try:
                df = pd.read_csv(tmp_path)
                required_cols = {'timestamp', 'user', 'ip', 'action', 'status', 'resource'}
                if required_cols.issubset(set(df.columns)):
                    df['_tenant_id'] = current_user.id
                    csv_path = os.path.join(os.path.dirname(tmp_path), f"parsed_{int(time.time())}.csv")
                    df.to_csv(csv_path, index=False)
                    os.remove(tmp_path)
                    events = df.head(3).to_dict('records')
                    return {
                        "message": f"{file.filename} parsed successfully (standard CSV format)",
                        "events_count": len(df),
                        "sample_events": events,
                        "log_format": "standard_csv",
                    }
            except Exception:
                pass

        # Fallback: use log format parsers
        events = parse_log_file(tmp_path)
        if not events:
            return {"message": "File parsed but no events matched known log formats.", "events_count": 0}

        df = pd.DataFrame(events)
        df['_tenant_id'] = current_user.id
        csv_path = os.path.join(os.path.dirname(tmp_path), f"parsed_{int(time.time())}.csv")
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
    playbooks = get_all_playbooks()
    # Enrich with actions count so frontend shows step counts
    for pb in playbooks:
        pb["actions"] = pb.get("steps", [])
        pb["actions_count"] = len(pb.get("steps", []))
    return {"data": playbooks}

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
def get_osint_feeds(current_user: User = Depends(require_admin)):
    from src.osint_feeds import fetch_tor_exit_nodes, fetch_emerging_threats_ips, fetch_urlhaus_recent as fetch_urlhaus
    # Trigger fetches if cache is empty
    try:
        fetch_tor_exit_nodes()
        fetch_emerging_threats_ips()
        fetch_urlhaus()
    except Exception:
        pass
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
