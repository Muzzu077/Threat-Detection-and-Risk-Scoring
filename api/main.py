"""
ThreatPulse FastAPI Backend
REST + WebSocket API for the React frontend dashboard.
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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import pandas as pd
import io
import time

from src.database import db
from src.attack_graph import build_graph, graph_to_json, get_attack_chains
from src.ml_engine import get_ml_metrics
from src.threat_intel import check_ip, get_known_bad_ips
from src.response_engine import execute_response, get_response_log, get_blocked_ips, get_disabled_accounts
from src.mitre_mapping import get_mitre_mapping, get_all_techniques
from src.explainability_shap import load_cached_shap, get_static_feature_importance
from src.threat_predictor import get_prediction_from_db_events

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
    # Start background broadcaster
    task = asyncio.create_task(broadcast_live_events())
    yield
    task.cancel()

# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ThreatPulse API",
    description="AI-Powered Threat Detection and Risk Scoring Platform",
    version="2.0.0",
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

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "online", "service": "ThreatPulse API v2.0"}

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# Events
@app.get("/api/events")
def get_events(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    min_risk: float = Query(0, ge=0, le=100)
):
    events, total = db.fetch_events_paginated(page=page, limit=limit, min_risk=min_risk)
    return {
        "data": [serialize_event(e) for e in events],
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit
    }

# Real-world Data Ingestion
@app.post("/api/ingest/csv")
async def ingest_csv(file: UploadFile = File(...)):
    """Accepts a CSV file of real logs and drops it into logs_ingest folder."""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")
    
    content = await file.read()
    try:
        df = pd.read_csv(io.StringIO(content.decode('utf-8')))
        required_cols = {'timestamp', 'user', 'ip', 'action', 'status', 'resource'}
        if not required_cols.issubset(set(df.columns)):
            raise HTTPException(status_code=400, detail=f"CSV must contain columns: {required_cols}")
        
        # Save to ingested folder
        save_dir = os.path.join(os.path.dirname(__file__), '..', 'logs_ingest')
        os.makedirs(save_dir, exist_ok=True)
        filename = f"real_data_{int(time.time())}.csv"
        filepath = os.path.join(save_dir, filename)
        df.to_csv(filepath, index=False)
        
        return {"message": "CSV uploaded and queued for ingestion.", "events_count": len(df), "file": filename}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process CSV: {str(e)}")

@app.post("/api/ingest/json")
def ingest_json(batch: LogBatchSchema):
    """Accepts JSON events and writes them as a CSV for ingestion."""
    if not batch.events:
        raise HTTPException(status_code=400, detail="Empty event batch.")
        
    df = pd.DataFrame([e.dict() for e in batch.events])
    
    save_dir = os.path.join(os.path.dirname(__file__), '..', 'logs_ingest')
    os.makedirs(save_dir, exist_ok=True)
    filename = f"real_data_{int(time.time())}.csv"
    filepath = os.path.join(save_dir, filename)
    df.to_csv(filepath, index=False)
    
    return {"message": "Logs uploaded and queued for ingestion.", "events_count": len(df), "file": filename}

# Stats / KPIs
@app.get("/api/stats")
def get_stats():
    stats = db.get_stats()
    return stats

# Incidents
@app.get("/api/incidents")
def get_incidents(status: Optional[str] = None):
    incidents = db.fetch_incidents(status=status)
    return {"data": [serialize_incident(i) for i in incidents]}

@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int):
    incident, log_event = db.get_incident_details(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = serialize_incident(incident)
    if log_event:
        result["log_event"] = serialize_event(log_event)
    return result

@app.post("/api/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, body: StatusUpdate):
    valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    db.update_incident_status(incident_id, body.status, body.owner)
    return {"success": True, "incident_id": incident_id, "new_status": body.status}

# SOAR Response
@app.post("/api/response/{incident_id}")
def trigger_response(incident_id: int, body: ResponseTrigger):
    incident, log_event = db.get_incident_details(incident_id)
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
def get_response_log_endpoint(limit: int = Query(50, ge=1, le=200)):
    return {"data": get_response_log(limit=limit)}

@app.get("/api/response/blocked-ips")
def get_blocked_ips_endpoint():
    return {"data": get_blocked_ips()}

@app.get("/api/response/disabled-accounts")
def get_disabled_accounts_endpoint():
    return {"data": get_disabled_accounts()}

# Attack Graph
@app.get("/api/attack-graph")
def get_attack_graph():
    events = db.get_recent_events_for_graph(limit=200)
    if not events:
        return {"nodes": [], "links": [], "node_count": 0, "link_count": 0}
    G = build_graph(events)
    return graph_to_json(G)

@app.get("/api/attack-chains")
def get_attack_chains_endpoint():
    events = db.get_recent_events_for_graph(limit=300)
    chains = get_attack_chains(events, window_minutes=15)
    return {"data": chains, "count": len(chains)}

# ML Metrics
@app.get("/api/ml-metrics")
def get_ml_metrics_endpoint():
    metrics = get_ml_metrics()
    if not metrics:
        return {"message": "No ML metrics found. Run utils/train_ml_engine.py first."}
    return metrics

# Threat Intelligence
@app.get("/api/threat-intel/{ip}")
def get_threat_intel(ip: str):
    result = check_ip(ip)
    return result

@app.get("/api/threat-intel/known-bad")
def get_known_bad():
    return {"data": get_known_bad_ips()}

# Country Distribution (for world map)
@app.get("/api/geo-distribution")
def get_geo_distribution():
    events, _ = db.fetch_events_paginated(page=1, limit=500, min_risk=50)
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
    action: str = Query("")
):
    mapping = get_mitre_mapping(attack_type, action)
    return mapping

@app.get("/api/mitre/techniques")
def list_mitre_techniques():
    return {"data": get_all_techniques()}

@app.get("/api/mitre/event/{event_id}")
def get_event_mitre(event_id: int):
    events, _ = db.fetch_events_paginated(page=1, limit=1000)
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
def get_explainability():
    cached = load_cached_shap()
    if cached.get("features"):
        return cached
    return get_static_feature_importance()

# Threat Prediction
@app.get("/api/prediction")
def get_threat_prediction():
    events = db.get_recent_events_for_graph(limit=100)
    return get_prediction_from_db_events(events)

# Attack Timeline
@app.get("/api/timeline/{incident_id}")
def get_incident_timeline(incident_id: int):
    incident, log_event = db.get_incident_details(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Get nearby events within +/- 30 min from same user or IP
    all_events, _ = db.fetch_events_paginated(page=1, limit=500)
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
    min_risk: float = Query(50, ge=0, le=100)
):
    events, total = db.fetch_events_paginated(page=1, limit=limit, min_risk=min_risk)
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

