"""
TrustFlow — SIEM Export Connector
Pipes high-risk events into the customer's existing SOC tooling.

Supported targets (per-tenant config in NotificationPreference):
    splunk   — HTTP Event Collector (HEC), token auth
    elastic  — _bulk index API, optional Basic auth via token
    datadog  — /v1/input logs API, DD-API-KEY header
    webhook  — generic HTTPS POST with Bearer token

All transports are best-effort and time out at 5s. Failures are logged and
swallowed so they never block the ingest path.
"""
import json
from datetime import datetime
import requests

_TIMEOUT = 5.0


def _to_cef(event: dict, incident_id: int) -> str:
    """ArcSight Common Event Format — universally accepted by SIEMs."""
    risk = float(event.get("risk_score", 0))
    severity = min(10, max(1, int(risk / 10)))
    fields = {
        "src":      event.get("ip", ""),
        "suser":    event.get("user", ""),
        "request":  event.get("resource", ""),
        "act":      event.get("action", ""),
        "outcome":  event.get("status", ""),
        "cs1":      event.get("attack_type", ""),
        "cs1Label": "AttackType",
        "cn1":      str(int(risk)),
        "cn1Label": "RiskScore",
        "msg":      (event.get("explanation", "") or "").replace("\n", " ")[:500],
        "externalId": f"INC-{str(incident_id).zfill(4)}",
    }
    extension = " ".join(f"{k}={v}" for k, v in fields.items() if v != "")
    return f"CEF:0|TrustFlow|TrustFlow|3.0|{event.get('attack_type','unknown')}|TrustFlow Alert|{severity}|{extension}"


def _send_splunk(prefs, event: dict, incident_id: int) -> dict:
    """Splunk HEC — POST {url}/services/collector/event"""
    if not prefs.siem_url or not prefs.siem_token:
        return {"ok": False, "error": "splunk url/token missing"}
    url = prefs.siem_url.rstrip("/") + "/services/collector/event"
    payload = {
        "time": int(datetime.utcnow().timestamp()),
        "host": "trustflow",
        "source": "trustflow-saas",
        "sourcetype": "trustflow:incident",
        "index": prefs.siem_index or "trustflow",
        "event": {
            "incident_id": incident_id,
            "user":        event.get("user"),
            "ip":          event.get("ip"),
            "action":      event.get("action"),
            "resource":    event.get("resource"),
            "risk_score":  event.get("risk_score"),
            "attack_type": event.get("attack_type"),
            "explanation": event.get("explanation"),
            "country":     event.get("country"),
        },
    }
    headers = {"Authorization": f"Splunk {prefs.siem_token}", "Content-Type": "application/json"}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=_TIMEOUT, verify=False)
        return {"ok": r.status_code in (200, 201), "status": r.status_code, "body": r.text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _send_elastic(prefs, event: dict, incident_id: int) -> dict:
    """Elasticsearch _bulk — POST {url}/{index}/_bulk"""
    if not prefs.siem_url:
        return {"ok": False, "error": "elastic url missing"}
    index = prefs.siem_index or "trustflow"
    url = prefs.siem_url.rstrip("/") + f"/{index}/_bulk"
    doc = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "incident_id": incident_id,
        "event.action": event.get("action"),
        "event.outcome": event.get("status"),
        "source.ip": event.get("ip"),
        "user.name": event.get("user"),
        "url.path": event.get("resource"),
        "trustflow.risk_score": event.get("risk_score"),
        "trustflow.attack_type": event.get("attack_type"),
        "message": event.get("explanation"),
    }
    body = (
        json.dumps({"index": {"_index": index}}) + "\n"
        + json.dumps(doc) + "\n"
    )
    headers = {"Content-Type": "application/x-ndjson"}
    if prefs.siem_token:
        headers["Authorization"] = f"ApiKey {prefs.siem_token}"
    try:
        r = requests.post(url, data=body, headers=headers, timeout=_TIMEOUT, verify=False)
        return {"ok": r.status_code in (200, 201), "status": r.status_code, "body": r.text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _send_datadog(prefs, event: dict, incident_id: int) -> dict:
    """Datadog Logs Intake — POST https://http-intake.logs.datadoghq.com/v1/input/{API_KEY}"""
    if not prefs.siem_token:
        return {"ok": False, "error": "datadog api key missing"}
    base = prefs.siem_url.rstrip("/") if prefs.siem_url else "https://http-intake.logs.datadoghq.com"
    url = f"{base}/v1/input/{prefs.siem_token}"
    payload = {
        "ddsource": "trustflow",
        "ddtags":   f"env:saas,attack_type:{event.get('attack_type','unknown')},incident_id:{incident_id}",
        "hostname": "trustflow-saas",
        "service":  "trustflow",
        "message":  event.get("explanation", ""),
        "trustflow": {
            "incident_id": incident_id,
            "risk_score":  event.get("risk_score"),
            "attack_type": event.get("attack_type"),
            "user":        event.get("user"),
            "ip":          event.get("ip"),
            "resource":    event.get("resource"),
        },
        "level": "ERROR" if (event.get("risk_score", 0) >= 80) else "WARN",
    }
    try:
        r = requests.post(url, json=payload, timeout=_TIMEOUT)
        return {"ok": r.status_code in (200, 202), "status": r.status_code, "body": r.text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _send_webhook(prefs, event: dict, incident_id: int) -> dict:
    """Generic HTTPS POST — JSON body, optional Bearer token."""
    if not prefs.siem_url:
        return {"ok": False, "error": "webhook url missing"}
    payload = {
        "incident_id": incident_id,
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "cef":         _to_cef(event, incident_id),
        "event":       {
            "user":        event.get("user"),
            "ip":          event.get("ip"),
            "action":      event.get("action"),
            "resource":    event.get("resource"),
            "status":      event.get("status"),
            "risk_score":  event.get("risk_score"),
            "attack_type": event.get("attack_type"),
            "explanation": event.get("explanation"),
            "country":     event.get("country"),
        },
    }
    headers = {"Content-Type": "application/json"}
    if prefs.siem_token:
        headers["Authorization"] = f"Bearer {prefs.siem_token}"
    try:
        r = requests.post(prefs.siem_url, json=payload, headers=headers, timeout=_TIMEOUT)
        return {"ok": r.status_code in (200, 201, 202, 204), "status": r.status_code, "body": r.text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


_DISPATCHERS = {
    "splunk":  _send_splunk,
    "elastic": _send_elastic,
    "datadog": _send_datadog,
    "webhook": _send_webhook,
}


def export_event(prefs, event: dict, incident_id: int) -> dict:
    """
    Push a single event to the tenant's configured SIEM.
    Returns: {ok: bool, siem_type, status?, error?, body?}
    """
    if prefs is None or not prefs.enable_siem or not prefs.siem_type:
        return {"ok": False, "skipped": True, "reason": "siem disabled"}
    fn = _DISPATCHERS.get((prefs.siem_type or "").lower())
    if fn is None:
        return {"ok": False, "error": f"unknown siem_type: {prefs.siem_type}"}
    result = fn(prefs, event, incident_id)
    result["siem_type"] = prefs.siem_type
    return result


def test_connection(prefs) -> dict:
    """Send a test/heartbeat event so users can validate their SIEM config."""
    if prefs is None or not prefs.siem_type:
        return {"ok": False, "error": "no SIEM configured"}
    test_event = {
        "user":        "trustflow-system",
        "ip":          "0.0.0.0",
        "action":      "TEST",
        "resource":    "/trustflow/siem-test",
        "status":      "success",
        "risk_score":  0,
        "attack_type": "test_event",
        "explanation": "TrustFlow SIEM connection test — if you see this, your integration is wired up.",
        "country":     "LOCAL",
    }
    return export_event(prefs, test_event, incident_id=0)
