"""
TrustFlow — Custom Playbook Runner

Executes user-defined playbooks against ingested events. A playbook is:
    {
      trigger: { attack_types: [...], min_risk: 70.0, application_id: null },
      steps:   [{ type, params }, ...]
    }

Step types:
    - block_ip            params: {duration_seconds?: int}
    - disable_account     params: {}
    - dispatch_alert      params: {severity_override?: 'CRITICAL'|...}
    - run_webhook         params: {url, method?, headers?, body_template?}
    - set_incident_status params: {status: 'RESOLVED'|'FALSE_POSITIVE'|'INVESTIGATING'}
    - siem_export         params: {}
    - delay               params: {seconds: int}  (capped at 5s in-line)
"""
import json
import time
from datetime import datetime
import requests


def _csv_to_list(s: str) -> list:
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def _matches_trigger(playbook, event: dict, application_id: int = None) -> bool:
    """Decide if the playbook should fire for this event."""
    if not playbook.enabled:
        return False
    if (event.get("risk_score") or 0) < (playbook.trigger_min_risk or 0):
        return False
    types = _csv_to_list(playbook.trigger_attack_types)
    if types and (event.get("attack_type") or "unknown") not in types:
        return False
    if playbook.trigger_application_id and application_id and \
       playbook.trigger_application_id != application_id:
        return False
    return True


def _exec_step(step: dict, event: dict, incident_id: int, db, prefs) -> dict:
    """Execute one step. Returns {action, status, message}."""
    stype = step.get("type", "")
    params = step.get("params", {}) or {}
    t0 = time.time()

    try:
        if stype == "block_ip":
            from src.response_engine import block_ip
            r = block_ip(event.get("ip", ""))
            ok = r.get("status") in ("success", "blocked", "already_blocked")
            return _result(stype, ok, f"{r.get('status')}: {event.get('ip')}", t0)

        if stype == "disable_account":
            from src.response_engine import disable_account
            r = disable_account(event.get("user", ""))
            ok = r.get("status") in ("success", "disabled", "already_disabled")
            return _result(stype, ok, f"{r.get('status')}: {event.get('user')}", t0)

        if stype == "dispatch_alert":
            from utils.alert_dispatcher import dispatch_alert_for_user
            override = params.get("severity_override")
            ev = dict(event)
            if override == "CRITICAL":
                ev["risk_score"] = max(ev.get("risk_score", 0), 90)
            results = dispatch_alert_for_user(ev, incident_id, user=None, prefs=prefs) if prefs else {}
            ok = any(results.values()) if isinstance(results, dict) else False
            return _result(stype, ok, f"Alerts: {results}", t0)

        if stype == "run_webhook":
            url = params.get("url", "")
            if not url:
                return _result(stype, False, "missing url", t0)
            method = (params.get("method") or "POST").upper()
            headers = params.get("headers") or {"Content-Type": "application/json"}
            template = params.get("body_template")
            if template:
                # Substitute {var} placeholders
                try:
                    body = template.format(**event, incident_id=incident_id)
                except Exception:
                    body = template
            else:
                body = json.dumps({"event": event, "incident_id": incident_id})
            try:
                r = requests.request(method, url, data=body, headers=headers, timeout=5)
                return _result(stype, r.status_code < 400, f"HTTP {r.status_code}", t0)
            except Exception as e:
                return _result(stype, False, str(e), t0)

        if stype == "set_incident_status":
            status = params.get("status", "INVESTIGATING")
            try:
                db.update_incident_status(incident_id, status, "playbook")
                return _result(stype, True, f"status → {status}", t0)
            except Exception as e:
                return _result(stype, False, str(e), t0)

        if stype == "siem_export":
            if not prefs or not prefs.enable_siem:
                return _result(stype, False, "siem not enabled for tenant", t0)
            from src.siem_export import export_event
            r = export_event(prefs, event, incident_id)
            return _result(stype, r.get("ok", False), str(r), t0)

        if stype == "delay":
            secs = min(5, int(params.get("seconds", 1)))
            time.sleep(secs)
            return _result(stype, True, f"slept {secs}s", t0)

        return _result(stype, False, "unknown step type", t0)
    except Exception as e:
        return _result(stype, False, f"exception: {e}", t0)


def _result(stype, ok, msg, t0):
    return {
        "action":  stype,
        "status":  "success" if ok else "failed",
        "message": msg,
        "duration_ms": int((time.time() - t0) * 1000),
    }


def run_matching_playbooks(event: dict, incident_id: int, tenant_id: int,
                           application_id: int, db, prefs) -> list:
    """Find every playbook that matches `event` and execute its steps in order."""
    if not tenant_id:
        return []
    playbooks = db.list_playbooks(tenant_id=tenant_id)
    executed = []
    for pb in playbooks:
        if not _matches_trigger(pb, event, application_id):
            continue
        try:
            steps = json.loads(pb.steps or "[]")
        except Exception:
            continue
        run_log = []
        for step in steps:
            run_log.append(_exec_step(step, event, incident_id, db, prefs))
        executed.append({
            "playbook_id":   pb.id,
            "playbook_name": pb.name,
            "step_count":    len(run_log),
            "actions":       run_log,
            "executed_at":   datetime.utcnow().isoformat(),
        })
    return executed


def dry_run(playbook_dict: dict, sample_event: dict) -> dict:
    """Validate trigger match + return the action list that would fire — no side effects."""
    class _Pb:
        pass
    pb = _Pb()
    pb.enabled              = playbook_dict.get("enabled", True)
    pb.trigger_attack_types = playbook_dict.get("trigger_attack_types", "")
    pb.trigger_min_risk     = playbook_dict.get("trigger_min_risk", 70.0)
    pb.trigger_application_id = playbook_dict.get("trigger_application_id")
    matched = _matches_trigger(pb, sample_event, sample_event.get("application_id"))
    return {
        "matches": matched,
        "would_execute": playbook_dict.get("steps", []) if matched else [],
        "trigger_summary": {
            "attack_types": _csv_to_list(pb.trigger_attack_types),
            "min_risk": pb.trigger_min_risk,
            "application_id": pb.trigger_application_id,
        },
    }
