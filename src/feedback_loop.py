"""
ThreatPulse — Online Learning / Analyst Feedback Loop
Stores analyst feedback (false positives, confirmed threats) and provides
incremental model improvement capabilities.
"""
import os
import json
from datetime import datetime

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
FEEDBACK_FILE = os.path.join(_PROJECT_ROOT, 'data', 'analyst_feedback.jsonl')
DRIFT_FILE = os.path.join(_PROJECT_ROOT, 'data', 'model_drift.json')


def record_feedback(incident_id: int, event_data: dict, analyst_label: str, original_prediction: str, analyst: str = "Admin"):
    """
    Record analyst feedback on a prediction.
    analyst_label: 'false_positive', 'confirmed_threat', 'escalated', 'benign'
    """
    os.makedirs(os.path.dirname(FEEDBACK_FILE), exist_ok=True)
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "incident_id": incident_id,
        "analyst": analyst,
        "original_prediction": original_prediction,
        "analyst_label": analyst_label,
        "event_data": {
            "user": event_data.get("user", ""),
            "action": event_data.get("action", ""),
            "ip": event_data.get("ip", ""),
            "resource": event_data.get("resource", ""),
            "risk_score": event_data.get("risk_score", 0),
            "attack_type": event_data.get("attack_type", ""),
        },
    }
    with open(FEEDBACK_FILE, 'a') as f:
        f.write(json.dumps(entry) + '\n')

    _update_drift_metrics()
    return entry


def get_feedback_stats() -> dict:
    """Get summary statistics of analyst feedback."""
    if not os.path.exists(FEEDBACK_FILE):
        return {"total_feedback": 0, "false_positives": 0, "confirmed_threats": 0, "fp_rate": 0, "feedback": []}

    entries = []
    with open(FEEDBACK_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass

    total = len(entries)
    fp = sum(1 for e in entries if e.get("analyst_label") == "false_positive")
    confirmed = sum(1 for e in entries if e.get("analyst_label") == "confirmed_threat")

    # FP rate by attack type
    fp_by_type = {}
    total_by_type = {}
    for e in entries:
        atype = e.get("original_prediction", "unknown")
        total_by_type[atype] = total_by_type.get(atype, 0) + 1
        if e.get("analyst_label") == "false_positive":
            fp_by_type[atype] = fp_by_type.get(atype, 0) + 1

    fp_rates = {}
    for atype, count in total_by_type.items():
        fp_rates[atype] = round(fp_by_type.get(atype, 0) / count * 100, 1) if count > 0 else 0

    return {
        "total_feedback": total,
        "false_positives": fp,
        "confirmed_threats": confirmed,
        "fp_rate": round(fp / total * 100, 1) if total > 0 else 0,
        "fp_rates_by_type": fp_rates,
        "recent_feedback": entries[-10:][::-1],  # Last 10, newest first
    }


def _update_drift_metrics():
    """Calculate model drift indicators based on feedback trends."""
    stats = get_feedback_stats()

    drift = {
        "timestamp": datetime.utcnow().isoformat(),
        "fp_rate": stats["fp_rate"],
        "total_feedback": stats["total_feedback"],
        "needs_retraining": stats["fp_rate"] > 15,  # Flag if FP rate exceeds 15%
        "drift_score": min(100, stats["fp_rate"] * 2),  # 0-100 drift score
        "recommendation": (
            "Model performing well" if stats["fp_rate"] < 5
            else "Monitor - slight drift detected" if stats["fp_rate"] < 15
            else "Retraining recommended - high false positive rate"
        ),
    }

    os.makedirs(os.path.dirname(DRIFT_FILE), exist_ok=True)
    with open(DRIFT_FILE, 'w') as f:
        json.dump(drift, f, indent=2)

    return drift


def get_drift_metrics() -> dict:
    """Get current model drift metrics."""
    if os.path.exists(DRIFT_FILE):
        with open(DRIFT_FILE, 'r') as f:
            return json.load(f)
    return {
        "drift_score": 0,
        "fp_rate": 0,
        "needs_retraining": False,
        "recommendation": "No feedback data yet — model drift unknown",
        "total_feedback": 0,
    }


def get_retraining_dataset() -> list:
    """
    Get corrected training examples from analyst feedback.
    These can be merged with the original dataset for retraining.
    """
    if not os.path.exists(FEEDBACK_FILE):
        return []

    corrections = []
    with open(FEEDBACK_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("analyst_label") == "false_positive":
                    corrections.append({
                        **entry.get("event_data", {}),
                        "attack_type": "normal",  # Analyst says it's not an attack
                        "feedback_source": "analyst_correction",
                    })
                elif entry.get("analyst_label") == "confirmed_threat":
                    corrections.append({
                        **entry.get("event_data", {}),
                        "feedback_source": "analyst_confirmed",
                    })
            except Exception:
                pass

    return corrections
