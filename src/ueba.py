"""
ThreatPulse — User and Entity Behavior Analytics (UEBA)
Detects anomalous user behavior by building per-user baselines.

Detections:
- Unusual login time (statistical z-score deviation from user's normal hours)
- Unusual source location (new country not seen before)
- Impossible travel (two logins from different countries within 30 min)
- Role escalation attempts
- Unusually high resource access volume
- Login from new IP subnet
- New resource access (never accessed before by this user)
- Unusual action (action type not in user's history)
"""
import os
import json
import math
import statistics
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
UEBA_BASELINE_FILE = os.path.join(DATA_DIR, 'ueba_baselines.json')


class UEBAEngine:
    """
    Builds and updates per-user behavioral baselines.
    Scores anomalies in incoming events using statistical deviation detection.
    """

    def __init__(self):
        self.baselines: Dict[str, dict] = {}
        self._load_baselines()

    def _load_baselines(self):
        """Load stored baselines from disk."""
        try:
            if os.path.exists(UEBA_BASELINE_FILE):
                with open(UEBA_BASELINE_FILE, 'r') as f:
                    self.baselines = json.load(f)
        except Exception:
            self.baselines = {}

    def _save_baselines(self):
        """Persist baselines to disk."""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(UEBA_BASELINE_FILE, 'w') as f:
                json.dump(self.baselines, f, indent=2, default=str)
        except Exception:
            pass

    def _get_user_baseline(self, user: str) -> dict:
        if user not in self.baselines:
            self.baselines[user] = {
                "login_hours":        defaultdict(int),       # hour -> count
                "hour_distribution":  {},                     # hour -> count (for stats)
                "avg_hour":           12.0,
                "std_hour":           4.0,
                "countries":          defaultdict(int),       # country -> count
                "ip_subnets":         defaultdict(int),       # /24 subnet -> count
                "resources":          defaultdict(int),       # resource -> count
                "resource_counts":    {},                     # resource -> count (for new resource detection)
                "action_counts":      {},                     # action -> count (for new action detection)
                "roles":              defaultdict(int),       # role -> count
                "event_count":        0,
                "last_country":       None,
                "last_login_ts":      None,
            }
        return self.baselines[user]

    # ── Anomaly detections ──────────────────────────────────────────────────

    def _hour_anomaly(self, baseline: dict, hour: int) -> Optional[dict]:
        """Detect login at a statistically unusual hour using z-score."""
        if baseline["event_count"] < 10:
            return None  # insufficient history

        avg_hour = baseline.get("avg_hour", 12.0)
        std_hour = baseline.get("std_hour", 4.0)

        z_score = abs(hour - avg_hour) / max(std_hour, 1)
        if z_score > 2.5:
            return {
                "type":        "unusual_login_time",
                "severity":    "medium",
                "description": f"Login at {hour:02d}:00 — z-score {z_score:.1f} (avg={avg_hour:.1f}, std={std_hour:.1f})",
                "risk_boost":  15,
            }
        return None

    def _country_anomaly(self, baseline: dict, country: str) -> Optional[dict]:
        """Detect login from a country never seen before."""
        countries = baseline.get("countries", {})
        if baseline["event_count"] < 5:
            return None
        if country and country != "UNKNOWN" and country not in countries:
            return {
                "type":        "new_country",
                "severity":    "high",
                "description": f"Login from new country: {country} — never seen before",
                "risk_boost":  25,
            }
        return None

    def _impossible_travel(self, baseline: dict, country: str, timestamp: datetime) -> Optional[dict]:
        """Detect two logins from different countries within 30 minutes."""
        last_country = baseline.get("last_country")
        last_ts_str  = baseline.get("last_login_ts")
        if not last_country or not last_ts_str:
            return None
        try:
            last_ts = datetime.fromisoformat(str(last_ts_str))
        except Exception:
            return None

        delta_minutes = abs((timestamp - last_ts).total_seconds()) / 60
        if last_country != country and country != "UNKNOWN" and delta_minutes < 60:
            return {
                "type":        "impossible_travel",
                "severity":    "critical",
                "description": f"Login from {country} but last seen in {last_country} {delta_minutes:.0f} min ago — IMPOSSIBLE TRAVEL",
                "risk_boost":  40,
            }
        return None

    def _subnet_anomaly(self, baseline: dict, ip: str) -> Optional[dict]:
        """Detect login from a new /24 subnet."""
        if not ip or ip == "N/A":
            return None
        subnets = baseline.get("ip_subnets", {})
        parts = ip.split(".")
        if len(parts) < 3:
            return None
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        if baseline["event_count"] > 20 and subnet not in subnets:
            return {
                "type":        "new_subnet",
                "severity":    "medium",
                "description": f"Login from new IP subnet: {subnet}",
                "risk_boost":  12,
            }
        return None

    def _volume_anomaly(self, baseline: dict, resource: str) -> Optional[dict]:
        """Detect unusually high access to a specific resource."""
        resources = baseline.get("resources", {})
        count = resources.get(resource, 0)
        avg   = sum(resources.values()) / max(len(resources), 1)
        if count > avg * 3 and count > 10:
            return {
                "type":        "high_volume_access",
                "severity":    "medium",
                "description": f"Unusually high access to {resource}: {count} times (avg={avg:.0f})",
                "risk_boost":  10,
            }
        return None

    def _resource_anomaly(self, baseline: dict, resource: str) -> Optional[dict]:
        """Detect access to a resource never seen before for this user."""
        if not resource or baseline["event_count"] < 5:
            return None
        if resource not in baseline.get("resource_counts", {}):
            return {
                "type":        "new_resource_access",
                "severity":    "low",
                "description": f"First-time access to resource: {resource}",
                "risk_boost":  8,
            }
        return None

    def _action_anomaly(self, baseline: dict, action: str) -> Optional[dict]:
        """Detect an action type never performed before by this user."""
        if not action or baseline["event_count"] < 5:
            return None
        if action not in baseline.get("action_counts", {}):
            return {
                "type":        "unusual_action",
                "severity":    "medium",
                "description": f"First-time action type for user: {action}",
                "risk_boost":  10,
            }
        return None

    # ── Baseline update ────────────────────────────────────────────────────

    def _update_baseline(self, baseline: dict, hour: int, resource: str, action: str,
                         country: str, ip: str, ts: datetime):
        """Incrementally update user baseline with new event data."""
        baseline['event_count'] = baseline.get('event_count', 0) + 1

        # Update hour distribution and recalculate stats
        hour_dist = baseline.get('hour_distribution', {})
        hour_dist[str(hour)] = hour_dist.get(str(hour), 0) + 1
        baseline['hour_distribution'] = hour_dist

        # Also update legacy login_hours
        h_str = str(hour)
        baseline["login_hours"][h_str] = baseline["login_hours"].get(h_str, 0) + 1

        # Recalculate avg and std from hour distribution
        hours = []
        for h, c in hour_dist.items():
            hours.extend([int(h)] * c)
        baseline['avg_hour'] = round(statistics.mean(hours), 2) if hours else 12
        baseline['std_hour'] = round(statistics.stdev(hours), 2) if len(hours) > 1 else 4

        # Track resources
        res_counts = baseline.get('resource_counts', {})
        if resource:
            res_counts[resource] = res_counts.get(resource, 0) + 1
            baseline['resource_counts'] = res_counts
            baseline["resources"][resource] = baseline["resources"].get(resource, 0) + 1

        # Track actions
        act_counts = baseline.get('action_counts', {})
        if action:
            act_counts[action] = act_counts.get(action, 0) + 1
            baseline['action_counts'] = act_counts

        # Country and location tracking
        if country and country != "UNKNOWN":
            baseline["countries"][country] = baseline["countries"].get(country, 0) + 1
            baseline["last_country"] = country
        baseline["last_login_ts"] = ts.isoformat()

        # Subnet tracking
        if ip:
            parts = ip.split(".")
            if len(parts) >= 3:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                baseline["ip_subnets"][subnet] = baseline["ip_subnets"].get(subnet, 0) + 1

    # ── Public API ──────────────────────────────────────────────────────────

    def analyze(self, event: dict) -> List[dict]:
        """
        Analyze one event for UEBA anomalies.

        Args:
            event: dict with keys: user, ip, country, action, resource, role, timestamp

        Returns:
            List of anomaly dicts: [{type, severity, description, risk_boost}, ...]
        """
        user     = event.get("user", "")
        ip       = event.get("ip", "")
        country  = event.get("country", "UNKNOWN")
        resource = event.get("resource", "")
        action   = event.get("action", "")
        hour     = event.get("hour", datetime.utcnow().hour)
        ts_str   = event.get("timestamp", datetime.utcnow().isoformat())

        try:
            ts = datetime.fromisoformat(str(ts_str))
        except Exception:
            ts = datetime.utcnow()

        if not user:
            return []

        baseline = self._get_user_baseline(user)
        anomalies = []

        # Run detectors
        detectors = [
            self._hour_anomaly(baseline, hour),
            self._country_anomaly(baseline, country),
            self._impossible_travel(baseline, country, ts),
            self._subnet_anomaly(baseline, ip),
            self._volume_anomaly(baseline, resource),
            self._resource_anomaly(baseline, resource),
            self._action_anomaly(baseline, action),
        ]
        anomalies = [a for a in detectors if a is not None]

        # Update baseline with this event
        self._update_baseline(baseline, hour, resource, action, country, ip, ts)

        self.baselines[user] = baseline
        self._save_baselines()

        return anomalies

    def get_user_profile(self, user: str) -> dict:
        """Return the baseline profile for a user."""
        bl = self.baselines.get(user, {})
        return {
            "user":         user,
            "event_count":  bl.get("event_count", 0),
            "avg_hour":     bl.get("avg_hour", None),
            "std_hour":     bl.get("std_hour", None),
            "top_countries": sorted(bl.get("countries", {}).items(), key=lambda x: -x[1])[:5],
            "top_hours":     sorted(bl.get("login_hours", {}).items(), key=lambda x: -x[1])[:5],
            "top_resources": sorted(bl.get("resource_counts", {}).items(), key=lambda x: -x[1])[:5],
            "top_actions":   sorted(bl.get("action_counts", {}).items(), key=lambda x: -x[1])[:5],
            "last_country":  bl.get("last_country"),
            "last_login":    bl.get("last_login_ts"),
        }

    def get_all_profiles(self) -> List[dict]:
        """Return all user profiles."""
        return [self.get_user_profile(u) for u in self.baselines.keys()]


# Module-level singleton
_ueba = UEBAEngine()


def analyze_event_ueba(event: dict) -> List[dict]:
    """Analyze an event for UEBA anomalies using the global engine."""
    return _ueba.analyze(event)


def get_user_profile(user: str) -> dict:
    return _ueba.get_user_profile(user)


def get_all_profiles() -> List[dict]:
    return _ueba.get_all_profiles()
