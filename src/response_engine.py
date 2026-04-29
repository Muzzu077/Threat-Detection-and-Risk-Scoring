"""
SOAR Response Engine — Automated Security Actions

All actions are safe cross-platform simulations (no actual system changes).
Storage is partitioned by tenant_id so each tenant only sees the actions
that fired against their own events.

Storage layout:
  data/blocked_ips.json         -> {tenant_id_str: [ip, ...]}
  data/disabled_accounts.json   -> {tenant_id_str: [user, ...]}
  data/rate_limits.json         -> flat dict (no tenant scoping needed; per-IP/user keys)
  data/response_log.jsonl       -> append-only JSONL, each entry carries tenant_id
"""
import os
import json
import time
from datetime import datetime
from typing import Optional, List

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_DATA_DIR = os.path.join(_PROJECT_ROOT, 'data')

BLOCKED_IPS_FILE = os.path.join(_DATA_DIR, "blocked_ips.json")
DISABLED_ACCOUNTS_FILE = os.path.join(_DATA_DIR, "disabled_accounts.json")
RATE_LIMITS_FILE = os.path.join(_DATA_DIR, "rate_limits.json")
RESPONSE_LOG_FILE = os.path.join(_DATA_DIR, "response_log.jsonl")

# Legacy flat-list files — migrated on first read.
_LEGACY_BLOCKED_IPS_TXT = os.path.join(_DATA_DIR, "blocked_ips.txt")
_LEGACY_DISABLED_ACCOUNTS_TXT = os.path.join(_DATA_DIR, "disabled_accounts.txt")

# Tenant bucket used when no tenant context is available (e.g. legacy data).
_UNSCOPED = "_global"

os.makedirs(_DATA_DIR, exist_ok=True)


# ── tenant-scoped JSON store helpers ─────────────────────────────────────────

def _load_scoped(path: str, legacy_txt: Optional[str] = None) -> dict:
    """Load a tenant-scoped JSON store. Migrates legacy flat .txt to _UNSCOPED."""
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    if legacy_txt and os.path.exists(legacy_txt):
        try:
            with open(legacy_txt, "r") as f:
                items = sorted({line.strip() for line in f if line.strip()})
            if items:
                return {_UNSCOPED: items}
        except Exception:
            pass
    return {}


def _save_scoped(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def _bucket_key(tenant_id: Optional[int]) -> str:
    if tenant_id is None:
        return _UNSCOPED
    return str(int(tenant_id))


def _flatten_buckets(data: dict, tenant_id: Optional[int]) -> List[str]:
    """Return items for a tenant — or all items deduped if tenant_id is None."""
    if tenant_id is None:
        seen = []
        seen_set = set()
        for items in data.values():
            for item in items:
                if item not in seen_set:
                    seen.append(item)
                    seen_set.add(item)
        return seen
    return list(data.get(_bucket_key(tenant_id), []))


# ── Response log (JSONL with tenant_id field) ────────────────────────────────

def _log_response(incident_id: Optional[int], actions: list, event: dict,
                  tenant_id: Optional[int] = None):
    """Append a response action entry to the log file."""
    if tenant_id is None:
        tenant_id = event.get("tenant_id")
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "tenant_id": int(tenant_id) if tenant_id is not None else None,
        "incident_id": incident_id,
        "user": event.get("user", "unknown"),
        "ip": event.get("ip", "unknown"),
        "risk_score": event.get("risk_score", 0),
        "actions_taken": actions,
    }
    with open(RESPONSE_LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── Action implementations (tenant-aware) ────────────────────────────────────

def block_ip(ip: str, tenant_id: Optional[int] = None) -> dict:
    """Simulate blocking an attacker IP for a specific tenant."""
    if not ip or ip in ("127.0.0.1", "::1", "unknown"):
        return {"action": "block_ip", "status": "skipped", "reason": "local/unknown ip"}

    data = _load_scoped(BLOCKED_IPS_FILE, _LEGACY_BLOCKED_IPS_TXT)
    bucket = _bucket_key(tenant_id)
    items = list(data.get(bucket, []))

    if ip in items:
        return {"action": "block_ip", "status": "already_blocked", "ip": ip}

    items.append(ip)
    data[bucket] = sorted(set(items))
    _save_scoped(BLOCKED_IPS_FILE, data)

    iptables_cmd = f"iptables -A INPUT -s {ip} -j DROP"
    return {
        "action": "block_ip",
        "status": "success",
        "ip": ip,
        "command": iptables_cmd,
        "message": f"IP {ip} added to blocklist. Command: {iptables_cmd}",
    }


def disable_account(user: str, tenant_id: Optional[int] = None) -> dict:
    """Simulate disabling a compromised user account for a specific tenant."""
    if not user or user in ("unknown", ""):
        return {"action": "disable_account", "status": "skipped"}

    data = _load_scoped(DISABLED_ACCOUNTS_FILE, _LEGACY_DISABLED_ACCOUNTS_TXT)
    bucket = _bucket_key(tenant_id)
    items = list(data.get(bucket, []))

    if user in items:
        return {"action": "disable_account", "status": "already_disabled", "user": user}

    items.append(user)
    data[bucket] = sorted(set(items))
    _save_scoped(DISABLED_ACCOUNTS_FILE, data)

    return {
        "action": "disable_account",
        "status": "success",
        "user": user,
        "message": f"Account '{user}' disabled pending investigation.",
    }


def apply_rate_limit(ip: str, user: str, tenant_id: Optional[int] = None) -> dict:
    """Flag IP/user for rate limiting. tenant_id kept for log parity but key namespace is shared."""
    rate_limits = {}
    if os.path.exists(RATE_LIMITS_FILE):
        try:
            with open(RATE_LIMITS_FILE, "r") as f:
                rate_limits = json.load(f)
        except Exception:
            rate_limits = {}

    key = ip or user
    rate_limits[key] = {
        "ip": ip,
        "user": user,
        "tenant_id": int(tenant_id) if tenant_id is not None else None,
        "rate": "10_per_minute",
        "applied_at": datetime.utcnow().isoformat(),
        "expires_at": datetime.fromtimestamp(time.time() + 3600).isoformat(),
    }

    with open(RATE_LIMITS_FILE, "w") as f:
        json.dump(rate_limits, f, indent=2)

    return {
        "action": "rate_limit",
        "status": "success",
        "target": key,
        "message": f"Rate limit applied to {key} (10 req/min for 1 hour).",
    }


def generate_firewall_rule(ip: str, action: str) -> dict:
    """Generate a firewall rule string for the detected threat type."""
    if "sql" in action.lower() or "injection" in action.lower():
        rule = f"WAF RULE: BLOCK SQL patterns from {ip}"
        rule_type = "WAF_SQL_BLOCK"
    elif "brute" in action.lower() or "login" in action.lower():
        rule = f"FIREWALL: RATE LIMIT ssh/http from {ip} to 5/min"
        rule_type = "RATE_LIMIT_LOGIN"
    elif "scan" in action.lower() or "port" in action.lower():
        rule = f"FIREWALL: DROP all incoming from {ip} for 24h"
        rule_type = "PORT_SCAN_BLOCK"
    else:
        rule = f"FIREWALL: LOG and ALERT traffic from {ip}"
        rule_type = "GENERIC_ALERT"

    return {
        "action": "firewall_rule",
        "status": "generated",
        "rule_type": rule_type,
        "rule": rule,
        "ip": ip,
    }


def execute_response(event_dict: dict, incident_id: Optional[int] = None,
                     tenant_id: Optional[int] = None) -> dict:
    """
    Main SOAR orchestrator. Determines which actions to take based on event context.
    `tenant_id` defaults to event_dict["tenant_id"] when not passed explicitly.
    """
    if tenant_id is None:
        tenant_id = event_dict.get("tenant_id")

    ip = event_dict.get("ip", "unknown")
    user = event_dict.get("user", "unknown")
    action = event_dict.get("action", "")
    risk_score = event_dict.get("risk_score", 0)

    actions_taken = []

    if risk_score >= 85:
        actions_taken.append(block_ip(ip, tenant_id=tenant_id))

    if any(kw in action.lower() for kw in ["brute", "login", "password", "credential"]):
        actions_taken.append(disable_account(user, tenant_id=tenant_id))

    if risk_score >= 70:
        actions_taken.append(apply_rate_limit(ip, user, tenant_id=tenant_id))

    actions_taken.append(generate_firewall_rule(ip, action))

    _log_response(incident_id, actions_taken, event_dict, tenant_id=tenant_id)

    return {
        "incident_id": incident_id,
        "tenant_id": int(tenant_id) if tenant_id is not None else None,
        "timestamp": datetime.utcnow().isoformat(),
        "risk_score": risk_score,
        "actions_count": len(actions_taken),
        "actions_taken": actions_taken,
    }


# ── Read APIs (tenant-aware) ─────────────────────────────────────────────────

def get_response_log(limit: int = 50, tenant_id: Optional[int] = None) -> list:
    """Read the last N response log entries, optionally filtered to a tenant."""
    if not os.path.exists(RESPONSE_LOG_FILE):
        return []
    entries = []
    with open(RESPONSE_LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            if tenant_id is not None:
                if entry.get("tenant_id") != int(tenant_id):
                    continue
            entries.append(entry)
    return list(reversed(entries))[:limit]


def get_blocked_ips(tenant_id: Optional[int] = None) -> list:
    """Return blocked IPs for a tenant (or all tenants when tenant_id is None)."""
    data = _load_scoped(BLOCKED_IPS_FILE, _LEGACY_BLOCKED_IPS_TXT)
    return _flatten_buckets(data, tenant_id)


def get_disabled_accounts(tenant_id: Optional[int] = None) -> list:
    """Return disabled accounts for a tenant (or all tenants when tenant_id is None)."""
    data = _load_scoped(DISABLED_ACCOUNTS_FILE, _LEGACY_DISABLED_ACCOUNTS_TXT)
    return _flatten_buckets(data, tenant_id)
