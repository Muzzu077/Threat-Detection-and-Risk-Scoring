"""
SOAR Response Engine — Automated Security Actions
Simulates: IP blocking, account disabling, rate limiting, firewall rule generation.
All actions are safe cross-platform simulations (no actual system changes).
"""
import os
import json
import time
from datetime import datetime
from typing import Optional

BLOCKED_IPS_FILE = "data/blocked_ips.txt"
DISABLED_ACCOUNTS_FILE = "data/disabled_accounts.txt"
RATE_LIMITS_FILE = "data/rate_limits.json"
RESPONSE_LOG_FILE = "data/response_log.jsonl"

os.makedirs("data", exist_ok=True)


def _log_response(incident_id: Optional[int], actions: list, event: dict):
    """Append a response action entry to the log file."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "incident_id": incident_id,
        "user": event.get("user", "unknown"),
        "ip": event.get("ip", "unknown"),
        "risk_score": event.get("risk_score", 0),
        "actions_taken": actions
    }
    with open(RESPONSE_LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def block_ip(ip: str) -> dict:
    """Simulate blocking an attacker IP address."""
    if not ip or ip in ("127.0.0.1", "::1", "unknown"):
        return {"action": "block_ip", "status": "skipped", "reason": "local/unknown ip"}

    # Read existing blocked IPs
    blocked = set()
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            blocked = {line.strip() for line in f if line.strip()}

    if ip in blocked:
        return {"action": "block_ip", "status": "already_blocked", "ip": ip}

    blocked.add(ip)
    with open(BLOCKED_IPS_FILE, "w") as f:
        f.write("\n".join(sorted(blocked)) + "\n")

    # Generate simulated iptables command (for display only)
    iptables_cmd = f"iptables -A INPUT -s {ip} -j DROP"

    return {
        "action": "block_ip",
        "status": "success",
        "ip": ip,
        "command": iptables_cmd,
        "message": f"IP {ip} added to blocklist. Command: {iptables_cmd}"
    }


def disable_account(user: str) -> dict:
    """Simulate disabling a compromised user account."""
    if not user or user in ("unknown", ""):
        return {"action": "disable_account", "status": "skipped"}

    disabled = set()
    if os.path.exists(DISABLED_ACCOUNTS_FILE):
        with open(DISABLED_ACCOUNTS_FILE, "r") as f:
            disabled = {line.strip() for line in f if line.strip()}

    if user in disabled:
        return {"action": "disable_account", "status": "already_disabled", "user": user}

    disabled.add(user)
    with open(DISABLED_ACCOUNTS_FILE, "w") as f:
        f.write("\n".join(sorted(disabled)) + "\n")

    return {
        "action": "disable_account",
        "status": "success",
        "user": user,
        "message": f"Account '{user}' disabled pending investigation."
    }


def apply_rate_limit(ip: str, user: str) -> dict:
    """Flag IP/user for rate limiting."""
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
        "rate": "10_per_minute",
        "applied_at": datetime.utcnow().isoformat(),
        "expires_at": datetime.fromtimestamp(time.time() + 3600).isoformat()
    }

    with open(RATE_LIMITS_FILE, "w") as f:
        json.dump(rate_limits, f, indent=2)

    return {
        "action": "rate_limit",
        "status": "success",
        "target": key,
        "message": f"Rate limit applied to {key} (10 req/min for 1 hour)."
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
        "ip": ip
    }


def execute_response(event_dict: dict, incident_id: Optional[int] = None) -> dict:
    """
    Main SOAR orchestrator. Determines which actions to take based on event context.
    Returns summary of all actions taken.
    """
    ip = event_dict.get("ip", "unknown")
    user = event_dict.get("user", "unknown")
    action = event_dict.get("action", "")
    risk_score = event_dict.get("risk_score", 0)

    actions_taken = []

    # Always block the IP for critical events
    if risk_score >= 85:
        result = block_ip(ip)
        actions_taken.append(result)

    # Disable account for identity-based attacks
    if any(kw in action.lower() for kw in ["brute", "login", "password", "credential"]):
        result = disable_account(user)
        actions_taken.append(result)

    # Apply rate limiting for most threats
    if risk_score >= 70:
        result = apply_rate_limit(ip, user)
        actions_taken.append(result)

    # Generate firewall rule
    fw_result = generate_firewall_rule(ip, action)
    actions_taken.append(fw_result)

    # Log everything
    _log_response(incident_id, actions_taken, event_dict)

    return {
        "incident_id": incident_id,
        "timestamp": datetime.utcnow().isoformat(),
        "risk_score": risk_score,
        "actions_count": len(actions_taken),
        "actions_taken": actions_taken
    }


def get_response_log(limit: int = 50) -> list:
    """Read the last N response log entries."""
    if not os.path.exists(RESPONSE_LOG_FILE):
        return []
    entries = []
    with open(RESPONSE_LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    return list(reversed(entries))[-limit:]


def get_blocked_ips() -> list:
    """Return list of currently blocked IPs."""
    if not os.path.exists(BLOCKED_IPS_FILE):
        return []
    with open(BLOCKED_IPS_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]


def get_disabled_accounts() -> list:
    """Return list of currently disabled accounts."""
    if not os.path.exists(DISABLED_ACCOUNTS_FILE):
        return []
    with open(DISABLED_ACCOUNTS_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]
