"""
ThreatPulse — SOAR Playbook Engine
Conditional response playbooks based on attack type and risk level.
Each playbook defines a sequence of automated response actions.
"""
import os
import json
from datetime import datetime

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# ── Playbook Definitions ─────────────────────────────────────────────────────

PLAYBOOKS = {
    "brute_force": {
        "name": "Brute Force Response",
        "description": "Lock account, block IP, enforce MFA reset, notify security team",
        "severity_threshold": 70,
        "mitre_technique": "T1110",
        "steps": [
            {"action": "disable_account", "condition": "risk >= 80", "description": "Lock compromised account"},
            {"action": "block_ip", "condition": "risk >= 70", "description": "Block source IP"},
            {"action": "rate_limit", "condition": "always", "description": "Rate limit IP to 5 req/min"},
            {"action": "firewall_rule", "condition": "risk >= 90", "description": "Add DROP rule for source"},
            {"action": "notify", "condition": "always", "description": "Alert SOC team for MFA reset"},
        ],
    },
    "sql_injection": {
        "name": "SQL Injection Response",
        "description": "Block IP, deploy WAF rule, quarantine request logs, preserve evidence",
        "severity_threshold": 60,
        "mitre_technique": "T1190",
        "steps": [
            {"action": "block_ip", "condition": "always", "description": "Immediately block attacker IP"},
            {"action": "firewall_rule", "condition": "always", "description": "Deploy WAF SQL pattern block"},
            {"action": "rate_limit", "condition": "always", "description": "Rate limit all requests from subnet"},
            {"action": "notify", "condition": "always", "description": "Alert DBA team for log review"},
        ],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration Response",
        "description": "Kill session, block IP, disable account, preserve forensic evidence",
        "severity_threshold": 60,
        "mitre_technique": "T1041",
        "steps": [
            {"action": "disable_account", "condition": "always", "description": "Immediately disable user account"},
            {"action": "block_ip", "condition": "always", "description": "Block data destination IP"},
            {"action": "firewall_rule", "condition": "always", "description": "Block outbound to destination"},
            {"action": "rate_limit", "condition": "risk >= 70", "description": "Throttle all user's connections"},
            {"action": "notify", "condition": "always", "description": "Escalate to incident commander"},
        ],
    },
    "port_scan": {
        "name": "Port Scan Response",
        "description": "Rate limit scanner, add to watchlist, monitor for follow-up attacks",
        "severity_threshold": 50,
        "mitre_technique": "T1046",
        "steps": [
            {"action": "rate_limit", "condition": "always", "description": "Rate limit scanner IP"},
            {"action": "block_ip", "condition": "risk >= 80", "description": "Block persistent scanners"},
            {"action": "firewall_rule", "condition": "risk >= 70", "description": "DROP scan traffic for 24h"},
            {"action": "notify", "condition": "risk >= 80", "description": "Alert if scan persists"},
        ],
    },
    "xss": {
        "name": "XSS Attack Response",
        "description": "Block attacker, deploy CSP headers, sanitize affected pages",
        "severity_threshold": 60,
        "mitre_technique": "T1059.007",
        "steps": [
            {"action": "block_ip", "condition": "always", "description": "Block source IP immediately"},
            {"action": "firewall_rule", "condition": "always", "description": "Deploy WAF XSS pattern filter"},
            {"action": "rate_limit", "condition": "always", "description": "Rate limit requests with script payloads"},
            {"action": "notify", "condition": "always", "description": "Alert web team for CSP review"},
        ],
    },
    "privilege_escalation": {
        "name": "Privilege Escalation Response",
        "description": "Lock account, revoke elevated permissions, audit access logs",
        "severity_threshold": 70,
        "mitre_technique": "T1068",
        "steps": [
            {"action": "disable_account", "condition": "always", "description": "Lock affected user account"},
            {"action": "block_ip", "condition": "risk >= 80", "description": "Block if from external IP"},
            {"action": "firewall_rule", "condition": "risk >= 85", "description": "Block lateral movement paths"},
            {"action": "notify", "condition": "always", "description": "Escalate to security ops for privilege audit"},
        ],
    },
    "dos_attack": {
        "name": "DoS/DDoS Response",
        "description": "Rate limit aggressively, activate DDoS mitigation, block source ranges",
        "severity_threshold": 60,
        "mitre_technique": "T1498",
        "steps": [
            {"action": "rate_limit", "condition": "always", "description": "Aggressive rate limiting on source"},
            {"action": "block_ip", "condition": "always", "description": "Block flooding source IP"},
            {"action": "firewall_rule", "condition": "risk >= 70", "description": "Deploy subnet-wide block rules"},
            {"action": "notify", "condition": "always", "description": "Alert NOC team for DDoS mitigation"},
        ],
    },
    "command_injection": {
        "name": "Command Injection Response",
        "description": "Block IP, quarantine process, deploy WAF rules, preserve evidence",
        "severity_threshold": 70,
        "mitre_technique": "T1059",
        "steps": [
            {"action": "block_ip", "condition": "always", "description": "Immediately block attacker IP"},
            {"action": "firewall_rule", "condition": "always", "description": "Deploy WAF command pattern filter"},
            {"action": "rate_limit", "condition": "always", "description": "Rate limit all requests from subnet"},
            {"action": "notify", "condition": "always", "description": "Alert DevOps for input validation review"},
        ],
    },
    "directory_traversal": {
        "name": "Directory Traversal Response",
        "description": "Block source, patch path validation, audit accessed files",
        "severity_threshold": 60,
        "mitre_technique": "T1083",
        "steps": [
            {"action": "block_ip", "condition": "always", "description": "Block traversal source IP"},
            {"action": "firewall_rule", "condition": "risk >= 70", "description": "Deploy path validation WAF rule"},
            {"action": "rate_limit", "condition": "always", "description": "Rate limit file access requests"},
            {"action": "notify", "condition": "risk >= 70", "description": "Alert DevOps for path sanitization"},
        ],
    },
    "session_hijacking": {
        "name": "Session Hijacking Response",
        "description": "Invalidate sessions, force re-auth, block suspicious token usage",
        "severity_threshold": 70,
        "mitre_technique": "T1550",
        "steps": [
            {"action": "disable_account", "condition": "always", "description": "Force logout and invalidate all sessions"},
            {"action": "block_ip", "condition": "always", "description": "Block hijacker IP"},
            {"action": "rate_limit", "condition": "always", "description": "Rate limit token-based requests"},
            {"action": "notify", "condition": "always", "description": "Alert user and SOC for session review"},
        ],
    },
    "credential_stuffing": {
        "name": "Credential Stuffing Response",
        "description": "Block IPs, enable CAPTCHA, enforce MFA, check breached credentials",
        "severity_threshold": 65,
        "mitre_technique": "T1110.004",
        "steps": [
            {"action": "rate_limit", "condition": "always", "description": "Rate limit login attempts from source"},
            {"action": "block_ip", "condition": "risk >= 75", "description": "Block persistent stuffing sources"},
            {"action": "firewall_rule", "condition": "risk >= 80", "description": "Deploy CAPTCHA challenge rule"},
            {"action": "notify", "condition": "always", "description": "Alert SOC to check breached credential lists"},
        ],
    },
    "ssrf": {
        "name": "SSRF Response",
        "description": "Block source, restrict internal access, audit server-side requests",
        "severity_threshold": 70,
        "mitre_technique": "T1090",
        "steps": [
            {"action": "block_ip", "condition": "always", "description": "Block SSRF source IP"},
            {"action": "firewall_rule", "condition": "always", "description": "Restrict server-side outbound requests"},
            {"action": "rate_limit", "condition": "always", "description": "Rate limit URL-fetching endpoints"},
            {"action": "notify", "condition": "always", "description": "Alert DevOps for URL allowlist review"},
        ],
    },
    "malware": {
        "name": "Malware Response",
        "description": "Quarantine file, disable account, block C2, trigger EDR scan",
        "severity_threshold": 60,
        "mitre_technique": "T1204",
        "steps": [
            {"action": "disable_account", "condition": "always", "description": "Disable uploader account immediately"},
            {"action": "block_ip", "condition": "always", "description": "Block malware source/C2 IP"},
            {"action": "firewall_rule", "condition": "always", "description": "Block outbound to known C2 domains"},
            {"action": "rate_limit", "condition": "risk >= 70", "description": "Throttle all file upload endpoints"},
            {"action": "notify", "condition": "always", "description": "Trigger EDR scan and alert IR team"},
        ],
    },
    "insider_threat": {
        "name": "Insider Threat Response",
        "description": "Monitor account, restrict data access, alert HR and legal",
        "severity_threshold": 65,
        "mitre_technique": "T1078",
        "steps": [
            {"action": "rate_limit", "condition": "always", "description": "Throttle bulk data operations"},
            {"action": "disable_account", "condition": "risk >= 85", "description": "Suspend account if high risk"},
            {"action": "firewall_rule", "condition": "risk >= 80", "description": "Block external data transfer"},
            {"action": "notify", "condition": "always", "description": "Alert HR, legal, and security team"},
        ],
    },
    "default": {
        "name": "Default Response",
        "description": "Generic response for unclassified threats",
        "severity_threshold": 80,
        "mitre_technique": "N/A",
        "steps": [
            {"action": "rate_limit", "condition": "risk >= 70", "description": "Apply rate limiting"},
            {"action": "block_ip", "condition": "risk >= 90", "description": "Block if critical risk"},
            {"action": "firewall_rule", "condition": "risk >= 85", "description": "Generate firewall rule"},
            {"action": "notify", "condition": "risk >= 80", "description": "Alert security team"},
        ],
    },
}


def get_playbook(attack_type: str) -> dict:
    """Get the appropriate playbook for an attack type."""
    return PLAYBOOKS.get(attack_type, PLAYBOOKS["default"])


def get_all_playbooks() -> list:
    """Return all playbook definitions."""
    return [{"id": k, **v} for k, v in PLAYBOOKS.items()]


def evaluate_playbook(attack_type: str, risk_score: float) -> dict:
    """
    Evaluate which steps of a playbook should execute based on risk score.
    Returns the playbook with each step marked as 'execute' or 'skip'.
    """
    playbook = get_playbook(attack_type)
    evaluated_steps = []

    for step in playbook["steps"]:
        condition = step["condition"]
        should_execute = False

        if condition == "always":
            should_execute = True
        elif condition.startswith("risk >= "):
            threshold = float(condition.split("risk >= ")[1])
            should_execute = risk_score >= threshold
        elif condition.startswith("risk > "):
            threshold = float(condition.split("risk > ")[1])
            should_execute = risk_score > threshold

        evaluated_steps.append({
            **step,
            "will_execute": should_execute,
            "reason": f"Risk {risk_score:.0f} {'meets' if should_execute else 'below'} threshold ({condition})",
        })

    return {
        "playbook_name": playbook["name"],
        "attack_type": attack_type,
        "risk_score": risk_score,
        "description": playbook["description"],
        "mitre_technique": playbook["mitre_technique"],
        "steps": evaluated_steps,
        "actions_to_execute": sum(1 for s in evaluated_steps if s["will_execute"]),
        "total_steps": len(evaluated_steps),
    }


def execute_playbook(event_dict: dict, incident_id: int = None) -> dict:
    """
    Execute the appropriate SOAR playbook based on attack type and risk.
    Uses the existing response engine for actual actions.
    """
    from src.response_engine import block_ip, disable_account, apply_rate_limit, generate_firewall_rule, _log_response

    attack_type = event_dict.get("attack_type", "unknown")
    risk_score = event_dict.get("risk_score", 0)
    ip = event_dict.get("ip", "unknown")
    user = event_dict.get("user", "unknown")
    action = event_dict.get("action", "")

    evaluation = evaluate_playbook(attack_type, risk_score)
    actions_taken = []

    action_handlers = {
        "block_ip": lambda: block_ip(ip),
        "disable_account": lambda: disable_account(user),
        "rate_limit": lambda: apply_rate_limit(ip, user),
        "firewall_rule": lambda: generate_firewall_rule(ip, action),
        "notify": lambda: {"action": "notify", "status": "sent", "message": f"SOC team notified about INC-{incident_id}"},
    }

    for step in evaluation["steps"]:
        if step["will_execute"]:
            handler = action_handlers.get(step["action"])
            if handler:
                result = handler()
                result["playbook_step"] = step["description"]
                actions_taken.append(result)

    _log_response(incident_id, actions_taken, event_dict)

    return {
        "incident_id": incident_id,
        "playbook": evaluation["playbook_name"],
        "attack_type": attack_type,
        "risk_score": risk_score,
        "timestamp": datetime.utcnow().isoformat(),
        "actions_count": len(actions_taken),
        "actions_taken": actions_taken,
        "evaluation": evaluation,
    }
