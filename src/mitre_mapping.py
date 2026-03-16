"""
MITRE ATT&CK Framework Mapping Module
Maps detected attack types and actions to MITRE ATT&CK Techniques (ATT&CK v14).
Provides technique IDs, tactic categories, descriptions, and mitigations.
"""

# Full MITRE ATT&CK mapping:  attack_type / keyword → (TID, Tactic, Technique Name, Description, Mitigation)
MITRE_ATTACK_MAP = {
    # === By ML-detected attack_type ===
    "brute_force": {
        "technique_id": "T1110",
        "tactic": "Credential Access",
        "technique_name": "Brute Force",
        "sub_technique": "T1110.001 - Password Guessing",
        "description": "Adversaries attempt to gain access to accounts by systematically guessing passwords.",
        "mitigation": "Enable MFA, Account Lockout Policies, Monitor for multiple failed logins.",
        "severity_boost": 15,
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "sql_injection": {
        "technique_id": "T1190",
        "tactic": "Initial Access",
        "technique_name": "Exploit Public-Facing Application",
        "sub_technique": "T1190 - SQL Injection",
        "description": "Adversaries exploit weaknesses in internet-facing web applications to inject malicious SQL.",
        "mitigation": "Input validation, WAF deployment, Parameterized queries, Least privilege DB accounts.",
        "severity_boost": 20,
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "data_exfiltration": {
        "technique_id": "T1041",
        "tactic": "Exfiltration",
        "technique_name": "Exfiltration Over C2 Channel",
        "sub_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "description": "Adversaries steal data by transferring it to external systems over network connections.",
        "mitigation": "DLP solutions, Egress monitoring, Data classification, User behavior analytics.",
        "severity_boost": 25,
        "url": "https://attack.mitre.org/techniques/T1041/"
    },
    "port_scan": {
        "technique_id": "T1046",
        "tactic": "Discovery",
        "technique_name": "Network Service Discovery",
        "sub_technique": "T1046 - Port Scanning",
        "description": "Adversaries scan ports to discover open services and plan further attacks.",
        "mitigation": "Network segmentation, IDS/IPS, Firewall rules, Honeypots.",
        "severity_boost": 10,
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "normal": {
        "technique_id": None,
        "tactic": "N/A",
        "technique_name": "No Threat Detected",
        "sub_technique": None,
        "description": "Traffic pattern matches normal user behaviour baseline.",
        "mitigation": "Continue monitoring.",
        "severity_boost": 0,
        "url": None
    },
    "unknown": {
        "technique_id": "T1036",
        "tactic": "Defense Evasion",
        "technique_name": "Masquerading",
        "sub_technique": "T1036.005 - Match Legitimate Name / Location",
        "description": "Unknown pattern — possibly obfuscated attack evading detection signatures.",
        "mitigation": "Investigate further. Apply process and network monitoring.",
        "severity_boost": 5,
        "url": "https://attack.mitre.org/techniques/T1036/"
    },
}

# === Action keyword → MITRE mapping ===
ACTION_KEYWORD_MAP = {
    "sql":          MITRE_ATTACK_MAP["sql_injection"],
    "inject":       MITRE_ATTACK_MAP["sql_injection"],
    "exfil":        MITRE_ATTACK_MAP["data_exfiltration"],
    "bulk_export":  MITRE_ATTACK_MAP["data_exfiltration"],
    "download":     MITRE_ATTACK_MAP["data_exfiltration"],
    "scan":         MITRE_ATTACK_MAP["port_scan"],
    "probe":        MITRE_ATTACK_MAP["port_scan"],
    "brute":        MITRE_ATTACK_MAP["brute_force"],
    "login":        MITRE_ATTACK_MAP["brute_force"],
    "password":     MITRE_ATTACK_MAP["brute_force"],
    "credential":   {
        "technique_id": "T1003",
        "tactic": "Credential Access",
        "technique_name": "OS Credential Dumping",
        "sub_technique": "T1003.001 - LSASS Memory",
        "description": "Adversaries attempt to dump credential material from OS memory.",
        "mitigation": "Credential Guard, Protected Users group, Disable WDigest.",
        "severity_boost": 20,
        "url": "https://attack.mitre.org/techniques/T1003/"
    },
    "privilege":    {
        "technique_id": "T1068",
        "tactic": "Privilege Escalation",
        "technique_name": "Exploitation for Privilege Escalation",
        "sub_technique": "T1068",
        "description": "Adversaries exploit software vulnerabilities to execute code at higher privilege levels.",
        "mitigation": "Patch management, Least privilege, Application whitelisting.",
        "severity_boost": 25,
        "url": "https://attack.mitre.org/techniques/T1068/"
    },
    "malware":      {
        "technique_id": "T1059",
        "tactic": "Execution",
        "technique_name": "Command and Scripting Interpreter",
        "sub_technique": "T1059.003 - Windows Command Shell",
        "description": "Adversaries abuse command interpreters to execute malicious code.",
        "mitigation": "Application control, Script blocking, PowerShell logging.",
        "severity_boost": 30,
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "ddos":         {
        "technique_id": "T1498",
        "tactic": "Impact",
        "technique_name": "Network Denial of Service",
        "sub_technique": "T1498.001 - Direct Network Flood",
        "description": "Adversaries perform denial of service attacks to degrade or block availability.",
        "mitigation": "Rate limiting, CDN/scrubbing services, Anycast diffusion.",
        "severity_boost": 20,
        "url": "https://attack.mitre.org/techniques/T1498/"
    },
    "admin":        {
        "technique_id": "T1078",
        "tactic": "Defense Evasion / Persistence",
        "technique_name": "Valid Accounts",
        "sub_technique": "T1078.002 - Domain Accounts",
        "description": "Adversaries use valid credentials to access admin systems.",
        "mitigation": "MFA, Privileged Access Workstations, Just-in-time access.",
        "severity_boost": 15,
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
}


def get_mitre_mapping(attack_type: str, action: str = "") -> dict:
    """
    Return MITRE ATT&CK mapping for a given attack_type and/or action.
    Priority: attack_type → action keywords → default.
    """
    attack_type = (attack_type or "").lower().strip()
    action_lower = (action or "").lower()

    # 1. Direct attack_type match
    if attack_type in MITRE_ATTACK_MAP:
        result = MITRE_ATTACK_MAP[attack_type].copy()
        result["source"] = "ml_classifier"
        return result

    # 2. Action keyword scan
    for keyword, mapping in ACTION_KEYWORD_MAP.items():
        if keyword in action_lower:
            result = mapping.copy()
            result["source"] = f"keyword:{keyword}"
            return result

    # 3. Fallback
    result = MITRE_ATTACK_MAP["unknown"].copy()
    result["source"] = "fallback"
    return result


def enrich_event_with_mitre(event_dict: dict) -> dict:
    """Add MITRE mapping fields to an event dict."""
    mapping = get_mitre_mapping(
        event_dict.get("attack_type", ""),
        event_dict.get("action", "")
    )
    event_dict["mitre_technique_id"] = mapping.get("technique_id", "")
    event_dict["mitre_tactic"] = mapping.get("tactic", "")
    event_dict["mitre_technique_name"] = mapping.get("technique_name", "")
    event_dict["mitre_sub_technique"] = mapping.get("sub_technique", "")
    event_dict["mitre_url"] = mapping.get("url", "")
    return event_dict


def get_all_techniques() -> list:
    """Return all unique MITRE techniques in the map."""
    seen = set()
    result = []
    for mapping in list(MITRE_ATTACK_MAP.values()) + list(ACTION_KEYWORD_MAP.values()):
        tid = mapping.get("technique_id")
        if tid and tid not in seen:
            seen.add(tid)
            result.append({
                "technique_id": tid,
                "tactic": mapping.get("tactic"),
                "technique_name": mapping.get("technique_name"),
                "url": mapping.get("url"),
            })
    return sorted(result, key=lambda x: x["technique_id"] or "")
