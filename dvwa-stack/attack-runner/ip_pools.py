"""
IP pool definitions per attack module — aligned with api/main.py _ip_to_country() ranges.
Each module gets a deterministic IP per cycle that rotates across cycles.
"""

import random

# Maps module name → first-octet range (inclusive)
ATTACK_IP_POOLS = {
    "brute_force":       {"lo": 176, "hi": 185},   # RU
    "sql_injection":     {"lo": 201, "hi": 210},   # CN
    "sqli_blind":        {"lo": 221, "hi": 230},   # CN
    "xss_reflected":     {"lo": 81,  "hi": 95},    # EU
    "xss_stored":        {"lo": 51,  "hi": 80},    # EU
    "xss_dom":           {"lo": 91,  "hi": 95},    # EU
    "command_injection": {"lo": 176, "hi": 185},   # RU
    "file_inclusion":    {"lo": 211, "hi": 220},   # KR
    "file_upload":       {"lo": 121, "hi": 130},   # JP
    "csrf":              {"lo": 186, "hi": 190},   # BR
    "weak_session_ids":  {"lo": 196, "hi": 200},   # ZA
    "normal_traffic":    {"lo": 1,   "hi": 50},    # US
}


def get_session_ip_sticky(module_name: str, cycle_id: int) -> str:
    """Return a deterministic IP for (module, cycle) — same within a cycle, rotates across."""
    pool = ATTACK_IP_POOLS.get(module_name, {"lo": 1, "hi": 50})
    rng = random.Random(f"{module_name}:{cycle_id}")
    o1 = rng.randint(pool["lo"], pool["hi"])
    o2 = rng.randint(1, 254)
    o3 = rng.randint(1, 254)
    o4 = rng.randint(1, 254)
    return f"{o1}.{o2}.{o3}.{o4}"
