"""
ThreatPulse — Adversarial Robustness Testing Module
Tests ML model resilience against evasion techniques.
"""
import os
import json
import numpy as np
import pandas as pd
from datetime import datetime

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RESULTS_FILE = os.path.join(_PROJECT_ROOT, 'data', 'adversarial_results.json')


def run_adversarial_tests(model, encoders) -> dict:
    """
    Run a suite of adversarial evasion tests against the ML model.
    Returns detection rates for each evasion technique.
    """
    if model is None or encoders is None:
        return {"error": "Model not loaded", "tests": []}

    from src.ml_engine import predict_attack_type, CATEGORICAL_COLS

    tests = []

    # Test 1: Slow Brute Force (spread login attempts over time to evade rate detection)
    slow_brute = _generate_slow_brute_force(20)
    detected = 0
    for _, row in slow_brute.iterrows():
        result = predict_attack_type(pd.DataFrame([row]), model, encoders)
        if result.get("predicted_class") != "normal":
            detected += 1
    tests.append({
        "name": "Slow Brute Force",
        "description": "Login attempts spread across hours to evade rate-based detection",
        "technique": "T1110.001 - Password Guessing (low-and-slow)",
        "total_samples": len(slow_brute),
        "detected": detected,
        "detection_rate": round(detected / len(slow_brute) * 100, 1),
        "evasion_method": "Temporal spreading",
    })

    # Test 2: Mimicry Attack (attack actions disguised as normal traffic)
    mimicry = _generate_mimicry_attacks(20)
    detected = 0
    for _, row in mimicry.iterrows():
        result = predict_attack_type(pd.DataFrame([row]), model, encoders)
        if result.get("predicted_class") != "normal":
            detected += 1
    tests.append({
        "name": "Mimicry Attack",
        "description": "Malicious actions disguised using normal user patterns",
        "technique": "T1036 - Masquerading",
        "total_samples": len(mimicry),
        "detected": detected,
        "detection_rate": round(detected / len(mimicry) * 100, 1),
        "evasion_method": "Feature mimicry",
    })

    # Test 3: IP Rotation (scanning from different IPs)
    ip_rotation = _generate_ip_rotation_scan(20)
    detected = 0
    for _, row in ip_rotation.iterrows():
        result = predict_attack_type(pd.DataFrame([row]), model, encoders)
        if result.get("predicted_class") != "normal":
            detected += 1
    tests.append({
        "name": "IP Rotation Scan",
        "description": "Port scanning distributed across many source IPs",
        "technique": "T1046 - Network Service Discovery (distributed)",
        "total_samples": len(ip_rotation),
        "detected": detected,
        "detection_rate": round(detected / len(ip_rotation) * 100, 1),
        "evasion_method": "Source diversification",
    })

    # Test 4: Insider Threat (legitimate user performing exfiltration)
    insider = _generate_insider_exfil(20)
    detected = 0
    for _, row in insider.iterrows():
        result = predict_attack_type(pd.DataFrame([row]), model, encoders)
        if result.get("predicted_class") != "normal":
            detected += 1
    tests.append({
        "name": "Insider Data Exfiltration",
        "description": "Legitimate user slowly exfiltrating data using normal access patterns",
        "technique": "T1041 - Exfiltration Over C2 (insider)",
        "total_samples": len(insider),
        "detected": detected,
        "detection_rate": round(detected / len(insider) * 100, 1),
        "evasion_method": "Credential misuse",
    })

    # Test 5: Encoded SQL Injection
    encoded_sqli = _generate_encoded_sqli(20)
    detected = 0
    for _, row in encoded_sqli.iterrows():
        result = predict_attack_type(pd.DataFrame([row]), model, encoders)
        if result.get("predicted_class") != "normal":
            detected += 1
    tests.append({
        "name": "Encoded SQL Injection",
        "description": "SQL injection with URL encoding and comment obfuscation",
        "technique": "T1190 - Exploit Public-Facing Application (obfuscated)",
        "total_samples": len(encoded_sqli),
        "detected": detected,
        "detection_rate": round(detected / len(encoded_sqli) * 100, 1),
        "evasion_method": "Payload obfuscation",
    })

    # Overall metrics
    total_samples = sum(t["total_samples"] for t in tests)
    total_detected = sum(t["detected"] for t in tests)
    overall_rate = round(total_detected / total_samples * 100, 1) if total_samples > 0 else 0

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "overall_detection_rate": overall_rate,
        "overall_evasion_rate": round(100 - overall_rate, 1),
        "total_adversarial_samples": total_samples,
        "total_detected": total_detected,
        "tests": tests,
        "verdict": (
            "ROBUST" if overall_rate >= 80
            else "MODERATE" if overall_rate >= 60
            else "VULNERABLE"
        ),
    }

    # Cache results
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)

    return results


def get_cached_results() -> dict:
    """Get cached adversarial test results."""
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, 'r') as f:
            return json.load(f)
    return {"tests": [], "overall_detection_rate": 0, "verdict": "NOT TESTED"}


def _generate_slow_brute_force(n: int) -> pd.DataFrame:
    """Brute force attempts that look like normal login traffic."""
    records = []
    for i in range(n):
        records.append({
            "user": np.random.choice(["alice", "bob", "charlie"]),
            "role": "user",
            "ip": f"192.168.1.{np.random.randint(2, 254)}",
            "action": np.random.choice(["login", "failed_login", "login_attempt"]),
            "status": "failed",
            "resource": "login_page",
            "hour": np.random.randint(9, 17),
        })
    return pd.DataFrame(records)


def _generate_mimicry_attacks(n: int) -> pd.DataFrame:
    """SQL injection disguised as normal API calls from legitimate users."""
    records = []
    for i in range(n):
        records.append({
            "user": np.random.choice(["alice", "bob", "david"]),
            "role": "user",
            "ip": np.random.choice(["192.168.1.5", "10.0.0.2", "10.0.0.3"]),
            "action": np.random.choice(["api_call", "form_submit", "view_page"]),
            "status": "success",
            "resource": np.random.choice(["database", "api/data", "user_settings"]),
            "hour": np.random.randint(9, 17),
        })
    return pd.DataFrame(records)


def _generate_ip_rotation_scan(n: int) -> pd.DataFrame:
    """Port scanning from many different IPs."""
    records = []
    for i in range(n):
        records.append({
            "user": f"scanner_{i}",
            "role": "unknown",
            "ip": f"{np.random.randint(1,254)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}",
            "action": np.random.choice(["port_probe", "service_detect", "api_call"]),
            "status": np.random.choice(["failed", "403_forbidden"]),
            "resource": np.random.choice(["admin_panel", "config", "api/data"]),
            "hour": np.random.randint(0, 23),
        })
    return pd.DataFrame(records)


def _generate_insider_exfil(n: int) -> pd.DataFrame:
    """Legitimate user doing data exfiltration during work hours."""
    records = []
    for i in range(n):
        records.append({
            "user": np.random.choice(["charlie", "alice"]),
            "role": np.random.choice(["admin", "user"]),
            "ip": np.random.choice(["192.168.1.5", "10.0.0.2"]),
            "action": np.random.choice(["download_file", "bulk_export", "data_transfer"]),
            "status": "success",
            "resource": np.random.choice(["database", "backup", "config"]),
            "hour": np.random.randint(10, 16),
        })
    return pd.DataFrame(records)


def _generate_encoded_sqli(n: int) -> pd.DataFrame:
    """SQL injection with obfuscated payloads."""
    records = []
    for i in range(n):
        records.append({
            "user": np.random.choice(["hacker_xyz", "bot_001", "unknown_user"]),
            "role": "unknown",
            "ip": f"{np.random.randint(40,200)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}",
            "action": np.random.choice(["sql_inject_attempt", "sql_query", "form_submit"]),
            "status": np.random.choice(["failed", "success"]),
            "resource": np.random.choice(["database", "admin_panel", "api/data"]),
            "hour": np.random.randint(0, 23),
        })
    return pd.DataFrame(records)
