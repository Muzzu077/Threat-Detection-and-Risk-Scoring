"""
ML Engine Training Script
Generates synthetic labeled attack dataset and trains the LightGBM/RF classifier.
Run this once before starting the system:
    python utils/train_ml_engine.py
"""
import os
import sys
import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# ─── Dataset Configuration ────────────────────────────────────────────────────

USERS_NORMAL = ["alice", "bob", "charlie", "david", "emma"]
USERS_ATTACKER = ["hacker_xyz", "bot_001", "scanner_99", "pentest_agent"]

ROLES = {
    "alice": "user", "bob": "user", "charlie": "admin",
    "david": "user", "emma": "guest",
    "hacker_xyz": "unknown", "bot_001": "impersonator",
    "scanner_99": "unknown", "pentest_agent": "unknown"
}

IPS_NORMAL = ["192.168.1.5", "192.168.1.6", "10.0.0.2", "10.0.0.3"]
IPS_ATTACKER = ["45.33.22.11", "182.21.4.9", "103.24.21.10", "91.234.55.1"]

RESOURCES = ["home", "about", "products", "login_page", "admin_panel",
             "user_settings", "api/data", "database", "config", "backup"]

ATTACK_PROFILES = {
    "normal": {
        "users": USERS_NORMAL,
        "ips": IPS_NORMAL,
        "actions": ["view_page", "login", "logout", "api_call", "download_file"],
        "statuses": ["success"] * 9 + ["failed"],
        "resources": ["home", "about", "products", "user_settings"],
        "hours": list(range(9, 18)),  # Business hours
        "weight": 0.55
    },
    "brute_force": {
        "users": USERS_ATTACKER + ["unknown_user"],
        "ips": IPS_ATTACKER,
        "actions": ["login", "failed_login", "login_attempt", "password_reset"],
        "statuses": ["failed"] * 8 + ["success"] * 2,
        "resources": ["login_page", "admin_panel"],
        "hours": list(range(0, 6)) + list(range(22, 24)),  # Night hours
        "weight": 0.12
    },
    "sql_injection": {
        "users": USERS_ATTACKER,
        "ips": IPS_ATTACKER,
        "actions": ["sql_inject_attempt", "sql_query", "api_call", "form_submit"],
        "statuses": ["failed"] * 7 + ["success"] * 3,
        "resources": ["database", "api/data", "admin_panel", "user_settings"],
        "hours": list(range(0, 24)),
        "weight": 0.11
    },
    "data_exfiltration": {
        "users": USERS_ATTACKER + ["charlie"],  # Including insider threat
        "ips": IPS_ATTACKER + ["10.0.0.2"],
        "actions": ["download_file", "bulk_export", "api_call", "data_transfer"],
        "statuses": ["success"] * 8 + ["failed"] * 2,
        "resources": ["database", "backup", "config", "api/data"],
        "hours": list(range(1, 5)) + list(range(22, 24)),  # Late night
        "weight": 0.11
    },
    "port_scan": {
        "users": ["scanner_99", "bot_001"],
        "ips": IPS_ATTACKER,
        "actions": ["api_call", "port_probe", "service_detect", "banner_grab"],
        "statuses": ["failed"] * 6 + ["403_forbidden"] * 3 + ["success"],
        "resources": ["home", "about", "config", "admin_panel", "api/data"],
        "hours": list(range(0, 24)),
        "weight": 0.11
    }
}


def generate_labeled_dataset(n_samples: int = 5000) -> pd.DataFrame:
    """Generate synthetic labeled log events for all attack classes."""
    records = []
    attack_types = list(ATTACK_PROFILES.keys())
    weights = [ATTACK_PROFILES[a]["weight"] for a in attack_types]

    base_time = datetime.now() - timedelta(days=30)

    for i in range(n_samples):
        # Choose attack type based on weights
        attack_type = random.choices(attack_types, weights=weights, k=1)[0]
        profile = ATTACK_PROFILES[attack_type]

        user = random.choice(profile["users"])
        ip = random.choice(profile["ips"])
        action = random.choice(profile["actions"])
        status = random.choice(profile["statuses"])
        resource = random.choice(profile["resources"])
        hour = random.choice(profile["hours"])
        role = ROLES.get(user, "user")

        # Add time noise
        ts = base_time + timedelta(
            days=random.randint(0, 29),
            hours=hour,
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )

        records.append({
            "timestamp": ts.isoformat(),
            "user": user,
            "role": role,
            "ip": ip,
            "action": action,
            "status": status,
            "resource": resource,
            "hour": hour,
            "attack_type": attack_type
        })

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
    return df


def main():
    print("=" * 60)
    print("  ThreatPulse ML Engine — Training Script")
    print("=" * 60)

    os.makedirs("data", exist_ok=True)

    # Generate dataset
    print("\n📊 Generating synthetic labeled dataset (5000 events)...")
    df = generate_labeled_dataset(n_samples=5000)

    data_path = "data/labeled_logs.csv"
    df.to_csv(data_path, index=False)
    print(f"✅ Dataset saved → {data_path}")

    # Print class distribution
    print("\n📈 Class Distribution:")
    for cls, count in df["attack_type"].value_counts().items():
        pct = count / len(df) * 100
        print(f"   {cls:<22} {count:>5} events  ({pct:.1f}%)")

    # Train the model
    print("\n" + "=" * 60)
    from src.ml_engine import train_ml_engine
    metrics = train_ml_engine(data_path=data_path)

    print("\n" + "=" * 60)
    print("  TRAINING COMPLETE — Model Metrics Summary")
    print("=" * 60)
    print(f"  Model Type : {metrics['model_type']}")
    print(f"  Accuracy   : {metrics['accuracy']}%")
    print(f"  Precision  : {metrics['precision']}%")
    print(f"  Recall     : {metrics['recall']}%")
    print(f"  F1 Score   : {metrics['f1_score']}%")
    print("=" * 60)
    print("\n✅ Run the system with: .\\start_enterprise.ps1\n")


if __name__ == "__main__":
    main()
