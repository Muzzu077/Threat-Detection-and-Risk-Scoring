"""
ML Engine Training Script
Generates synthetic labeled attack dataset with CIC-IDS2017 compatible network features
and trains the LightGBM/RF classifier.
Run this once before starting the system:
    python utils/train_ml_engine.py
"""
import io
import os
import sys
import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Windows encoding fix for emoji output
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

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
        "weight": 0.35
    },
    "brute_force": {
        "users": USERS_ATTACKER + ["unknown_user"],
        "ips": IPS_ATTACKER,
        "actions": ["login", "failed_login", "login_attempt", "password_reset"],
        "statuses": ["failed"] * 8 + ["success"] * 2,
        "resources": ["login_page", "admin_panel"],
        "hours": list(range(0, 6)) + list(range(22, 24)),  # Night hours
        "weight": 0.08
    },
    "sql_injection": {
        "users": USERS_ATTACKER,
        "ips": IPS_ATTACKER,
        "actions": ["sql_inject_attempt", "sql_query", "api_call", "form_submit"],
        "statuses": ["failed"] * 7 + ["success"] * 3,
        "resources": ["database", "api/data", "admin_panel", "user_settings"],
        "hours": list(range(0, 24)),
        "weight": 0.07
    },
    "data_exfiltration": {
        "users": USERS_ATTACKER + ["charlie"],  # Including insider threat
        "ips": IPS_ATTACKER + ["10.0.0.2"],
        "actions": ["download_file", "bulk_export", "api_call", "data_transfer"],
        "statuses": ["success"] * 8 + ["failed"] * 2,
        "resources": ["database", "backup", "config", "api/data"],
        "hours": list(range(1, 5)) + list(range(22, 24)),  # Late night
        "weight": 0.07
    },
    "port_scan": {
        "users": ["scanner_99", "bot_001"],
        "ips": IPS_ATTACKER,
        "actions": ["api_call", "port_probe", "service_detect", "banner_grab"],
        "statuses": ["failed"] * 6 + ["403_forbidden"] * 3 + ["success"],
        "resources": ["home", "about", "config", "admin_panel", "api/data"],
        "hours": list(range(0, 24)),
        "weight": 0.07
    },
    "xss": {
        "users": USERS_ATTACKER + ["unknown_user"],
        "ips": IPS_ATTACKER,
        "actions": ["xss_payload", "script_injection", "form_submit", "api_call"],
        "statuses": ["failed"] * 6 + ["success"] * 4,
        "resources": ["user_settings", "api/data", "home", "products"],
        "hours": list(range(0, 24)),
        "weight": 0.05
    },
    "privilege_escalation": {
        "users": USERS_ATTACKER + ["charlie"],
        "ips": IPS_ATTACKER + ["10.0.0.2"],
        "actions": ["escalate_privilege", "sudo_attempt", "role_change", "admin_access"],
        "statuses": ["failed"] * 5 + ["success"] * 5,
        "resources": ["admin_panel", "config", "database", "user_settings"],
        "hours": list(range(0, 6)) + list(range(20, 24)),
        "weight": 0.04
    },
    "dos_attack": {
        "users": USERS_ATTACKER + ["bot_001"],
        "ips": IPS_ATTACKER,
        "actions": ["flood_request", "api_call", "resource_exhaust", "connection_flood"],
        "statuses": ["failed"] * 3 + ["429_rate_limited"] * 5 + ["success"] * 2,
        "resources": ["home", "api/data", "login_page", "products"],
        "hours": list(range(0, 24)),
        "weight": 0.05
    },
    "command_injection": {
        "users": USERS_ATTACKER,
        "ips": IPS_ATTACKER,
        "actions": ["cmd_inject", "shell_exec", "api_call", "form_submit"],
        "statuses": ["failed"] * 7 + ["success"] * 3,
        "resources": ["admin_panel", "config", "api/data", "database"],
        "hours": list(range(0, 24)),
        "weight": 0.04
    },
    "directory_traversal": {
        "users": USERS_ATTACKER + ["unknown_user"],
        "ips": IPS_ATTACKER,
        "actions": ["path_traversal", "file_read", "api_call", "directory_listing"],
        "statuses": ["failed"] * 7 + ["success"] * 3,
        "resources": ["config", "backup", "admin_panel", "database"],
        "hours": list(range(0, 24)),
        "weight": 0.04
    },
    "session_hijacking": {
        "users": USERS_ATTACKER + ["bob"],
        "ips": IPS_ATTACKER + ["192.168.1.5"],
        "actions": ["session_steal", "cookie_hijack", "token_replay", "api_call"],
        "statuses": ["success"] * 6 + ["failed"] * 4,
        "resources": ["user_settings", "admin_panel", "api/data", "database"],
        "hours": list(range(0, 24)),
        "weight": 0.04
    },
    "credential_stuffing": {
        "users": ["bot_001", "scanner_99"] + USERS_ATTACKER,
        "ips": IPS_ATTACKER,
        "actions": ["login", "failed_login", "credential_test", "api_call"],
        "statuses": ["failed"] * 8 + ["success"] * 2,
        "resources": ["login_page", "api/data"],
        "hours": list(range(0, 24)),
        "weight": 0.04
    },
    "ssrf": {
        "users": USERS_ATTACKER,
        "ips": IPS_ATTACKER,
        "actions": ["ssrf_attempt", "internal_request", "api_call", "url_fetch"],
        "statuses": ["failed"] * 6 + ["success"] * 4,
        "resources": ["api/data", "config", "admin_panel", "database"],
        "hours": list(range(0, 24)),
        "weight": 0.03
    },
    "malware": {
        "users": USERS_ATTACKER + ["unknown_user"],
        "ips": IPS_ATTACKER,
        "actions": ["malware_upload", "file_execute", "payload_delivery", "download_file"],
        "statuses": ["failed"] * 5 + ["success"] * 5,
        "resources": ["admin_panel", "backup", "config", "api/data"],
        "hours": list(range(0, 6)) + list(range(22, 24)),
        "weight": 0.03
    },
    "insider_threat": {
        "users": ["charlie", "emma", "david"],
        "ips": IPS_NORMAL,
        "actions": ["bulk_export", "data_transfer", "download_file", "privilege_abuse"],
        "statuses": ["success"] * 8 + ["failed"] * 2,
        "resources": ["database", "backup", "config", "api/data"],
        "hours": list(range(1, 5)) + list(range(21, 24)),
        "weight": 0.04
    },
}

# ─── CIC-IDS2017 Compatible Network Feature Distributions ────────────────────

NETWORK_PROFILES = {
    "normal": {
        "flow_duration": (2500000, 1500000),       # mean, std (microseconds)
        "total_fwd_packets": (8, 5),
        "total_bwd_packets": (6, 4),
        "flow_bytes_per_s": (2500, 1500),
        "fwd_packet_length_mean": (500, 200),
        "bwd_packet_length_mean": (400, 150),
        "flow_iat_mean": (275000, 150000),
        "fwd_psh_flags": (0.5, 0.5),
        "syn_flag_count": (1, 0.5),
        "rst_flag_count": (0.3, 0.3),
        "ack_flag_count": (8, 5),
        "down_up_ratio": (1.2, 0.5),
        "active_mean": (150000, 80000),
        "idle_mean": (500000, 200000),
    },
    "brute_force": {
        "flow_duration": (800000, 400000),
        "total_fwd_packets": (200, 150),
        "total_bwd_packets": (50, 30),
        "flow_bytes_per_s": (8000, 4000),
        "fwd_packet_length_mean": (300, 100),
        "bwd_packet_length_mean": (200, 80),
        "flow_iat_mean": (3000, 1500),
        "fwd_psh_flags": (1.5, 1),
        "syn_flag_count": (5, 3),
        "rst_flag_count": (3, 2),
        "ack_flag_count": (100, 60),
        "down_up_ratio": (1.5, 0.8),
        "active_mean": (50000, 30000),
        "idle_mean": (100000, 60000),
    },
    "sql_injection": {
        "flow_duration": (1500000, 800000),
        "total_fwd_packets": (15, 10),
        "total_bwd_packets": (10, 6),
        "flow_bytes_per_s": (10000, 5000),
        "fwd_packet_length_mean": (1400, 400),
        "bwd_packet_length_mean": (600, 250),
        "flow_iat_mean": (100000, 60000),
        "fwd_psh_flags": (3.5, 1),
        "syn_flag_count": (2, 1),
        "rst_flag_count": (1, 0.8),
        "ack_flag_count": (15, 8),
        "down_up_ratio": (1.8, 0.7),
        "active_mean": (200000, 100000),
        "idle_mean": (300000, 150000),
    },
    "data_exfiltration": {
        "flow_duration": (5000000, 2000000),
        "total_fwd_packets": (5, 3),
        "total_bwd_packets": (30, 20),
        "flow_bytes_per_s": (200000, 150000),
        "fwd_packet_length_mean": (400, 150),
        "bwd_packet_length_mean": (1200, 400),
        "flow_iat_mean": (200000, 100000),
        "fwd_psh_flags": (1, 0.8),
        "syn_flag_count": (1.5, 1),
        "rst_flag_count": (0.5, 0.5),
        "ack_flag_count": (25, 15),
        "down_up_ratio": (12, 5),
        "active_mean": (300000, 150000),
        "idle_mean": (800000, 300000),
    },
    "port_scan": {
        "flow_duration": (200000, 150000),
        "total_fwd_packets": (2, 1),
        "total_bwd_packets": (1, 0.8),
        "flow_bytes_per_s": (1500, 800),
        "fwd_packet_length_mean": (100, 50),
        "bwd_packet_length_mean": (60, 30),
        "flow_iat_mean": (10000, 8000),
        "fwd_psh_flags": (0.3, 0.3),
        "syn_flag_count": (50, 30),
        "rst_flag_count": (25, 15),
        "ack_flag_count": (3, 2),
        "down_up_ratio": (0.8, 0.4),
        "active_mean": (20000, 15000),
        "idle_mean": (50000, 30000),
    },
    "xss": {
        "flow_duration": (1200000, 600000),
        "total_fwd_packets": (12, 8),
        "total_bwd_packets": (8, 5),
        "flow_bytes_per_s": (6000, 3000),
        "fwd_packet_length_mean": (1100, 350),
        "bwd_packet_length_mean": (500, 200),
        "flow_iat_mean": (80000, 40000),
        "fwd_psh_flags": (3, 1.5),
        "syn_flag_count": (2, 1),
        "rst_flag_count": (0.8, 0.6),
        "ack_flag_count": (12, 7),
        "down_up_ratio": (1.5, 0.6),
        "active_mean": (180000, 90000),
        "idle_mean": (250000, 120000),
    },
    "privilege_escalation": {
        "flow_duration": (3000000, 1500000),
        "total_fwd_packets": (25, 15),
        "total_bwd_packets": (20, 12),
        "flow_bytes_per_s": (5000, 2500),
        "fwd_packet_length_mean": (600, 250),
        "bwd_packet_length_mean": (800, 300),
        "flow_iat_mean": (120000, 70000),
        "fwd_psh_flags": (2, 1),
        "syn_flag_count": (3, 2),
        "rst_flag_count": (1.5, 1),
        "ack_flag_count": (30, 18),
        "down_up_ratio": (1.0, 0.4),
        "active_mean": (250000, 130000),
        "idle_mean": (400000, 200000),
    },
    "dos_attack": {
        "flow_duration": (100000, 80000),
        "total_fwd_packets": (500, 300),
        "total_bwd_packets": (10, 8),
        "flow_bytes_per_s": (50000, 30000),
        "fwd_packet_length_mean": (200, 80),
        "bwd_packet_length_mean": (50, 30),
        "flow_iat_mean": (500, 300),
        "fwd_psh_flags": (0.5, 0.4),
        "syn_flag_count": (100, 60),
        "rst_flag_count": (50, 30),
        "ack_flag_count": (200, 120),
        "down_up_ratio": (0.3, 0.2),
        "active_mean": (10000, 8000),
        "idle_mean": (20000, 15000),
    },
    "command_injection": {
        "flow_duration": (1800000, 900000),
        "total_fwd_packets": (10, 6),
        "total_bwd_packets": (8, 5),
        "flow_bytes_per_s": (8000, 4000),
        "fwd_packet_length_mean": (1300, 400),
        "bwd_packet_length_mean": (700, 300),
        "flow_iat_mean": (90000, 50000),
        "fwd_psh_flags": (4, 2),
        "syn_flag_count": (2, 1),
        "rst_flag_count": (1, 0.7),
        "ack_flag_count": (10, 6),
        "down_up_ratio": (1.6, 0.7),
        "active_mean": (200000, 100000),
        "idle_mean": (300000, 150000),
    },
    "directory_traversal": {
        "flow_duration": (900000, 500000),
        "total_fwd_packets": (8, 5),
        "total_bwd_packets": (12, 8),
        "flow_bytes_per_s": (4000, 2000),
        "fwd_packet_length_mean": (800, 300),
        "bwd_packet_length_mean": (1000, 400),
        "flow_iat_mean": (60000, 35000),
        "fwd_psh_flags": (2, 1),
        "syn_flag_count": (2, 1),
        "rst_flag_count": (1.5, 1),
        "ack_flag_count": (15, 9),
        "down_up_ratio": (2.0, 0.8),
        "active_mean": (150000, 80000),
        "idle_mean": (200000, 100000),
    },
    "session_hijacking": {
        "flow_duration": (2000000, 1000000),
        "total_fwd_packets": (15, 10),
        "total_bwd_packets": (15, 10),
        "flow_bytes_per_s": (4500, 2200),
        "fwd_packet_length_mean": (500, 200),
        "bwd_packet_length_mean": (500, 200),
        "flow_iat_mean": (150000, 80000),
        "fwd_psh_flags": (1.5, 1),
        "syn_flag_count": (1, 0.5),
        "rst_flag_count": (0.5, 0.4),
        "ack_flag_count": (20, 12),
        "down_up_ratio": (1.1, 0.3),
        "active_mean": (200000, 100000),
        "idle_mean": (350000, 180000),
    },
    "credential_stuffing": {
        "flow_duration": (600000, 300000),
        "total_fwd_packets": (150, 100),
        "total_bwd_packets": (40, 25),
        "flow_bytes_per_s": (7000, 3500),
        "fwd_packet_length_mean": (280, 90),
        "bwd_packet_length_mean": (180, 70),
        "flow_iat_mean": (2500, 1200),
        "fwd_psh_flags": (1.2, 0.8),
        "syn_flag_count": (4, 2.5),
        "rst_flag_count": (2.5, 1.5),
        "ack_flag_count": (80, 50),
        "down_up_ratio": (1.4, 0.7),
        "active_mean": (40000, 25000),
        "idle_mean": (80000, 50000),
    },
    "ssrf": {
        "flow_duration": (1500000, 800000),
        "total_fwd_packets": (6, 4),
        "total_bwd_packets": (20, 12),
        "flow_bytes_per_s": (12000, 6000),
        "fwd_packet_length_mean": (900, 350),
        "bwd_packet_length_mean": (1100, 400),
        "flow_iat_mean": (100000, 60000),
        "fwd_psh_flags": (2.5, 1.2),
        "syn_flag_count": (3, 2),
        "rst_flag_count": (1, 0.8),
        "ack_flag_count": (18, 10),
        "down_up_ratio": (4.0, 2.0),
        "active_mean": (180000, 90000),
        "idle_mean": (280000, 140000),
    },
    "malware": {
        "flow_duration": (4000000, 2000000),
        "total_fwd_packets": (8, 5),
        "total_bwd_packets": (25, 15),
        "flow_bytes_per_s": (100000, 60000),
        "fwd_packet_length_mean": (350, 150),
        "bwd_packet_length_mean": (1400, 500),
        "flow_iat_mean": (180000, 100000),
        "fwd_psh_flags": (1, 0.8),
        "syn_flag_count": (2, 1),
        "rst_flag_count": (0.5, 0.4),
        "ack_flag_count": (22, 14),
        "down_up_ratio": (8.0, 4.0),
        "active_mean": (300000, 150000),
        "idle_mean": (600000, 300000),
    },
    "insider_threat": {
        "flow_duration": (6000000, 3000000),
        "total_fwd_packets": (6, 4),
        "total_bwd_packets": (35, 20),
        "flow_bytes_per_s": (180000, 100000),
        "fwd_packet_length_mean": (400, 150),
        "bwd_packet_length_mean": (1100, 350),
        "flow_iat_mean": (250000, 130000),
        "fwd_psh_flags": (1, 0.7),
        "syn_flag_count": (1, 0.5),
        "rst_flag_count": (0.3, 0.3),
        "ack_flag_count": (28, 16),
        "down_up_ratio": (10, 5),
        "active_mean": (350000, 180000),
        "idle_mean": (900000, 400000),
    },
}


def generate_labeled_dataset(n_samples: int = 10000) -> pd.DataFrame:
    """Generate synthetic labeled log events with CIC-IDS2017 compatible network features."""
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

        # Generate CIC-IDS2017 compatible network features
        net_profile = NETWORK_PROFILES[attack_type]
        net_features = {}
        for feat, (mean, std) in net_profile.items():
            val = np.random.normal(mean, std)
            # Ensure non-negative values for counts and durations
            if feat in ("total_fwd_packets", "total_bwd_packets", "fwd_psh_flags",
                         "syn_flag_count", "rst_flag_count", "ack_flag_count"):
                val = max(0, round(val))
            elif feat in ("flow_duration", "flow_bytes_per_s", "flow_iat_mean",
                           "active_mean", "idle_mean"):
                val = max(0, round(val, 2))
            elif feat == "down_up_ratio":
                val = max(0.01, round(val, 3))
            else:
                val = max(0, round(val, 2))
            net_features[feat] = val

        # Derive flow_packets_per_s from total packets and flow_duration
        flow_dur_sec = net_features["flow_duration"] / 1e6  # convert microseconds to seconds
        total_packets = net_features["total_fwd_packets"] + net_features["total_bwd_packets"]
        net_features["flow_packets_per_s"] = round(total_packets / max(flow_dur_sec, 0.001), 2)

        record = {
            "timestamp": ts.isoformat(),
            "user": user,
            "role": role,
            "ip": ip,
            "action": action,
            "status": status,
            "resource": resource,
            "hour": hour,
            **net_features,
            "attack_type": attack_type
        }
        records.append(record)

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
    return df


def main():
    print("=" * 60)
    print("  ThreatPulse ML Engine — Training Script")
    print("=" * 60)

    os.makedirs("data", exist_ok=True)

    # Generate dataset
    print("\n Generating synthetic CIC-IDS2017 compatible dataset (10000 events)...")
    df = generate_labeled_dataset(n_samples=10000)

    data_path = "data/labeled_logs.csv"
    df.to_csv(data_path, index=False)
    print(f" Dataset saved -> {data_path}")

    # Print class distribution
    print("\n Class Distribution:")
    for cls, count in df["attack_type"].value_counts().items():
        pct = count / len(df) * 100
        print(f"   {cls:<22} {count:>5} events  ({pct:.1f}%)")

    # Print network feature summary
    net_cols = ['flow_duration', 'total_fwd_packets', 'total_bwd_packets',
                'flow_bytes_per_s', 'flow_packets_per_s', 'fwd_packet_length_mean',
                'bwd_packet_length_mean', 'flow_iat_mean', 'fwd_psh_flags',
                'syn_flag_count', 'rst_flag_count', 'ack_flag_count',
                'down_up_ratio', 'active_mean', 'idle_mean']
    print(f"\n Network Features: {len(net_cols)} CIC-IDS2017 compatible features added")

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
    print("\n Run the system with: .\\start_enterprise.ps1\n")


if __name__ == "__main__":
    main()
