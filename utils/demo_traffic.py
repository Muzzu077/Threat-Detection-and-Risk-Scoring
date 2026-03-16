#!/usr/bin/env python3
"""
ThreatPulse Demo Traffic Generator
===================================
Simulates realistic web application traffic for demo/showcase purposes.
Sends events directly to the /api/v1/ingest endpoint using an API key.

Usage:
  python utils/demo_traffic.py --api-key tp_live_xxx --mode demo
  python utils/demo_traffic.py --api-key tp_live_xxx --mode attack
  python utils/demo_traffic.py --api-key tp_live_xxx --mode live
  python utils/demo_traffic.py --api-key tp_live_xxx --mode verify

Modes:
  verify  — Send 5 test events to check pipeline works
  demo    — Burst of ~100 mixed events (normal + attacks) in ~15 seconds
  attack  — Scripted attack narrative over ~60 seconds (recon → breach → exfil)
  live    — Continuous background traffic (runs forever, Ctrl+C to stop)

Zero dependencies — uses only Python stdlib.
"""

import argparse
import json
import random
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta


# ─── Realistic Data Pools ────────────────────────────────────────────────────

NORMAL_USERS = [
    "sarah@startupcompass.app",
    "mike.chen@startupcompass.app",
    "emma.wilson@startupcompass.app",
    "raj.patel@startupcompass.app",
    "lisa.kim@startupcompass.app",
    "david.garcia@startupcompass.app",
    "anna.mueller@startupcompass.app",
    "james.taylor@startupcompass.app",
    "priya.sharma@startupcompass.app",
    "tom.anderson@startupcompass.app",
]

ATTACKER_USERS = ["anonymous", "anonymous", "anonymous", "admin", "root", "test"]

NORMAL_IPS = [
    "192.168.1.45", "192.168.1.102", "192.168.1.78", "10.0.0.15", "10.0.0.88",
    "172.16.5.20", "172.16.5.34", "203.0.113.50", "198.51.100.12", "100.24.56.78",
]

ATTACKER_IPS = [
    "185.220.101.34",   # Known Tor exit node range
    "45.155.205.99",    # Hosting provider (common for attacks)
    "103.152.220.44",   # Southeast Asia hosting
    "91.240.118.172",   # Eastern Europe
    "5.188.62.18",      # Russian hosting
]

# Normal web app routes (StartupCompass-style)
NORMAL_ROUTES = [
    ("GET",  "/", "success"),
    ("GET",  "/dashboard", "success"),
    ("GET",  "/api/ideas", "success"),
    ("GET",  "/api/ideas?page=1&limit=20", "success"),
    ("POST", "/api/ideas", "success"),
    ("GET",  "/api/analytics/overview", "success"),
    ("GET",  "/api/analytics/growth", "success"),
    ("GET",  "/profile", "success"),
    ("GET",  "/settings", "success"),
    ("PUT",  "/api/settings/notifications", "success"),
    ("GET",  "/api/users/me", "success"),
    ("GET",  "/api/ideas/trending", "success"),
    ("POST", "/api/ideas/vote", "success"),
    ("GET",  "/api/categories", "success"),
    ("GET",  "/api/search?q=market+analysis", "success"),
    ("POST", "/api/auth/login", "success"),
    ("POST", "/api/auth/logout", "success"),
    ("GET",  "/api/notifications", "success"),
    ("GET",  "/api/teams", "success"),
    ("POST", "/api/feedback", "success"),
    ("GET",  "/api/export/csv", "success"),
    ("GET",  "/docs", "success"),
    ("GET",  "/pricing", "success"),
    ("GET",  "/favicon.ico", "success"),
    ("GET",  "/assets/logo.svg", "success"),
    # Occasional failures (404, 403)
    ("GET",  "/api/ideas/99999", "failure"),
    ("GET",  "/old-page", "failure"),
    ("POST", "/api/ideas", "failure"),  # validation error
]

# ─── Attack Event Generators ─────────────────────────────────────────────────

def gen_recon_events(attacker_ip, ts):
    """Phase 1: Reconnaissance — probing for vulnerabilities."""
    probes = [
        ("GET", "/robots.txt", "success"),
        ("GET", "/.env", "failure"),
        ("GET", "/.git/config", "failure"),
        ("GET", "/wp-admin", "failure"),
        ("GET", "/wp-login.php", "failure"),
        ("GET", "/api-docs", "failure"),
        ("GET", "/swagger.json", "failure"),
        ("GET", "/actuator/health", "failure"),
        ("GET", "/server-status", "failure"),
        ("GET", "/phpinfo.php", "failure"),
        ("GET", "/.htaccess", "failure"),
        ("GET", "/admin/config.json", "failure"),
    ]
    events = []
    for method, path, status in probes:
        ts += timedelta(seconds=random.uniform(0.5, 3.0))
        events.append(make_event(ts, "anonymous", attacker_ip, method, status, path))
    return events, ts


def gen_brute_force_events(attacker_ip, ts):
    """Phase 2: Brute force login attempts."""
    targets = ["admin@startupcompass.app", "sarah@startupcompass.app", "root", "administrator", "ceo@startupcompass.app"]
    events = []
    for user in targets:
        for _ in range(random.randint(3, 6)):
            ts += timedelta(seconds=random.uniform(0.3, 1.5))
            events.append(make_event(ts, user, attacker_ip, "POST", "failure", "/api/auth/login"))
    return events, ts


def gen_credential_stuffing_events(attacker_ip, ts):
    """Phase 3: Credential stuffing — trying leaked credentials."""
    leaked_creds = [
        ("mike.chen@startupcompass.app", "failure"),
        ("emma.wilson@startupcompass.app", "failure"),
        ("raj.patel@startupcompass.app", "failure"),
        ("lisa.kim@startupcompass.app", "success"),  # This one works!
    ]
    events = []
    for user, status in leaked_creds:
        ts += timedelta(seconds=random.uniform(1.0, 4.0))
        events.append(make_event(ts, user, attacker_ip, "POST", status, "/api/auth/login"))
    return events, ts


def gen_escalation_events(attacker_ip, compromised_user, ts):
    """Phase 4: Privilege escalation with the compromised account."""
    actions = [
        ("GET",  "/api/users/me", "success"),
        ("GET",  "/admin", "failure"),
        ("GET",  "/api/admin/users", "failure"),
        ("PUT",  "/api/users/role", "failure"),
        ("GET",  "/api/admin/settings", "failure"),
        ("POST", "/api/permissions/elevate", "failure"),
        ("GET",  "/api/users?role=admin", "success"),
    ]
    events = []
    for method, path, status in actions:
        ts += timedelta(seconds=random.uniform(2.0, 8.0))
        events.append(make_event(ts, compromised_user, attacker_ip, method, status, path))
    return events, ts


def gen_exfiltration_events(attacker_ip, compromised_user, ts):
    """Phase 5: Data exfiltration — stealing data."""
    actions = [
        ("GET",  "/api/export/all-data", "success"),
        ("GET",  "/api/ideas?limit=10000", "success"),
        ("GET",  "/api/users?limit=5000", "success"),
        ("POST", "/api/export/csv?table=users", "success"),
        ("GET",  "/api/analytics/raw?from=2020-01-01", "success"),
        ("POST", "/api/webhooks", "success"),  # Setting up data tunnel
    ]
    events = []
    for method, path, status in actions:
        ts += timedelta(seconds=random.uniform(3.0, 10.0))
        events.append(make_event(ts, compromised_user, attacker_ip, method, status, path))
    return events, ts


def gen_injection_events(attacker_ip, ts):
    """Generate SQL injection / XSS / command injection attempts."""
    injections = [
        ("GET", "/api/search?q=' OR '1'='1' --", "failure"),
        ("GET", "/api/ideas?id=1 UNION SELECT * FROM users --", "failure"),
        ("GET", "/api/users?name=<script>alert('xss')</script>", "failure"),
        ("POST", "/api/feedback?msg='; DROP TABLE ideas; --", "failure"),
        ("GET", "/api/files?path=../../../etc/passwd", "failure"),
        ("GET", "/api/proxy?url=http://169.254.169.254/metadata", "failure"),
        ("POST", "/api/upload/shell.php", "failure"),
    ]
    events = []
    for method, path, status in injections:
        ts += timedelta(seconds=random.uniform(1.0, 5.0))
        events.append(make_event(ts, "anonymous", attacker_ip, method, status, path))
    return events, ts


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_event(ts, user, ip, action, status, resource):
    return {
        "timestamp": ts.isoformat() + "Z",
        "user": user,
        "ip": ip,
        "action": action,
        "status": status,
        "resource": resource,
    }


def make_normal_event(ts=None):
    """Generate a single realistic normal traffic event."""
    if ts is None:
        ts = datetime.utcnow()
    user = random.choice(NORMAL_USERS)
    ip = random.choice(NORMAL_IPS)
    method, path, status = random.choice(NORMAL_ROUTES)
    return make_event(ts, user, ip, method, status, path)


def send_batch(endpoint, api_key, events):
    """POST a batch of events to the ThreatPulse ingest endpoint."""
    url = f"{endpoint}/api/v1/ingest"
    payload = json.dumps({"events": events}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        print(f"  [ERROR] HTTP {e.code}: {body}")
        return None
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None


def print_header(title):
    print(f"\n{'='*60}")
    print(f"  THREATPULSE TRAFFIC GENERATOR — {title}")
    print(f"{'='*60}\n")


# ─── Mode: verify ────────────────────────────────────────────────────────────

def mode_verify(endpoint, api_key):
    print_header("VERIFY")
    print("Sending 5 test events to verify the pipeline...\n")

    events = []
    now = datetime.utcnow()
    for i in range(5):
        events.append(make_event(
            now + timedelta(seconds=i),
            f"test-user-{i}@verify.com",
            f"10.0.0.{i+1}",
            "GET",
            "success",
            f"/health-check-{i}",
        ))

    result = send_batch(endpoint, api_key, events)
    if result:
        print(f"  [OK] {result.get('accepted', 0)} events accepted")
        print(f"  [OK] Pipeline is working!\n")
    else:
        print("  [FAIL] Could not reach ThreatPulse API.")
        print(f"  Check that the server is running at {endpoint}\n")


# ─── Mode: demo ──────────────────────────────────────────────────────────────

def mode_demo(endpoint, api_key):
    print_header("DEMO BURST")
    print("Generating ~100 mixed events (normal + attacks)...\n")

    all_events = []
    now = datetime.utcnow() - timedelta(minutes=5)  # Start 5 min ago for spread

    # 60 normal events spread over 5 minutes
    print("  [1/4] Generating normal user traffic...")
    for i in range(60):
        ts = now + timedelta(seconds=random.uniform(0, 300))
        all_events.append(make_normal_event(ts))

    # 12 recon probes
    print("  [2/4] Generating reconnaissance probes...")
    attacker_ip = random.choice(ATTACKER_IPS)
    recon_ts = now + timedelta(seconds=random.uniform(30, 90))
    recon_events, _ = gen_recon_events(attacker_ip, recon_ts)
    all_events.extend(recon_events)

    # 15 brute force attempts
    print("  [3/4] Generating brute force attempts...")
    bf_ts = now + timedelta(seconds=random.uniform(120, 180))
    bf_events, _ = gen_brute_force_events(random.choice(ATTACKER_IPS), bf_ts)
    all_events.extend(bf_events)

    # 7 injection attempts
    print("  [4/4] Generating injection attacks...")
    inj_ts = now + timedelta(seconds=random.uniform(200, 280))
    inj_events, _ = gen_injection_events(random.choice(ATTACKER_IPS), inj_ts)
    all_events.extend(inj_events)

    # Sort by timestamp
    all_events.sort(key=lambda e: e["timestamp"])

    # Send in batches of 25
    total_accepted = 0
    total_incidents = 0
    for i in range(0, len(all_events), 25):
        batch = all_events[i:i+25]
        result = send_batch(endpoint, api_key, batch)
        if result:
            total_accepted += result.get("accepted", 0)
            total_incidents += result.get("incidents_created", 0)
            sys.stdout.write(f"\r  Sent {min(i+25, len(all_events))}/{len(all_events)} events...")
            sys.stdout.flush()
        time.sleep(0.3)

    print(f"\n\n  [DONE] {total_accepted} events ingested, {total_incidents} incidents created")
    print(f"  Open your ThreatPulse dashboard to see the results!\n")


# ─── Mode: attack ────────────────────────────────────────────────────────────

def mode_attack(endpoint, api_key):
    print_header("ATTACK SCENARIO")
    print("Simulating a multi-phase attack narrative...\n")
    print("  Storyline: Attacker probes the app, brute-forces login,")
    print("  compromises an account, escalates privileges, exfiltrates data.\n")

    attacker_ip = random.choice(ATTACKER_IPS)
    compromised_user = "lisa.kim@startupcompass.app"
    ts = datetime.utcnow()

    phases = [
        ("Phase 1: RECONNAISSANCE", gen_recon_events, (attacker_ip, ts)),
        ("Phase 2: BRUTE FORCE", gen_brute_force_events, (attacker_ip, None)),
        ("Phase 3: CREDENTIAL STUFFING", gen_credential_stuffing_events, (attacker_ip, None)),
        ("Phase 4: PRIVILEGE ESCALATION", gen_escalation_events, (attacker_ip, compromised_user, None)),
        ("Phase 5: DATA EXFILTRATION", gen_exfiltration_events, (attacker_ip, compromised_user, None)),
        ("Phase 6: INJECTION ATTEMPTS", gen_injection_events, (attacker_ip, None)),
    ]

    total_accepted = 0
    total_incidents = 0

    for phase_name, gen_fn, args in phases:
        print(f"  [{phase_name}]")

        # Generate some normal background traffic alongside attack
        bg_events = [make_normal_event(ts + timedelta(seconds=random.uniform(0, 15))) for _ in range(random.randint(3, 8))]

        # Update timestamp arg (last element of args tuple)
        args_list = list(args)
        args_list[-1] = ts
        events, ts = gen_fn(*args_list)

        # Merge background + attack, sort by time
        combined = bg_events + events
        combined.sort(key=lambda e: e["timestamp"])

        result = send_batch(endpoint, api_key, combined)
        if result:
            accepted = result.get("accepted", 0)
            incidents = result.get("incidents_created", 0)
            total_accepted += accepted
            total_incidents += incidents
            print(f"    -> {accepted} events sent, {incidents} incidents created")
        else:
            print(f"    -> FAILED to send events")

        # Real-time delay between phases
        delay = random.uniform(3, 8)
        print(f"    -> Waiting {delay:.0f}s before next phase...")
        time.sleep(delay)
        ts = datetime.utcnow()  # Reset to real time

    print(f"\n  [ATTACK COMPLETE]")
    print(f"  Total: {total_accepted} events, {total_incidents} incidents")
    print(f"  Attacker IP: {attacker_ip}")
    print(f"  Compromised account: {compromised_user}")
    print(f"\n  Check the Attack Graph and Kill Chain pages!\n")


# ─── Mode: live ───────────────────────────────────────────────────────────────

def mode_live(endpoint, api_key, rate=3):
    print_header("LIVE CONTINUOUS TRAFFIC")
    print(f"  Rate: ~{rate} events/second")
    print(f"  Mix: 85% normal / 15% suspicious")
    print(f"  Press Ctrl+C to stop\n")

    total = 0
    incidents = 0
    batch = []
    attack_cooldown = 0

    try:
        while True:
            now = datetime.utcnow()

            # Decide: normal or suspicious
            if attack_cooldown <= 0 and random.random() < 0.15:
                # Generate a burst of suspicious activity
                attack_type = random.choice(["recon", "brute", "injection"])
                attacker_ip = random.choice(ATTACKER_IPS)

                if attack_type == "recon":
                    probes = [
                        ("GET", "/.env", "failure"),
                        ("GET", "/.git/config", "failure"),
                        ("GET", "/wp-admin", "failure"),
                    ]
                    for method, path, status in random.sample(probes, random.randint(1, 3)):
                        batch.append(make_event(now, "anonymous", attacker_ip, method, status, path))

                elif attack_type == "brute":
                    for _ in range(random.randint(2, 5)):
                        batch.append(make_event(now, random.choice(ATTACKER_USERS), attacker_ip, "POST", "failure", "/api/auth/login"))

                elif attack_type == "injection":
                    payloads = [
                        "/api/search?q=' OR '1'='1",
                        "/api/users?id=1 UNION SELECT * FROM users",
                        "/api/files?path=../../../etc/passwd",
                    ]
                    batch.append(make_event(now, "anonymous", attacker_ip, "GET", "failure", random.choice(payloads)))

                attack_cooldown = random.randint(10, 30)
            else:
                batch.append(make_normal_event(now))
                attack_cooldown -= 1

            # Flush when batch is full
            if len(batch) >= 10:
                result = send_batch(endpoint, api_key, batch)
                if result:
                    accepted = result.get("accepted", 0)
                    inc = result.get("incidents_created", 0)
                    total += accepted
                    incidents += inc
                    status_str = f"  [{now.strftime('%H:%M:%S')}] Sent {accepted} events (total: {total}, incidents: {incidents})"
                    if inc > 0:
                        status_str += f"  ** {inc} NEW INCIDENT(S)! **"
                    print(status_str)
                batch = []

            time.sleep(1.0 / rate)

    except KeyboardInterrupt:
        # Flush remaining
        if batch:
            result = send_batch(endpoint, api_key, batch)
            if result:
                total += result.get("accepted", 0)
        print(f"\n\n  [STOPPED] Total events sent: {total}, incidents: {incidents}\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ThreatPulse Demo Traffic Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  verify   Quick 5-event test to check the pipeline
  demo     Burst of ~100 mixed events (normal + attacks)
  attack   Scripted multi-phase attack narrative
  live     Continuous background traffic (Ctrl+C to stop)

Examples:
  python utils/demo_traffic.py --api-key tp_live_xxx --mode verify
  python utils/demo_traffic.py --api-key tp_live_xxx --mode demo
  python utils/demo_traffic.py --api-key tp_live_xxx --mode attack
  python utils/demo_traffic.py --api-key tp_live_xxx --mode live --rate 5
        """,
    )
    parser.add_argument("--api-key", required=True, help="Your ThreatPulse API key (tp_live_...)")
    parser.add_argument("--endpoint", default="http://localhost:8000", help="ThreatPulse API URL (default: http://localhost:8000)")
    parser.add_argument("--mode", required=True, choices=["verify", "demo", "attack", "live"], help="Traffic generation mode")
    parser.add_argument("--rate", type=float, default=3, help="Events per second for live mode (default: 3)")

    args = parser.parse_args()

    if args.mode == "verify":
        mode_verify(args.endpoint, args.api_key)
    elif args.mode == "demo":
        mode_demo(args.endpoint, args.api_key)
    elif args.mode == "attack":
        mode_attack(args.endpoint, args.api_key)
    elif args.mode == "live":
        mode_live(args.endpoint, args.api_key, rate=args.rate)


if __name__ == "__main__":
    main()
