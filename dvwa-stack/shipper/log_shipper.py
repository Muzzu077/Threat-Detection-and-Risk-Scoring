"""
Log shipper — tails nginx access.log, extracts XFF IPs, ships events to ThreatPulse /api/v1/ingest.
"""

import os
import re
import sys
import json
import time
import logging
import requests
from datetime import datetime

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("shipper")

API_URL = os.environ.get("THREATPULSE_API_URL", "http://host.docker.internal:8000")
API_KEY = os.environ.get("DVWA_API_KEY", "")
LOG_PATH = os.environ.get("NGINX_LOG_PATH", "/var/log/nginx/access.log")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "2.0"))

# Regex for the dvwa_combined log format
# Example: 172.19.0.3 - - [16/Mar/2026:10:00:00 +0000] "GET /vuln?id=1 HTTP/1.1" 200 1234 "-" "python-requests/2.31" rt=0.005 xff="201.42.133.7" meta="sql_injection|admin"
LOG_REGEX = re.compile(
    r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)" '
    r'rt=(?P<request_time>\S+) xff="(?P<xff>[^"]*)" meta="(?P<meta>[^"]*)"'
)

# Attack classification patterns based on URL
ATTACK_PATTERNS = [
    (re.compile(r"/vulnerabilities/sqli_blind", re.I), "sqli_blind"),
    (re.compile(r"/vulnerabilities/sqli", re.I), "sqli"),
    (re.compile(r"/vulnerabilities/xss_s", re.I), "xss_stored"),
    (re.compile(r"/vulnerabilities/xss_r", re.I), "xss_reflected"),
    (re.compile(r"/vulnerabilities/xss_d", re.I), "xss_dom"),
    (re.compile(r"/vulnerabilities/exec", re.I), "command_injection"),
    (re.compile(r"/vulnerabilities/fi", re.I), "file_inclusion"),
    (re.compile(r"/vulnerabilities/upload", re.I), "file_upload"),
    (re.compile(r"/vulnerabilities/csrf", re.I), "csrf"),
    (re.compile(r"/vulnerabilities/weak_id", re.I), "weak_session"),
    (re.compile(r"/vulnerabilities/brute", re.I), "brute_force"),
]

PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)


def is_public_ip(ip: str) -> bool:
    """Check if IP looks like a valid public IPv4 address."""
    if not ip or ip == "-":
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    if PRIVATE_IP_RE.match(ip):
        return False
    return True


def classify_attack(url: str) -> str:
    """Classify request URL into an attack type."""
    for pattern, attack_type in ATTACK_PATTERNS:
        if pattern.search(url):
            return attack_type
    return "normal"


def parse_timestamp(time_local: str) -> str:
    """Convert nginx timestamp to ISO 8601."""
    try:
        dt = datetime.strptime(time_local, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except ValueError:
        return datetime.utcnow().isoformat()


def parse_log_line(line: str) -> dict | None:
    """Parse a single nginx log line into an event dict."""
    m = LOG_REGEX.match(line.strip())
    if not m:
        return None

    d = m.groupdict()
    url = d["url"]
    xff = d["xff"].strip()
    remote_addr = d["remote_addr"]
    meta = d["meta"].strip()

    # IP priority: use XFF if it's a valid public IP
    ip = xff if is_public_ip(xff) else remote_addr

    # Extract user from meta header (format: "module_name|username")
    user = "anonymous"
    if meta and "|" in meta:
        parts = meta.split("|", 1)
        if len(parts) == 2 and parts[1]:
            user = parts[1]

    # Map HTTP method + URL to action string
    method = d["method"]
    attack_type = classify_attack(url)
    if attack_type != "normal":
        action = f"{method} {attack_type}"
    else:
        action = f"{method} page_view"

    return {
        "timestamp": parse_timestamp(d["time_local"]),
        "user": user,
        "ip": ip,
        "action": action,
        "status": d["status"],
        "resource": url,
    }


def ship_batch(events: list):
    """POST a batch of events to ThreatPulse /api/v1/ingest."""
    if not events:
        return
    if not API_KEY:
        logger.warning("No API key configured — skipping ship")
        return

    payload = {"events": events}
    try:
        r = requests.post(
            f"{API_URL}/api/v1/ingest",
            json=payload,
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            logger.info(
                "Shipped %d events — accepted: %d, incidents: %d",
                len(events), data.get("accepted", 0), data.get("incidents_created", 0),
            )
        else:
            logger.error("Ingest failed (%d): %s", r.status_code, r.text[:200])
    except requests.RequestException as e:
        logger.error("Ship error: %s", e)


def tail_and_ship():
    """Main loop — tail the log file and ship parsed events in batches."""
    logger.info("Shipper starting — log: %s, API: %s", LOG_PATH, API_URL)

    # Wait for log file to exist
    while not os.path.exists(LOG_PATH):
        logger.info("Waiting for log file: %s", LOG_PATH)
        time.sleep(3)

    # Track file position manually to handle Docker shared volumes
    # where seek may not work on first open
    file_size = 0
    try:
        file_size = os.path.getsize(LOG_PATH)
    except OSError:
        pass

    position = file_size  # Start from end — only ship new lines
    batch = []

    while True:
        try:
            current_size = os.path.getsize(LOG_PATH)
        except OSError:
            time.sleep(POLL_INTERVAL)
            continue

        if current_size < position:
            # Log was rotated
            logger.info("Log file rotated, resetting position")
            position = 0

        if current_size == position:
            if batch:
                ship_batch(batch)
                batch = []
            time.sleep(POLL_INTERVAL)
            continue

        with open(LOG_PATH, "r") as f:
            f.seek(position)
            for line in f:
                event = parse_log_line(line)
                if event:
                    batch.append(event)
                if len(batch) >= BATCH_SIZE:
                    ship_batch(batch)
                    batch = []
            position = f.tell()

        if batch:
            ship_batch(batch)
            batch = []
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    tail_and_ship()
