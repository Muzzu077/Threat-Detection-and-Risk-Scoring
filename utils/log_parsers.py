"""
ThreatPulse — Real-World Log Parsers
Parse actual security logs from Linux, Apache, Nginx, Windows.

Supported formats:
  - Linux /var/log/auth.log  (SSH login attempts)
  - Apache/Nginx access.log  (web request logs)
  - Windows Security Event Log (CSV export)
  - Firewall logs (basic syslog format)

Output: list of normalized event dicts compatible with the ingestion pipeline.
"""
import re
import os
import csv
import json
import gzip
from datetime import datetime, timezone
from typing import List, Optional, Iterator
import io


# ── Normalized event schema ───────────────────────────────────────────────────
def _base_event(timestamp: str, user: str, ip: str, action: str,
                status: str, resource: str, source: str) -> dict:
    return {
        "timestamp": timestamp,
        "user":      user,
        "ip":        ip,
        "action":    action,
        "status":    status,
        "resource":  resource,
        "_source":   source,
    }


# ── Linux auth.log parser ─────────────────────────────────────────────────────
# Sample lines:
# Mar 11 18:43:02 server sshd[1234]: Failed password for root from 185.220.101.4 port 52312 ssh2
# Mar 11 18:43:05 server sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 44123 ssh2
# Mar 11 18:43:10 server sudo:   ubuntu : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash

AUTH_FAILED   = re.compile(r'(\w{3}\s+\d+ \d+:\d+:\d+) .+ sshd\[\d+\]: Failed password for (\S+) from ([\d.]+)')
AUTH_ACCEPTED = re.compile(r'(\w{3}\s+\d+ \d+:\d+:\d+) .+ sshd\[\d+\]: Accepted password for (\S+) from ([\d.]+)')
SUDO_CMD      = re.compile(r'(\w{3}\s+\d+ \d+:\d+:\d+) .+ sudo:.+USER=(\S+) ; COMMAND=(.+)')
INVALID_USER  = re.compile(r'(\w{3}\s+\d+ \d+:\d+:\d+) .+ sshd\[\d+\]: Invalid user (\S+) from ([\d.]+)')
SU_SESSION    = re.compile(r'(\w{3}\s+\d+ \d+:\d+:\d+) .+ su.+opened for user (\S+) by (\S+)')


def _parse_auth_timestamp(ts_str: str) -> str:
    """Convert 'Mar 11 18:43:02' to ISO format."""
    try:
        year  = datetime.utcnow().year
        dt    = datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except Exception:
        return datetime.utcnow().isoformat()


def parse_auth_log(filepath: str) -> List[dict]:
    """Parse Linux /var/log/auth.log into normalized events."""
    events = []
    try:
        opener = gzip.open if filepath.endswith('.gz') else open
        with opener(filepath, 'rt', errors='ignore') as f:
            for line in f:
                # Failed SSH
                m = AUTH_FAILED.search(line)
                if m:
                    events.append(_base_event(
                        timestamp=_parse_auth_timestamp(m.group(1)),
                        user=m.group(2), ip=m.group(3),
                        action='ssh_login_failed', status='FAILURE',
                        resource='ssh', source='auth.log'
                    ))
                    continue

                # Accepted SSH
                m = AUTH_ACCEPTED.search(line)
                if m:
                    events.append(_base_event(
                        timestamp=_parse_auth_timestamp(m.group(1)),
                        user=m.group(2), ip=m.group(3),
                        action='ssh_login_success', status='SUCCESS',
                        resource='ssh', source='auth.log'
                    ))
                    continue

                # Invalid user
                m = INVALID_USER.search(line)
                if m:
                    events.append(_base_event(
                        timestamp=_parse_auth_timestamp(m.group(1)),
                        user=m.group(2), ip=m.group(3),
                        action='ssh_invalid_user', status='FAILURE',
                        resource='ssh', source='auth.log'
                    ))
                    continue

                # Sudo command
                m = SUDO_CMD.search(line)
                if m:
                    events.append(_base_event(
                        timestamp=_parse_auth_timestamp(m.group(1)),
                        user=m.group(2), ip='127.0.0.1',
                        action=f'sudo: {m.group(3).strip()[:60]}', status='SUCCESS',
                        resource='sudo', source='auth.log'
                    ))
    except FileNotFoundError:
        print(f"⚠️ auth.log not found: {filepath}")
    except Exception as e:
        print(f"❌ auth.log parse error: {e}")
    return events


# ── Apache / Nginx access.log parser ─────────────────────────────────────────
# Combined Log Format:
# 192.168.1.1 - frank [10/Oct/2023:13:55:36 -0700] "GET /admin HTTP/1.1" 403 2312

COMBINED_LOG = re.compile(
    r'([\d.]+) \S+ (\S+) \[([^\]]+)\] "(\w+) ([^"]+) HTTP\S*" (\d+) (\d+)'
)

def _parse_apache_ts(ts_str: str) -> str:
    try:
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except Exception:
        return datetime.utcnow().isoformat()

def _apache_action(method: str, url: str, status: int) -> tuple:
    """Determine action and threat level from HTTP request."""
    url_lower = url.lower()
    suspicious = any(p in url_lower for p in [
        '/admin', '/wp-login', '/.env', '/shell', '/../', '/etc/passwd',
        'union+select', 'script>', '<script', '/phpmyadmin', '/.git',
    ])
    if suspicious:
        return f"web_{method.lower()}_suspicious", "FAILURE" if status >= 400 else "SUCCESS"
    if status >= 400:
        return f"web_{method.lower()}_error", "FAILURE"
    return f"web_{method.lower()}", "SUCCESS"


def parse_apache_log(filepath: str) -> List[dict]:
    """Parse Apache/Nginx access.log into normalized events."""
    events = []
    try:
        opener = gzip.open if filepath.endswith('.gz') else open
        with opener(filepath, 'rt', errors='ignore') as f:
            for line in f:
                m = COMBINED_LOG.search(line)
                if not m:
                    continue
                ip, user, ts_str, method, url, status_str, _ = m.groups()
                status = int(status_str)
                user   = user if user != '-' else 'anonymous'
                action, status_label = _apache_action(method, url, status)
                events.append(_base_event(
                    timestamp=_parse_apache_ts(ts_str),
                    user=user, ip=ip,
                    action=action, status=status_label,
                    resource=url[:100],
                    source='apache_access_log'
                ))
    except FileNotFoundError:
        print(f"⚠️ Apache log not found: {filepath}")
    except Exception as e:
        print(f"❌ Apache log parse error: {e}")
    return events


# ── Windows Security Event Log (CSV export from Event Viewer) ─────────────────
# Columns: date, time, event_id, user, computer, description
# Key Event IDs:
#   4625 = Failed logon
#   4624 = Successful logon
#   4648 = Logon with explicit credentials
#   4672 = Special privilege logon
#   4720 = User account created
#   4726 = User account deleted

WIN_EVENT_ACTIONS = {
    '4625': ('windows_logon_failed',          'FAILURE'),
    '4624': ('windows_logon_success',         'SUCCESS'),
    '4648': ('windows_explicit_credentials',  'SUCCESS'),
    '4672': ('windows_privilege_logon',       'SUCCESS'),
    '4720': ('windows_account_created',       'SUCCESS'),
    '4726': ('windows_account_deleted',       'SUCCESS'),
    '4732': ('windows_group_added',           'SUCCESS'),
    '4740': ('windows_account_locked',        'FAILURE'),
}

def parse_windows_event_csv(filepath: str) -> List[dict]:
    """Parse Windows Security Event Log exported as CSV from Event Viewer."""
    events = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                event_id = str(row.get('Event ID', '')).strip()
                if event_id not in WIN_EVENT_ACTIONS:
                    continue
                action, status = WIN_EVENT_ACTIONS[event_id]
                ts_str   = f"{row.get('Date','').strip()} {row.get('Time','').strip()}"
                user     = row.get('User', 'SYSTEM').strip() or 'SYSTEM'
                computer = row.get('Computer', 'localhost').strip()
                try:
                    dt = datetime.strptime(ts_str, "%m/%d/%Y %H:%M:%S")
                    ts = dt.isoformat()
                except Exception:
                    ts = datetime.utcnow().isoformat()
                events.append(_base_event(
                    timestamp=ts, user=user,
                    ip=computer, action=action,
                    status=status, resource='windows_event_log',
                    source='windows_event_log'
                ))
    except FileNotFoundError:
        print(f"⚠️ Windows Event CSV not found: {filepath}")
    except Exception as e:
        print(f"❌ Windows Event CSV parse error: {e}")
    return events


# ── Firewall / Syslog parser ──────────────────────────────────────────────────
# Typical syslog format with ACCEPT/DROP decisions

SYSLOG_FW = re.compile(
    r'(\w{3}\s+\d+ \d+:\d+:\d+).+(ACCEPT|DROP|REJECT).+SRC=([\d.]+).+DST=([\d.]+).*DPT=(\d+)'
)

def parse_firewall_log(filepath: str) -> List[dict]:
    """Parse iptables/ufw syslog firewall logs."""
    events = []
    try:
        opener = gzip.open if filepath.endswith('.gz') else open
        with opener(filepath, 'rt', errors='ignore') as f:
            for line in f:
                m = SYSLOG_FW.search(line)
                if not m:
                    continue
                ts_str, decision, src_ip, dst_ip, dport = m.groups()
                action = f"firewall_{decision.lower()}_port_{dport}"
                status = 'FAILURE' if decision in ('DROP', 'REJECT') else 'SUCCESS'
                events.append(_base_event(
                    timestamp=_parse_auth_timestamp(ts_str),
                    user='firewall', ip=src_ip,
                    action=action, status=status,
                    resource=f"{dst_ip}:{dport}",
                    source='firewall_log'
                ))
    except FileNotFoundError:
        print(f"⚠️ Firewall log not found: {filepath}")
    except Exception as e:
        print(f"❌ Firewall log parse error: {e}")
    return events


# ── Universal log auto-detector ───────────────────────────────────────────────
def parse_log_file(filepath: str) -> List[dict]:
    """
    Auto-detect log format and parse it.
    Supports: auth.log, access.log, event.csv, firewall.log
    """
    name = os.path.basename(filepath).lower()

    if 'auth' in name or 'secure' in name or 'syslog' in name:
        if 'fw' in name or 'firewall' in name or 'iptables' in name or 'ufw' in name:
            return parse_firewall_log(filepath)
        return parse_auth_log(filepath)
    elif 'access' in name or 'nginx' in name or 'apache' in name or 'httpd' in name:
        return parse_apache_log(filepath)
    elif name.endswith('.csv') and ('event' in name or 'security' in name or 'windows' in name):
        return parse_windows_event_csv(filepath)
    elif 'firewall' in name or 'ufw' in name or 'iptables' in name:
        return parse_firewall_log(filepath)
    else:
        # Try auth.log format as default
        print(f"ℹ️ Unknown log format for {name}, trying auth.log parser…")
        return parse_auth_log(filepath)


def parse_log_directory(dirpath: str, recursive: bool = False) -> List[dict]:
    """
    Parse all log files in a directory.
    Returns combined list of normalized events.
    """
    all_events = []
    walk = os.walk(dirpath) if recursive else [(dirpath, [], os.listdir(dirpath))]
    for root, _, files in walk:
        for fname in files:
            if fname.endswith(('.log', '.log.gz', '.csv', '.txt')):
                fpath = os.path.join(root, fname)
                parsed = parse_log_file(fpath)
                all_events.extend(parsed)
                print(f"  Parsed {len(parsed)} events from {fname}")
    return all_events
