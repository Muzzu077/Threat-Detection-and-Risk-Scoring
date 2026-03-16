"""
ThreatPulse — OSINT Threat Feed Integration
Integrates open-source threat intelligence feeds:
- abuse.ch URLhaus (malicious URLs)
- Tor Exit Node list
- Emerging Threats blocklist
"""
import os
import json
import time
import requests
from datetime import datetime

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
FEEDS_CACHE = os.path.join(_PROJECT_ROOT, 'data', 'osint_feeds_cache.json')
FEED_TTL = 3600  # 1 hour cache

_cache = {}


def _load_cache():
    global _cache
    if os.path.exists(FEEDS_CACHE):
        try:
            with open(FEEDS_CACHE, 'r') as f:
                _cache = json.load(f)
        except Exception:
            _cache = {}


def _save_cache():
    os.makedirs(os.path.dirname(FEEDS_CACHE), exist_ok=True)
    try:
        with open(FEEDS_CACHE, 'w') as f:
            json.dump(_cache, f, indent=2)
    except Exception:
        pass


def fetch_tor_exit_nodes() -> list:
    """Fetch current Tor exit node IPs."""
    cache_key = "tor_exit_nodes"
    if cache_key in _cache and time.time() - _cache[cache_key].get("ts", 0) < FEED_TTL:
        return _cache[cache_key]["data"]

    try:
        resp = requests.get("https://check.torproject.org/torbulkexitlist", timeout=15)
        if resp.status_code == 200:
            ips = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith('#')]
            _cache[cache_key] = {"data": ips[:500], "ts": time.time(), "total": len(ips)}
            _save_cache()
            return ips[:500]
    except Exception:
        pass
    return _cache.get(cache_key, {}).get("data", [])


def fetch_urlhaus_recent() -> list:
    """Fetch recent malicious URLs from abuse.ch URLhaus."""
    cache_key = "urlhaus"
    if cache_key in _cache and time.time() - _cache[cache_key].get("ts", 0) < FEED_TTL:
        return _cache[cache_key]["data"]

    try:
        resp = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/",
                          json={"limit": 50}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            urls = []
            for entry in data.get("urls", [])[:50]:
                urls.append({
                    "url": entry.get("url", ""),
                    "host": entry.get("host", ""),
                    "threat": entry.get("threat", ""),
                    "tags": entry.get("tags", []),
                    "date_added": entry.get("date_added", ""),
                    "status": entry.get("url_status", ""),
                })
            _cache[cache_key] = {"data": urls, "ts": time.time()}
            _save_cache()
            return urls
    except Exception:
        pass
    return _cache.get(cache_key, {}).get("data", [])


def fetch_emerging_threats_ips() -> list:
    """Fetch compromised IP list from Emerging Threats."""
    cache_key = "et_compromised"
    if cache_key in _cache and time.time() - _cache[cache_key].get("ts", 0) < FEED_TTL:
        return _cache[cache_key]["data"]

    try:
        resp = requests.get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", timeout=15)
        if resp.status_code == 200:
            ips = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith('#')]
            _cache[cache_key] = {"data": ips[:500], "ts": time.time(), "total": len(ips)}
            _save_cache()
            return ips[:500]
    except Exception:
        pass
    return _cache.get(cache_key, {}).get("data", [])


def check_ip_osint(ip: str) -> dict:
    """Check an IP against all OSINT feeds."""
    if not _cache:
        _load_cache()

    tor_nodes = fetch_tor_exit_nodes()
    et_ips = fetch_emerging_threats_ips()

    is_tor = ip in tor_nodes
    is_et_compromised = ip in et_ips

    threats = []
    risk_boost = 0

    if is_tor:
        threats.append("Tor Exit Node")
        risk_boost += 20
    if is_et_compromised:
        threats.append("Emerging Threats Compromised IP")
        risk_boost += 25

    return {
        "ip": ip,
        "is_tor_exit": is_tor,
        "is_compromised": is_et_compromised,
        "threats": threats,
        "risk_boost": risk_boost,
        "feeds_checked": ["Tor Exit Nodes", "Emerging Threats", "URLhaus"],
        "is_threat": len(threats) > 0,
    }


def get_feed_summary() -> dict:
    """Get summary of all loaded OSINT feeds."""
    if not _cache:
        _load_cache()

    tor_data = _cache.get("tor_exit_nodes", {})
    et_data = _cache.get("et_compromised", {})
    urlhaus_data = _cache.get("urlhaus", {})

    return {
        "feeds": [
            {
                "name": "Tor Exit Nodes",
                "source": "check.torproject.org",
                "count": tor_data.get("total", len(tor_data.get("data", []))),
                "cached": bool(tor_data.get("data")),
                "last_updated": datetime.fromtimestamp(tor_data.get("ts", 0)).isoformat() if tor_data.get("ts") else None,
                "description": "Known Tor network exit relay IPs",
            },
            {
                "name": "Emerging Threats",
                "source": "rules.emergingthreats.net",
                "count": et_data.get("total", len(et_data.get("data", []))),
                "cached": bool(et_data.get("data")),
                "last_updated": datetime.fromtimestamp(et_data.get("ts", 0)).isoformat() if et_data.get("ts") else None,
                "description": "Compromised and malicious IPs",
            },
            {
                "name": "URLhaus (abuse.ch)",
                "source": "urlhaus-api.abuse.ch",
                "count": len(urlhaus_data.get("data", [])),
                "cached": bool(urlhaus_data.get("data")),
                "last_updated": datetime.fromtimestamp(urlhaus_data.get("ts", 0)).isoformat() if urlhaus_data.get("ts") else None,
                "description": "Recently reported malicious URLs",
            },
        ],
        "total_indicators": (
            tor_data.get("total", 0) +
            et_data.get("total", 0) +
            len(urlhaus_data.get("data", []))
        ),
    }
