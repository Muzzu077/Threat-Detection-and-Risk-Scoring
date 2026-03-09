"""
Threat Intelligence Module — AbuseIPDB Integration
Checks IP reputation with local in-memory + file cache (TTL 1 hour).
Degrades gracefully if API key is absent.
"""
import os
import json
import time
import requests
from typing import Optional, Dict

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
CACHE_FILE = "data/threat_intel_cache.json"
CACHE_TTL_SECONDS = 3600  # 1 hour

# In-memory cache: { ip: { data: {...}, timestamp: float } }
_cache: Dict[str, dict] = {}


def _load_cache_from_disk():
    """Load cache from disk on startup."""
    global _cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                _cache = json.load(f)
        except Exception:
            _cache = {}


def _save_cache_to_disk():
    """Persist cache to disk."""
    os.makedirs("data", exist_ok=True)
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(_cache, f, indent=2)
    except Exception:
        pass


def _is_cache_valid(ip: str) -> bool:
    """Check if cached entry exists and is not expired."""
    if ip in _cache:
        age = time.time() - _cache[ip].get("timestamp", 0)
        return age < CACHE_TTL_SECONDS
    return False


def check_ip(ip: Optional[str]) -> dict:
    """
    Check IP reputation via AbuseIPDB.
    Returns dict with: abuse_score, country, total_reports, is_suspicious, data_source
    """
    if not ip or ip in ("", "unknown", "127.0.0.1", "::1"):
        return _make_result(ip, 0, "LOCAL", 0, False, "skipped")

    # Cache check
    if not _cache:
        _load_cache_from_disk()

    if _is_cache_valid(ip):
        cached = _cache[ip]["data"]
        cached["data_source"] = "cache"
        return cached

    # No API key — return neutral result
    if not ABUSEIPDB_API_KEY:
        result = _make_result(ip, 0, "UNKNOWN", 0, False, "no_api_key")
        _store_cache(ip, result)
        return result

    # Query AbuseIPDB
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Accept": "application/json",
                "Key": ABUSEIPDB_API_KEY
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": False
            },
            timeout=5
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode", "UNKNOWN")
            total_reports = data.get("totalReports", 0)
            is_suspicious = abuse_score >= 25

            result = _make_result(ip, abuse_score, country, total_reports, is_suspicious, "abuseipdb")
            _store_cache(ip, result)
            return result

        elif response.status_code == 429:
            # Rate limited
            result = _make_result(ip, 0, "UNKNOWN", 0, False, "rate_limited")
            _store_cache(ip, result)
            return result
        else:
            result = _make_result(ip, 0, "UNKNOWN", 0, False, f"api_error_{response.status_code}")
            return result

    except requests.exceptions.Timeout:
        return _make_result(ip, 0, "UNKNOWN", 0, False, "timeout")
    except Exception as e:
        return _make_result(ip, 0, "UNKNOWN", 0, False, f"error: {str(e)[:50]}")


def _make_result(ip, abuse_score, country, total_reports, is_suspicious, data_source) -> dict:
    return {
        "ip": ip,
        "abuse_score": abuse_score,
        "country": country,
        "total_reports": total_reports,
        "is_suspicious": is_suspicious,
        "data_source": data_source
    }


def _store_cache(ip: str, data: dict):
    """Store result in cache and persist to disk."""
    _cache[ip] = {"data": data, "timestamp": time.time()}
    _save_cache_to_disk()


def get_known_bad_ips() -> list:
    """Return list of IPs with high abuse scores from cache."""
    _load_cache_from_disk()
    return [
        ip for ip, entry in _cache.items()
        if entry.get("data", {}).get("abuse_score", 0) >= 25
    ]
