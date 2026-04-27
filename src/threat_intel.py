"""
Threat Intelligence — AbuseIPDB integration.

Caching strategy:
  1. Redis (TTL 1h) — preferred; survives process restarts, shared across workers.
  2. Process-local dict — fallback when Redis is unavailable (e.g., Redis is
     down and we don't want to hammer AbuseIPDB on every request).

Degrades gracefully if ABUSEIPDB_API_KEY is absent — returns a neutral result.
"""
import os
import time
import requests
from typing import Optional, Dict

from src import redis_cache

CACHE_TTL_SECONDS = 3600  # 1 hour

# Process-local fallback when Redis is down
_local_cache: Dict[str, dict] = {}


def _cache_key(ip: str) -> str:
    return f"trustflow:ti:abuseipdb:{ip}"


def _cache_get(ip: str) -> Optional[dict]:
    cached = redis_cache.get_json(_cache_key(ip))
    if cached is not None:
        cached["data_source"] = "cache"
        return cached
    entry = _local_cache.get(ip)
    if entry and (time.time() - entry["timestamp"]) < CACHE_TTL_SECONDS:
        result = dict(entry["data"])
        result["data_source"] = "cache"
        return result
    return None


def _cache_set(ip: str, data: dict) -> None:
    if not redis_cache.set_json(_cache_key(ip), data, CACHE_TTL_SECONDS):
        _local_cache[ip] = {"data": data, "timestamp": time.time()}


def check_ip(ip: Optional[str]) -> dict:
    """
    Check IP reputation via AbuseIPDB.
    Returns dict with: ip, abuse_score, country, total_reports, is_suspicious, data_source
    """
    if not ip or ip in ("", "unknown", "127.0.0.1", "::1"):
        return _make_result(ip, 0, "LOCAL", 0, False, "skipped")

    cached = _cache_get(ip)
    if cached is not None:
        return cached

    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        result = _make_result(ip, 0, "UNKNOWN", 0, False, "no_api_key")
        _cache_set(ip, result)
        return result

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": api_key},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            timeout=5,
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode", "UNKNOWN")
            total_reports = data.get("totalReports", 0)
            is_suspicious = abuse_score >= 25
            result = _make_result(ip, abuse_score, country, total_reports, is_suspicious, "abuseipdb")
            _cache_set(ip, result)
            return result

        if response.status_code == 429:
            result = _make_result(ip, 0, "UNKNOWN", 0, False, "rate_limited")
            _cache_set(ip, result)
            return result

        return _make_result(ip, 0, "UNKNOWN", 0, False, f"api_error_{response.status_code}")

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
        "data_source": data_source,
    }


def get_known_bad_ips() -> list:
    """Return process-local IPs flagged as suspicious. Redis-cached entries are
    not enumerable here (would require a SCAN); use the dashboard for the
    authoritative list backed by the database."""
    return [ip for ip, entry in _local_cache.items()
            if entry.get("data", {}).get("abuse_score", 0) >= 25]
