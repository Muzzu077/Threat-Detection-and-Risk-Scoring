"""
ThreatPulse — Extended Threat Intelligence
Adds AlienVault OTX and VirusTotal to the existing AbuseIPDB module.

Priority of checks:
  1. Local cache (all sources)
  2. AbuseIPDB
  3. AlienVault OTX
  4. VirusTotal
"""
import os
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, '.env'), override=True)

OTX_API_KEY        = os.getenv("OTX_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

OTX_BASE        = "https://otx.alienvault.com/api/v1"
VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"

# Simple in-memory cache {ip: (result, expiry)}
_cache: dict = {}
CACHE_TTL = 3600  # 1 hour


def _cached(ip: str):
    if ip in _cache:
        result, expiry = _cache[ip]
        if time.time() < expiry:
            return result
    return None


def _store_cache(ip: str, result: dict):
    _cache[ip] = (result, time.time() + CACHE_TTL)


# ── AlienVault OTX ────────────────────────────────────────────────────────────
def check_otx(ip: str) -> dict:
    """Check IP reputation via AlienVault OTX."""
    if not OTX_API_KEY:
        return {"source": "otx", "error": "OTX_API_KEY not set"}

    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        url     = f"{OTX_BASE}/indicators/IPv4/{ip}/general"
        resp    = requests.get(url, headers=headers, timeout=10)

        if resp.status_code != 200:
            return {"source": "otx", "error": f"HTTP {resp.status_code}"}

        data         = resp.json()
        pulse_count  = data.get("pulse_info", {}).get("count", 0)
        reputation   = data.get("reputation", 0)
        country      = data.get("country_name", "UNKNOWN")
        city         = data.get("city", "")
        asn          = data.get("asn", "")

        malicious    = pulse_count > 0 or reputation < -1

        return {
            "source":      "otx",
            "ip":          ip,
            "malicious":   malicious,
            "pulse_count": pulse_count,
            "reputation":  reputation,
            "country":     country,
            "city":        city,
            "asn":         asn,
            "risk_score":  min(100, pulse_count * 10 + max(0, -reputation * 5)),
        }
    except Exception as e:
        return {"source": "otx", "error": str(e)}


# ── VirusTotal ────────────────────────────────────────────────────────────────
def check_virustotal(ip: str) -> dict:
    """Check IP reputation via VirusTotal API v3."""
    if not VIRUSTOTAL_API_KEY:
        return {"source": "virustotal", "error": "VIRUSTOTAL_API_KEY not set"}

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url     = f"{VIRUSTOTAL_BASE}/ip_addresses/{ip}"
        resp    = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 404:
            return {"source": "virustotal", "ip": ip, "malicious": False, "risk_score": 0}
        if resp.status_code != 200:
            return {"source": "virustotal", "error": f"HTTP {resp.status_code}"}

        data      = resp.json().get("data", {}).get("attributes", {})
        stats     = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total     = sum(stats.values()) or 1

        country   = data.get("country", "UNKNOWN")
        asn       = data.get("asn", "")
        vendor    = data.get("as_owner", "")

        risk = min(100, int((malicious / total) * 100) + suspicious * 2)

        return {
            "source":       "virustotal",
            "ip":           ip,
            "malicious":    malicious > 0,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total,
            "risk_score":   risk,
            "country":      country,
            "asn":          asn,
            "vendor":       vendor,
        }
    except Exception as e:
        return {"source": "virustotal", "error": str(e)}


# ── Combined multi-source check ───────────────────────────────────────────────
def extended_check_ip(ip: str) -> dict:
    """
    Run all available threat intelligence sources and combine results.
    Returns an aggregated risk profile for the IP.
    """
    cached = _cached(f"ext:{ip}")
    if cached:
        return {**cached, "cached": True}

    results = {}
    sources_used = []

    # AlienVault OTX
    if OTX_API_KEY:
        otx = check_otx(ip)
        if "error" not in otx:
            results["otx"] = otx
            sources_used.append("OTX")

    # VirusTotal
    if VIRUSTOTAL_API_KEY:
        vt = check_virustotal(ip)
        if "error" not in vt:
            results["virustotal"] = vt
            sources_used.append("VirusTotal")

    # Aggregate risk
    risk_scores   = [r.get("risk_score", 0) for r in results.values() if isinstance(r, dict)]
    is_malicious  = any(r.get("malicious", False) for r in results.values() if isinstance(r, dict))
    combined_risk = round(max(risk_scores) if risk_scores else 0, 1)

    country = (
        results.get("otx", {}).get("country") or
        results.get("virustotal", {}).get("country") or
        "UNKNOWN"
    )

    result = {
        "ip":            ip,
        "combined_risk": combined_risk,
        "is_malicious":  is_malicious,
        "country":       country,
        "sources_used":  sources_used,
        "details":       results,
        "timestamp":     datetime.utcnow().isoformat(),
    }

    _store_cache(f"ext:{ip}", result)
    return result


def check_domain_virustotal(domain: str) -> dict:
    """Check a domain's reputation on VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url     = f"{VIRUSTOTAL_BASE}/domains/{domain}"
        resp    = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}
        data      = resp.json().get("data", {}).get("attributes", {})
        stats     = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total     = sum(stats.values()) or 1
        return {
            "domain":    domain,
            "malicious": malicious > 0,
            "malicious_count": malicious,
            "total_engines":   total,
            "risk_score": min(100, int((malicious / total) * 100)),
            "categories": data.get("categories", {}),
        }
    except Exception as e:
        return {"error": str(e)}
