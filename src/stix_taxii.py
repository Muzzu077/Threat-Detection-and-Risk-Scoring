"""
TrustFlow — STIX 2.1 / TAXII 2.1 Threat-Intel Feed (Phase 4)

Pulls indicator-of-compromise (IOC) bundles from a configurable TAXII 2.1
server, parses STIX 2.1 objects, and caches indicators in Redis with a 6h TTL.

Configurable feeds via env (or sensible defaults):
    TAXII_SERVER_URL    — e.g. https://limo.anomali.com/api/v1/taxii2/feeds/
    TAXII_USERNAME      — basic auth user (optional)
    TAXII_PASSWORD      — basic auth pass (optional)
    TAXII_COLLECTIONS   — comma-separated collection IDs to pull (optional, default = all)

The IP-lookup path (`src/threat_intel.py`) consults the cached STIX IOCs
before hitting external APIs, giving customers a private feed layer.
"""
import os
import re
from datetime import datetime

from src import redis_cache

CACHE_KEY_PREFIX = "trustflow:stix:"
INDICATORS_CACHE = CACHE_KEY_PREFIX + "indicators"
LAST_PULL_KEY    = CACHE_KEY_PREFIX + "last_pull"
DEFAULT_TTL      = 6 * 3600  # 6h


def _server_url() -> str:
    return os.getenv("TAXII_SERVER_URL", "").strip()


def is_configured() -> bool:
    return bool(_server_url())


# ── Pattern parsing ──────────────────────────────────────────────────────────

_IPV4_RE   = re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]")
_IPV6_RE   = re.compile(r"\[ipv6-addr:value\s*=\s*'([^']+)'\]")
_DOMAIN_RE = re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]")
_URL_RE    = re.compile(r"\[url:value\s*=\s*'([^']+)'\]")
_HASH_RE   = re.compile(r"\[file:hashes\.[A-Za-z0-9-]+\s*=\s*'([^']+)'\]")


def _parse_pattern(pattern: str) -> dict:
    """Extract IOC types from a STIX 2.1 indicator pattern string."""
    out = {"ips": [], "domains": [], "urls": [], "hashes": []}
    if not pattern:
        return out
    out["ips"]     += _IPV4_RE.findall(pattern) + _IPV6_RE.findall(pattern)
    out["domains"] += _DOMAIN_RE.findall(pattern)
    out["urls"]    += _URL_RE.findall(pattern)
    out["hashes"]  += _HASH_RE.findall(pattern)
    return out


# ── Pull from TAXII server ───────────────────────────────────────────────────

def pull_feeds(max_indicators: int = 1000) -> dict:
    """Fetch the latest indicators from the configured TAXII server."""
    if not is_configured():
        return {"ok": False, "error": "TAXII_SERVER_URL not set"}

    url      = _server_url()
    user     = os.getenv("TAXII_USERNAME", "")
    password = os.getenv("TAXII_PASSWORD", "")
    only_ids = [c.strip() for c in os.getenv("TAXII_COLLECTIONS", "").split(",") if c.strip()]

    try:
        from taxii2client.v21 import Server, as_pages
    except ImportError:
        return {"ok": False, "error": "taxii2-client not installed"}

    indicators = {"ips": set(), "domains": set(), "urls": set(), "hashes": set()}
    sources = []
    try:
        server = Server(url, user=user, password=password)
        for api_root in server.api_roots:
            for collection in api_root.collections:
                if only_ids and collection.id not in only_ids:
                    continue
                pulled = 0
                try:
                    for envelope in as_pages(collection.get_objects, per_request=100):
                        for obj in envelope.get("objects", []):
                            if obj.get("type") != "indicator":
                                continue
                            parsed = _parse_pattern(obj.get("pattern", ""))
                            for k, vals in parsed.items():
                                indicators[k].update(vals)
                            pulled += 1
                            if pulled >= max_indicators:
                                break
                        if pulled >= max_indicators:
                            break
                except Exception as e:
                    sources.append({"collection": collection.id, "error": str(e)})
                    continue
                sources.append({"collection": collection.id, "indicator_count": pulled})
    except Exception as e:
        return {"ok": False, "error": f"server error: {e}"}

    # Persist to Redis as a flat dict
    payload = {k: sorted(v)[:max_indicators] for k, v in indicators.items()}
    payload["pulled_at"] = datetime.utcnow().isoformat() + "Z"
    payload["sources"]   = sources

    try:
        redis_cache.set_json(INDICATORS_CACHE, payload, DEFAULT_TTL)
        redis_cache.set_json(LAST_PULL_KEY, payload["pulled_at"], DEFAULT_TTL * 2)
    except Exception as e:
        print(f"⚠️  STIX cache write failed: {e}")

    return {"ok": True, **{k: len(v) for k, v in payload.items() if k in ("ips","domains","urls","hashes")},
            "pulled_at": payload["pulled_at"], "sources": sources}


# ── Read API ─────────────────────────────────────────────────────────────────

def get_cached_indicators() -> dict:
    cached = redis_cache.get_json(INDICATORS_CACHE)
    if not cached:
        return {"ips": [], "domains": [], "urls": [], "hashes": [], "cached": False}
    return {**cached, "cached": True}


def is_known_bad_ip(ip: str) -> bool:
    """Quick membership test used by threat_intel.py before external lookups."""
    cached = redis_cache.get_json(INDICATORS_CACHE)
    if not cached:
        return False
    return ip in (cached.get("ips") or [])


def is_known_bad_domain(domain: str) -> bool:
    cached = redis_cache.get_json(INDICATORS_CACHE)
    if not cached:
        return False
    return (domain or "").lower() in {d.lower() for d in (cached.get("domains") or [])}
