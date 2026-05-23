"""
Redis cache wrapper for TrustFlow.

- Lazy connection: nothing is contacted until first use.
- Graceful degradation: if Redis is unavailable, get() returns None and set()
  silently no-ops. This keeps threat-intel lookups working even if Redis is down.
- JSON-encoded values for any picklable dict; raw strings/ints supported via
  separate helpers.

Used by:
  - threat_intel*.py     — TTL-cached IP/domain reputation lookups
  - api_keys.py          — per-key sliding-window rate limiter
"""
from __future__ import annotations

import json
import os
from typing import Optional

try:
    import redis as _redis
except ImportError:  # pragma: no cover — redis is in requirements.txt
    _redis = None


_client: Optional["_redis.Redis"] = None
_client_failed: bool = False  # latched after first connection failure to avoid repeated retries


def _get_client():
    global _client, _client_failed
    if _client_failed:
        return None
    if _client is not None:
        return _client
    if _redis is None:
        _client_failed = True
        return None
    url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    try:
        _client = _redis.from_url(url, socket_connect_timeout=2, socket_timeout=2, decode_responses=True)
        _client.ping()
    except Exception:
        _client_failed = True
        _client = None
    return _client


def is_available() -> bool:
    return _get_client() is not None


def get_json(key: str) -> Optional[dict]:
    c = _get_client()
    if c is None:
        return None
    try:
        raw = c.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:
        return None


def set_json(key: str, value: dict, ttl_seconds: int) -> bool:
    c = _get_client()
    if c is None:
        return False
    try:
        c.set(key, json.dumps(value), ex=ttl_seconds)
        return True
    except Exception:
        return False


def incr_with_window(key: str, window_seconds: int) -> int:
    """True sliding-window rate limiter using Redis sorted sets.

    Each request is stored as a member with its timestamp as score.
    On every call we prune expired entries and count the remaining.
    Returns current count in the window. Returns 0 if Redis unavailable —
    callers should treat that as "skip the limiter, fail open".
    """
    c = _get_client()
    if c is None:
        return 0
    try:
        import time
        now = time.time()
        window_start = now - window_seconds
        member = f"{now}:{os.urandom(4).hex()}"
        pipe = c.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)     # prune expired
        pipe.zadd(key, {member: now})                    # add this request
        pipe.zcard(key)                                  # count in window
        pipe.expire(key, window_seconds + 1)             # auto-cleanup
        result = pipe.execute()
        return int(result[2])
    except Exception:
        return 0


def reset(key: str) -> None:
    c = _get_client()
    if c is None:
        return
    try:
        c.delete(key)
    except Exception:
        pass
