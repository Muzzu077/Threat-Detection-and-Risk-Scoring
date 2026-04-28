"""
TrustFlow API Key Module
Generates, hashes, and validates API keys for SDK authentication.
Includes per-key sliding-window rate limiting (Redis-backed, fail-open).
"""
import os
import hashlib
from datetime import datetime

from fastapi import Request, HTTPException

from src.database import db, ApiKey, User
from src import redis_cache

# Per-key rate limit: 1000 requests / 60s window.
RATE_LIMIT_REQUESTS = int(os.getenv("API_KEY_RATE_LIMIT_REQUESTS", "1000"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("API_KEY_RATE_LIMIT_WINDOW", "60"))


def generate_api_key() -> tuple:
    """Generate a new API key. Returns (full_key, prefix, key_hash)."""
    random_bytes = os.urandom(24)
    hex_part = random_bytes.hex()
    full_key = f"tf_live_{hex_part}"
    prefix = full_key[:16]  # "tf_live_" + first 8 hex chars
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return full_key, prefix, key_hash


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _enforce_rate_limit(key_hash: str) -> None:
    """Raise 429 if this key has exceeded its window. Fails open if Redis is down."""
    bucket = f"trustflow:rl:apikey:{key_hash[:16]}"
    count = redis_cache.incr_with_window(bucket, RATE_LIMIT_WINDOW_SECONDS)
    if count > RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW_SECONDS}s)",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )


def get_api_key_user(request: Request) -> User:
    """FastAPI dependency — extracts API key from X-API-Key header, returns User."""
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    key_hash = hash_api_key(api_key)
    _enforce_rate_limit(key_hash)

    session = db.Session()
    try:
        ak = session.query(ApiKey).filter(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True,
        ).first()
        if not ak:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")

        ak.last_used_at = datetime.utcnow()
        session.commit()

        user = session.query(User).filter(User.id == ak.user_id, User.is_active == True).first()
        if not user:
            raise HTTPException(status_code=401, detail="API key owner not found or inactive")

        # Attach the calling key's application_id so the ingest endpoint can
        # stamp every event/incident with the correct app scope.
        application_id = ak.application_id
        session.expunge(user)
        # SQLAlchemy InstanceState forbids ad-hoc attrs on detached instances
        # via __setattr__; use object.__setattr__ to bypass.
        object.__setattr__(user, "_tf_application_id", application_id)
        return user
    finally:
        session.close()
