"""
ThreatPulse API Key Module
Generates, hashes, and validates API keys for SDK authentication.
"""
import os
import hashlib
from datetime import datetime

from fastapi import Request, HTTPException

from src.database import db, ApiKey, User


def generate_api_key() -> tuple:
    """Generate a new API key. Returns (full_key, prefix, key_hash)."""
    random_bytes = os.urandom(24)
    hex_part = random_bytes.hex()
    full_key = f"tp_live_{hex_part}"
    prefix = full_key[:16]  # "tp_live_" + first 8 hex chars
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return full_key, prefix, key_hash


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def get_api_key_user(request: Request) -> User:
    """FastAPI dependency — extracts API key from X-API-Key header, returns User."""
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    key_hash = hash_api_key(api_key)
    session = db.Session()
    try:
        ak = session.query(ApiKey).filter(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True,
        ).first()
        if not ak:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")

        # Update last_used_at
        ak.last_used_at = datetime.utcnow()
        session.commit()

        user = session.query(User).filter(User.id == ak.user_id, User.is_active == True).first()
        if not user:
            raise HTTPException(status_code=401, detail="API key owner not found or inactive")

        session.expunge(user)
        return user
    finally:
        session.close()
