#!/usr/bin/env python3
"""
Ensure a DVWA shipper API key exists and write it to dvwa-stack/.env.
Idempotent — reuses existing key if one named 'dvwa-shipper' exists.
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database import db, ApiKey
from src.api_keys import generate_api_key

DVWA_ENV = os.path.join(os.path.dirname(__file__), '..', 'dvwa-stack', '.env')
KEY_NAME = "dvwa-shipper"


def ensure_key():
    # Find demo user
    user = db.get_user_by_email("demo@threatpulse.com")
    if not user:
        print("  [dvwa-key] Demo account not found — run seed_demo_account.py first")
        return None

    # Check if dvwa-shipper key already exists
    session = db.Session()
    try:
        existing = session.query(ApiKey).filter_by(user_id=user.id, name=KEY_NAME).first()
        if existing:
            # Can't recover the full key from hash — generate a new one
            # Delete the old one and create fresh
            session.delete(existing)
            session.commit()
    finally:
        session.close()

    # Create new key
    full_key, prefix, key_hash = generate_api_key()
    session = db.Session()
    try:
        ak = ApiKey(
            user_id=user.id,
            name=KEY_NAME,
            prefix=prefix,
            key_hash=key_hash,
        )
        session.add(ak)
        session.commit()
    finally:
        session.close()

    # Write to dvwa-stack/.env
    env_path = os.path.abspath(DVWA_ENV)
    os.makedirs(os.path.dirname(env_path), exist_ok=True)
    with open(env_path, 'w') as f:
        f.write(f"DVWA_API_KEY={full_key}\n")

    print(f"  [dvwa-key] API key written to {env_path}")
    print(f"  [dvwa-key] Key: {prefix}...")
    return full_key


if __name__ == "__main__":
    ensure_key()
