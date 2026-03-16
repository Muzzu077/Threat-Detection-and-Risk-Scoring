#!/usr/bin/env python3
"""
Create the ThreatPulse demo account for showcase/judging.
Run once — safe to re-run (idempotent).
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database import db
from src.auth import hash_password
from src.api_keys import generate_api_key
from src.database import ApiKey

EMAIL = "demo@threatpulse.com"
PASSWORD = "ThreatPulse2025"
DISPLAY_NAME = "Demo Operator"
ROLE = "admin"

def seed():
    # Check if already exists
    existing = db.get_user_by_email(EMAIL)
    if existing:
        print(f"\n  Demo account already exists (id={existing.id})")
        print(f"\n  ================================")
        print(f"  EMAIL:    {EMAIL}")
        print(f"  PASSWORD: {PASSWORD}")
        print(f"  ROLE:     {existing.role}")
        print(f"  USER ID:  {existing.id}")
        print(f"  ================================\n")
        return existing

    user = db.create_user(
        email=EMAIL,
        password_hash=hash_password(PASSWORD),
        display_name=DISPLAY_NAME,
        role=ROLE,
    )

    # Create a demo API key
    full_key, prefix, key_hash = generate_api_key()
    session = db.Session()
    try:
        ak = ApiKey(
            user_id=user.id,
            name="Demo Key",
            prefix=prefix,
            key_hash=key_hash,
        )
        session.add(ak)
        session.commit()
    finally:
        session.close()

    print(f"\n  ================================")
    print(f"  DEMO ACCOUNT CREATED")
    print(f"  ================================")
    print(f"  EMAIL:    {EMAIL}")
    print(f"  PASSWORD: {PASSWORD}")
    print(f"  ROLE:     {ROLE}")
    print(f"  USER ID:  {user.id}")
    print(f"  API KEY:  {full_key}")
    print(f"  ================================\n")
    return user


if __name__ == "__main__":
    seed()
