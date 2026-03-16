"""
Shared fixtures for ThreatPulse test suite.
Uses an isolated in-memory SQLite database for every test.
"""
import os
import sys
import pytest

# Ensure project root is on the path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.database import Base, Database, User, ApiKey, RefreshToken, LogEvent, Incident, AttackChain


class TestDatabase(Database):
    """A Database subclass that uses an in-memory SQLite DB and skips migration.

    Uses StaticPool so every Session shares the same in-memory connection.
    """
    def __init__(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            echo=False,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def _migrate_tenant_columns(self):
        pass  # Not needed — tables created from scratch


@pytest.fixture()
def test_db(monkeypatch):
    """Provide a fresh in-memory Database instance and monkeypatch the global `db`."""
    tdb = TestDatabase()
    # Patch the singleton everywhere it's imported
    import src.database
    monkeypatch.setattr(src.database, "db", tdb)
    import src.auth
    monkeypatch.setattr(src.auth, "db", tdb)
    import src.api_keys
    monkeypatch.setattr(src.api_keys, "db", tdb)
    return tdb


@pytest.fixture()
def sample_user(test_db):
    """Create and return a sample user."""
    from src.auth import hash_password
    user = test_db.create_user(
        email="test@example.com",
        password_hash=hash_password("password123"),
        display_name="Test User",
        role="user",
    )
    return user


@pytest.fixture()
def admin_user(test_db):
    """Create and return an admin user."""
    from src.auth import hash_password
    user = test_db.create_user(
        email="admin@example.com",
        password_hash=hash_password("adminpass"),
        display_name="Admin",
        role="admin",
    )
    return user


@pytest.fixture()
def sample_event_dict():
    """Return a minimal event dict for insertion."""
    from datetime import datetime
    return {
        "timestamp": datetime(2024, 1, 15, 10, 30, 0),
        "user": "john",
        "role": "employee",
        "ip": "192.168.1.100",
        "action": "login",
        "status": "success",
        "resource": "/api/auth",
        "anomaly_score": 0.3,
        "risk_score": 45.0,
        "time_risk": 0.1,
        "role_risk": 0.2,
        "resource_risk": 0.1,
        "explanation": "Normal login",
        "attack_type": "normal",
        "ml_confidence": 0.95,
        "country": "US",
        "threat_intel_score": 0.0,
        "threat_intel_reason": "",
        "response_actions": "",
        "tenant_id": None,
    }


@pytest.fixture()
def high_risk_event_dict(sample_event_dict):
    """Return an event dict with risk > 80 (triggers incident creation)."""
    d = dict(sample_event_dict)
    d["risk_score"] = 92.0
    d["attack_type"] = "brute_force"
    d["user"] = "attacker"
    return d
