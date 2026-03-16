"""
Tests for api/main.py — FastAPI endpoint integration tests.
Uses TestClient with an isolated in-memory database.
"""
import pytest
import sys
import os
import json

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.database import Base, Database, User, ApiKey


class TestDatabase(Database):
    """In-memory DB for endpoint tests."""
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
        pass


@pytest.fixture(autouse=True)
def patch_db(monkeypatch):
    """Replace the global db singleton with an in-memory version for all endpoint tests."""
    tdb = TestDatabase()

    import src.database
    monkeypatch.setattr(src.database, "db", tdb)
    import src.auth
    monkeypatch.setattr(src.auth, "db", tdb)
    import src.api_keys
    monkeypatch.setattr(src.api_keys, "db", tdb)

    # Patch `db` inside api.main BEFORE importing the app
    # We need to reload api.main to pick up patched db
    import api.main as api_main
    monkeypatch.setattr(api_main, "db", tdb)

    return tdb


@pytest.fixture()
def client(patch_db):
    """Create a TestClient for the FastAPI app."""
    from api.main import app
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def registered_user(client):
    """Register a user and return (user_data, tokens)."""
    resp = client.post("/api/auth/register", json={
        "email": "testuser@example.com",
        "password": "securepass123",
        "display_name": "Test User",
    })
    assert resp.status_code == 200
    data = resp.json()
    return data


@pytest.fixture()
def auth_headers(registered_user):
    """Return Authorization headers for the registered user."""
    return {"Authorization": f"Bearer {registered_user['access_token']}"}


# ─── Auth Endpoints ──────────────────────────────────────────────────────────

class TestAuthRegister:
    def test_register_success(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "new@example.com",
            "password": "pass123",
            "display_name": "New User",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["user"]["email"] == "new@example.com"
        assert data["user"]["display_name"] == "New User"
        assert data["user"]["role"] == "user"

    def test_register_short_password(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "short@x.com",
            "password": "12345",
        })
        assert resp.status_code == 400

    def test_register_duplicate_email(self, client, registered_user):
        resp = client.post("/api/auth/register", json={
            "email": "testuser@example.com",
            "password": "another",
        })
        assert resp.status_code == 409

    def test_register_missing_fields(self, client):
        resp = client.post("/api/auth/register", json={"email": "x@y.com"})
        assert resp.status_code == 422  # Pydantic validation


class TestAuthLogin:
    def test_login_success(self, client, registered_user):
        resp = client.post("/api/auth/login", json={
            "email": "testuser@example.com",
            "password": "securepass123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["email"] == "testuser@example.com"

    def test_login_wrong_password(self, client, registered_user):
        resp = client.post("/api/auth/login", json={
            "email": "testuser@example.com",
            "password": "wrongpass",
        })
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "nobody@example.com",
            "password": "whatever",
        })
        assert resp.status_code == 401


class TestAuthMe:
    def test_me_authenticated(self, client, auth_headers):
        resp = client.get("/api/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["user"]["email"] == "testuser@example.com"

    def test_me_no_token(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_bad_token(self, client):
        resp = client.get("/api/auth/me", headers={"Authorization": "Bearer garbage"})
        assert resp.status_code == 401


class TestAuthRefresh:
    def test_refresh_success(self, client, registered_user):
        resp = client.post("/api/auth/refresh", json={
            "refresh_token": registered_user["refresh_token"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

    def test_refresh_invalid_token(self, client):
        resp = client.post("/api/auth/refresh", json={
            "refresh_token": "not.a.real.token",
        })
        assert resp.status_code == 401


class TestAuthLogout:
    def test_logout_success(self, client, registered_user):
        resp = client.post("/api/auth/logout", json={
            "refresh_token": registered_user["refresh_token"],
        })
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_refresh_after_logout_fails(self, client, registered_user):
        client.post("/api/auth/logout", json={
            "refresh_token": registered_user["refresh_token"],
        })
        resp = client.post("/api/auth/refresh", json={
            "refresh_token": registered_user["refresh_token"],
        })
        assert resp.status_code == 401


# ─── API Key Endpoints ───────────────────────────────────────────────────────

class TestApiKeyEndpoints:
    def test_create_key(self, client, auth_headers):
        resp = client.post("/api/keys", json={"name": "My Key"}, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"].startswith("tp_live_")
        assert data["name"] == "My Key"
        assert "prefix" in data

    def test_list_keys(self, client, auth_headers):
        client.post("/api/keys", json={"name": "Key1"}, headers=auth_headers)
        client.post("/api/keys", json={"name": "Key2"}, headers=auth_headers)
        resp = client.get("/api/keys", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 2
        # Full key should NOT be returned in list
        for k in data:
            assert "key" not in k
            assert "prefix" in k

    def test_revoke_key(self, client, auth_headers):
        create_resp = client.post("/api/keys", json={"name": "ToRevoke"}, headers=auth_headers)
        key_id = create_resp.json()["id"]

        resp = client.delete(f"/api/keys/{key_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["success"] is True

        # Verify it shows as inactive
        list_resp = client.get("/api/keys", headers=auth_headers)
        keys = list_resp.json()["data"]
        revoked = [k for k in keys if k["id"] == key_id][0]
        assert revoked["is_active"] is False

    def test_revoke_nonexistent_key(self, client, auth_headers):
        resp = client.delete("/api/keys/99999", headers=auth_headers)
        assert resp.status_code == 404

    def test_create_key_no_auth(self, client):
        resp = client.post("/api/keys", json={"name": "x"})
        assert resp.status_code == 401


# ─── SDK Ingest Endpoint ─────────────────────────────────────────────────────

class TestSDKIngest:
    def _create_api_key(self, client, auth_headers):
        resp = client.post("/api/keys", json={"name": "SDK"}, headers=auth_headers)
        return resp.json()["key"]

    def test_ingest_success(self, client, auth_headers):
        api_key = self._create_api_key(client, auth_headers)
        resp = client.post("/api/v1/ingest",
            json={"events": [{
                "timestamp": "2024-01-15T10:30:00Z",
                "user": "john",
                "ip": "10.0.0.1",
                "action": "GET",
                "status": "success",
                "resource": "/dashboard",
            }]},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] == 1
        assert data["stored"] is True

    def test_ingest_empty_batch(self, client, auth_headers):
        api_key = self._create_api_key(client, auth_headers)
        resp = client.post("/api/v1/ingest",
            json={"events": []},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 400

    def test_ingest_no_api_key(self, client):
        resp = client.post("/api/v1/ingest", json={"events": [
            {"timestamp": "2024-01-01T00:00:00Z", "user": "x", "ip": "1.1.1.1",
             "action": "a", "status": "s", "resource": "r"}
        ]})
        assert resp.status_code == 401

    def test_ingest_invalid_api_key(self, client):
        resp = client.post("/api/v1/ingest",
            json={"events": [
                {"timestamp": "2024-01-01T00:00:00Z", "user": "x", "ip": "1.1.1.1",
                 "action": "a", "status": "s", "resource": "r"}
            ]},
            headers={"X-API-Key": "tp_live_invalid_key_here"},
        )
        assert resp.status_code == 401

    def test_ingest_over_1000_events(self, client, auth_headers):
        api_key = self._create_api_key(client, auth_headers)
        events = [{"timestamp": "2024-01-01T00:00:00Z", "user": "x", "ip": "1.1.1.1",
                    "action": "a", "status": "s", "resource": "r"}] * 1001
        resp = client.post("/api/v1/ingest",
            json={"events": events},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 400


# ─── Protected Data Endpoints ────────────────────────────────────────────────

class TestProtectedEndpoints:
    """Ensure all data endpoints require authentication."""

    PROTECTED_GETS = [
        "/api/events",
        "/api/stats",
        "/api/incidents",
        "/api/metrics/mttd-mttr",
        "/api/attack-graph",
        "/api/attack-chains",
        "/api/ml-metrics",
        "/api/threat-intel/known-bad",
        "/api/geo-distribution",
        "/api/mitre/techniques",
        "/api/explainability",
        "/api/prediction",
        "/api/events/mitre",
        "/api/ueba/profiles",
        "/api/feedback/stats",
        "/api/model/drift",
        "/api/adversarial/results",
        "/api/playbooks",
        "/api/osint/feeds",
        "/api/telegram/status",
        "/api/keys",
    ]

    @pytest.mark.parametrize("endpoint", PROTECTED_GETS)
    def test_get_requires_auth(self, client, endpoint):
        resp = client.get(endpoint)
        assert resp.status_code == 401, f"{endpoint} should require auth"

    def test_events_with_auth(self, client, auth_headers):
        resp = client.get("/api/events", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "data" in data
        assert "total" in data

    def test_stats_with_auth(self, client, auth_headers):
        resp = client.get("/api/stats", headers=auth_headers)
        assert resp.status_code == 200
        assert "total_events" in resp.json()

    def test_incidents_with_auth(self, client, auth_headers):
        resp = client.get("/api/incidents", headers=auth_headers)
        assert resp.status_code == 200

    def test_incident_not_found(self, client, auth_headers):
        resp = client.get("/api/incidents/99999", headers=auth_headers)
        assert resp.status_code == 404


# ─── Public Routes ────────────────────────────────────────────────────────────

class TestPublicRoutes:
    def test_root(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "online" in resp.json()["status"]

    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
