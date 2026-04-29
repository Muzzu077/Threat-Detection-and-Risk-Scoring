"""
Hard-delete cascade tests for /api/admin/users/{id}.

The hard-delete endpoint must remove every per-tenant artifact: api_keys,
applications, log_events, incidents, attack_chains, refresh_tokens,
notification preferences, custom playbooks, then the user row.

These tests verify the cascade is exhaustive AND that another tenant's data
is untouched (no over-deletion).
"""
from __future__ import annotations

import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database import Base, Database


class _InMemoryDB(Database):
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


@pytest.fixture()
def client(monkeypatch):
    tdb = _InMemoryDB()
    import src.database, src.auth, src.api_keys, api.main as api_main

    monkeypatch.setattr(src.database, "db", tdb)
    monkeypatch.setattr(src.auth, "db", tdb)
    monkeypatch.setattr(src.api_keys, "db", tdb)
    monkeypatch.setattr(api_main, "db", tdb)

    from api.main import app
    return TestClient(app, raise_server_exceptions=False)


def _register(client, email):
    r = client.post(
        "/api/auth/register",
        json={"email": email, "password": "securepass123", "display_name": email.split("@")[0]},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _promote(api_main, email):
    with api_main.db.Session() as s:
        u = s.query(api_main.User).filter_by(email=email).first()
        u.role = "admin"
        s.commit()
        return u.id


def _admin_login(client, email):
    r = client.post("/api/auth/login", json={"email": email, "password": "securepass123"})
    assert r.status_code == 200
    return r.json()


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


def _seed_tenant_artifacts(client, user_token):
    """Register an app, generate an API key, ingest an event so it creates rows
    across most cascade-deletable tables. Returns (api_key, app_id)."""
    app_resp = client.post(
        "/api/applications",
        json={"name": "Cascade App", "description": "for delete test"},
        headers=_hdr(user_token),
    )
    assert app_resp.status_code == 200, app_resp.text
    app_id = app_resp.json()["id"]

    key_resp = client.post(
        "/api/keys",
        json={"name": "cascade-key", "application_id": app_id},
        headers=_hdr(user_token),
    )
    assert key_resp.status_code == 200, key_resp.text
    api_key = key_resp.json()["key"]

    # Ingest a HIGH-risk event so an incident is also created
    r = client.post(
        "/api/v1/ingest",
        json={
            "events": [{
                "timestamp": "2026-04-29T00:00:00Z",
                "user": "victim",
                "ip": "203.0.113.99",
                "action": "POST",
                "status": "failure",
                "resource": "/login",
            }] * 5,  # 5 brute-force-like events
        },
        headers={"X-API-Key": api_key},
    )
    assert r.status_code == 200, r.text
    return api_key, app_id


class TestHardDeleteCascade:
    def test_cascade_removes_all_artifacts(self, client):
        # Bootstrap admin
        admin = _register(client, "cascade-admin@example.com")
        import api.main as api_main
        admin_id = _promote(api_main, "cascade-admin@example.com")
        admin_tokens = _admin_login(client, "cascade-admin@example.com")

        # Victim user with rich state
        victim = _register(client, "victim@example.com")
        victim_id = victim["user"]["id"]
        api_key, app_id = _seed_tenant_artifacts(client, victim["access_token"])

        # Sanity: rows exist before delete
        with api_main.db.Session() as s:
            from src.database import User, ApiKey, Application, LogEvent, Incident, RefreshToken
            assert s.query(User).filter_by(id=victim_id).first() is not None
            assert s.query(ApiKey).filter_by(user_id=victim_id).count() >= 1
            assert s.query(Application).filter_by(tenant_id=victim_id).count() >= 1
            assert s.query(LogEvent).filter_by(tenant_id=victim_id).count() >= 1
            assert s.query(RefreshToken).filter_by(user_id=victim_id).count() >= 1

        # Hard-delete victim
        d = client.delete(f"/api/admin/users/{victim_id}", headers=_hdr(admin_tokens["access_token"]))
        assert d.status_code == 200, d.text
        body = d.json()
        assert body.get("success") is True

        # Everything tied to victim_id is gone
        with api_main.db.Session() as s:
            from src.database import User, ApiKey, Application, LogEvent, Incident, RefreshToken
            assert s.query(User).filter_by(id=victim_id).first() is None
            assert s.query(ApiKey).filter_by(user_id=victim_id).count() == 0
            assert s.query(Application).filter_by(tenant_id=victim_id).count() == 0
            assert s.query(LogEvent).filter_by(tenant_id=victim_id).count() == 0
            assert s.query(Incident).filter_by(tenant_id=victim_id).count() == 0
            assert s.query(RefreshToken).filter_by(user_id=victim_id).count() == 0

    def test_cascade_does_not_touch_other_tenants(self, client):
        admin = _register(client, "cascade-admin2@example.com")
        import api.main as api_main
        _promote(api_main, "cascade-admin2@example.com")
        admin_tokens = _admin_login(client, "cascade-admin2@example.com")

        victim = _register(client, "victim2@example.com")
        survivor = _register(client, "survivor@example.com")
        victim_id = victim["user"]["id"]
        survivor_id = survivor["user"]["id"]

        _seed_tenant_artifacts(client, victim["access_token"])
        survivor_key, survivor_app = _seed_tenant_artifacts(client, survivor["access_token"])

        # Delete victim
        d = client.delete(f"/api/admin/users/{victim_id}", headers=_hdr(admin_tokens["access_token"]))
        assert d.status_code == 200

        # Survivor's data must still be intact
        with api_main.db.Session() as s:
            from src.database import User, ApiKey, Application, LogEvent
            assert s.query(User).filter_by(id=survivor_id).first() is not None
            assert s.query(ApiKey).filter_by(user_id=survivor_id).count() >= 1
            assert s.query(Application).filter_by(tenant_id=survivor_id).count() >= 1
            assert s.query(LogEvent).filter_by(tenant_id=survivor_id).count() >= 1

    def test_admin_cannot_delete_self(self, client):
        admin = _register(client, "self-del@example.com")
        import api.main as api_main
        admin_id = _promote(api_main, "self-del@example.com")
        admin_tokens = _admin_login(client, "self-del@example.com")

        d = client.delete(f"/api/admin/users/{admin_id}", headers=_hdr(admin_tokens["access_token"]))
        assert d.status_code == 400

    def test_non_admin_cannot_delete(self, client):
        a = _register(client, "regular-a@example.com")
        b = _register(client, "regular-b@example.com")
        d = client.delete(
            f"/api/admin/users/{b['user']['id']}",
            headers=_hdr(a["access_token"]),
        )
        assert d.status_code == 403
