"""
HTTP-level cross-tenant isolation tests.

For each shared resource, user B must not be able to see, modify, or revoke
user A's data — even by guessing the integer ID. The expected response is a
404 (not 403) so we don't leak the existence of A's resources.

Admin must still see both tenants' data.
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


def _hdr(t):
    return {"Authorization": f"Bearer {t}"}


def _create_app(client, token, name):
    r = client.post("/api/applications", json={"name": name}, headers=_hdr(token))
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _create_key(client, token, app_id=None, name="k"):
    body = {"name": name}
    if app_id is not None:
        body["application_id"] = app_id
    r = client.post("/api/keys", json=body, headers=_hdr(token))
    assert r.status_code == 200, r.text
    return r.json()


def _ingest_one(client, api_key, ip="10.0.0.1", resource="/x"):
    r = client.post(
        "/api/v1/ingest",
        json={"events": [{
            "timestamp": "2026-04-29T00:00:00Z",
            "user": "u",
            "ip": ip,
            "action": "GET",
            "status": "success",
            "resource": resource,
        }]},
        headers={"X-API-Key": api_key},
    )
    assert r.status_code == 200, r.text


class TestEventsScope:
    def test_user_only_sees_own_events(self, client):
        a = _register(client, "a-events@x.com")
        b = _register(client, "b-events@x.com")
        a_key = _create_key(client, a["access_token"], None, "ak")["key"]
        b_key = _create_key(client, b["access_token"], None, "bk")["key"]

        _ingest_one(client, a_key, ip="1.1.1.1", resource="/a-only")
        _ingest_one(client, b_key, ip="2.2.2.2", resource="/b-only")

        a_resp = client.get("/api/events", headers=_hdr(a["access_token"]))
        b_resp = client.get("/api/events", headers=_hdr(b["access_token"]))
        assert a_resp.status_code == b_resp.status_code == 200

        a_data = a_resp.json()["data"]
        b_data = b_resp.json()["data"]

        # Each user sees ONLY their own resources
        assert all("/a-only" in (e.get("resource") or "") for e in a_data) or len(a_data) == 0 or all(
            "/b-only" not in (e.get("resource") or "") for e in a_data
        )
        assert all("/a-only" not in (e.get("resource") or "") for e in b_data)


class TestApplicationsScope:
    def test_b_cannot_see_a_application(self, client):
        a = _register(client, "a-apps@x.com")
        b = _register(client, "b-apps@x.com")
        a_app = _create_app(client, a["access_token"], "A's app")

        # B reads the list — must not include A's app
        r = client.get("/api/applications", headers=_hdr(b["access_token"]))
        assert r.status_code == 200
        names = [a["name"] for a in r.json().get("data", [])]
        assert "A's app" not in names

        # B cannot fetch A's app by id
        detail = client.get(f"/api/applications/{a_app}", headers=_hdr(b["access_token"]))
        assert detail.status_code == 404, detail.text

        # B cannot fetch A's app keys
        keys = client.get(f"/api/applications/{a_app}/keys", headers=_hdr(b["access_token"]))
        assert keys.status_code == 404, keys.text


class TestApiKeysScope:
    def test_b_cannot_revoke_a_key(self, client):
        a = _register(client, "a-keys@x.com")
        b = _register(client, "b-keys@x.com")
        a_key_obj = _create_key(client, a["access_token"], None, "a-key")

        revoke = client.delete(
            f"/api/keys/{a_key_obj['id']}", headers=_hdr(b["access_token"])
        )
        assert revoke.status_code == 404, revoke.text

        # Verify A's key still active
        listed = client.get("/api/keys", headers=_hdr(a["access_token"]))
        kept = [k for k in listed.json()["data"] if k["id"] == a_key_obj["id"]][0]
        assert kept["is_active"] is True


class TestIncidentsScope:
    def test_b_cannot_read_a_incident(self, client):
        a = _register(client, "a-inc@x.com")
        b = _register(client, "b-inc@x.com")
        a_key = _create_key(client, a["access_token"], None, "a-inc-key")["key"]

        # Drive several brute-force-like events to maximise chance of incident creation
        for _ in range(8):
            client.post(
                "/api/v1/ingest",
                json={"events": [{
                    "timestamp": "2026-04-29T00:00:00Z",
                    "user": "attacker",
                    "ip": "9.9.9.9",
                    "action": "POST",
                    "status": "failure",
                    "resource": "/login",
                }]},
                headers={"X-API-Key": a_key},
            )

        a_incidents = client.get("/api/incidents", headers=_hdr(a["access_token"])).json()
        b_incidents = client.get("/api/incidents", headers=_hdr(b["access_token"])).json()

        # B's list must be empty (no shared incidents)
        b_data = b_incidents.get("data", b_incidents) if isinstance(b_incidents, dict) else b_incidents
        if isinstance(b_data, list):
            assert len(b_data) == 0

        a_data = a_incidents.get("data", a_incidents) if isinstance(a_incidents, dict) else a_incidents
        if isinstance(a_data, list) and a_data:
            inc_id = a_data[0]["id"]
            r = client.get(f"/api/incidents/{inc_id}", headers=_hdr(b["access_token"]))
            assert r.status_code == 404, r.text


class TestAdminCanSeeAll:
    def test_admin_sees_all_events(self, client):
        a = _register(client, "a-admin@x.com")
        admin = _register(client, "real-admin@x.com")
        import api.main as api_main
        with api_main.db.Session() as s:
            u = s.query(api_main.User).filter_by(email="real-admin@x.com").first()
            u.role = "admin"
            s.commit()
        admin_login = client.post(
            "/api/auth/login", json={"email": "real-admin@x.com", "password": "securepass123"}
        ).json()

        a_key = _create_key(client, a["access_token"], None, "a-admin-key")["key"]
        _ingest_one(client, a_key, resource="/admin-can-see-this")

        r = client.get("/api/events", headers=_hdr(admin_login["access_token"]))
        assert r.status_code == 200
        resources = [e.get("resource") for e in r.json()["data"]]
        assert any("/admin-can-see-this" in (s or "") for s in resources), \
            "Admin should see all tenants' events"
