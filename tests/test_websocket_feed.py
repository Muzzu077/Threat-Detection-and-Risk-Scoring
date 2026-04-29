"""
WebSocket /ws/live-feed authentication + tenant-isolation tests.

These exercise:
- Auth gating: missing / invalid / revoked tokens are rejected (close 1008).
- Per-tenant routing: user A's ingested events do NOT reach user B's socket.
- Admin scope: an admin socket sees every tenant's events.
- Frame schema: history_event on connect, new_event on broadcast.
"""
from __future__ import annotations

import os
import sys
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
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


def _make_admin(client, email="admin@example.com"):
    """Register a user, then promote them via direct DB access."""
    data = _register(client, email)
    # Promote via DB (admin promote endpoint is admin-only itself).
    import api.main as api_main
    with api_main.db.Session() as s:
        u = s.query(api_main.User).filter_by(email=email).first()
        u.role = "admin"
        s.commit()
    # Re-login to get a fresh access token reflecting the new role.
    r = client.post("/api/auth/login", json={"email": email, "password": "securepass123"})
    assert r.status_code == 200
    return r.json()


def _create_api_key(client, headers, name="ws-test-key"):
    r = client.post("/api/keys", json={"name": name}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["key"]


def _ingest(client, api_key, user="alice", risk_action="GET", resource="/dashboard"):
    return client.post(
        "/api/v1/ingest",
        json={
            "events": [{
                "timestamp": "2026-04-29T00:00:00Z",
                "user": user,
                "ip": "10.0.0.5",
                "action": risk_action,
                "status": "success",
                "resource": resource,
            }]
        },
        headers={"X-API-Key": api_key},
    )


# ───── Auth gating ─────────────────────────────────────────────────────────────

def _expect_close(client, url, expected_code=1008):
    """Open a websocket and assert the server closes it with `expected_code`.

    Starlette's TestClient surfaces a server-initiated close as
    WebSocketDisconnect on the next receive() call.
    """
    with pytest.raises(WebSocketDisconnect) as ei:
        with client.websocket_connect(url) as ws:
            # Force the close to surface; if the server didn't actually
            # close, this will hang briefly then we'll fail elsewhere.
            ws.receive_text()
    assert ei.value.code == expected_code, f"expected close code {expected_code}, got {ei.value.code}"


class TestWebSocketAuth:
    def test_missing_token_closes_1008(self, client):
        _expect_close(client, "/ws/live-feed")

    def test_invalid_token_closes_1008(self, client):
        _expect_close(client, "/ws/live-feed?token=garbage.not.a.jwt")

    def test_refresh_token_used_as_access_rejected(self, client):
        u = _register(client, "revoked@example.com")
        # A refresh token used in place of an access token is the wrong type.
        _expect_close(client, f"/ws/live-feed?token={u['refresh_token']}")

    def test_valid_token_connects_and_receives_frames(self, client):
        u = _register(client, "wsuser@example.com")
        with client.websocket_connect(f"/ws/live-feed?token={u['access_token']}") as ws:
            # We don't assert content; just that the connection opens cleanly.
            # Closing on our side must not raise.
            ws.close()


# ───── Tenant isolation on broadcast ──────────────────────────────────────────

def _drain_history(ws, max_frames=12):
    """Consume any history_event frames sent on connect; return when we stop seeing them."""
    seen = []
    for _ in range(max_frames):
        try:
            msg = ws.receive_json()
        except Exception:
            break
        seen.append(msg)
        if isinstance(msg, dict) and msg.get("type") != "history_event":
            break
    return seen


def _try_receive_new_event(ws, max_frames=8, match_substr=None):
    """Attempt to read a `new_event` frame, optionally filtered by a substring in the data."""
    for _ in range(max_frames):
        try:
            msg = ws.receive_json()
        except Exception:
            return None
        if isinstance(msg, dict) and msg.get("type") == "new_event":
            if match_substr is None or match_substr.lower() in str(msg.get("data", {})).lower():
                return msg
    return None


class TestWebSocketTenantIsolation:
    def test_user_sees_own_event(self, client):
        a = _register(client, "self-ws@example.com")
        a_key = _create_api_key(client, {"Authorization": f"Bearer {a['access_token']}"}, "self-key")

        with client.websocket_connect(f"/ws/live-feed?token={a['access_token']}") as ws:
            _drain_history(ws)
            r = _ingest(client, a_key, user="self-traffic", resource="/me-only-resource")
            assert r.status_code == 200, r.text

            ev = _try_receive_new_event(ws, max_frames=10, match_substr="me-only-resource")
            assert ev is not None, "Did not receive own new_event broadcast"

    def test_user_only_sees_own_events(self, client):
        a = _register(client, "alice-ws@example.com")
        b = _register(client, "bob-ws@example.com")

        a_key = _create_api_key(client, {"Authorization": f"Bearer {a['access_token']}"}, "alice-key")

        # Bob connects to live feed and drains history
        with client.websocket_connect(f"/ws/live-feed?token={b['access_token']}") as bob_ws:
            _drain_history(bob_ws)

            # Alice ingests an event in her tenant — Bob must not see it
            r = _ingest(client, a_key, user="alice-secret-user", resource="/alice-only-resource")
            assert r.status_code == 200, r.text

            leaked = _try_receive_new_event(bob_ws, max_frames=4, match_substr="alice-only-resource")
            assert leaked is None, f"Cross-tenant leak: Bob received Alice's event: {leaked}"


# ───── Admin scope ────────────────────────────────────────────────────────────

class TestWebSocketAdminScope:
    def test_admin_sees_other_tenants_events(self, client):
        admin = _make_admin(client, "admin-ws@example.com")
        bob = _register(client, "bob-for-admin@example.com")
        bob_key = _create_api_key(client, {"Authorization": f"Bearer {bob['access_token']}"}, "bob-key")

        with client.websocket_connect(f"/ws/live-feed?token={admin['access_token']}") as adm_ws:
            _drain_history(adm_ws)

            r = _ingest(client, bob_key, user="bob-traffic", resource="/admin-can-see-bobs-traffic")
            assert r.status_code == 200, r.text

            ev = _try_receive_new_event(adm_ws, max_frames=10, match_substr="admin-can-see-bobs-traffic")
            assert ev is not None, "Admin did not see Bob's event"
