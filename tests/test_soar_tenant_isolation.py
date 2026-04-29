"""
SOAR per-tenant isolation tests.

Each tenant only sees the SOAR actions logged against their own events.
Admins see the global view (across all tenants).
"""
from __future__ import annotations

import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database import Base, Database


class _InMemoryDB(Database):
    __test__ = False

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
def client(monkeypatch, tmp_path):
    """Wire up a fresh DB and an isolated data dir for SOAR storage."""
    tdb = _InMemoryDB()
    import src.database, src.auth, src.api_keys, api.main as api_main
    import src.response_engine as re_mod

    monkeypatch.setattr(src.database, "db", tdb)
    monkeypatch.setattr(src.auth, "db", tdb)
    monkeypatch.setattr(src.api_keys, "db", tdb)
    monkeypatch.setattr(api_main, "db", tdb)

    # Isolate SOAR storage per-test so we don't bleed into the project's data/.
    monkeypatch.setattr(re_mod, "_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(re_mod, "BLOCKED_IPS_FILE", str(tmp_path / "blocked_ips.json"))
    monkeypatch.setattr(re_mod, "DISABLED_ACCOUNTS_FILE", str(tmp_path / "disabled_accounts.json"))
    monkeypatch.setattr(re_mod, "RATE_LIMITS_FILE", str(tmp_path / "rate_limits.json"))
    monkeypatch.setattr(re_mod, "RESPONSE_LOG_FILE", str(tmp_path / "response_log.jsonl"))
    monkeypatch.setattr(re_mod, "_LEGACY_BLOCKED_IPS_TXT", str(tmp_path / "legacy_b.txt"))
    monkeypatch.setattr(re_mod, "_LEGACY_DISABLED_ACCOUNTS_TXT", str(tmp_path / "legacy_d.txt"))

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


def _promote_admin(email):
    """Direct DB promotion bypassing the API (no admin exists yet)."""
    from src.database import db, User
    s = db.Session()
    try:
        u = s.query(User).filter(User.email == email).first()
        u.role = "admin"
        s.commit()
    finally:
        s.close()


def _record_actions_directly(tenant_id: int, ip: str = None, account: str = None):
    """Bypass ingestion and write SOAR actions for the given tenant."""
    from src.response_engine import block_ip, disable_account, _log_response
    actions = []
    if ip:
        actions.append(block_ip(ip, tenant_id=tenant_id))
    if account:
        actions.append(disable_account(account, tenant_id=tenant_id))
    _log_response(
        incident_id=None,
        actions=actions,
        event={"user": account or "u", "ip": ip or "0.0.0.0", "tenant_id": tenant_id},
        tenant_id=tenant_id,
    )


class TestSoarTenantScope:
    def test_each_tenant_sees_only_their_blocked_ips(self, client):
        a = _register(client, "soar-a@x.com")
        b = _register(client, "soar-b@x.com")

        # User A's id == 1, user B's id == 2 (registered in order on a fresh DB)
        a_id = a["user"]["id"]
        b_id = b["user"]["id"]

        _record_actions_directly(tenant_id=a_id, ip="11.11.11.11")
        _record_actions_directly(tenant_id=b_id, ip="22.22.22.22")

        ra = client.get("/api/response/blocked-ips", headers=_hdr(a["access_token"]))
        rb = client.get("/api/response/blocked-ips", headers=_hdr(b["access_token"]))
        assert ra.status_code == 200 and rb.status_code == 200
        assert ra.json()["data"] == ["11.11.11.11"]
        assert rb.json()["data"] == ["22.22.22.22"]
        assert ra.json()["scope"] == "tenant"

    def test_each_tenant_sees_only_their_disabled_accounts(self, client):
        a = _register(client, "soar-c@x.com")
        b = _register(client, "soar-d@x.com")
        a_id, b_id = a["user"]["id"], b["user"]["id"]

        _record_actions_directly(tenant_id=a_id, account="alice@a.com")
        _record_actions_directly(tenant_id=b_id, account="bob@b.com")

        ra = client.get("/api/response/disabled-accounts", headers=_hdr(a["access_token"]))
        rb = client.get("/api/response/disabled-accounts", headers=_hdr(b["access_token"]))
        assert ra.json()["data"] == ["alice@a.com"]
        assert rb.json()["data"] == ["bob@b.com"]

    def test_each_tenant_sees_only_their_response_log(self, client):
        a = _register(client, "soar-e@x.com")
        b = _register(client, "soar-f@x.com")
        a_id, b_id = a["user"]["id"], b["user"]["id"]

        _record_actions_directly(tenant_id=a_id, ip="33.33.33.33")
        _record_actions_directly(tenant_id=b_id, ip="44.44.44.44")
        _record_actions_directly(tenant_id=b_id, ip="55.55.55.55")

        ra = client.get("/api/response/log", headers=_hdr(a["access_token"]))
        rb = client.get("/api/response/log", headers=_hdr(b["access_token"]))
        # User A logged 1 _log_response call → 1 block_ip action → 1 row
        assert ra.json()["scope"] == "tenant"
        a_targets = {row["target"] for row in ra.json()["data"]}
        b_targets = {row["target"] for row in rb.json()["data"]}
        assert "33.33.33.33" in a_targets
        assert "44.44.44.44" in b_targets and "55.55.55.55" in b_targets
        assert "44.44.44.44" not in a_targets
        assert "33.33.33.33" not in b_targets

    def test_admin_sees_global_view(self, client):
        a = _register(client, "soar-g@x.com")
        admin = _register(client, "soar-admin@x.com")
        _promote_admin("soar-admin@x.com")

        # Re-login admin to get a fresh access token after the role change
        r = client.post("/api/auth/login", json={"email": "soar-admin@x.com", "password": "securepass123"})
        admin_token = r.json()["access_token"]

        a_id = a["user"]["id"]
        admin_id = admin["user"]["id"]
        _record_actions_directly(tenant_id=a_id, ip="77.77.77.77")
        _record_actions_directly(tenant_id=admin_id, ip="88.88.88.88")

        r = client.get("/api/response/blocked-ips", headers=_hdr(admin_token))
        assert r.json()["scope"] == "all"
        assert set(r.json()["data"]) >= {"77.77.77.77", "88.88.88.88"}

    def test_endpoint_no_longer_admin_only(self, client):
        """Pre-fix this returned 403; now non-admins reach it and see their own data."""
        a = _register(client, "soar-h@x.com")
        r = client.get("/api/response/blocked-ips", headers=_hdr(a["access_token"]))
        assert r.status_code == 200
        assert r.json()["data"] == []
        assert r.json()["scope"] == "tenant"
