"""
Tests for src/database.py — models, CRUD, tenant isolation.
"""
import pytest
from datetime import datetime


# ─── Model creation tests ────────────────────────────────────────────────────

class TestUserCRUD:
    def test_create_user(self, test_db):
        from src.auth import hash_password
        user = test_db.create_user(
            email="alice@example.com",
            password_hash=hash_password("secret"),
            display_name="Alice",
        )
        assert user.id is not None
        assert user.email == "alice@example.com"
        assert user.display_name == "Alice"
        assert user.role == "user"
        assert user.is_active is True

    def test_create_admin_user(self, test_db):
        from src.auth import hash_password
        user = test_db.create_user(
            email="admin@corp.com",
            password_hash=hash_password("admin"),
            role="admin",
        )
        assert user.role == "admin"

    def test_duplicate_email_raises(self, test_db):
        from src.auth import hash_password
        test_db.create_user(email="dup@test.com", password_hash=hash_password("x"))
        with pytest.raises(Exception):
            test_db.create_user(email="dup@test.com", password_hash=hash_password("y"))

    def test_get_user_by_email(self, sample_user, test_db):
        found = test_db.get_user_by_email("test@example.com")
        assert found is not None
        assert found.id == sample_user.id

    def test_get_user_by_email_not_found(self, test_db):
        assert test_db.get_user_by_email("noone@nowhere.com") is None

    def test_get_user_by_id(self, sample_user, test_db):
        found = test_db.get_user_by_id(sample_user.id)
        assert found is not None
        assert found.email == "test@example.com"

    def test_get_user_by_id_not_found(self, test_db):
        assert test_db.get_user_by_id(99999) is None


# ─── Event insertion ─────────────────────────────────────────────────────────

class TestEventInsertion:
    def test_insert_normal_event(self, test_db, sample_event_dict):
        event_id, incident_id = test_db.insert_event(sample_event_dict)
        assert event_id is not None
        assert incident_id is None  # risk < 80

    def test_insert_high_risk_creates_incident(self, test_db, high_risk_event_dict):
        event_id, incident_id = test_db.insert_event(high_risk_event_dict)
        assert event_id is not None
        assert incident_id is not None

    def test_insert_event_with_tenant_id(self, test_db, sample_event_dict, sample_user):
        sample_event_dict["tenant_id"] = sample_user.id
        event_id, _ = test_db.insert_event(sample_event_dict)
        assert event_id is not None

    def test_incident_inherits_tenant_id(self, test_db, high_risk_event_dict, sample_user):
        high_risk_event_dict["tenant_id"] = sample_user.id
        event_id, incident_id = test_db.insert_event(high_risk_event_dict)
        inc, _ = test_db.get_incident_details(incident_id)
        assert inc.tenant_id == sample_user.id


# ─── Fetch events ────────────────────────────────────────────────────────────

class TestFetchEvents:
    def test_fetch_all_events(self, test_db, sample_event_dict):
        test_db.insert_event(sample_event_dict)
        events = test_db.fetch_all_events()
        assert len(events) == 1

    def test_fetch_events_paginated(self, test_db, sample_event_dict):
        for _ in range(5):
            test_db.insert_event(dict(sample_event_dict))
        events, total = test_db.fetch_events_paginated(page=1, limit=3)
        assert len(events) == 3
        assert total == 5

    def test_fetch_events_paginated_page2(self, test_db, sample_event_dict):
        for _ in range(5):
            test_db.insert_event(dict(sample_event_dict))
        events, total = test_db.fetch_events_paginated(page=2, limit=3)
        assert len(events) == 2
        assert total == 5

    def test_fetch_events_min_risk_filter(self, test_db, sample_event_dict, high_risk_event_dict):
        test_db.insert_event(sample_event_dict)  # risk 45
        test_db.insert_event(high_risk_event_dict)  # risk 92
        events, total = test_db.fetch_events_paginated(min_risk=80)
        assert total == 1
        assert events[0].risk_score == 92.0


# ─── Tenant isolation ────────────────────────────────────────────────────────

class TestTenantIsolation:
    def _insert_for_tenant(self, test_db, event_dict, tenant_id):
        d = dict(event_dict)
        d["tenant_id"] = tenant_id
        return test_db.insert_event(d)

    def test_user_sees_only_own_events(self, test_db, sample_event_dict):
        from src.auth import hash_password
        u1 = test_db.create_user(email="u1@t.com", password_hash=hash_password("a"))
        u2 = test_db.create_user(email="u2@t.com", password_hash=hash_password("b"))

        for _ in range(3):
            self._insert_for_tenant(test_db, sample_event_dict, u1.id)
        for _ in range(2):
            self._insert_for_tenant(test_db, sample_event_dict, u2.id)

        events_u1, total_u1 = test_db.fetch_events_paginated(tenant_id=u1.id, user_role="user")
        events_u2, total_u2 = test_db.fetch_events_paginated(tenant_id=u2.id, user_role="user")
        assert total_u1 == 3
        assert total_u2 == 2

    def test_admin_sees_all_events(self, test_db, sample_event_dict):
        from src.auth import hash_password
        u1 = test_db.create_user(email="u1b@t.com", password_hash=hash_password("a"))
        u2 = test_db.create_user(email="u2b@t.com", password_hash=hash_password("b"))

        self._insert_for_tenant(test_db, sample_event_dict, u1.id)
        self._insert_for_tenant(test_db, sample_event_dict, u2.id)

        events, total = test_db.fetch_events_paginated(tenant_id=u1.id, user_role="admin")
        assert total == 2  # admin sees all

    def test_tenant_isolation_on_incidents(self, test_db, high_risk_event_dict):
        from src.auth import hash_password
        u1 = test_db.create_user(email="inc1@t.com", password_hash=hash_password("a"))
        u2 = test_db.create_user(email="inc2@t.com", password_hash=hash_password("b"))

        self._insert_for_tenant(test_db, high_risk_event_dict, u1.id)
        self._insert_for_tenant(test_db, high_risk_event_dict, u2.id)

        inc_u1 = test_db.fetch_incidents(tenant_id=u1.id, user_role="user")
        inc_u2 = test_db.fetch_incidents(tenant_id=u2.id, user_role="user")
        assert len(inc_u1) == 1
        assert len(inc_u2) == 1

    def test_null_tenant_visible_to_admin(self, test_db, sample_event_dict):
        """Events with NULL tenant_id (legacy/simulator) should be visible to admin."""
        test_db.insert_event(sample_event_dict)  # tenant_id=None
        events, total = test_db.fetch_events_paginated(tenant_id=1, user_role="admin")
        assert total == 1

    def test_null_tenant_not_visible_to_user(self, test_db, sample_event_dict, sample_user):
        """Events with NULL tenant_id should NOT be visible to regular users filtering by their ID."""
        test_db.insert_event(sample_event_dict)  # tenant_id=None
        events, total = test_db.fetch_events_paginated(tenant_id=sample_user.id, user_role="user")
        assert total == 0


# ─── Incident operations ────────────────────────────────────────────────────

class TestIncidentOperations:
    def test_update_incident_status(self, test_db, high_risk_event_dict):
        _, inc_id = test_db.insert_event(high_risk_event_dict)
        test_db.update_incident_status(inc_id, "INVESTIGATING", owner="Analyst1")
        inc, _ = test_db.get_incident_details(inc_id)
        assert inc.status == "INVESTIGATING"
        assert inc.owner == "Analyst1"

    def test_resolve_sets_resolved_at(self, test_db, high_risk_event_dict):
        _, inc_id = test_db.insert_event(high_risk_event_dict)
        test_db.update_incident_status(inc_id, "RESOLVED")
        inc, _ = test_db.get_incident_details(inc_id)
        assert inc.status == "RESOLVED"
        assert inc.resolved_at is not None

    def test_update_incident_note(self, test_db, high_risk_event_dict):
        _, inc_id = test_db.insert_event(high_risk_event_dict)
        test_db.update_incident_note(inc_id, "AI summary here")
        inc, _ = test_db.get_incident_details(inc_id)
        assert inc.note == "AI summary here"

    def test_update_incident_response(self, test_db, high_risk_event_dict):
        _, inc_id = test_db.insert_event(high_risk_event_dict)
        test_db.update_incident_response(inc_id, '["block_ip"]')
        inc, _ = test_db.get_incident_details(inc_id)
        assert inc.response_actions == '["block_ip"]'
        assert inc.responded_at is not None

    def test_get_incident_details_returns_log_event(self, test_db, high_risk_event_dict):
        event_id, inc_id = test_db.insert_event(high_risk_event_dict)
        inc, le = test_db.get_incident_details(inc_id)
        assert inc is not None
        assert le is not None
        assert le.id == event_id

    def test_get_incident_details_not_found(self, test_db):
        inc, le = test_db.get_incident_details(99999)
        assert inc is None
        assert le is None

    def test_tenant_scoped_incident_update(self, test_db, high_risk_event_dict):
        """User can only update their own tenant's incidents."""
        from src.auth import hash_password
        u1 = test_db.create_user(email="own1@t.com", password_hash=hash_password("a"))
        u2 = test_db.create_user(email="own2@t.com", password_hash=hash_password("b"))

        d = dict(high_risk_event_dict)
        d["tenant_id"] = u1.id
        _, inc_id = test_db.insert_event(d)

        # u2 trying to update u1's incident — should have no effect
        test_db.update_incident_status(inc_id, "RESOLVED", tenant_id=u2.id, user_role="user")
        inc, _ = test_db.get_incident_details(inc_id)
        assert inc.status == "OPEN"  # unchanged


# ─── Stats ───────────────────────────────────────────────────────────────────

class TestStats:
    def test_get_stats_empty_db(self, test_db):
        stats = test_db.get_stats()
        assert stats["total_events"] == 0
        assert stats["open_incidents"] == 0
        assert stats["avg_risk"] == 0

    def test_get_stats_with_data(self, test_db, sample_event_dict, high_risk_event_dict):
        test_db.insert_event(sample_event_dict)
        test_db.insert_event(high_risk_event_dict)
        stats = test_db.get_stats()
        assert stats["total_events"] == 2
        assert stats["open_incidents"] == 1  # high-risk creates OPEN incident
        assert stats["critical_events"] == 1

    def test_get_stats_tenant_scoped(self, test_db, sample_event_dict):
        from src.auth import hash_password
        u1 = test_db.create_user(email="s1@t.com", password_hash=hash_password("a"))
        d1 = dict(sample_event_dict)
        d1["tenant_id"] = u1.id
        test_db.insert_event(d1)
        test_db.insert_event(sample_event_dict)  # no tenant

        stats = test_db.get_stats(tenant_id=u1.id, user_role="user")
        assert stats["total_events"] == 1

    def test_mttd_mttr_empty(self, test_db):
        stats = test_db.get_mttd_mttr_stats()
        assert stats["mttd_avg_seconds"] == 0
        assert stats["mttr_avg_seconds"] == 0
        assert len(stats["mttd_trend"]) == 7

    def test_mttd_mttr_with_resolved(self, test_db, high_risk_event_dict):
        _, inc_id = test_db.insert_event(high_risk_event_dict)
        test_db.update_incident_response(inc_id, "[]")  # sets responded_at
        test_db.update_incident_status(inc_id, "RESOLVED")  # sets resolved_at
        stats = test_db.get_mttd_mttr_stats()
        assert stats["incidents_with_response"] >= 1
        assert stats["incidents_resolved"] >= 1


# ─── Graph events ────────────────────────────────────────────────────────────

class TestGraphEvents:
    def test_get_recent_events_for_graph(self, test_db, sample_event_dict, high_risk_event_dict):
        test_db.insert_event(sample_event_dict)  # risk 45 — below threshold
        test_db.insert_event(high_risk_event_dict)  # risk 92
        events = test_db.get_recent_events_for_graph()
        assert len(events) == 1  # only risk >= 50

    def test_graph_events_tenant_scoped(self, test_db, high_risk_event_dict):
        from src.auth import hash_password
        u1 = test_db.create_user(email="g1@t.com", password_hash=hash_password("a"))
        u2 = test_db.create_user(email="g2@t.com", password_hash=hash_password("b"))

        d1 = dict(high_risk_event_dict)
        d1["tenant_id"] = u1.id
        test_db.insert_event(d1)

        d2 = dict(high_risk_event_dict)
        d2["tenant_id"] = u2.id
        test_db.insert_event(d2)

        events = test_db.get_recent_events_for_graph(tenant_id=u1.id, user_role="user")
        assert len(events) == 1


# ─── Attack chains ───────────────────────────────────────────────────────────

class TestAttackChains:
    def test_save_attack_chain(self, test_db):
        chain = {
            "chain_id": "chain-001",
            "max_risk": 95.0,
            "severity": "critical",
            "involved_ips": ["1.2.3.4"],
            "involved_users": ["attacker"],
            "events": [{"id": 1}],
            "start_time": "2024-01-15T10:00:00",
            "end_time": "2024-01-15T10:30:00",
        }
        test_db.save_attack_chain(chain)
        session = test_db.Session()
        from src.database import AttackChain
        ac = session.query(AttackChain).first()
        assert ac is not None
        assert ac.chain_id == "chain-001"
        assert ac.max_risk == 95.0
        session.close()

    def test_save_duplicate_chain_skipped(self, test_db):
        chain = {
            "chain_id": "chain-dup",
            "max_risk": 80.0,
            "severity": "high",
            "involved_ips": [],
            "involved_users": [],
            "events": [],
        }
        test_db.save_attack_chain(chain)
        test_db.save_attack_chain(chain)  # should be a no-op
        session = test_db.Session()
        from src.database import AttackChain
        count = session.query(AttackChain).filter(AttackChain.chain_id == "chain-dup").count()
        assert count == 1
        session.close()

    def test_save_chain_with_tenant(self, test_db, sample_user):
        chain = {
            "chain_id": "chain-tenant",
            "max_risk": 85.0,
            "severity": "high",
            "involved_ips": [],
            "involved_users": [],
            "events": [],
            "tenant_id": sample_user.id,
        }
        test_db.save_attack_chain(chain)
        session = test_db.Session()
        from src.database import AttackChain
        ac = session.query(AttackChain).filter(AttackChain.chain_id == "chain-tenant").first()
        assert ac.tenant_id == sample_user.id
        session.close()
