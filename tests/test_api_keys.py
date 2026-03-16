"""
Tests for src/api_keys.py — key generation, hashing, validation.
"""
import pytest
import hashlib
from unittest.mock import MagicMock

from fastapi import HTTPException

from src.database import ApiKey


class TestGenerateApiKey:
    def test_returns_tuple_of_3(self):
        from src.api_keys import generate_api_key
        result = generate_api_key()
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_key_format(self):
        from src.api_keys import generate_api_key
        full_key, prefix, key_hash = generate_api_key()
        assert full_key.startswith("tp_live_")
        assert len(full_key) == 8 + 48  # "tp_live_" + 48 hex chars

    def test_prefix_is_first_16_chars(self):
        from src.api_keys import generate_api_key
        full_key, prefix, _ = generate_api_key()
        assert prefix == full_key[:16]

    def test_hash_matches(self):
        from src.api_keys import generate_api_key
        full_key, _, key_hash = generate_api_key()
        expected = hashlib.sha256(full_key.encode()).hexdigest()
        assert key_hash == expected

    def test_keys_are_unique(self):
        from src.api_keys import generate_api_key
        keys = set()
        for _ in range(50):
            k, _, _ = generate_api_key()
            keys.add(k)
        assert len(keys) == 50


class TestHashApiKey:
    def test_hash_consistency(self):
        from src.api_keys import hash_api_key
        h1 = hash_api_key("tp_live_abc123")
        h2 = hash_api_key("tp_live_abc123")
        assert h1 == h2

    def test_different_keys_different_hashes(self):
        from src.api_keys import hash_api_key
        h1 = hash_api_key("tp_live_aaa")
        h2 = hash_api_key("tp_live_bbb")
        assert h1 != h2

    def test_hash_is_sha256(self):
        from src.api_keys import hash_api_key
        key = "tp_live_test123"
        result = hash_api_key(key)
        expected = hashlib.sha256(key.encode()).hexdigest()
        assert result == expected


class TestGetApiKeyUser:
    def _make_request(self, api_key=None):
        mock = MagicMock()
        headers = {}
        if api_key:
            headers["X-API-Key"] = api_key
        mock.headers = MagicMock()
        mock.headers.get = lambda key, default="": headers.get(key, default)
        return mock

    def test_missing_header(self, test_db):
        from src.api_keys import get_api_key_user
        request = self._make_request()
        with pytest.raises(HTTPException) as exc_info:
            get_api_key_user(request)
        assert exc_info.value.status_code == 401
        assert "Missing" in exc_info.value.detail

    def test_invalid_key(self, test_db):
        from src.api_keys import get_api_key_user
        request = self._make_request("tp_live_nonexistent_key_value_here")
        with pytest.raises(HTTPException) as exc_info:
            get_api_key_user(request)
        assert exc_info.value.status_code == 401

    def test_valid_key_returns_user(self, test_db, sample_user):
        from src.api_keys import generate_api_key, get_api_key_user
        full_key, prefix, key_hash = generate_api_key()

        # Store key in DB
        session = test_db.Session()
        ak = ApiKey(
            user_id=sample_user.id,
            name="Test Key",
            prefix=prefix,
            key_hash=key_hash,
        )
        session.add(ak)
        session.commit()
        session.close()

        request = self._make_request(full_key)
        user = get_api_key_user(request)
        assert user.id == sample_user.id
        assert user.email == sample_user.email

    def test_revoked_key_rejected(self, test_db, sample_user):
        from src.api_keys import generate_api_key, get_api_key_user
        full_key, prefix, key_hash = generate_api_key()

        session = test_db.Session()
        ak = ApiKey(
            user_id=sample_user.id,
            name="Revoked",
            prefix=prefix,
            key_hash=key_hash,
            is_active=False,
        )
        session.add(ak)
        session.commit()
        session.close()

        request = self._make_request(full_key)
        with pytest.raises(HTTPException) as exc_info:
            get_api_key_user(request)
        assert exc_info.value.status_code == 401

    def test_key_updates_last_used(self, test_db, sample_user):
        from src.api_keys import generate_api_key, get_api_key_user
        full_key, prefix, key_hash = generate_api_key()

        session = test_db.Session()
        ak = ApiKey(
            user_id=sample_user.id,
            name="Track Usage",
            prefix=prefix,
            key_hash=key_hash,
        )
        session.add(ak)
        session.commit()
        ak_id = ak.id
        session.close()

        request = self._make_request(full_key)
        get_api_key_user(request)

        session = test_db.Session()
        ak = session.query(ApiKey).filter(ApiKey.id == ak_id).first()
        assert ak.last_used_at is not None
        session.close()

    def test_inactive_user_key_rejected(self, test_db):
        """API key should be rejected if the user is inactive."""
        from src.auth import hash_password
        from src.api_keys import generate_api_key, get_api_key_user
        from src.database import User

        user = test_db.create_user(email="deact@t.com", password_hash=hash_password("x"))
        full_key, prefix, key_hash = generate_api_key()

        session = test_db.Session()
        ak = ApiKey(user_id=user.id, name="Key", prefix=prefix, key_hash=key_hash)
        session.add(ak)
        # Deactivate user
        u = session.query(User).filter(User.id == user.id).first()
        u.is_active = False
        session.commit()
        session.close()

        request = self._make_request(full_key)
        with pytest.raises(HTTPException) as exc_info:
            get_api_key_user(request)
        assert exc_info.value.status_code == 401
        assert "owner" in exc_info.value.detail.lower() or "inactive" in exc_info.value.detail.lower()
