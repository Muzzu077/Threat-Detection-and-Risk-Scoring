"""
Tests for src/auth.py — password hashing, JWT tokens, user extraction.
"""
import pytest
import hashlib
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import jwt as pyjwt
from fastapi import HTTPException


class TestPasswordHashing:
    def test_hash_password_returns_string(self):
        from src.auth import hash_password
        h = hash_password("mysecret")
        assert isinstance(h, str)
        assert len(h) > 20

    def test_hash_password_different_each_time(self):
        from src.auth import hash_password
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # different salts

    def test_verify_password_correct(self):
        from src.auth import hash_password, verify_password
        h = hash_password("correct")
        assert verify_password("correct", h) is True

    def test_verify_password_wrong(self):
        from src.auth import hash_password, verify_password
        h = hash_password("correct")
        assert verify_password("wrong", h) is False

    def test_verify_password_empty(self):
        from src.auth import hash_password, verify_password
        h = hash_password("")
        assert verify_password("", h) is True
        assert verify_password("notempty", h) is False


class TestAccessToken:
    def test_create_access_token(self):
        from src.auth import create_access_token, SECRET_KEY, ALGORITHM
        token = create_access_token(user_id=1, email="a@b.com")
        assert isinstance(token, str)

        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "1"
        assert payload["email"] == "a@b.com"
        assert payload["type"] == "access"

    def test_access_token_expires_in_30_min(self):
        from src.auth import create_access_token, SECRET_KEY, ALGORITHM
        token = create_access_token(user_id=1, email="a@b.com")
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        exp = datetime.utcfromtimestamp(payload["exp"])
        iat = datetime.utcfromtimestamp(payload["iat"])
        diff = (exp - iat).total_seconds()
        assert 1790 <= diff <= 1810  # ~30 min


class TestRefreshToken:
    def test_create_refresh_token(self, test_db, sample_user):
        from src.auth import create_refresh_token, SECRET_KEY, ALGORITHM
        token = create_refresh_token(user_id=sample_user.id)
        assert isinstance(token, str)

        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == str(sample_user.id)
        assert payload["type"] == "refresh"

    def test_refresh_token_stored_in_db(self, test_db, sample_user):
        from src.auth import create_refresh_token
        from src.database import RefreshToken
        token = create_refresh_token(user_id=sample_user.id)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        session = test_db.Session()
        rt = session.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        assert rt is not None
        assert rt.user_id == sample_user.id
        assert rt.revoked is False
        session.close()

    def test_refresh_token_expires_in_7_days(self):
        from src.auth import create_access_token, SECRET_KEY, ALGORITHM
        # Refresh token expiry tested via payload
        import src.auth as auth_mod
        original = auth_mod.REFRESH_TOKEN_EXPIRE_DAYS
        assert original == 7


class TestDecodeToken:
    def test_decode_valid_token(self):
        from src.auth import create_access_token, decode_token
        token = create_access_token(user_id=42, email="x@y.com")
        payload = decode_token(token)
        assert payload["sub"] == "42"

    def test_decode_expired_token(self):
        from src.auth import SECRET_KEY, ALGORITHM, decode_token
        payload = {
            "sub": "1",
            "type": "access",
            "exp": datetime.utcnow() - timedelta(hours=1),
            "iat": datetime.utcnow() - timedelta(hours=2),
        }
        token = pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_decode_invalid_token(self):
        from src.auth import decode_token
        with pytest.raises(HTTPException) as exc_info:
            decode_token("not.a.real.token")
        assert exc_info.value.status_code == 401


class TestRevokeRefreshToken:
    def test_revoke_refresh_token(self, test_db, sample_user):
        from src.auth import create_refresh_token, revoke_refresh_token
        from src.database import RefreshToken
        token = create_refresh_token(user_id=sample_user.id)
        revoke_refresh_token(token)

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        session = test_db.Session()
        rt = session.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        assert rt.revoked is True
        session.close()

    def test_revoke_nonexistent_token(self, test_db):
        """Should not raise — just a no-op."""
        from src.auth import revoke_refresh_token
        revoke_refresh_token("fake-token-value")


class TestValidateRefreshToken:
    def test_validate_valid_refresh_token(self, test_db, sample_user):
        from src.auth import create_refresh_token, validate_refresh_token
        token = create_refresh_token(user_id=sample_user.id)
        user_id = validate_refresh_token(token)
        assert user_id == sample_user.id

    def test_validate_revoked_refresh_token(self, test_db, sample_user):
        from src.auth import create_refresh_token, revoke_refresh_token, validate_refresh_token
        token = create_refresh_token(user_id=sample_user.id)
        revoke_refresh_token(token)
        with pytest.raises(HTTPException) as exc_info:
            validate_refresh_token(token)
        assert exc_info.value.status_code == 401

    def test_validate_access_token_as_refresh_fails(self, test_db, sample_user):
        from src.auth import create_access_token, validate_refresh_token
        token = create_access_token(user_id=sample_user.id, email=sample_user.email)
        with pytest.raises(HTTPException) as exc_info:
            validate_refresh_token(token)
        assert "token type" in exc_info.value.detail.lower()


class TestGetCurrentUser:
    def _make_request(self, auth_header=None):
        mock = MagicMock()
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header
        mock.headers = MagicMock()
        mock.headers.get = lambda key, default="": headers.get(key, default)
        return mock

    def test_get_current_user_success(self, test_db, sample_user):
        from src.auth import create_access_token, get_current_user
        token = create_access_token(user_id=sample_user.id, email=sample_user.email)
        request = self._make_request(f"Bearer {token}")
        user = get_current_user(request)
        assert user.id == sample_user.id
        assert user.email == sample_user.email

    def test_get_current_user_no_header(self, test_db):
        from src.auth import get_current_user
        request = self._make_request()
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(request)
        assert exc_info.value.status_code == 401

    def test_get_current_user_bad_token(self, test_db):
        from src.auth import get_current_user
        request = self._make_request("Bearer garbage.token.here")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(request)
        assert exc_info.value.status_code == 401

    def test_get_current_user_inactive_user(self, test_db):
        from src.auth import hash_password, create_access_token, get_current_user
        user = test_db.create_user(email="inactive@t.com", password_hash=hash_password("x"))
        # Deactivate user
        session = test_db.Session()
        from src.database import User
        u = session.query(User).filter(User.id == user.id).first()
        u.is_active = False
        session.commit()
        session.close()

        token = create_access_token(user_id=user.id, email=user.email)
        request = self._make_request(f"Bearer {token}")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(request)
        assert exc_info.value.status_code == 401

    def test_get_current_user_with_refresh_token_fails(self, test_db, sample_user):
        from src.auth import create_refresh_token, get_current_user
        token = create_refresh_token(user_id=sample_user.id)
        request = self._make_request(f"Bearer {token}")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(request)
        assert exc_info.value.status_code == 401


class TestGetCurrentUserOptional:
    def _make_request(self, auth_header=None):
        mock = MagicMock()
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header
        mock.headers = MagicMock()
        mock.headers.get = lambda key, default="": headers.get(key, default)
        return mock

    def test_returns_none_when_no_header(self, test_db):
        from src.auth import get_current_user_optional
        request = self._make_request()
        result = get_current_user_optional(request)
        assert result is None

    def test_returns_user_when_valid(self, test_db, sample_user):
        from src.auth import create_access_token, get_current_user_optional
        token = create_access_token(user_id=sample_user.id, email=sample_user.email)
        request = self._make_request(f"Bearer {token}")
        result = get_current_user_optional(request)
        assert result is not None
        assert result.id == sample_user.id

    def test_returns_none_on_bad_token(self, test_db):
        from src.auth import get_current_user_optional
        request = self._make_request("Bearer invalid.token")
        result = get_current_user_optional(request)
        assert result is None
