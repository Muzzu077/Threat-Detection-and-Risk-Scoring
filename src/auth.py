"""
ThreatPulse Authentication Module
JWT + bcrypt authentication for multi-tenant SaaS.
"""
import os
import hashlib
from datetime import datetime, timedelta

import bcrypt
import jwt
from fastapi import Request, HTTPException, Depends

from src.database import db, User, RefreshToken

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "threatpulse-jwt-secret-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(user_id: int, email: str) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "type": "access",
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: int) -> str:
    import uuid
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "exp": datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    # Store hash in DB
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session = db.Session()
    try:
        rt = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        )
        session.add(rt)
        session.commit()
    finally:
        session.close()
    return token


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(request: Request) -> User:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header[7:]
    # Check if token was revoked via logout
    try:
        from api.main import _revoked_access_tokens
        if token in _revoked_access_tokens:
            raise HTTPException(status_code=401, detail="Token has been revoked")
    except ImportError:
        pass
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    user_id = int(payload["sub"])
    session = db.Session()
    try:
        user = session.query(User).filter(User.id == user_id, User.is_active == True).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        # Detach from session so it can be used outside
        session.expunge(user)
        return user
    finally:
        session.close()


def get_current_user_optional(request: Request):
    """Returns User or None — for backward-compatible endpoints."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    try:
        return get_current_user(request)
    except HTTPException:
        return None


def revoke_refresh_token(token: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session = db.Session()
    try:
        rt = session.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        if rt:
            rt.revoked = True
            session.commit()
    finally:
        session.close()


def validate_refresh_token(token: str) -> int:
    """Validate refresh token and return user_id."""
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session = db.Session()
    try:
        rt = session.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
        ).first()
        if not rt:
            raise HTTPException(status_code=401, detail="Refresh token revoked or not found")
        if rt.expires_at < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Refresh token expired")
        return int(payload["sub"])
    finally:
        session.close()
