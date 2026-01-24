"""Tests for app.auth module."""
import pytest
from datetime import datetime, timedelta, timezone

from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    create_refresh_token,
    verify_refresh_token,
    revoke_refresh_token,
    verify_and_revoke_refresh_token,
)
from app.models import User, RefreshToken
from fastapi import HTTPException


def test_hash_password():
    """Test password hashing produces different hashes for same password."""
    password = "testpassword123"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    # Same password should produce different hashes (bcrypt auto-salts)
    assert hash1 != hash2
    assert len(hash1) == 60  # bcrypt hash length
    assert hash1.startswith("$2b$")  # bcrypt identifier


def test_verify_password_correct():
    """Test password verification succeeds with correct password."""
    password = "testpassword123"
    hashed = hash_password(password)

    assert verify_password(password, hashed) is True


def test_verify_password_incorrect():
    """Test password verification fails with incorrect password."""
    password = "testpassword123"
    wrong_password = "wrongpassword"
    hashed = hash_password(password)

    assert verify_password(wrong_password, hashed) is False


def test_create_access_token():
    """Test JWT access token creation."""
    data = {"sub": "test@example.com"}
    token = create_access_token(data)

    assert isinstance(token, str)
    assert len(token) > 0


def test_decode_access_token():
    """Test JWT access token decoding."""
    email = "test@example.com"
    token = create_access_token({"sub": email})

    payload = decode_access_token(token)

    assert payload["sub"] == email
    assert payload["type"] == "access"
    assert "exp" in payload


def test_create_refresh_token(db):
    """Test refresh token creation and database storage."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create refresh token
    token = create_refresh_token(user.id, db)

    assert isinstance(token, str)
    assert len(token) > 0

    # Verify token stored in database
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    assert db_token is not None
    assert db_token.user_id == user.id
    assert db_token.is_revoked is False
    # SQLite stores datetime without timezone, so we compare naive datetimes
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    assert db_token.expires_at > now_naive


def test_create_refresh_token_lazy_delete(db):
    """Test that creating refresh token deletes expired/revoked tokens."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create expired token
    expired_token = RefreshToken(
        token="expired_token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        is_revoked=False
    )
    db.add(expired_token)

    # Create revoked token
    revoked_token = RefreshToken(
        token="revoked_token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        is_revoked=True
    )
    db.add(revoked_token)
    db.commit()

    # Create new token (should trigger lazy delete)
    new_token = create_refresh_token(user.id, db)

    # Verify only new token exists
    tokens = db.query(RefreshToken).filter(RefreshToken.user_id == user.id).all()
    assert len(tokens) == 1
    assert tokens[0].token == new_token


def test_verify_refresh_token_valid(db):
    """Test refresh token verification with valid token."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create refresh token
    token = create_refresh_token(user.id, db)

    # Verify token
    verified_user = verify_refresh_token(token, db)
    assert verified_user.id == user.id
    assert verified_user.email == user.email


def test_verify_refresh_token_invalid(db):
    """Test refresh token verification with invalid token."""
    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token("invalid_token", db)

    assert exc_info.value.status_code == 401
    assert "Invalid refresh token" in exc_info.value.detail


def test_verify_refresh_token_expired(db):
    """Test refresh token verification with expired token."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create expired token
    expired_token = RefreshToken(
        token="expired_token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        is_revoked=False
    )
    db.add(expired_token)
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token("expired_token", db)

    assert exc_info.value.status_code == 401


def test_verify_refresh_token_revoked(db):
    """Test refresh token verification with revoked token."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create revoked token
    revoked_token = RefreshToken(
        token="revoked_token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        is_revoked=True
    )
    db.add(revoked_token)
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token("revoked_token", db)

    assert exc_info.value.status_code == 401


def test_revoke_refresh_token(db):
    """Test refresh token revocation."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create refresh token
    token = create_refresh_token(user.id, db)

    # Revoke token
    revoke_refresh_token(token, db)

    # Verify token is revoked
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    assert db_token.is_revoked is True


def test_verify_and_revoke_refresh_token(db):
    """Test atomic verify and revoke operation."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create refresh token
    token = create_refresh_token(user.id, db)

    # Verify and revoke
    verified_user = verify_and_revoke_refresh_token(token, db)
    assert verified_user.id == user.id

    # Verify token is now revoked
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    assert db_token.is_revoked is True

    # Trying to use same token again should fail
    with pytest.raises(HTTPException):
        verify_and_revoke_refresh_token(token, db)
