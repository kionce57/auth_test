"""Integration tests for authentication API endpoints."""
import time

import pytest
from fastapi import status
from sqlalchemy.orm import Session

from app.models import RefreshToken, User


# ============================================================================
# Register Endpoint Tests
# ============================================================================


def test_register_success(client, db: Session):
    """Test successful user registration."""
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "newuser@example.com", "password": "securepass123"}
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert "id" in data
    assert "hashed_password" not in data  # Ensure password is not leaked

    # Verify user is actually in database
    user = db.query(User).filter(User.email == "newuser@example.com").first()
    assert user is not None
    assert user.email == "newuser@example.com"


def test_register_duplicate_email(client, db: Session):
    """Test registration fails with duplicate email."""
    # Create first user
    response1 = client.post(
        "/api/v1/auth/register",
        json={"email": "duplicate@example.com", "password": "password123"}
    )
    assert response1.status_code == status.HTTP_201_CREATED

    # Attempt to create second user with same email
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "duplicate@example.com", "password": "different456"}
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "already registered" in response.json()["detail"].lower()


def test_register_invalid_email(client):
    """Test registration fails with invalid email format."""
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": "pass123"}
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_register_rate_limiting(client):
    """Test registration endpoint has rate limiting (3/minute)."""
    # Make 3 successful requests (should all succeed)
    for i in range(3):
        response = client.post(
            "/api/v1/auth/register",
            json={"email": f"user{i}@example.com", "password": "password123"}
        )
        assert response.status_code == status.HTTP_201_CREATED

    # 4th request should be rate limited
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "user4@example.com", "password": "password123"}
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS


# ============================================================================
# Login Endpoint Tests
# ============================================================================


def test_login_success(client, db: Session):
    """Test successful login returns cookies."""
    # Register user first
    client.post(
        "/api/v1/auth/register",
        json={"email": "loginuser@example.com", "password": "mypassword"}
    )

    # Login
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "loginuser@example.com", "password": "mypassword"}
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Login successful"

    # Verify cookies are set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    # Verify refresh token is in database
    refresh_token_value = response.cookies["refresh_token"]
    token_record = db.query(RefreshToken).filter(
        RefreshToken.token == refresh_token_value
    ).first()
    assert token_record is not None
    assert token_record.is_revoked is False


def test_login_invalid_credentials(client, db: Session):
    """Test login fails with wrong password."""
    # Register user
    client.post(
        "/api/v1/auth/register",
        json={"email": "testuser@example.com", "password": "correctpass"}
    )

    # Login with wrong password
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "testuser@example.com", "password": "wrongpass"}
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect" in response.json()["detail"].lower()


def test_login_nonexistent_user(client):
    """Test login fails with non-existent user."""
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "nobody@example.com", "password": "anypass"}
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect" in response.json()["detail"].lower()


def test_login_rate_limiting(client, db: Session):
    """Test login endpoint has rate limiting (5/minute)."""
    # Register a user
    client.post(
        "/api/v1/auth/register",
        json={"email": "ratelimit@example.com", "password": "password123"}
    )

    # Make 5 login attempts (should all succeed)
    for _ in range(5):
        response = client.post(
            "/api/v1/auth/login",
            data={"username": "ratelimit@example.com", "password": "password123"}
        )
        assert response.status_code == status.HTTP_200_OK

    # 6th request should be rate limited
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "ratelimit@example.com", "password": "password123"}
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS


# ============================================================================
# Logout Endpoint Tests
# ============================================================================


def test_logout_success(client, db: Session):
    """Test logout revokes refresh token and clears cookies."""
    # Register and login
    client.post(
        "/api/v1/auth/register",
        json={"email": "logoutuser@example.com", "password": "password123"}
    )
    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": "logoutuser@example.com", "password": "password123"}
    )
    refresh_token = login_response.cookies.get("refresh_token")
    assert refresh_token is not None, "Login should set refresh_token cookie"

    # Logout
    response = client.post("/api/v1/auth/logout")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Logout successful"

    # Verify cookies are cleared (check Set-Cookie headers for deletion)
    set_cookie_headers = response.headers.get("set-cookie", "")
    assert "access_token" in set_cookie_headers
    assert "refresh_token" in set_cookie_headers
    assert "Max-Age=0" in set_cookie_headers  # Cookie deletion marker

    # Verify refresh token is revoked in database
    db.expire_all()  # Refresh session to see committed changes
    token_record = db.query(RefreshToken).filter(
        RefreshToken.token == refresh_token
    ).first()
    assert token_record is not None, "Refresh token should still exist in DB"
    assert token_record.is_revoked is True


# ============================================================================
# Refresh Token Endpoint Tests
# ============================================================================


def test_refresh_token_success(client, db: Session):
    """Test successful token refresh returns new tokens."""
    # Register and login
    client.post(
        "/api/v1/auth/register",
        json={"email": "refreshuser@example.com", "password": "password123"}
    )
    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": "refreshuser@example.com", "password": "password123"}
    )

    old_access_token = login_response.cookies.get("access_token")
    old_refresh_token = login_response.cookies.get("refresh_token")
    assert old_access_token is not None, "Login should set access_token cookie"
    assert old_refresh_token is not None, "Login should set refresh_token cookie"

    # Wait to ensure different timestamp in JWT
    time.sleep(1)

    # Refresh tokens
    refresh_response = client.post("/api/v1/auth/refresh")

    assert refresh_response.status_code == status.HTTP_200_OK
    assert refresh_response.json()["message"] == "Token refreshed"

    # Verify new cookies are set
    assert "access_token" in refresh_response.cookies
    assert "refresh_token" in refresh_response.cookies

    new_access_token = refresh_response.cookies["access_token"]
    new_refresh_token = refresh_response.cookies["refresh_token"]

    # Verify refresh token is rotated (most critical for security)
    assert new_refresh_token != old_refresh_token
    # Access token should also be new (might have same exp if generated in same second)
    assert new_access_token != old_access_token

    # Verify old refresh token is removed from database (lazy deletion)
    db.expire_all()  # Refresh session to see committed changes
    old_token_record = db.query(RefreshToken).filter(
        RefreshToken.token == old_refresh_token
    ).first()
    # Old token should be deleted by lazy deletion mechanism
    assert old_token_record is None, "Old refresh token should be deleted (lazy deletion)"


def test_refresh_token_missing(client):
    """Test refresh fails without refresh token."""
    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "missing" in response.json()["detail"].lower()


def test_refresh_token_invalid(client, db: Session):
    """Test refresh fails with invalid refresh token."""
    # Set invalid refresh token in cookie
    client.cookies.set("refresh_token", "invalid_token_string")

    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_refresh_token_rotation_prevents_reuse(client, db: Session):
    """Test refresh token rotation - old token cannot be reused."""
    # Register and login
    client.post(
        "/api/v1/auth/register",
        json={"email": "rotation@example.com", "password": "password123"}
    )
    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": "rotation@example.com", "password": "password123"}
    )

    old_refresh_token = login_response.cookies.get("refresh_token")
    assert old_refresh_token is not None, "Login should set refresh_token cookie"

    # First refresh (should succeed)
    refresh_response = client.post("/api/v1/auth/refresh")
    assert refresh_response.status_code == status.HTTP_200_OK

    # Try to reuse old refresh token (should fail)
    client.cookies.set("refresh_token", old_refresh_token)
    reuse_response = client.post("/api/v1/auth/refresh")

    assert reuse_response.status_code == status.HTTP_401_UNAUTHORIZED

    # Verify old token was removed from database (lazy deletion)
    db.expire_all()  # Refresh session to see committed changes
    old_token_record = db.query(RefreshToken).filter(
        RefreshToken.token == old_refresh_token
    ).first()
    # Old token should be deleted by lazy deletion after first refresh
    assert old_token_record is None, "Old refresh token should be deleted (lazy deletion)"


def test_refresh_rate_limiting(client, db: Session):
    """Test refresh endpoint has rate limiting (20/minute)."""
    # Register and login
    client.post(
        "/api/v1/auth/register",
        json={"email": "refreshlimit@example.com", "password": "password123"}
    )
    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": "refreshlimit@example.com", "password": "password123"}
    )
    assert login_response.cookies.get("refresh_token") is not None

    # Make 20 refresh requests (should all succeed)
    for _ in range(20):
        response = client.post("/api/v1/auth/refresh")
        assert response.status_code == status.HTTP_200_OK

    # 21st request should be rate limited
    response = client.post("/api/v1/auth/refresh")
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
