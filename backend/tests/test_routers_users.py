"""Tests for user endpoints."""
import pytest
from app.models import User
from app.auth import hash_password, create_access_token


def test_get_current_user_success(client, db):
    """Test getting current user with valid access token."""
    # Create user
    user = User(email="test@example.com", hashed_password=hash_password("password123"))
    db.add(user)
    db.commit()

    # Login to get cookies
    client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "password123"}
    )

    # Get current user
    response = client.get("/api/v1/users/me")

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "id" in data
    assert "hashed_password" not in data


def test_get_current_user_no_token(client):
    """Test accessing protected endpoint without token fails."""
    response = client.get("/api/v1/users/me")

    assert response.status_code == 401


def test_get_current_user_invalid_token(client):
    """Test accessing protected endpoint with invalid token fails."""
    # Set invalid access token cookie
    client.cookies.set("access_token", "invalid_token_123")

    response = client.get("/api/v1/users/me")

    assert response.status_code == 401
