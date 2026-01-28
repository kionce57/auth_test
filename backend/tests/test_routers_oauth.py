"""Tests for OAuth API endpoints."""
import pytest
from unittest.mock import patch, AsyncMock
from app.models import User


def test_google_login_redirects_to_google(client):
    """測試：/google/login 重導向到 Google 授權頁面"""
    response = client.get("/api/v2/sessions/google/login", follow_redirects=False)

    assert response.status_code == 302
    location = response.headers["location"]
    assert "https://accounts.google.com/o/oauth2/v2/auth" in location
    assert "state=" in location
    assert "client_id=" in location


def test_google_login_rate_limit(client):
    """測試：Rate limiting (10/minute)"""
    # 連續呼叫 11 次
    for i in range(11):
        response = client.get("/api/v2/sessions/google/login", follow_redirects=False)
        if i < 10:
            assert response.status_code == 302
        else:
            assert response.status_code == 429  # Too Many Requests


def test_google_callback_invalid_state(client):
    """測試：State 驗證失敗"""
    response = client.get(
        "/api/v2/sessions/google/callback",
        params={"code": "mock_code", "state": "invalid_state"},
        follow_redirects=False
    )

    assert response.status_code == 302
    location = response.headers["location"]
    assert "error=invalid_state" in location


@patch('app.routers.auth.exchange_code_for_token')
@patch('app.routers.auth.verify_google_token')
def test_google_callback_success_new_user(mock_verify, mock_exchange, client, db):
    """測試：Google 登入成功，建立新使用者"""
    # Mock Google API 回應
    async def mock_exchange_async(code):
        return {"id_token": "mock_id_token"}

    mock_exchange.side_effect = mock_exchange_async
    mock_verify.return_value = {
        "google_id": "google_new_123",
        "email": "newuser@gmail.com",
        "name": "New User"
    }

    # 先建立有效的 state
    from app.services.oauth import state_manager
    valid_state = state_manager.create()

    # 模擬 callback
    response = client.get(
        "/api/v2/sessions/google/callback",
        params={"code": "mock_code", "state": valid_state},
        follow_redirects=False
    )

    # 驗證：重導向到前端
    assert response.status_code == 302
    location = response.headers["location"]
    assert "http://localhost:5173" in location

    # 驗證：cookies 已設定
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    # 驗證：使用者已建立
    user = db.query(User).filter(User.email == "newuser@gmail.com").first()
    assert user is not None
    assert user.google_id == "google_new_123"


@patch('app.routers.auth.exchange_code_for_token')
def test_google_callback_google_api_error(mock_exchange, client):
    """測試：Google API 錯誤"""
    import httpx

    async def mock_exchange_error(code):
        raise httpx.HTTPError("API Error")

    mock_exchange.side_effect = mock_exchange_error

    from app.services.oauth import state_manager
    valid_state = state_manager.create()

    response = client.get(
        "/api/v2/sessions/google/callback",
        params={"code": "mock_code", "state": valid_state},
        follow_redirects=False
    )

    assert response.status_code == 302
    assert "error=oauth_failed" in response.headers["location"]
