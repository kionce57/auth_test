"""Tests for OAuth service."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.oauth import StateManager, get_google_oauth_url


def test_state_manager_create_and_verify():
    """測試：建立和驗證 state token"""
    manager = StateManager()
    state = manager.create()

    assert len(state) > 20  # state 應該夠長
    assert manager.verify(state) is True
    assert manager.verify(state) is False  # 單次使用


def test_state_manager_invalid_state():
    """測試：無效的 state"""
    manager = StateManager()
    assert manager.verify("invalid_state_token") is False


def test_state_manager_expired_state():
    """測試：過期的 state"""
    import time
    manager = StateManager(ttl=1)  # 1 秒過期
    state = manager.create()
    time.sleep(2)
    assert manager.verify(state) is False


def test_get_google_oauth_url():
    """測試：產生 Google OAuth URL"""
    state = "test_state_token"
    url = get_google_oauth_url(state)

    assert "https://accounts.google.com/o/oauth2/v2/auth" in url
    assert f"state={state}" in url
    assert "scope=openid+email+profile" in url or "scope=openid%20email%20profile" in url
    assert "response_type=code" in url


@pytest.mark.asyncio
@patch('app.services.oauth.httpx.AsyncClient')
async def test_exchange_code_for_token_success(mock_client_class):
    """測試：成功交換授權碼為 token"""
    from app.services.oauth import exchange_code_for_token
    from unittest.mock import MagicMock

    # Mock HTTP response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "access_token": "mock_access_token",
        "id_token": "mock_id_token",
        "refresh_token": "mock_refresh_token"
    }
    mock_response.raise_for_status = MagicMock()

    # Mock async context manager
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client_class.return_value = mock_client

    result = await exchange_code_for_token("mock_code")

    assert result["access_token"] == "mock_access_token"
    assert result["id_token"] == "mock_id_token"


@pytest.mark.asyncio
@patch('app.services.oauth.httpx.AsyncClient')
async def test_exchange_code_for_token_failure(mock_client_class):
    """測試：交換 token 失敗"""
    from app.services.oauth import exchange_code_for_token
    import httpx

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.post.side_effect = httpx.HTTPError("API Error")
    mock_client_class.return_value = mock_client

    with pytest.raises(httpx.HTTPError):
        await exchange_code_for_token("invalid_code")
