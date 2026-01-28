"""Tests for OAuth service."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.oauth import StateManager, get_google_oauth_url
from app.models import User
from app.auth import hash_password


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


@patch('app.services.oauth.id_token.verify_oauth2_token')
def test_verify_google_token_success(mock_verify):
    """測試：成功驗證 Google ID token"""
    from app.services.oauth import verify_google_token

    mock_verify.return_value = {
        "sub": "google_12345",
        "email": "test@gmail.com",
        "email_verified": True,
        "name": "Test User",
        "picture": "https://example.com/photo.jpg"
    }

    result = verify_google_token("mock_id_token")

    assert result["google_id"] == "google_12345"
    assert result["email"] == "test@gmail.com"
    assert result["name"] == "Test User"


@patch('app.services.oauth.id_token.verify_oauth2_token')
def test_verify_google_token_email_not_verified(mock_verify):
    """測試：Email 未驗證"""
    from app.services.oauth import verify_google_token

    mock_verify.return_value = {
        "sub": "google_12345",
        "email": "test@gmail.com",
        "email_verified": False
    }

    with pytest.raises(ValueError, match="Email not verified"):
        verify_google_token("mock_id_token")


@patch('app.services.oauth.id_token.verify_oauth2_token')
def test_verify_google_token_invalid_token(mock_verify):
    """測試：無效的 token"""
    from app.services.oauth import verify_google_token
    from google.auth.exceptions import GoogleAuthError

    mock_verify.side_effect = GoogleAuthError("Invalid token")

    with pytest.raises(GoogleAuthError):
        verify_google_token("invalid_token")


def test_find_or_create_user_new_google_user(db):
    """測試：首次 Google 登入，建立新使用者"""
    from app.services.oauth import find_or_create_user

    user = find_or_create_user(
        google_id="google_123456789",
        email="newuser@gmail.com",
        db=db
    )

    assert user.google_id == "google_123456789"
    assert user.email == "newuser@gmail.com"
    assert user.auth_provider == "google"
    assert user.hashed_password is None
    assert user.is_active is True


def test_find_or_create_user_merge_existing_password_account(db):
    """測試：已有密碼帳號，Google 登入後合併"""
    from app.services.oauth import find_or_create_user

    # 先建立密碼帳號
    existing = User(
        email="existing@gmail.com",
        hashed_password=hash_password("password123"),
        auth_provider="local"
    )
    db.add(existing)
    db.commit()
    existing_id = existing.id

    # 用相同 email 的 Google 帳號登入
    user = find_or_create_user(
        google_id="google_987654321",
        email="existing@gmail.com",
        db=db
    )

    assert user.id == existing_id  # 同一個使用者
    assert user.google_id == "google_987654321"
    assert user.auth_provider == "both"
    assert user.hashed_password is not None  # 保留原密碼


def test_find_or_create_user_existing_google_user(db):
    """測試：已存在的 Google 使用者再次登入"""
    from app.services.oauth import find_or_create_user

    # 先建立 Google 使用者
    existing = User(
        email="google@gmail.com",
        google_id="google_111",
        auth_provider="google",
        hashed_password=None
    )
    db.add(existing)
    db.commit()
    existing_id = existing.id

    # 再次登入
    user = find_or_create_user(
        google_id="google_111",
        email="google@gmail.com",
        db=db
    )

    assert user.id == existing_id
    assert db.query(User).count() == 1  # 沒有建立新使用者
