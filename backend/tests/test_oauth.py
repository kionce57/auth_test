"""Tests for OAuth service."""
import pytest
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
