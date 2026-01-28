"""Tests for OAuth API endpoints."""
import pytest


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
