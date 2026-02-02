"""Google OAuth 服務模組。"""
import secrets
import time
from typing import Dict
from urllib.parse import urlencode
import httpx
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from sqlalchemy.orm import Session
from app.config import settings
from app.models import User


class StateManager:
    """管理 OAuth state tokens (CSRF 防護)。

    簡單的 in-memory 實作，適合開發環境。
    生產環境建議使用 Redis。
    """

    def __init__(self, ttl: int = 300):
        """初始化 state manager。

        Args:
            ttl: State token 存活時間（秒），預設 5 分鐘
        """
        self._states: Dict[str, float] = {}
        self._ttl = ttl

    def create(self) -> str:
        """建立新的 state token。

        Returns:
            隨機產生的 state token
        """
        state = secrets.token_urlsafe(32)
        self._states[state] = time.time()
        return state

    def verify(self, state: str) -> bool:
        """驗證並消費 state token。

        Args:
            state: 要驗證的 state token

        Returns:
            True 如果 state 有效且未過期，否則 False
        """
        if state not in self._states:
            return False

        created_at = self._states.pop(state)

        # 檢查是否過期
        if time.time() - created_at > self._ttl:
            return False

        return True

    def cleanup(self):
        """清理過期的 state tokens。"""
        now = time.time()
        expired_keys = [
            key for key, created_at in self._states.items()
            if now - created_at > self._ttl
        ]
        for key in expired_keys:
            del self._states[key]


def get_google_oauth_url(state: str) -> str:
    """產生 Google OAuth 授權 URL。

    Args:
        state: CSRF 防護 token

    Returns:
        完整的 Google OAuth 授權 URL
    """
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "consent"
    }

    base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    return f"{base_url}?{urlencode(params)}"


async def exchange_code_for_token(code: str) -> dict:
    """用授權碼交換 Google access token。

    Args:
        code: Google OAuth 授權碼

    Returns:
        包含 access_token, id_token, refresh_token 的 dict

    Raises:
        httpx.HTTPError: Google API 請求失敗
    """
    token_url = "https://oauth2.googleapis.com/token"

    data = {
        "code": code,
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        "redirect_uri": settings.google_redirect_uri,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
        response.raise_for_status()
        return response.json()


def verify_google_token(id_token_str: str) -> dict:
    """驗證 Google ID Token 並提取使用者資訊。

    Args:
        id_token_str: Google ID Token (JWT)

    Returns:
        包含 google_id, email, name, picture 的 dict

    Raises:
        ValueError: Email 未驗證
        google.auth.exceptions.GoogleAuthError: Token 無效
    """
    # 驗證 token 簽章與有效期限
    # clock_skew_in_seconds: 容許時鐘誤差（WSL2/Docker 常見問題）
    idinfo = id_token.verify_oauth2_token(
        id_token_str,
        google_requests.Request(),
        settings.google_client_id,
        clock_skew_in_seconds=10
    )

    # 確認 email 已驗證
    if not idinfo.get("email_verified"):
        raise ValueError("Email not verified")

    return {
        "google_id": idinfo["sub"],
        "email": idinfo["email"],
        "name": idinfo.get("name"),
        "picture": idinfo.get("picture")
    }


def find_or_create_user(google_id: str, email: str, db: Session) -> User:
    """查找或建立 Google 使用者，處理帳號合併。

    Args:
        google_id: Google 使用者 ID (sub claim)
        email: Google 帳號 email
        db: Database session

    Returns:
        User 物件（新建或已存在）
    """
    # 1. 用 google_id 查詢（已存在的 Google 使用者）
    user = db.query(User).filter(User.google_id == google_id).first()
    if user:
        return user

    # 2. 用 email 查詢（可能需要合併帳號）
    user = db.query(User).filter(User.email == email).first()
    if user:
        # 合併帳號：連結 Google ID
        user.google_id = google_id
        # 如果有密碼則為 "both"，否則為 "google"
        user.auth_provider = "both" if user.hashed_password else "google"
        db.commit()
        db.refresh(user)
        return user

    # 3. 建立新使用者
    user = User(
        email=email,
        hashed_password=None,
        google_id=google_id,
        auth_provider="google"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# Global state manager instance
state_manager = StateManager()
