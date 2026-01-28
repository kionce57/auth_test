# Google OAuth 登入功能實作計畫

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 為認證系統新增 Google OAuth 登入功能，允許使用者透過 Google 帳號一鍵登入

**Architecture:** 後端主導 OAuth flow，使用 google-auth library 驗證 ID token，自動建立/合併使用者帳號，複用現有 JWT + Refresh Token 機制

**Tech Stack:** FastAPI, SQLAlchemy, Alembic, google-auth, google-auth-oauthlib, httpx, pytest

---

## Task 1: 安裝依賴套件

**Files:**
- Modify: `backend/pyproject.toml`

**Step 1: 新增 Google OAuth 依賴**

在 `backend/pyproject.toml` 的 `dependencies` 陣列中新增：

```toml
dependencies = [
    "fastapi>=0.115.6",
    "sqlalchemy>=2.0.36",
    # ... 現有套件 ...
    "google-auth>=2.27.0",
    "google-auth-oauthlib>=1.2.0",
    "httpx>=0.26.0",
]
```

**Step 2: 同步依賴**

```bash
cd backend
uv sync
```

Expected: 成功安裝 google-auth, google-auth-oauthlib, httpx

**Step 3: 驗證套件安裝**

```bash
uv run python -c "import google.auth; import google_auth_oauthlib; import httpx; print('OK')"
```

Expected: 輸出 "OK"

**Step 4: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "build: add google oauth dependencies

新增 Google OAuth 登入所需依賴：
- google-auth: 驗證 Google ID Token
- google-auth-oauthlib: OAuth 2.0 flow
- httpx: 非同步 HTTP client

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 2: 更新環境變數設定

**Files:**
- Modify: `backend/app/config.py`
- Modify: `backend/.env.example`

**Step 1: 更新 Settings class**

在 `backend/app/config.py` 中的 `Settings` class 新增欄位：

```python
class Settings(BaseSettings):
    database_url: str = "postgresql://postgres:postgres@localhost:5432/auth_test"
    secret_key: str = "dev-secret-key-change-in-production"
    cors_origins: str = "http://localhost:5173"
    environment: str = "development"
    trust_proxy: bool = False

    # 🆕 Google OAuth 設定
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/api/v2/sessions/google/callback"

    model_config = SettingsConfigDict(case_sensitive=False, env_file=".env")
```

**Step 2: 更新 .env.example**

在 `backend/.env.example` 新增（如果檔案不存在則建立）：

```bash
# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/auth_test

# Security
SECRET_KEY=your-secret-key-min-32-chars
ENVIRONMENT=development
TRUST_PROXY=false

# CORS
CORS_ORIGINS=http://localhost:5173

# Google OAuth (可選)
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v2/sessions/google/callback
```

**Step 3: 驗證設定載入**

```bash
cd backend
uv run python -c "from app.config import settings; print(f'Google Client ID: {settings.google_client_id or \"(empty)\"}')"
```

Expected: 輸出 "Google Client ID: (empty)" 或實際設定值

**Step 4: Commit**

```bash
git add app/config.py .env.example
git commit -m "feat(config): add google oauth environment variables

新增 Google OAuth 所需環境變數：
- GOOGLE_CLIENT_ID: Google OAuth client ID
- GOOGLE_CLIENT_SECRET: Google OAuth client secret
- GOOGLE_REDIRECT_URI: OAuth callback URL

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 3: 修改 User Model Schema

**Files:**
- Modify: `backend/app/models.py:9-20`

**Step 1: 修改 User model**

在 `backend/app/models.py` 中修改 `User` class：

```python
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # ⚠️ 修改：改為 nullable（Google 使用者沒有密碼）
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # 🆕 新增：Google OAuth 欄位
    google_id: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True, index=True
    )
    auth_provider: Mapped[str] = mapped_column(
        String(20), server_default="local", nullable=False
    )
    # auth_provider 可能值: "local", "google", "both"

    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationship
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )
```

**Step 2: 驗證 model 定義**

```bash
cd backend
uv run python -c "from app.models import User; print('User model columns:', [c.name for c in User.__table__.columns])"
```

Expected: 輸出包含 'google_id' 和 'auth_provider'

**Step 3: Commit**

```bash
git add app/models.py
git commit -m "feat(models): add google oauth fields to user model

User model 新增欄位：
- google_id: 儲存 Google 使用者 ID (unique, nullable, indexed)
- auth_provider: 認證方式 (local/google/both)
- hashed_password: 改為 nullable (Google 使用者無密碼)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 4: 建立資料庫 Migration

**Files:**
- Create: `backend/alembic/versions/xxxx_add_google_oauth_support.py` (自動生成)

**Step 1: 產生 migration**

```bash
cd backend
uv run alembic revision --autogenerate -m "add google oauth support"
```

Expected: 建立新的 migration 檔案

**Step 2: 檢查 migration 內容**

```bash
# 找到最新的 migration 檔案
ls -t alembic/versions/*.py | head -1 | xargs cat
```

Expected output 應包含：
- `alter_column('users', 'hashed_password', nullable=True)`
- `add_column('users', sa.Column('google_id', ...))`
- `add_column('users', sa.Column('auth_provider', ...))`
- `create_index(..., 'google_id', ...)`

**Step 3: 執行 migration**

```bash
uv run alembic upgrade head
```

Expected: Successfully applied migration

**Step 4: 驗證資料庫 schema**

```bash
uv run python -c "
from app.database import engine
from sqlalchemy import inspect
inspector = inspect(engine)
columns = {c['name']: c for c in inspector.get_columns('users')}
print('google_id nullable:', columns['google_id']['nullable'])
print('auth_provider default:', columns['auth_provider'].get('default'))
print('hashed_password nullable:', columns['hashed_password']['nullable'])
"
```

Expected:
- google_id nullable: True
- hashed_password nullable: True
- auth_provider 有 default 值

**Step 5: Commit**

```bash
git add alembic/versions/*.py
git commit -m "db: add google oauth support migration

新增資料庫 migration：
- users.hashed_password 改為 nullable
- users.google_id 欄位 (varchar(255), unique, nullable, indexed)
- users.auth_provider 欄位 (varchar(20), default='local')

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 5: 實作 OAuth Service - State 管理

**Files:**
- Create: `backend/app/services/__init__.py`
- Create: `backend/app/services/oauth.py`

**Step 1: 建立 services 目錄**

```bash
cd backend
mkdir -p app/services
touch app/services/__init__.py
```

**Step 2: 寫入 State 管理測試**

Create `backend/tests/test_oauth.py`:

```python
"""Tests for OAuth service."""
import pytest
from app.services.oauth import StateManager


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
```

**Step 3: 執行測試確認失敗**

```bash
uv run pytest tests/test_oauth.py::test_state_manager_create_and_verify -v
```

Expected: FAIL - "ModuleNotFoundError: No module named 'app.services.oauth'"

**Step 4: 實作 State 管理**

Create `backend/app/services/oauth.py`:

```python
"""Google OAuth 服務模組。"""
import secrets
import time
from typing import Dict


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


# Global state manager instance
state_manager = StateManager()
```

**Step 5: 執行測試確認通過**

```bash
uv run pytest tests/test_oauth.py -v
```

Expected: All tests PASS

**Step 6: Commit**

```bash
git add app/services/ tests/test_oauth.py
git commit -m "feat(oauth): implement state token manager for csrf protection

實作 OAuth state token 管理：
- 建立隨機 state token (32 bytes)
- 驗證並單次消費 token
- 5 分鐘自動過期
- In-memory 儲存（開發環境）

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 6: 實作 OAuth Service - Google URL 產生

**Files:**
- Modify: `backend/app/services/oauth.py`
- Modify: `backend/tests/test_oauth.py`

**Step 1: 寫入測試**

在 `backend/tests/test_oauth.py` 新增：

```python
from app.services.oauth import get_google_oauth_url


def test_get_google_oauth_url():
    """測試：產生 Google OAuth URL"""
    state = "test_state_token"
    url = get_google_oauth_url(state)

    assert "https://accounts.google.com/o/oauth2/v2/auth" in url
    assert f"state={state}" in url
    assert "scope=openid+email+profile" in url or "scope=openid%20email%20profile" in url
    assert "response_type=code" in url
```

**Step 2: 執行測試確認失敗**

```bash
uv run pytest tests/test_oauth.py::test_get_google_oauth_url -v
```

Expected: FAIL - "ImportError: cannot import name 'get_google_oauth_url'"

**Step 3: 實作函式**

在 `backend/app/services/oauth.py` 新增：

```python
from urllib.parse import urlencode
from app.config import settings


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
```

**Step 4: 執行測試確認通過**

```bash
uv run pytest tests/test_oauth.py::test_get_google_oauth_url -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add app/services/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add google oauth url generator

實作 Google OAuth 授權 URL 產生：
- 包含 client_id, redirect_uri, scope
- 加入 state token 防 CSRF
- 請求 offline access 取得 refresh token

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 7: 實作 OAuth Service - Token 交換

**Files:**
- Modify: `backend/app/services/oauth.py`
- Modify: `backend/tests/test_oauth.py`

**Step 1: 寫入測試**

在 `backend/tests/test_oauth.py` 新增：

```python
from unittest.mock import AsyncMock, patch
import pytest


@pytest.mark.asyncio
@patch('app.services.oauth.httpx.AsyncClient')
async def test_exchange_code_for_token_success(mock_client_class):
    """測試：成功交換授權碼為 token"""
    from app.services.oauth import exchange_code_for_token

    # Mock HTTP response
    mock_response = AsyncMock()
    mock_response.json.return_value = {
        "access_token": "mock_access_token",
        "id_token": "mock_id_token",
        "refresh_token": "mock_refresh_token"
    }
    mock_response.raise_for_status = AsyncMock()

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.post.return_value = mock_response
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
```

**Step 2: 執行測試確認失敗**

```bash
uv run pytest tests/test_oauth.py::test_exchange_code_for_token_success -v
```

Expected: FAIL - "ImportError: cannot import name 'exchange_code_for_token'"

**Step 3: 實作函式**

在 `backend/app/services/oauth.py` 新增：

```python
import httpx


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
```

**Step 4: 執行測試確認通過**

```bash
uv run pytest tests/test_oauth.py::test_exchange_code_for_token_success -v
uv run pytest tests/test_oauth.py::test_exchange_code_for_token_failure -v
```

Expected: All tests PASS

**Step 5: Commit**

```bash
git add app/services/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): implement google token exchange

實作授權碼交換 token：
- 呼叫 Google token endpoint
- 取得 access_token, id_token, refresh_token
- 錯誤處理（HTTPError）

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 8: 實作 OAuth Service - Token 驗證

**Files:**
- Modify: `backend/app/services/oauth.py`
- Modify: `backend/tests/test_oauth.py`

**Step 1: 寫入測試**

在 `backend/tests/test_oauth.py` 新增：

```python
from unittest.mock import patch


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
```

**Step 2: 執行測試確認失敗**

```bash
uv run pytest tests/test_oauth.py::test_verify_google_token_success -v
```

Expected: FAIL - "ImportError: cannot import name 'verify_google_token'"

**Step 3: 實作函式**

在 `backend/app/services/oauth.py` 新增：

```python
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests


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
    idinfo = id_token.verify_oauth2_token(
        id_token_str,
        google_requests.Request(),
        settings.google_client_id
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
```

**Step 4: 執行測試確認通過**

```bash
uv run pytest tests/test_oauth.py -k "verify_google_token" -v
```

Expected: All tests PASS

**Step 5: Commit**

```bash
git add app/services/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): implement google id token verification

實作 Google ID Token 驗證：
- 使用 google-auth library 驗證簽章
- 檢查 email_verified 狀態
- 提取使用者資訊 (google_id, email, name, picture)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 9: 實作 OAuth Service - 使用者查找/建立

**Files:**
- Modify: `backend/app/services/oauth.py`
- Modify: `backend/tests/test_oauth.py`

**Step 1: 寫入測試**

在 `backend/tests/test_oauth.py` 新增：

```python
from app.models import User
from app.auth import hash_password


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
```

**Step 2: 執行測試確認失敗**

```bash
uv run pytest tests/test_oauth.py::test_find_or_create_user_new_google_user -v
```

Expected: FAIL - "ImportError: cannot import name 'find_or_create_user'"

**Step 3: 實作函式**

在 `backend/app/services/oauth.py` 新增：

```python
from sqlalchemy.orm import Session
from app.models import User


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
```

**Step 4: 執行測試確認通過**

```bash
uv run pytest tests/test_oauth.py -k "find_or_create_user" -v
```

Expected: All tests PASS

**Step 5: Commit**

```bash
git add app/services/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): implement user find/create/merge logic

實作使用者查找與帳號合併：
- 用 google_id 查詢已存在使用者
- 用 email 查詢並合併現有密碼帳號
- 建立新 Google 使用者（無密碼）
- 正確設定 auth_provider (local/google/both)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 10: 實作 API 端點 - Google Login

**Files:**
- Modify: `backend/app/routers/auth.py`
- Create: `backend/tests/test_routers_oauth.py`

**Step 1: 寫入測試**

Create `backend/tests/test_routers_oauth.py`:

```python
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
```

**Step 2: 執行測試確認失敗**

```bash
uv run pytest tests/test_routers_oauth.py::test_google_login_redirects_to_google -v
```

Expected: FAIL - 404 Not Found

**Step 3: 實作端點**

在 `backend/app/routers/auth.py` 的 `router_v2` 區塊新增：

```python
from fastapi.responses import RedirectResponse
from app.services.oauth import state_manager, get_google_oauth_url


@router_v2.get("/google/login")
@limiter.limit("10/minute")
def google_login(request: Request):
    """初始化 Google OAuth flow。

    重導向使用者到 Google 授權頁面。
    """
    # 建立 state token (CSRF 防護)
    state = state_manager.create()

    # 產生 Google OAuth URL
    auth_url = get_google_oauth_url(state)

    return RedirectResponse(url=auth_url, status_code=302)
```

**Step 4: 執行測試確認通過**

```bash
uv run pytest tests/test_routers_oauth.py::test_google_login_redirects_to_google -v
uv run pytest tests/test_routers_oauth.py::test_google_login_rate_limit -v
```

Expected: All tests PASS

**Step 5: Commit**

```bash
git add app/routers/auth.py tests/test_routers_oauth.py
git commit -m "feat(api): add google oauth login endpoint

實作 GET /api/v2/sessions/google/login：
- 產生 state token (CSRF 防護)
- 重導向到 Google 授權頁面
- Rate limit: 10/minute

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 11: 實作 API 端點 - Google Callback

**Files:**
- Modify: `backend/app/routers/auth.py`
- Modify: `backend/tests/test_routers_oauth.py`

**Step 1: 寫入測試**

在 `backend/tests/test_routers_oauth.py` 新增：

```python
from unittest.mock import patch, AsyncMock
from app.models import User


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


@patch('app.services.oauth.exchange_code_for_token')
@patch('app.services.oauth.verify_google_token')
async def test_google_callback_success_new_user(mock_verify, mock_exchange, client, db):
    """測試：Google 登入成功，建立新使用者"""
    # Mock Google API 回應
    mock_exchange.return_value = {"id_token": "mock_id_token"}
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

    # 驗證：重導向到 dashboard
    assert response.status_code == 302
    location = response.headers["location"]
    assert "/dashboard" in location or location == "http://localhost:5173/"

    # 驗證：cookies 已設定
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    # 驗證：使用者已建立
    user = db.query(User).filter(User.email == "newuser@gmail.com").first()
    assert user is not None
    assert user.google_id == "google_new_123"


@patch('app.services.oauth.exchange_code_for_token')
async def test_google_callback_google_api_error(mock_exchange, client):
    """測試：Google API 錯誤"""
    import httpx
    mock_exchange.side_effect = httpx.HTTPError("API Error")

    from app.services.oauth import state_manager
    valid_state = state_manager.create()

    response = client.get(
        "/api/v2/sessions/google/callback",
        params={"code": "mock_code", "state": valid_state},
        follow_redirects=False
    )

    assert response.status_code == 302
    assert "error=oauth_failed" in response.headers["location"]
```

**Step 2: 執行測試確認失敗**

```bash
uv run pytest tests/test_routers_oauth.py::test_google_callback_invalid_state -v
```

Expected: FAIL - 404 Not Found

**Step 3: 實作端點**

在 `backend/app/routers/auth.py` 的 `router_v2` 區塊新增：

```python
from app.services.oauth import (
    state_manager,
    exchange_code_for_token,
    verify_google_token,
    find_or_create_user
)
from app.auth import create_access_token, create_refresh_token
from app.config import settings


@router_v2.get("/google/callback")
@limiter.limit("20/minute")
async def google_callback(
    request: Request,
    response: Response,
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db)
):
    """Google OAuth 回調端點。

    處理 Google 授權完成後的回調，建立/合併使用者並設定 session。
    """
    frontend_url = settings.cors_origins.split(',')[0]  # 取第一個 origin

    try:
        # 1. 驗證 state token (CSRF 防護)
        if not state_manager.verify(state):
            return RedirectResponse(
                url=f"{frontend_url}/login?error=invalid_state",
                status_code=302
            )

        # 2. 用 code 交換 access token
        token_data = await exchange_code_for_token(code)

        # 3. 驗證 ID token 並取得使用者資訊
        user_info = verify_google_token(token_data["id_token"])

        # 4. 查找或建立使用者（處理帳號合併）
        user = find_or_create_user(
            google_id=user_info["google_id"],
            email=user_info["email"],
            db=db
        )

        # 5. 檢查帳號是否停用
        if not user.is_active:
            return RedirectResponse(
                url=f"{frontend_url}/login?error=account_disabled",
                status_code=302
            )

        # 6. 建立 JWT tokens（複用現有邏輯）
        access_token = create_access_token(data={"sub": user.email})
        refresh_token_value = create_refresh_token(user.id, db)

        # 7. 設定 HttpOnly cookies
        response = RedirectResponse(url=frontend_url, status_code=302)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
            max_age=900  # 15 分鐘
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token_value,
            httponly=True,
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
            max_age=604800  # 7 天
        )

        return response

    except ValueError as e:
        # Email 未驗證
        if "Email not verified" in str(e):
            return RedirectResponse(
                url=f"{frontend_url}/login?error=email_not_verified",
                status_code=302
            )
        raise

    except Exception as e:
        # Google API 錯誤或其他錯誤
        return RedirectResponse(
            url=f"{frontend_url}/login?error=oauth_failed",
            status_code=302
        )
```

同時需要在檔案頂部新增 import：

```python
from fastapi import Query
```

**Step 4: 執行測試確認通過**

```bash
uv run pytest tests/test_routers_oauth.py -k "callback" -v
```

Expected: All tests PASS

**Step 5: Commit**

```bash
git add app/routers/auth.py tests/test_routers_oauth.py
git commit -m "feat(api): add google oauth callback endpoint

實作 GET /api/v2/sessions/google/callback：
- 驗證 state token (CSRF 防護)
- 交換授權碼為 access token
- 驗證 Google ID token
- 查找/建立/合併使用者
- 設定 JWT cookies
- 錯誤處理與重導向
- Rate limit: 20/minute

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 12: 執行完整後端測試

**Step 1: 執行所有 OAuth 相關測試**

```bash
cd backend
uv run pytest tests/test_oauth.py tests/test_routers_oauth.py -v
```

Expected: All tests PASS

**Step 2: 執行完整測試套件**

```bash
uv run pytest -v
```

Expected: All tests PASS

**Step 3: 檢查測試覆蓋率**

```bash
uv run pytest --cov=app --cov-report=term-missing
```

Expected: Coverage report 顯示，新增的 `app/services/oauth.py` 和 `app/routers/auth.py` (Google 相關部分) 有良好覆蓋率

**Step 4: 如果有測試失敗，修正後重新測試**

---

## Task 13: 前端 - Google 登入按鈕元件

**Files:**
- Create: `frontend/src/components/GoogleLoginButton.tsx`
- Create: `frontend/src/components/GoogleLoginButton.test.tsx`

**Step 1: 寫入測試**

Create `frontend/src/components/GoogleLoginButton.test.tsx`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/react';
import { GoogleLoginButton } from './GoogleLoginButton';

describe('GoogleLoginButton', () => {
  beforeEach(() => {
    // Mock window.location
    delete (window as any).location;
    (window as any).location = { href: '' };

    // Mock sessionStorage
    vi.spyOn(Storage.prototype, 'setItem');
  });

  it('renders google login button', () => {
    const { getByRole } = render(<GoogleLoginButton />);
    const button = getByRole('button');

    expect(button).toBeTruthy();
    expect(button.textContent).toContain('Google');
  });

  it('redirects to oauth endpoint on click', () => {
    const { getByRole } = render(<GoogleLoginButton />);
    const button = getByRole('button');

    fireEvent.click(button);

    expect(window.location.href).toBe('/api/v2/sessions/google/login');
  });

  it('saves current location before redirect', () => {
    const { getByRole } = render(<GoogleLoginButton />);
    const button = getByRole('button');

    fireEvent.click(button);

    expect(sessionStorage.setItem).toHaveBeenCalledWith(
      'redirectAfterLogin',
      expect.any(String)
    );
  });
});
```

**Step 2: 執行測試確認失敗**

```bash
cd frontend
npm run test -- GoogleLoginButton.test.tsx
```

Expected: FAIL - "Cannot find module './GoogleLoginButton'"

**Step 3: 實作元件**

Create `frontend/src/components/GoogleLoginButton.tsx`:

```typescript
import './GoogleLoginButton.css';

export function GoogleLoginButton() {
  const handleGoogleLogin = () => {
    // 儲存當前頁面，登入後返回
    sessionStorage.setItem('redirectAfterLogin', window.location.pathname);

    // 重導向到後端 OAuth 端點
    window.location.href = '/api/v2/sessions/google/login';
  };

  return (
    <button
      onClick={handleGoogleLogin}
      className="google-login-btn"
      type="button"
    >
      <svg
        className="google-icon"
        viewBox="0 0 24 24"
        width="20"
        height="20"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          fill="#4285F4"
          d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
        />
        <path
          fill="#34A853"
          d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
        />
        <path
          fill="#FBBC05"
          d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
        />
        <path
          fill="#EA4335"
          d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
        />
      </svg>
      <span>使用 Google 登入</span>
    </button>
  );
}
```

Create `frontend/src/components/GoogleLoginButton.css`:

```css
.google-login-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  width: 100%;
  padding: 12px 24px;
  background-color: white;
  border: 1px solid #dadce0;
  border-radius: 4px;
  font-size: 14px;
  font-weight: 500;
  color: #3c4043;
  cursor: pointer;
  transition: all 0.2s;
}

.google-login-btn:hover {
  background-color: #f8f9fa;
  border-color: #c6c6c6;
}

.google-login-btn:active {
  background-color: #f1f3f4;
}

.google-icon {
  flex-shrink: 0;
}
```

**Step 4: 執行測試確認通過**

```bash
npm run test -- GoogleLoginButton.test.tsx
```

Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/components/GoogleLoginButton.*
git commit -m "feat(frontend): add google login button component

實作 Google 登入按鈕元件：
- Google 品牌圖示
- 點擊重導向到 OAuth 端點
- 儲存當前位置供登入後返回
- 單元測試涵蓋

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 14: 前端 - 整合到登入頁面

**Files:**
- Modify: `frontend/src/pages/LoginPage.tsx`

**Step 1: 讀取現有登入頁面**

```bash
cd frontend
cat src/pages/LoginPage.tsx
```

**Step 2: 修改登入頁面，新增 Google 按鈕**

在 `frontend/src/pages/LoginPage.tsx` 中，在 `<LoginForm />` 後方新增：

```typescript
import { GoogleLoginButton } from '../components/GoogleLoginButton';

// 在 LoginForm 之後新增：
<div className="divider">
  <span>或</span>
</div>

<GoogleLoginButton />
```

同時新增對應的 CSS 到 `LoginPage.css`（如果有的話）：

```css
.divider {
  display: flex;
  align-items: center;
  margin: 24px 0;
  color: #666;
  font-size: 14px;
}

.divider::before,
.divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background-color: #dadce0;
}

.divider span {
  padding: 0 16px;
}
```

**Step 3: 測試前端編譯**

```bash
npm run build
```

Expected: Build success, no errors

**Step 4: 啟動開發伺服器手動測試**

```bash
npm run dev
```

瀏覽 http://localhost:5173/login，確認：
- Google 登入按鈕顯示正確
- 點擊按鈕會重導向（會失敗因為後端可能沒設定 Google credentials）

**Step 5: Commit**

```bash
git add src/pages/LoginPage.*
git commit -m "feat(frontend): integrate google login button to login page

登入頁面新增 Google 登入選項：
- 在 email/password 表單下方
- 分隔線「或」
- Google 登入按鈕

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 15: 前端 - OAuth 錯誤處理

**Files:**
- Modify: `frontend/src/context/AuthContext.tsx` or `frontend/src/App.tsx`

**Step 1: 決定放置位置**

```bash
cd frontend
# 檢查是否有 AuthContext
test -f src/context/AuthContext.tsx && echo "Use AuthContext" || echo "Use App.tsx"
```

**Step 2: 新增 OAuth 錯誤處理**

在適當的檔案（通常是 `AuthContext.tsx` 或 `App.tsx`）的頂層元件中新增 `useEffect`：

```typescript
import { useEffect } from 'react';

// 在元件內部新增：
useEffect(() => {
  const params = new URLSearchParams(window.location.search);
  const error = params.get('error');

  const errorMessages: Record<string, string> = {
    'oauth_failed': 'Google 登入失敗，請稍後再試',
    'invalid_state': '登入請求已過期，請重新嘗試',
    'email_not_verified': '請先在 Google 驗證您的 email',
    'access_denied': '您已取消 Google 登入',
    'account_disabled': '您的帳號已被停用'
  };

  if (error && errorMessages[error]) {
    // 顯示錯誤訊息（使用現有的錯誤處理機制）
    alert(errorMessages[error]); // 或使用更好的 toast/notification

    // 清除 URL 參數
    window.history.replaceState({}, '', window.location.pathname);
  }
}, []);
```

**Step 3: 測試錯誤處理**

手動測試：訪問 `http://localhost:5173/login?error=oauth_failed`，確認：
- 顯示錯誤訊息
- URL 參數被清除

**Step 4: Commit**

```bash
git add src/context/AuthContext.tsx  # 或 src/App.tsx
git commit -m "feat(frontend): add oauth error handling

處理 OAuth 回調錯誤：
- 解析 URL error 參數
- 顯示使用者友善錯誤訊息
- 自動清除 URL 參數

錯誤類型：oauth_failed, invalid_state, email_not_verified,
access_denied, account_disabled

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 16: 執行前端測試

**Step 1: 執行所有測試**

```bash
cd frontend
npm run test
```

Expected: All tests PASS

**Step 2: 生成覆蓋率報告**

```bash
npm run test:coverage
```

Expected: Coverage report 包含新增的 GoogleLoginButton 元件

---

## Task 17: 更新文件 - CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

**Step 1: 更新 API Endpoints 章節**

在 `CLAUDE.md` 的 "API v2 Endpoints (RESTful)" 章節新增：

```markdown
**Sessions** (`/api/v2/sessions`)
- POST /api/v2/sessions - 建立 session (登入), 使用 JSON body
- DELETE /api/v2/sessions - 刪除 session (登出)
- POST /api/v2/sessions/refresh - 刷新 session
- 🆕 GET /api/v2/sessions/google/login - Google OAuth 登入 (Rate Limit: 10/min)
- 🆕 GET /api/v2/sessions/google/callback - Google OAuth 回調 (Rate Limit: 20/min)
```

**Step 2: 更新環境設定章節**

在 `CLAUDE.md` 的 "環境設定" 章節新增：

```markdown
### 環境變數
```bash
# backend/.env (範例)
DATABASE_URL=postgresql://postgres:password@localhost:5432/auth_test
SECRET_KEY=your-secret-key-min-32-chars
ENVIRONMENT=development
TRUST_PROXY=false
CORS_ORIGINS=http://localhost:5173

# 🆕 Google OAuth (可選)
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v2/sessions/google/callback
```
```

**Step 3: 更新測試章節**

在 `CLAUDE.md` 的 "Testing" 章節新增：

```markdown
### 後端測試 (pytest)
# ... 現有測試 ...

# 🆕 測試 Google OAuth
uv run pytest tests/test_oauth.py -v
uv run pytest tests/test_routers_oauth.py -v
```

**Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for google oauth feature

更新開發文件：
- API 端點新增 Google OAuth 路由
- 環境變數新增 Google 相關設定
- 測試指令新增 OAuth 測試

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 18: 更新文件 - README.md

**Files:**
- Modify: `README.md`

**Step 1: 更新安全特性**

在 `README.md` 的安全特性章節新增：

```markdown
## 🔒 安全特性

- ✅ HttpOnly Cookie（防 XSS）
- ✅ Token Rotation（防重放攻擊）
- ✅ Rate Limiting（防暴力破解）
- ✅ bcrypt 密碼雜湊
- ✅ SameSite Cookie（防 CSRF）
- ✅ SELECT FOR UPDATE（防 Race Condition）
- ✅ 🆕 Google OAuth 2.0 登入
- ✅ 🆕 State Parameter（CSRF 防護）
- ✅ 🆕 自動帳號合併
```

**Step 2: 新增 Google OAuth 設定步驟**

在 `README.md` 的快速開始章節新增：

```markdown
### 4. Google OAuth 設定（可選）

如需啟用 Google 登入功能：

1. 前往 [Google Cloud Console](https://console.cloud.google.com/)
2. 建立 OAuth 2.0 用戶端 ID（Web 應用程式）
3. 設定授權重導向 URI: `http://localhost:8000/api/v2/sessions/google/callback`
4. 將 Client ID 和 Secret 加入 `backend/.env`:
   ```bash
   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=GOCSPX-your-secret
   ```
```

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README for google oauth feature

更新使用文件：
- 安全特性新增 Google OAuth
- 快速開始新增 Google Cloud Console 設定步驟

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 19: 更新 Docker 環境變數

**Files:**
- Modify: `docker-compose.yml`

**Step 1: 更新 backend service 環境變數**

在 `docker-compose.yml` 的 `backend` service 中新增：

```yaml
services:
  backend:
    # ... 現有設定 ...
    environment:
      DATABASE_URL: postgresql://postgres:postgres@db:5432/auth_test
      SECRET_KEY: ${SECRET_KEY:-dev-secret-key-change-in-production-2024}
      CORS_ORIGINS: http://localhost:3000,http://localhost:5173
      ENVIRONMENT: ${ENVIRONMENT:-development}
      TRUST_PROXY: "false"
      # 🆕 Google OAuth
      GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID:-}
      GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET:-}
      GOOGLE_REDIRECT_URI: ${GOOGLE_REDIRECT_URI:-http://localhost:8000/api/v2/sessions/google/callback}
```

**Step 2: 測試 Docker Compose**

```bash
docker compose config
```

Expected: 成功解析設定，無錯誤

**Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "build(docker): add google oauth environment variables

Docker Compose 新增 Google OAuth 環境變數：
- GOOGLE_CLIENT_ID (可選，預設空字串)
- GOOGLE_CLIENT_SECRET (可選，預設空字串)
- GOOGLE_REDIRECT_URI (預設 localhost:8000)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 20: 手動端到端測試

**注意**：此任務需要實際的 Google OAuth 憑證。如果沒有憑證，可以跳過實際測試，僅驗證程式碼邏輯。

**Step 1: 設定 Google OAuth 憑證（可選）**

如果要進行實際測試：

1. 前往 https://console.cloud.google.com/
2. 建立新專案或選擇現有專案
3. 啟用 Google+ API 或 People API
4. 建立 OAuth 2.0 Client ID（Web application）
5. 設定授權重導向 URI: `http://localhost:8000/api/v2/sessions/google/callback`
6. 複製 Client ID 和 Secret 到 `backend/.env`

**Step 2: 啟動完整服務**

```bash
# Terminal 1: 資料庫
docker compose up -d db

# Terminal 2: 後端
cd backend
uv run uvicorn app.main:app --reload --port 8000

# Terminal 3: 前端
cd frontend
npm run dev
```

**Step 3: 測試 Google 登入流程**

1. 瀏覽 http://localhost:5173/login
2. 點擊「使用 Google 登入」按鈕
3. （如果有設定憑證）應跳轉到 Google 授權頁面
4. （如果沒有憑證）應看到錯誤訊息
5. 檢查瀏覽器 Network tab，確認：
   - GET /api/v2/sessions/google/login 返回 302
   - 重導向到 Google 或顯示錯誤

**Step 4: 測試錯誤處理**

手動訪問：
- `http://localhost:5173/login?error=oauth_failed` → 應顯示錯誤訊息
- `http://localhost:5173/login?error=invalid_state` → 應顯示錯誤訊息

**Step 5: 記錄測試結果**

建立簡單的測試記錄：

```bash
echo "## 手動測試結果 ($(date))" >> TESTING.md
echo "" >> TESTING.md
echo "### Google OAuth 登入流程" >> TESTING.md
echo "- [ ] Google 登入按鈕顯示正常" >> TESTING.md
echo "- [ ] 點擊按鈕重導向到 /api/v2/sessions/google/login" >> TESTING.md
echo "- [ ] OAuth 錯誤處理運作正常" >> TESTING.md
echo "" >> TESTING.md
```

**Step 6: Commit 測試記錄（如果有）**

```bash
git add TESTING.md
git commit -m "test: add manual e2e test checklist for google oauth

記錄 Google OAuth 手動測試項目

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## 實作完成檢查清單

執行完所有 Task 後，確認以下項目：

### 後端
- [x] Google OAuth 依賴已安裝
- [x] 環境變數設定已更新（config.py, .env.example）
- [x] User model 新增 google_id, auth_provider 欄位
- [x] 資料庫 migration 已建立並執行
- [x] OAuth service 完整實作（state, URL, token, verify, user）
- [x] API 端點實作（/google/login, /google/callback）
- [x] 所有後端測試通過

### 前端
- [x] Google 登入按鈕元件實作
- [x] 登入頁面整合 Google 按鈕
- [x] OAuth 錯誤處理實作
- [x] 所有前端測試通過

### 文件
- [x] CLAUDE.md 更新
- [x] README.md 更新
- [x] Docker Compose 環境變數更新

### 測試
- [x] 後端單元測試（OAuth service）
- [x] 後端整合測試（API endpoints）
- [x] 前端元件測試（Google 按鈕）
- [x] 手動 E2E 測試（可選，需要 Google 憑證）

---

## 預估時間與實際記錄

| Task | 預估 | 實際 | 備註 |
|------|------|------|------|
| Task 1-4: Database | 30min | | Migration + Schema |
| Task 5-9: Service Layer | 90min | | OAuth service 實作 |
| Task 10-11: API Routes | 60min | | Google login + callback |
| Task 12: Backend Tests | 30min | | 測試驗證 |
| Task 13-16: Frontend | 60min | | 按鈕 + 錯誤處理 |
| Task 17-19: Documentation | 30min | | 文件更新 |
| Task 20: Manual Testing | 30min | | E2E 測試 |
| **總計** | **5.5 小時** | | |

---

## 下一步

實作完成後，可以考慮：

1. **生產環境部署**：
   - 設定實際的 Google OAuth 憑證
   - 使用 Redis 儲存 state tokens
   - 設定正確的 redirect URI

2. **進階功能**：
   - 使用者個人資料頁面顯示連結的登入方式
   - 解除 Google 帳號綁定功能
   - 支援更多 OAuth providers（Facebook, GitHub）

3. **監控與日誌**：
   - 記錄 OAuth 登入事件
   - 監控 Google API 使用量
   - 異常登入偵測
