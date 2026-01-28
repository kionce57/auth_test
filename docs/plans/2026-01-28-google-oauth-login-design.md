# Google OAuth 登入功能設計文件

**日期**: 2026-01-28
**狀態**: 已驗證 (Validated)
**架構方案**: 最小侵入式設計 (Minimal Invasive Design)

## 概述

為現有認證系統新增 Google OAuth 登入功能，允許使用者透過 Google 帳號一鍵登入。採用後端主導 OAuth flow，確保安全性並與現有 JWT + Refresh Token 機制無縫整合。

## 核心決策

1. **OAuth Flow**: 後端主導 (Server-side)
2. **首次登入**: 自動建立帳號 (Auto-registration)
3. **帳號合併**: 自動連結相同 email 的現有帳號
4. **密碼處理**: 允許 `hashed_password` 為 `NULL`

## 資料庫 Schema 設計

### User Model 變更

```python
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # ⚠️ 修改：改為 nullable
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # 🆕 新增欄位
    google_id: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True, index=True
    )
    auth_provider: Mapped[str] = mapped_column(
        String(20), server_default="local", nullable=False
    )
    # auth_provider 可能值:
    # - "local": 僅密碼登入
    # - "google": 僅 Google 登入
    # - "both": 兩種方式皆可

    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )
```

### Alembic Migration

```bash
# 建立 migration
uv run alembic revision --autogenerate -m "add google oauth support"

# 執行 migration
uv run alembic upgrade head
```

**Migration 內容**:
- `hashed_password`: 修改為 `nullable=True`
- `google_id`: 新增欄位 + unique index
- `auth_provider`: 新增欄位，預設值 "local"
- 現有使用者的 `auth_provider` 自動設為 "local"

## API 端點設計

### 新增端點 (API v2)

```
GET /api/v2/sessions/google/login
    描述: 初始化 Google OAuth flow
    Query Params:
      - redirect_uri (optional): 登入完成後前端跳轉位置
    回應: 302 重導向到 Google 授權頁面
    Rate Limit: 10/minute

GET /api/v2/sessions/google/callback
    描述: Google OAuth 回調端點
    Query Params:
      - code: Google 授權碼
      - state: CSRF 防護 token
    回應: 302 重導向到前端，設定 HttpOnly cookies
    Rate Limit: 20/minute
    錯誤處理: 重導向到 /login?error={error_code}
```

### OAuth Flow

```
1. 使用者點擊「Google 登入」
   → window.location.href = '/api/v2/sessions/google/login'

2. 後端產生 state token (CSRF 防護)
   → 重導向到 Google 授權頁面
   → URL: https://accounts.google.com/o/oauth2/v2/auth
   → Params: client_id, redirect_uri, scope=openid email profile, state

3. 使用者在 Google 授權頁面同意

4. Google 重導向回 /api/v2/sessions/google/callback?code=xxx&state=yyy

5. 後端處理:
   a. 驗證 state token (防 CSRF)
   b. 用 code 交換 access token
   c. 取得使用者資訊 (google_id, email, email_verified)
   d. 驗證 email_verified = true
   e. 查找/建立/合併使用者 (見下方邏輯)
   f. 建立 JWT access_token + refresh_token
   g. 設定 HttpOnly cookies
   h. 重導向到前端 dashboard

6. 前端自動進入已登入狀態
```

### 使用者查找/建立邏輯

```python
def find_or_create_user(google_id: str, email: str, db: Session) -> User:
    # 1. 用 google_id 查詢
    user = db.query(User).filter(User.google_id == google_id).first()
    if user:
        return user  # 已存在的 Google 使用者

    # 2. 用 email 查詢（帳號合併）
    user = db.query(User).filter(User.email == email).first()
    if user:
        # 合併帳號：連結 Google ID
        user.google_id = google_id
        user.auth_provider = "both" if user.hashed_password else "google"
        db.commit()
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
    return user
```

## 安全機制

### CSRF 防護 (State Parameter)

```python
# /login 端點
state = secrets.token_urlsafe(32)
# 儲存到 Redis/session，5 分鐘過期
redis.setex(f"oauth_state:{state}", 300, "1")
# 加入授權 URL
google_auth_url += f"&state={state}"

# /callback 端點
state = request.query_params.get("state")
if not redis.exists(f"oauth_state:{state}"):
    raise HTTPException(status_code=400, detail="Invalid state")
redis.delete(f"oauth_state:{state}")  # 單次使用
```

### 錯誤處理

| 錯誤場景 | HTTP 狀態 | 處理方式 |
|---------|----------|---------|
| Google API 失敗 | 302 | 重導向到 `/login?error=oauth_failed` |
| State 驗證失敗 | 302 | 重導向到 `/login?error=invalid_state` |
| Email 未驗證 | 302 | 重導向到 `/login?error=email_not_verified` |
| 使用者拒絕授權 | 302 | 重導向到 `/login?error=access_denied` |
| 帳號已停用 | 302 | 重導向到 `/login?error=account_disabled` |

### Rate Limiting

```python
@router_v2.get("/sessions/google/login")
@limiter.limit("10/minute")
def google_login(...): pass

@router_v2.get("/sessions/google/callback")
@limiter.limit("20/minute")
def google_callback(...): pass
```

### 安全檢查清單

- ✅ State parameter 防 CSRF 攻擊
- ✅ 驗證 Google ID Token (使用 google-auth library)
- ✅ 確認 email_verified = true
- ✅ HTTPS only in production
- ✅ Client Secret 儲存在環境變數
- ✅ 使用相同的 HttpOnly Cookie 機制
- ✅ Rate Limiting 防止濫用

## 前端整合

### 登入頁面新增 Google 按鈕

```tsx
// src/pages/LoginPage.tsx
import { GoogleIcon } from '../components/icons';

function LoginPage() {
  const handleGoogleLogin = () => {
    // 儲存當前頁面，登入後返回
    sessionStorage.setItem('redirectAfterLogin', window.location.pathname);

    // 重導向到後端 OAuth 端點
    window.location.href = '/api/v2/sessions/google/login';
  };

  return (
    <div className="login-container">
      <h2>登入</h2>

      {/* 原有的 email/password 表單 */}
      <LoginForm />

      {/* 分隔線 */}
      <div className="divider">
        <span>或</span>
      </div>

      {/* Google 登入按鈕 */}
      <button
        onClick={handleGoogleLogin}
        className="google-login-btn"
        type="button"
      >
        <GoogleIcon />
        <span>使用 Google 登入</span>
      </button>
    </div>
  );
}
```

### 錯誤處理

```tsx
// src/App.tsx 或 AuthContext.tsx
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
    showError(errorMessages[error]);
    // 清除 URL 參數
    window.history.replaceState({}, '', window.location.pathname);
  }
}, []);
```

### AuthContext 無需修改

- Google 登入後會設定相同的 HttpOnly Cookie
- 現有的 `useAuth()` hook 自動支援
- `/api/v2/users/me` 端點自動識別使用者
- 前端無需區分登入方式

## 後端實作結構

### 依賴套件

```toml
# backend/pyproject.toml
dependencies = [
    # ... 現有套件 ...
    "google-auth>=2.27.0",           # 驗證 Google ID Token
    "google-auth-oauthlib>=1.2.0",   # OAuth 2.0 flow
    "httpx>=0.26.0",                 # 非同步 HTTP client
]
```

### 檔案結構

```
backend/app/
├── routers/
│   └── auth.py                  # ✏️ 修改
│       ├── router_v2 (現有)
│       ├── google_login()       # 🆕 GET /sessions/google/login
│       └── google_callback()    # 🆕 GET /sessions/google/callback
│
├── services/
│   └── oauth.py                 # 🆕 新增檔案
│       ├── get_google_oauth_url()        # 產生授權 URL + state
│       ├── exchange_code_for_token()     # 用 code 換 access token
│       ├── verify_google_token()         # 驗證並解析 ID token
│       ├── get_google_user_info()        # 取得使用者資訊
│       └── find_or_create_user()         # 查找/建立/合併使用者
│
├── config.py                    # ✏️ 修改
│   └── Settings
│       ├── google_client_id: str
│       ├── google_client_secret: str
│       └── google_redirect_uri: str
│
└── models.py                    # ✏️ 修改 User model
```

### 核心服務實作 (Pseudocode)

```python
# services/oauth.py
import secrets
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import httpx

async def get_google_oauth_url(state: str) -> str:
    """產生 Google OAuth 授權 URL"""
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "consent"
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

async def exchange_code_for_token(code: str) -> dict:
    """用授權碼交換 access token"""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.google_redirect_uri,
                "grant_type": "authorization_code"
            }
        )
        return response.json()

def verify_google_token(id_token_str: str) -> dict:
    """驗證 Google ID Token"""
    idinfo = id_token.verify_oauth2_token(
        id_token_str,
        google_requests.Request(),
        settings.google_client_id
    )

    if not idinfo.get("email_verified"):
        raise ValueError("Email not verified")

    return {
        "google_id": idinfo["sub"],
        "email": idinfo["email"],
        "name": idinfo.get("name"),
        "picture": idinfo.get("picture")
    }

def find_or_create_user(google_id: str, email: str, db: Session) -> User:
    """查找或建立 Google 使用者，處理帳號合併"""
    # 1. 用 google_id 查詢
    user = db.query(User).filter(User.google_id == google_id).first()
    if user:
        return user

    # 2. 用 email 查詢（帳號合併）
    user = db.query(User).filter(User.email == email).first()
    if user:
        user.google_id = google_id
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

## 測試策略

### 後端單元測試

```python
# tests/test_oauth.py (新增檔案)
import pytest
from app.services.oauth import find_or_create_user
from app.models import User

def test_find_or_create_user_new_google_user(db):
    """測試：首次 Google 登入，建立新使用者"""
    user = find_or_create_user(
        google_id="google_123456789",
        email="newuser@gmail.com",
        db=db
    )

    assert user.google_id == "google_123456789"
    assert user.email == "newuser@gmail.com"
    assert user.auth_provider == "google"
    assert user.hashed_password is None

def test_find_or_create_user_merge_existing_password_account(db):
    """測試：已有密碼帳號，Google 登入後合併"""
    # 先建立密碼帳號
    existing = User(
        email="existing@gmail.com",
        hashed_password="$2b$12$...",
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

### 後端整合測試

```python
# tests/test_routers_oauth.py (新增檔案)
from unittest.mock import patch, MagicMock
import pytest

@patch('app.services.oauth.exchange_code_for_token')
@patch('app.services.oauth.verify_google_token')
def test_google_callback_success_new_user(
    mock_verify, mock_exchange, client, db
):
    """測試：Google 登入成功，建立新使用者"""
    # Mock Google API 回應
    mock_exchange.return_value = {"id_token": "mock_id_token"}
    mock_verify.return_value = {
        "google_id": "google_new_123",
        "email": "newuser@gmail.com",
        "name": "New User"
    }

    # 模擬 callback（需要先設定有效的 state）
    response = client.get(
        "/api/v2/sessions/google/callback",
        params={"code": "mock_code", "state": "valid_state"}
    )

    # 驗證：重導向到 dashboard
    assert response.status_code == 302
    assert "/dashboard" in response.headers["location"]

    # 驗證：cookies 已設定
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    # 驗證：使用者已建立
    user = db.query(User).filter(User.email == "newuser@gmail.com").first()
    assert user is not None
    assert user.google_id == "google_new_123"
    assert user.auth_provider == "google"

def test_google_callback_invalid_state(client):
    """測試：State 驗證失敗"""
    response = client.get(
        "/api/v2/sessions/google/callback",
        params={"code": "mock_code", "state": "invalid_state"}
    )

    assert response.status_code == 302
    assert "error=invalid_state" in response.headers["location"]

@patch('app.services.oauth.exchange_code_for_token')
def test_google_callback_google_api_error(mock_exchange, client):
    """測試：Google API 錯誤"""
    mock_exchange.side_effect = Exception("Google API error")

    response = client.get(
        "/api/v2/sessions/google/callback",
        params={"code": "mock_code", "state": "valid_state"}
    )

    assert response.status_code == 302
    assert "error=oauth_failed" in response.headers["location"]
```

### 前端測試

```typescript
// src/components/GoogleLoginButton.test.tsx
import { render, fireEvent } from '@testing-library/react';
import { GoogleLoginButton } from './GoogleLoginButton';

describe('GoogleLoginButton', () => {
  it('redirects to OAuth endpoint on click', () => {
    const { getByRole } = render(<GoogleLoginButton />);
    const button = getByRole('button', { name: /google/i });

    // Mock window.location
    delete window.location;
    window.location = { href: '' } as any;

    fireEvent.click(button);

    expect(window.location.href).toBe('/api/v2/sessions/google/login');
  });

  it('saves current location before redirect', () => {
    const { getByRole } = render(<GoogleLoginButton />);
    const button = getByRole('button', { name: /google/i });

    // Mock sessionStorage
    const mockSetItem = jest.spyOn(Storage.prototype, 'setItem');

    fireEvent.click(button);

    expect(mockSetItem).toHaveBeenCalledWith(
      'redirectAfterLogin',
      expect.any(String)
    );
  });
});
```

## 環境設定

### 環境變數

```bash
# backend/.env
# ... 現有變數 ...

# 🆕 Google OAuth Configuration
GOOGLE_CLIENT_ID=123456789-abc.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxxx
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v2/sessions/google/callback
```

### Google Cloud Console 設定

**步驟**：

1. 前往 [Google Cloud Console](https://console.cloud.google.com/)
2. 建立新專案或選擇現有專案
3. 啟用 **Google+ API** 或 **People API**
4. 前往「憑證」頁面
5. 建立「OAuth 2.0 用戶端 ID」
   - 應用程式類型：**網頁應用程式**
   - 名稱：`Auth Test Development`
6. 設定「已授權的重新導向 URI」：
   - Development: `http://localhost:8000/api/v2/sessions/google/callback`
   - Production: `https://yourdomain.com/api/v2/sessions/google/callback`
7. 複製「用戶端 ID」和「用戶端密鑰」到 `.env`

**OAuth 同意畫面設定**：
- 使用者類型：外部 (External)
- 應用程式名稱：Auth Test
- 授權網域：localhost (開發) / yourdomain.com (正式)
- 範圍：`openid`, `email`, `profile`

### Docker 部署

```yaml
# docker-compose.yml
services:
  backend:
    # ... 現有設定 ...
    environment:
      # ... 現有環境變數 ...
      GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID}
      GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET}
      GOOGLE_REDIRECT_URI: ${GOOGLE_REDIRECT_URI:-http://localhost:8000/api/v2/sessions/google/callback}
```

```bash
# .env (docker compose)
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v2/sessions/google/callback
```

## 文件更新

### CLAUDE.md

**API Architecture 章節新增**：
```markdown
### API v2 Endpoints (RESTful)

**Sessions** (`/api/v2/sessions`)
- POST /api/v2/sessions
- DELETE /api/v2/sessions
- POST /api/v2/sessions/refresh
- 🆕 GET /api/v2/sessions/google/login - Google OAuth 登入
- 🆕 GET /api/v2/sessions/google/callback - Google OAuth 回調
```

**環境設定章節新增**：
```markdown
### 環境變數
# ... 現有變數 ...

# Google OAuth
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v2/sessions/google/callback
```

**Testing 章節新增**：
```markdown
### 後端測試 (pytest)
# 測試 Google OAuth
uv run pytest tests/test_oauth.py -v
uv run pytest tests/test_routers_oauth.py -v
```

### README.md

**安全特性新增**：
```markdown
- ✅ Google OAuth 2.0 登入
- ✅ State Parameter (CSRF 防護)
- ✅ 自動帳號合併
```

**快速開始新增 Google 設定步驟**：
```markdown
### 4. Google OAuth 設定 (可選)

如需啟用 Google 登入：
1. 前往 Google Cloud Console 建立 OAuth 2.0 憑證
2. 將 Client ID 和 Secret 加入 `.env`
3. 設定授權重導向 URI: `http://localhost:8000/api/v2/sessions/google/callback`
```

## 實作檢查清單

### Phase 1: 資料庫 Schema
- [ ] 修改 `models.py` User model
  - [ ] `hashed_password` 改為 nullable
  - [ ] 新增 `google_id` 欄位 + unique index
  - [ ] 新增 `auth_provider` 欄位
- [ ] 建立 Alembic migration
- [ ] 執行 migration
- [ ] 驗證 schema 正確

### Phase 2: 後端服務層
- [ ] 新增 `services/oauth.py`
  - [ ] `get_google_oauth_url()`
  - [ ] `exchange_code_for_token()`
  - [ ] `verify_google_token()`
  - [ ] `find_or_create_user()`
- [ ] 更新 `config.py` 新增 Google 環境變數
- [ ] 安裝依賴：`google-auth`, `google-auth-oauthlib`, `httpx`

### Phase 3: API 路由
- [ ] 更新 `routers/auth.py`
  - [ ] `google_login()` 端點
  - [ ] `google_callback()` 端點
  - [ ] State 儲存機制（Redis 或 in-memory）
  - [ ] Rate limiting
  - [ ] 錯誤處理

### Phase 4: 前端整合
- [ ] 新增 Google 登入按鈕 UI
- [ ] OAuth 錯誤處理（URL params）
- [ ] 測試登入流程

### Phase 5: 測試
- [ ] 後端單元測試 (`test_oauth.py`)
- [ ] 後端整合測試 (`test_routers_oauth.py`)
- [ ] 前端元件測試
- [ ] 手動端到端測試

### Phase 6: 文件與部署
- [ ] 更新 CLAUDE.md
- [ ] 更新 README.md
- [ ] 更新 `.env.example`
- [ ] Google Cloud Console 設定文件
- [ ] Docker Compose 環境變數

## 預估工作量

| 階段 | 預估時間 |
|-----|---------|
| Phase 1: Database Schema | 1 小時 |
| Phase 2: Backend Service | 2-3 小時 |
| Phase 3: API Routes | 2 小時 |
| Phase 4: Frontend | 2 小時 |
| Phase 5: Testing | 2-3 小時 |
| Phase 6: Documentation | 1 小時 |
| **總計** | **10-12 小時** |

## 風險與限制

### 風險

1. **Google API 配額限制**
   - 免費配額：10,000 requests/day
   - 緩解：生產環境監控 API 使用量

2. **Email 變更問題**
   - 使用者在 Google 更改 email 後，系統無法自動更新
   - 緩解：定期同步或提供手動更新功能

3. **State Token 儲存**
   - 開發環境使用 in-memory 儲存，重啟後失效
   - 緩解：生產環境使用 Redis

### 限制

- 只支援 Google OAuth，不支援其他 provider
- 無法阻止使用者建立多個 Google 帳號
- 使用者無法解除 Google 帳號綁定（未來功能）

## 未來擴展

1. **支援更多 OAuth Provider**
   - Facebook, GitHub, Microsoft
   - 重構為 `OAuthAccount` table（方案 B）

2. **使用者帳號管理**
   - 查看已連結的登入方式
   - 解除 Google 帳號綁定
   - 連結新的 OAuth 帳號

3. **進階安全功能**
   - 記錄登入歷史（IP, device, provider）
   - 異常登入偵測
   - 二次驗證（2FA）整合

## 參考資料

- [Google OAuth 2.0 文件](https://developers.google.com/identity/protocols/oauth2)
- [FastAPI OAuth2 with Password (and hashing), Bearer with JWT tokens](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)
- [OWASP OAuth 2.0 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2_0_Security_Cheat_Sheet.html)
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
