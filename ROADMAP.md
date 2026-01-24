# 後續開發計畫 (Roadmap)

## 當前狀態 (v1.0)

✅ **核心認證系統已完成**
- HttpOnly Cookie + JWT + Refresh Token with Token Rotation
- Rate Limiting (防暴力破解)
- 所有 Critical 和 Important 安全問題已修正
- RESTful API v1 with 向後相容

✅ **安全機制完善**
- XSS, CSRF, SQL Injection, IP Spoofing 防護
- bcrypt password hashing
- Race Condition 防護 (SELECT FOR UPDATE)
- Token 自動清理機制

✅ **使用者體驗良好**
- 多 Tab 同步 (BroadcastChannel)
- Rate Limiting 倒數計時
- 專屬錯誤訊息

---

## Phase 1: 測試與品質保證（優先級：P0）

### 目標
建立完整的測試覆蓋率，確保系統穩定性與可維護性。

### 1.1 後端單元測試 (pytest)

**安裝依賴**
```toml
# backend/pyproject.toml
[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "httpx>=0.24.0",  # FastAPI TestClient
    "pytest-cov>=4.1.0",
]
```

**測試範圍**
```
backend/tests/
├── conftest.py              # pytest fixtures (db, client)
├── test_auth.py             # 認證邏輯單元測試
│   ├── test_hash_password
│   ├── test_verify_password
│   ├── test_create_access_token
│   ├── test_create_refresh_token
│   ├── test_verify_and_revoke_refresh_token
│   └── test_race_condition_handling
├── test_routers_auth.py     # 認證端點整合測試
│   ├── test_register_success
│   ├── test_register_duplicate_email
│   ├── test_login_success
│   ├── test_login_invalid_credentials
│   ├── test_logout_revokes_token
│   ├── test_refresh_token_rotation
│   └── test_rate_limiting
└── test_routers_users.py    # 使用者端點測試
    └── test_get_current_user
```

**關鍵測試案例**
- Token Rotation 原子性（併發測試）
- Rate Limiting 邊界值
- Cookie HttpOnly/Secure 標記正確性
- 懶刪除機制有效性

**執行**
```bash
cd backend
uv run pytest --cov=app --cov-report=html
```

**成功標準**
- 測試覆蓋率 ≥ 80%
- 所有 Critical Path 有測試

---

### 1.2 前端單元測試 (Vitest + React Testing Library)

**安裝依賴**
```bash
cd frontend
npm install -D vitest @testing-library/react @testing-library/jest-dom \
  @testing-library/user-event jsdom
```

**測試範圍**
```
frontend/src/
├── utils/errorHandler.test.ts     # 錯誤處理邏輯
├── components/
│   ├── LoginForm.test.tsx         # 登入表單（含 Rate Limit UX）
│   ├── RegisterForm.test.tsx      # 註冊表單
│   └── Navbar.test.tsx            # 導航列
├── context/
│   └── AuthContext.test.tsx       # 認證 Context
└── services/
    └── api.test.ts                # axios interceptor（模擬 BroadcastChannel）
```

**關鍵測試案例**
- Rate Limiting 倒數計時顯示
- BroadcastChannel 事件處理
- 錯誤訊息格式正確性（401, 429, 500）
- Token 自動刷新重試邏輯

**執行**
```bash
npm run test
npm run test:coverage
```

**成功標準**
- 測試覆蓋率 ≥ 70%
- 所有使用者互動流程有測試

---

### 1.3 E2E 測試 (Playwright - Optional)

**僅測試核心流程**
```
e2e/
├── auth.spec.ts              # 註冊 → 登入 → 登出
├── protected-route.spec.ts   # 未登入跳轉 → 登入後存取
└── rate-limiting.spec.ts     # 連續登入失敗顯示倒數
```

**成功標準**
- 3 個核心使用者流程通過

---

## Phase 2: 完整 RESTful 改造（優先級：P1）

### 目標
將 `/auth/*` 端點改為真正的 RESTful 設計（資源導向）。

### 2.1 API 重新設計

**當前 (v1)** → **RESTful (v2)**
| 當前端點 | RESTful 端點 | HTTP Method | 說明 |
|----------|--------------|-------------|------|
| POST /auth/register | POST /users | POST | 建立使用者資源 |
| POST /auth/login | POST /sessions | POST | 建立 session 資源 |
| POST /auth/logout | DELETE /sessions | DELETE | 刪除 session |
| POST /auth/refresh | POST /sessions/refresh | POST | 刷新 session |
| GET /users/me | GET /users/me | GET | 保持不變 |

**實作方式**
```python
# backend/app/main.py
api_v2 = APIRouter(prefix="/api/v2")
api_v2.include_router(sessions_router, prefix="/sessions")
api_v2.include_router(users_router, prefix="/users")

# 保留 v1 向後相容
app.include_router(api_v1)
app.include_router(api_v2)
```

**新增檔案**
- `backend/app/routers/sessions.py` - Session 管理（login, logout, refresh）
- `backend/app/routers/users.py` - 擴充為包含 POST /users（註冊）

**成功標準**
- `/api/v2` 端點符合 RESTful 命名
- v1 和 v2 同時運作
- Swagger UI 顯示兩個版本

---

## Phase 3: Email 驗證與密碼重設（優先級：P1）

### 目標
提供真實應用必備的 Email 功能。

### 3.1 Email 服務整合

**技術選擇**
- 開發環境：SMTP4Dev (Docker)
- 生產環境：SendGrid / AWS SES / Mailgun

**新增依賴**
```toml
dependencies = [
    "fastapi-mail>=1.4.0",
]
```

**資料庫遷移**
```python
# 新增欄位至 User 模型
class User(Base):
    # ... 現有欄位 ...
    is_verified: Mapped[bool] = mapped_column(Boolean, server_default="false")
    verification_token: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reset_token: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reset_token_expires: Mapped[datetime | None] = mapped_column(nullable=True)
```

**新增端點**
- `POST /api/v2/users/verify-email` - 發送驗證信
- `GET /api/v2/users/verify/{token}` - 驗證 Email
- `POST /api/v2/users/reset-password` - 發送重設密碼信
- `POST /api/v2/users/reset-password/{token}` - 重設密碼

**成功標準**
- 註冊後自動發送驗證信
- 未驗證使用者無法登入（或顯示警告）
- 密碼重設流程正常運作

---

## Phase 4: Docker 容器化部署（優先級：P1）

### 目標
提供完整的容器化部署方案，讓其他人能快速啟動專案。

### 4.1 Dockerfile

**後端 Dockerfile**
```dockerfile
# backend/Dockerfile
FROM python:3.12-slim

WORKDIR /app

# 安裝 uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# 複製依賴檔案
COPY pyproject.toml ./
RUN uv sync --frozen

# 複製應用程式
COPY . .

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**前端 Dockerfile**
```dockerfile
# frontend/Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### 4.2 更新 docker-compose.yml

```yaml
version: '3.8'

services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: auth_test
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://postgres:password@db:5432/auth_test
      SECRET_KEY: ${SECRET_KEY}
      ENVIRONMENT: production
      CORS_ORIGINS: http://localhost:3000
    depends_on:
      db:
        condition: service_healthy
    command: >
      sh -c "uv run alembic upgrade head &&
             uv run uvicorn app.main:app --host 0.0.0.0 --port 8000"

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:80"
    depends_on:
      - backend

volumes:
  postgres_data:
```

**使用方式**
```bash
# 一鍵啟動所有服務
docker compose up -d

# 訪問 http://localhost:3000
```

**成功標準**
- `docker compose up` 可啟動完整應用
- 資料持久化（volume）
- 健康檢查正常

---

## Phase 5: CI/CD Pipeline（優先級：P2）

### 目標
自動化測試與部署流程。

### 5.1 GitHub Actions

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: password
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v3
      - uses: astral-sh/setup-uv@v1
      - name: Run backend tests
        run: |
          cd backend
          uv run pytest --cov=app

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: 18
      - name: Run frontend tests
        run: |
          cd frontend
          npm ci
          npm run test

  docker-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Docker images
        run: docker compose build
```

**成功標準**
- 每次 push 自動執行測試
- 測試失敗時 PR 無法 merge
- Docker 建置成功

---

## Phase 6: 監控與日誌（優先級：P2）

### 目標
生產環境可觀測性。

### 6.1 結構化日誌

**安裝依賴**
```toml
dependencies = [
    "structlog>=23.1.0",
]
```

**配置**
```python
# backend/app/logging.py
import structlog

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)

logger = structlog.get_logger()

# 使用範例
logger.info("user_login", user_id=user.id, ip=client_ip)
```

### 6.2 Prometheus Metrics (Optional)

```toml
dependencies = [
    "prometheus-fastapi-instrumentator>=6.1.0",
]
```

```python
# backend/app/main.py
from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)
```

**成功標準**
- 所有登入/登出事件有日誌
- Rate Limiting 事件可追蹤
- Prometheus `/metrics` 端點運作

---

## Phase 7: 進階功能（優先級：P3）

### 7.1 多因素認證 (2FA/TOTP)

**技術選擇**
- pyotp (Python TOTP 生成)
- qrcode (生成 QR Code)

**新增端點**
- `POST /api/v2/users/me/2fa/enable` - 啟用 2FA，返回 QR Code
- `POST /api/v2/users/me/2fa/verify` - 驗證 TOTP code
- `POST /api/v2/users/me/2fa/disable` - 關閉 2FA

**資料庫遷移**
```python
class User(Base):
    # ... 現有欄位 ...
    totp_secret: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_2fa_enabled: Mapped[bool] = mapped_column(Boolean, server_default="false")
```

---

### 7.2 OAuth2 第三方登入

**支援平台**
- Google OAuth2
- GitHub OAuth2

**技術選擇**
- authlib (OAuth 客戶端)

**新增端點**
- `GET /api/v2/auth/oauth/google` - 跳轉至 Google 授權頁
- `GET /api/v2/auth/oauth/google/callback` - Google 回調
- `GET /api/v2/auth/oauth/github` - GitHub 授權
- `GET /api/v2/auth/oauth/github/callback` - GitHub 回調

**資料庫遷移**
```python
class User(Base):
    # ... 現有欄位 ...
    oauth_provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    oauth_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
```

---

### 7.3 Redis-based Rate Limiting

**問題**
當前使用 in-memory rate limiting，多伺服器部署時會失效。

**解決方案**
```toml
dependencies = [
    "redis>=5.0.0",
    "slowapi[redis]>=0.1.9",
]
```

```python
# backend/app/main.py
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
import redis

redis_client = redis.Redis(host='localhost', port=6379, db=0)
limiter = Limiter(key_func=get_remote_address, storage_uri="redis://localhost:6379")
```

**成功標準**
- 多個後端實例共享 rate limit 計數
- Redis 重啟後 limit 正確重置

---

## Phase 8: 效能優化（優先級：P3）

### 8.1 Redis Token 快取

**問題**
每次 `/users/me` 都查詢資料庫驗證 JWT。

**解決方案**
```python
# 快取 user 資料 (TTL = 15 分鐘，與 access token 同步)
@cache(ttl=900)
async def get_user_by_email(email: str, db: Session):
    return db.query(User).filter(User.email == email).first()
```

**成功標準**
- `/users/me` 平均回應時間 < 50ms（vs 當前 ~100ms）

---

### 8.2 資料庫連線池優化

```python
# backend/app/database.py
engine = create_engine(
    settings.database_url,
    pool_size=20,        # 預設 5
    max_overflow=40,     # 預設 10
    pool_pre_ping=True,  # 自動檢測失效連線
)
```

---

## 優先級總結

| Phase | 項目 | 優先級 | 工作量 | 價值 |
|-------|------|--------|--------|------|
| 1 | 測試（pytest + Vitest） | P0 | 3-5 天 | ⭐⭐⭐⭐⭐ |
| 2 | 完整 RESTful 改造 | P1 | 1-2 天 | ⭐⭐⭐⭐ |
| 3 | Email 驗證 + 密碼重設 | P1 | 2-3 天 | ⭐⭐⭐⭐⭐ |
| 4 | Docker 容器化部署 | P1 | 1 天 | ⭐⭐⭐⭐ |
| 5 | CI/CD (GitHub Actions) | P2 | 1 天 | ⭐⭐⭐⭐ |
| 6 | 監控與日誌 | P2 | 2 天 | ⭐⭐⭐ |
| 7.1 | 2FA/TOTP | P3 | 2 天 | ⭐⭐⭐ |
| 7.2 | OAuth2 第三方登入 | P3 | 3 天 | ⭐⭐⭐ |
| 7.3 | Redis Rate Limiting | P3 | 1 天 | ⭐⭐ |
| 8 | 效能優化 | P3 | 2 天 | ⭐⭐ |

---

## 建議執行順序

### Sprint 1 (1 週) - 穩定性與測試
1. ✅ Phase 1.1: 後端單元測試 (pytest)
2. ✅ Phase 1.2: 前端單元測試 (Vitest)
3. ✅ Phase 4: Docker 容器化部署

**交付成果**：80% 測試覆蓋率 + `docker compose up` 一鍵啟動

---

### Sprint 2 (1 週) - 完整功能
1. ✅ Phase 3: Email 驗證 + 密碼重設
2. ✅ Phase 2: 完整 RESTful 改造 (v2 API)
3. ✅ Phase 5: CI/CD Pipeline

**交付成果**：生產就緒的認證系統 + 自動化測試

---

### Sprint 3 (選擇性) - 進階功能
1. Phase 7.1: 2FA/TOTP
2. Phase 7.2: OAuth2 第三方登入
3. Phase 6: 監控與日誌

**交付成果**：企業級認證系統

---

## Linus "Good Taste" 檢查

✅ **務實優先**：Phase 1-4 都是必要功能，非過度設計
✅ **循序漸進**：先穩定性（測試），再擴充功能（Email）
✅ **避免過早優化**：Redis 快取列為 P3（先證明有瓶頸再優化）
✅ **保持簡單**：每個 Phase 聚焦單一目標，不混合多個概念

❌ **避免陷阱**
- 不要跳過測試直接做 2FA（Phase 7 前必須完成 Phase 1）
- 不要為了「完美 RESTful」犧牲向後相容（保留 v1 端點）
- 不要過早引入微服務架構（當前單體足夠）

---

## 結論

當前專案（v1.0）已是**生產就緒的安全認證系統**。

**下一步建議**：
1. **如果目標是學習/示範**：執行 Sprint 1（測試 + Docker）
2. **如果目標是真實應用**：執行 Sprint 1 + 2（加上 Email 驗證）
3. **如果目標是企業級系統**：執行完整 3 個 Sprint

每個 Phase 都是獨立的，可根據需求選擇性實作。
