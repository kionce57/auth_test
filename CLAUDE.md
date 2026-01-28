# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Output Language
- Always reason in native American English, output in Traditional Chinese (繁體中文)

## Project Overview
Full-stack 認證系統示範專案，實作業界最佳實踐的安全認證機制。

**技術棧**：
- **Backend**: FastAPI + PostgreSQL + SQLAlchemy + Alembic
- **Frontend**: React 18 + TypeScript + Vite + React Router
- **認證**: JWT (Access Token) + Refresh Token with Token Rotation
- **安全**: HttpOnly Cookie, Rate Limiting, CORS, bcrypt password hashing

## Development Environment

### Backend
- **Python Version**: 3.12+
- **Package Manager**: `uv` (必須使用)
- **Database**: PostgreSQL (via Docker Compose)
- **Dependencies**: 定義於 `backend/pyproject.toml`

### Frontend
- **Node Version**: 18+ (建議使用 LTS)
- **Package Manager**: npm
- **Build Tool**: Vite
- **Dependencies**: 定義於 `frontend/package.json`

## Running the Project

### 啟動完整服務
```bash
# 1. 啟動資料庫
docker compose up -d

# 2. 啟動後端 (Terminal 1)
cd backend
uv run uvicorn app.main:app --reload --port 8000

# 3. 啟動前端 (Terminal 2)
cd frontend
npm run dev
```

訪問：
- **前端**: http://localhost:5173
- **後端 API**: http://localhost:8000/docs (Swagger UI)
- **健康檢查**: http://localhost:8000/health

### 使用 Docker 啟動（推薦）

**一鍵啟動所有服務**：
```bash
# 建置並啟動
docker compose up -d

# 查看日誌
docker compose logs -f

# 停止服務
docker compose down

# 停止並刪除資料（重置資料庫）
docker compose down -v
```

**訪問**：
- **前端**: http://localhost:3000
- **後端 API**: http://localhost:8000/docs
- **健康檢查**: http://localhost:8000/health（直接訪問後端）

**開發模式**：
- 後端程式碼掛載為 volume，修改自動重載
- 前端為生產建置（需重建映像檔才能看到更改）

**注意**：
- Docker 部署自動執行資料庫 migrations
- 前端透過 nginx 代理 `/api/*` 到後端
- 所有服務在同一 Docker 網路中通訊

### Docker 開發模式

**後端 Hot Reload**：
- 後端程式碼掛載為 volume：`./backend/app:/app/app`
- 修改程式碼後自動重載，無需重建映像檔

**前端修改**：
- 前端為生產建置，修改後需重建：
  ```bash
  docker compose up -d --build frontend
  ```

**查看即時日誌**：
```bash
# 所有服務
docker compose logs -f

# 特定服務
docker compose logs -f backend
docker compose logs -f frontend
```

**執行後端指令**：
```bash
# 進入後端容器
docker compose exec backend sh

# 執行 Alembic 指令
docker compose exec backend uv run alembic upgrade head

# 執行測試
docker compose exec backend uv run pytest
```

**完全重置環境**：
```bash
# 停止並刪除所有資料（包含資料庫）
docker compose down -v

# 重新建置並啟動
docker compose up -d --build
```

### 資料庫遷移
```bash
cd backend

# 建立新遷移
uv run alembic revision --autogenerate -m "描述"

# 執行遷移
uv run alembic upgrade head

# 回滾遷移
uv run alembic downgrade -1
```

## Project Structure

```
auth_test/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI 應用入口
│   │   ├── config.py            # 環境變數設定
│   │   ├── database.py          # SQLAlchemy 設定
│   │   ├── models.py            # ORM 模型 (User, RefreshToken)
│   │   ├── schemas.py           # Pydantic schemas
│   │   ├── auth.py              # 認證邏輯 (JWT, bcrypt, refresh token)
│   │   ├── dependencies.py      # FastAPI dependencies
│   │   └── routers/
│   │       ├── auth.py          # 認證端點 (login, register, logout, refresh)
│   │       └── users.py         # 使用者端點 (/me)
│   ├── alembic/                 # 資料庫遷移
│   ├── pyproject.toml
│   └── .env                     # 環境變數 (需自行建立)
├── frontend/
│   ├── src/
│   │   ├── main.tsx             # React 入口
│   │   ├── App.tsx              # 路由設定
│   │   ├── components/          # UI 元件
│   │   ├── context/             # React Context (AuthContext)
│   │   ├── pages/               # 頁面元件
│   │   ├── services/            # API 服務 (api.ts, auth.ts)
│   │   ├── types/               # TypeScript 類型定義
│   │   └── utils/               # 工具函式 (errorHandler)
│   ├── package.json
│   └── vite.config.ts
├── docker-compose.yml           # PostgreSQL 容器
└── CLAUDE.md                    # 本檔案
```

## API Architecture

### API Versioning Strategy
專案採用版本化 API 設計，同時保留向後相容：

- **API v1** (`/api/v1/*`): RPC 風格端點（form-urlencoded login）
- **API v2** (`/api/v2/*`): RESTful 風格端點（JSON body, resource-oriented）
- **Legacy** (`/auth/*`, `/users/*`): 已標記為 deprecated，僅維持相容性

### API v1 Endpoints

**Authentication** (`/api/v1/auth`)
- `POST /register` - 註冊新使用者 (Rate Limit: 3/min)
- `POST /login` - 登入，使用 form-urlencoded (Rate Limit: 5/min)
- `POST /logout` - 登出 (撤銷 refresh token)
- `POST /refresh` - 刷新 access token (Rate Limit: 20/min)

**Users** (`/api/v1/users`)
- `GET /me` - 取得當前使用者資訊 (需認證)

### API v2 Endpoints (RESTful)

**Sessions** (`/api/v2/sessions`) - Resource-oriented 設計
- `POST /api/v2/sessions` - 建立 session (登入), 使用 JSON body (Rate Limit: 5/min)
- `DELETE /api/v2/sessions` - 刪除 session (登出)
- `POST /api/v2/sessions/refresh` - 刷新 session (Rate Limit: 20/min)

**Users** (`/api/v2/users`)
- `POST /api/v2/users` - 建立使用者 (註冊) (Rate Limit: 3/min)
- `GET /api/v2/users/me` - 取得當前使用者資訊 (需認證)

**Health**
- `GET /health` - 健康檢查（無版本前綴）

**重要差異**：
- v1 login 使用 `application/x-www-form-urlencoded`（OAuth2 相容）
- v2 sessions 使用 `application/json`（更符合現代 API 慣例）
- v2 採用 HTTP 動詞對應 CRUD 操作（POST 建立、DELETE 刪除）

## Security Features

### 已實作的安全機制
✅ **XSS 防護**：Access Token 與 Refresh Token 儲存於 HttpOnly Cookie（JavaScript 無法存取）
✅ **Token Rotation**：每次使用 Refresh Token 都會撤銷並發放新的
✅ **Race Condition 防護**：使用 `SELECT FOR UPDATE` 確保原子性驗證與撤銷
✅ **Rate Limiting**：登入/註冊/刷新端點有速率限制，防止暴力破解
✅ **Password Hashing**：bcrypt (2^12 rounds) + 自動加鹽
✅ **CSRF 防護**：Cookie SameSite 設定（生產環境 strict，開發環境 lax）
✅ **IP Spoofing 防護**：安全的 IP 取得機制（支援反向代理）
✅ **SQL Injection 防護**：SQLAlchemy ORM
✅ **Token 清理**：懶刪除機制防止資料庫累積過期 token
✅ **多 Tab 同步**：BroadcastChannel API 避免重複刷新
✅ **錯誤處理 UX**：Rate Limiting 倒數計時、專屬錯誤訊息

### Token 生命周期
- **Access Token**: 15 分鐘（HttpOnly Cookie）
- **Refresh Token**: 7 天（HttpOnly Cookie + 資料庫儲存）
- **自動刷新**: 前端 axios interceptor 自動處理 401 錯誤

### 環境設定
```bash
# backend/.env (範例)
DATABASE_URL=postgresql://postgres:password@localhost:5432/auth_test
SECRET_KEY=your-secret-key-min-32-chars  # 使用 openssl rand -hex 32 生成
ENVIRONMENT=development  # 或 production
TRUST_PROXY=false        # 如果使用反向代理設為 true
CORS_ORIGINS=http://localhost:5173
```

## Code Architecture Deep Dive

### Router 分層架構
FastAPI 路由採用多層架構，支援 API 版本化與向後相容：

```
app/main.py
├── api_v1 (APIRouter: prefix="/api/v1")
│   ├── auth.router (prefix="", tags=["Authentication"])
│   └── users.router (prefix="", tags=["Users"])
├── api_v2 (APIRouter: prefix="/api/v2")
│   ├── auth.router_v2 (prefix="/sessions", tags=["Sessions (v2)"])
│   └── users.router_v2 (prefix="/users", tags=["Users (v2)"])
└── Legacy routers (deprecated=True)
    ├── auth.router (直接掛載，無前綴)
    └── users.router (直接掛載，無前綴)
```

**設計原則**：
- **單一檔案多路由器**：`routers/auth.py` 同時匯出 `router` (v1) 和 `router_v2`
- **URL 結構**：
  - v1: `/api/v1/auth/login` (動詞導向)
  - v2: `/api/v2/sessions` (資源導向)
  - Legacy: `/auth/login` (向後相容)
- **標籤隔離**：不同版本使用不同 Swagger tags 避免混淆

### Token Rotation 資料流
```
1. 客戶端發送 refresh_token (HttpOnly Cookie)
2. verify_and_revoke_refresh_token(token, db):
   ├─ SELECT FOR UPDATE (行級鎖，防 race condition)
   ├─ 驗證 token 未過期且未撤銷
   ├─ 立即標記為 revoked=True (原子操作)
   └─ 回傳 user
3. create_refresh_token(user.id, db):
   ├─ 生成新 token (secrets.token_urlsafe)
   ├─ 插入資料庫 (expires_at = now + 7 days)
   └─ 懶刪除舊 token (WHERE expires_at < now)
4. 回傳新 access_token + refresh_token (HttpOnly Cookies)
```

**關鍵設計**：
- `SELECT FOR UPDATE` 避免多個請求同時使用同一 token
- 立即撤銷 (revoke) 而非刪除，保留審計記錄
- 懶刪除 (lazy cleanup) 避免每次操作都清理，降低資料庫負擔

### 前端錯誤處理架構
```
services/api.ts (axios interceptor)
├── Response Interceptor (401 錯誤)
│   ├─ 檢查 refreshing flag (防重複刷新)
│   ├─ BroadcastChannel 通知其他 Tab
│   ├─ 呼叫 /refresh 端點
│   └─ 重試原請求
└── Error Handler
    ├─ parseError(error) → 友善訊息
    └─ 特殊處理 429 (Rate Limit) → 倒數計時
```

**多 Tab 同步機制**：
- Tab A 觸發 401 → 設定 `isRefreshing = true` → 廣播 "token-refreshing"
- Tab B 收到廣播 → 等待 "token-refreshed" 事件
- Tab A 完成刷新 → 廣播 "token-refreshed" → Tab B 重試請求

## Development Guidelines

### 後端開發

**基本原則**：
- **所有指令必須使用 `uv run` 前綴**：`uv run uvicorn`, `uv run alembic`, `uv run python`
- **資料庫操作必須使用 Alembic**：不可直接修改資料庫 schema
- **新增端點必須加入 Rate Limiting**：使用 `@limiter.limit("N/minute")`
- **認證端點必須使用 HttpOnly Cookie**：不可回傳 token 於 JSON body
- **密碼處理必須使用 bcrypt**：不可使用其他 hash 演算法

**新增 API 端點 Checklist**：
1. **選擇 API 版本**：v1 (動詞導向) 或 v2 (RESTful)
2. **定義 Pydantic schemas**：在 `schemas.py` 新增 request/response models
3. **實作路由函式**：
   - v1: 新增至 `routers/auth.py::router` 或 `routers/users.py::router`
   - v2: 新增至 `routers/auth.py::router_v2` 或 `routers/users.py::router_v2`
4. **加入 Rate Limiting**：敏感端點（登入、註冊）必須限制
5. **撰寫測試**：在 `tests/test_routers_*.py` 新增測試案例
6. **更新文件**：更新本檔案的 API Endpoints 章節

**範例 - 新增 v2 端點**：
```python
# backend/app/schemas.py
class PasswordResetRequest(BaseModel):
    email: EmailStr

# backend/app/routers/users.py
@router_v2.post("/password-reset")
@limiter.limit("3/hour")
def request_password_reset(
    request: Request,
    data: PasswordResetRequest,
    db: Session = Depends(get_db)
):
    # 實作邏輯
    pass
```

### 前端開發

**基本原則**：
- **API 呼叫必須使用 `services/api.ts`**：自動處理 Cookie 與 token refresh
- **錯誤處理必須使用 `utils/errorHandler.ts`**：統一錯誤訊息格式
- **不可使用 localStorage 儲存 token**：安全性風險
- **表單錯誤必須顯示使用者友善訊息**：使用 `parseError()` 函式

**新增 React 元件 Checklist**：
1. **使用 TypeScript**：定義 Props 和 State 類型
2. **使用 AuthContext**：需認證的元件透過 `useAuth()` 取得使用者狀態
3. **錯誤處理**：使用 try-catch 包裹 API 呼叫，使用 `parseError()` 處理錯誤
4. **撰寫測試**：在同目錄建立 `*.test.tsx` 檔案，使用 vitest + testing-library
5. **表單驗證**：客戶端驗證（即時回饋）+ 伺服器端驗證（最終驗證）

**範例 - 新增受保護的頁面**：
```typescript
// src/pages/ProfilePage.tsx
import { useAuth } from '../context/AuthContext';

export default function ProfilePage() {
  const { user } = useAuth();

  if (!user) {
    return <Navigate to="/login" />;
  }

  // 實作頁面邏輯
}
```

### Linus "Good Taste" 檢查清單
- ✅ 資料結構優先：RefreshToken 模型、BroadcastChannel 消除邊界情況
- ✅ 避免邊界情況：Token Rotation 消除重放攻擊、HttpOnly 消除 XSS
- ✅ 實用性優於純粹性：保留舊端點向後相容、使用 slowapi 而非自建
- ✅ 保持簡單：Refresh Token 僅 3 個函式、自動刷新封裝於單一 interceptor

## Testing

### 後端測試 (pytest)

```bash
cd backend

# 執行所有測試
uv run pytest

# 執行特定測試檔案
uv run pytest tests/test_auth.py

# 執行特定測試函式
uv run pytest tests/test_routers_auth.py::test_register_success

# 生成覆蓋率報告
uv run pytest --cov=app --cov-report=html
# 報告位於 htmlcov/index.html

# 顯示詳細輸出
uv run pytest -v -s
```

**測試結構**：
- `tests/conftest.py` - pytest fixtures（測試資料庫、client）
- `tests/test_auth.py` - 認證邏輯單元測試
- `tests/test_routers_auth.py` - 認證端點整合測試
- `tests/test_routers_users.py` - 使用者端點整合測試

### 前端測試 (vitest)

```bash
cd frontend

# 執行所有測試
npm test

# 監視模式（開發時使用）
npm run test

# 生成覆蓋率報告
npm run test:coverage

# 使用 UI 介面
npm run test:ui
```

**測試檔案**：
- `src/components/LoginForm.test.tsx` - 登入表單元件測試
- `src/components/RegisterForm.test.tsx` - 註冊表單元件測試
- `src/services/api.test.ts` - API service 測試
- `src/utils/errorHandler.test.ts` - 錯誤處理工具測試

### 手動 API 測試

**測試 API v1 (form-urlencoded)**：
```bash
# 1. 註冊新使用者
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "testpass123"}'

# 2. 登入並儲存 Cookie
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test@example.com&password=testpass123" \
  -c cookies.txt -v

# 3. 存取受保護端點
curl http://localhost:8000/api/v1/users/me -b cookies.txt

# 4. 刷新 token
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -b cookies.txt -c cookies.txt -v

# 5. 登出
curl -X POST http://localhost:8000/api/v1/auth/logout \
  -b cookies.txt
```

**測試 API v2 (JSON)**：
```bash
# 1. 註冊新使用者
curl -X POST http://localhost:8000/api/v2/users \
  -H "Content-Type: application/json" \
  -d '{"email": "test2@example.com", "password": "testpass123"}'

# 2. 建立 session (登入)
curl -X POST http://localhost:8000/api/v2/sessions \
  -H "Content-Type: application/json" \
  -d '{"email": "test2@example.com", "password": "testpass123"}' \
  -c cookies.txt -v

# 3. 存取受保護端點
curl http://localhost:8000/api/v2/users/me -b cookies.txt

# 4. 刷新 session
curl -X POST http://localhost:8000/api/v2/sessions/refresh \
  -b cookies.txt -c cookies.txt

# 5. 刪除 session (登出)
curl -X DELETE http://localhost:8000/api/v2/sessions \
  -b cookies.txt
```

### Rate Limiting 測試
```bash
# 快速連續呼叫 6 次（超過 5/min 限制）
for i in {1..6}; do
  curl -X POST http://localhost:8000/api/v1/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test@example.com&password=wrong" \
    -w "\nStatus: %{http_code}\n"
done
# 第 6 次應返回 429 Too Many Requests
```

### 前端整合測試場景
- **多 Tab 測試**：開啟多個 Tab 同時觸發 401，驗證只有一個 Tab 刷新 token
- **Rate Limiting UX**：連續登入失敗 6 次，驗證倒數計時顯示
- **錯誤訊息**：測試不同錯誤（401, 400, 429, 500）顯示專屬訊息
- **Token 自動刷新**：等待 15 分鐘後操作，驗證自動刷新機制

## Known Issues & Limitations

### 已實作的功能（v1.0+）
- ✅ XSS 風險（localStorage）→ 改用 HttpOnly Cookie
- ✅ 無 Refresh Token → 實作 7 天 Refresh Token + Rotation
- ✅ 無 Rate Limiting → 使用 slowapi 實作
- ✅ Logout 未撤銷 token → 新增資料庫撤銷邏輯
- ✅ Cookie Secure 硬編碼 → 環境變數控制
- ✅ IP Spoofing 風險 → 安全 IP 取得函式
- ✅ Race Condition → SELECT FOR UPDATE 鎖定
- ✅ Token 累積 → 懶刪除機制
- ✅ 多 Tab 重複刷新 → BroadcastChannel 同步
- ✅ 錯誤訊息不友善 → errorHandler utility
- ✅ Docker 容器化部署 → 完整的 multi-service docker-compose
- ✅ RESTful API v2 → Resource-oriented endpoints
- ✅ 測試框架 → pytest (後端) + vitest (前端)

### 當前限制
- 無 CI/CD pipeline（GitHub Actions 或類似）
- 無監控與日誌系統（Sentry, Prometheus 等）
- 無 2FA/TOTP 多因素認證
- 無 Email 驗證功能
- 無密碼重設功能
- 前端測試覆蓋率有限（僅核心元件）
- 無 E2E 測試（Playwright, Cypress）

## Troubleshooting

### 後端無法啟動
```bash
# 檢查資料庫是否運行
docker compose ps

# 檢查環境變數
cat backend/.env

# 重新建立虛擬環境
cd backend
uv sync
```

### 前端無法連線後端
```bash
# 檢查 CORS 設定
grep CORS_ORIGINS backend/.env

# 檢查 Vite proxy 設定
cat frontend/vite.config.ts
```

### Alembic 遷移失敗
```bash
# 檢查當前版本
uv run alembic current

# 查看遷移歷史
uv run alembic history

# 重設資料庫（開發環境）
docker compose down -v
docker compose up -d
uv run alembic upgrade head
```

## References

- **FastAPI 文件**: https://fastapi.tiangolo.com/
- **SQLAlchemy 2.0**: https://docs.sqlalchemy.org/en/20/
- **JWT Best Practices**: https://datatracker.ietf.org/doc/html/rfc8725
- **OAuth 2.1 (Token Rotation)**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-09
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
