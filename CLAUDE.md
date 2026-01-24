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

## API Endpoints

### Authentication (API v1)
- `POST /api/v1/auth/register` - 註冊新使用者 (Rate Limit: 3/min)
- `POST /api/v1/auth/login` - 登入 (設定 HttpOnly Cookie) (Rate Limit: 5/min)
- `POST /api/v1/auth/logout` - 登出 (撤銷 refresh token)
- `POST /api/v1/auth/refresh` - 刷新 access token (Token Rotation) (Rate Limit: 20/min)

### Users (API v1)
- `GET /api/v1/users/me` - 取得當前使用者資訊 (需認證)

### Health
- `GET /health` - 健康檢查

**注意**：舊的 `/auth/*` 和 `/users/*` 端點已標記為 deprecated，請使用 `/api/v1/*` 版本。

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

## Development Guidelines

### 後端開發
- **所有指令必須使用 `uv run` 前綴**：`uv run uvicorn`, `uv run alembic`, `uv run python`
- **資料庫操作必須使用 Alembic**：不可直接修改資料庫 schema
- **新增端點必須加入 Rate Limiting**：使用 `@limiter.limit("N/minute")`
- **認證端點必須使用 HttpOnly Cookie**：不可回傳 token 於 JSON body
- **密碼處理必須使用 bcrypt**：不可使用其他 hash 演算法

### 前端開發
- **API 呼叫必須使用 `services/api.ts`**：自動處理 Cookie 與 token refresh
- **錯誤處理必須使用 `utils/errorHandler.ts`**：統一錯誤訊息格式
- **不可使用 localStorage 儲存 token**：安全性風險
- **表單錯誤必須顯示使用者友善訊息**：使用 `parseError()` 函式

### Linus "Good Taste" 檢查清單
- ✅ 資料結構優先：RefreshToken 模型、BroadcastChannel 消除邊界情況
- ✅ 避免邊界情況：Token Rotation 消除重放攻擊、HttpOnly 消除 XSS
- ✅ 實用性優於純粹性：保留舊端點向後相容、使用 slowapi 而非自建
- ✅ 保持簡單：Refresh Token 僅 3 個函式、自動刷新封裝於單一 interceptor

## Testing

### 手動測試流程
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

### 前端測試
- **多 Tab 測試**：開啟多個 Tab 同時觸發 401，驗證只有一個 Tab 刷新 token
- **Rate Limiting UX**：連續登入失敗 6 次，驗證倒數計時顯示
- **錯誤訊息**：測試不同錯誤（401, 400, 429, 500）顯示專屬訊息

## Known Issues & Limitations

### 已修正的問題（v1.0）
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

### 當前限制
- 無單元測試與整合測試
- 無 Docker 容器化部署（僅資料庫使用 Docker）
- 無 CI/CD pipeline
- 無監控與日誌系統
- 無 2FA/TOTP 多因素認證
- 無 Email 驗證功能
- 無密碼重設功能

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
