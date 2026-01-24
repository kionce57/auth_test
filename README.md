# 🔐 Auth Test - Full-Stack 認證系統

一個採用業界最佳實踐的 Full-Stack 認證系統示範專案。

## 技術棧

| 層級     | 技術                                                   |
| -------- | ------------------------------------------------------ |
| **後端** | FastAPI + PostgreSQL + SQLAlchemy + Alembic            |
| **前端** | React 18 + TypeScript + Vite                           |
| **認證** | JWT (Access Token) + Refresh Token with Token Rotation |
| **安全** | HttpOnly Cookie, Rate Limiting, CORS, bcrypt           |

---

## 🚀 快速開始

### 前置需求

- Python 3.12+
- Node.js 18+
- Docker & Docker Compose
- [uv](https://github.com/astral-sh/uv) (Python 套件管理)

### 1. 啟動資料庫

```bash
docker compose up -d
```

### 2. 後端設定

```bash
cd backend

# 安裝相依套件
uv sync

# 建立環境變數檔
cp .env.example .env  # 或手動建立

# 執行資料庫遷移
uv run alembic upgrade head

# 啟動後端伺服器
uv run uvicorn app.main:app --reload --port 8000
```

**`.env` 範例**：

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/auth_test
SECRET_KEY=your-secret-key-min-32-chars
ENVIRONMENT=development
CORS_ORIGINS=http://localhost:5173
```

> 💡 生產環境請使用 `openssl rand -hex 32` 生成 SECRET_KEY

### 3. 前端設定

```bash
cd frontend

# 安裝相依套件
npm install

# 啟動開發伺服器
npm run dev
```

### 4. 訪問應用

| 服務          | 網址                         |
| ------------- | ---------------------------- |
| 前端          | http://localhost:5173        |
| 後端 API 文件 | http://localhost:8000/docs   |
| 健康檢查      | http://localhost:8000/health |

---

## 🧪 功能測試

### 使用 cURL 測試 API

```bash
# 1. 註冊新使用者
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "testpass123"}'

# 2. 登入（儲存 Cookie 到檔案）
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test@example.com&password=testpass123" \
  -c cookies.txt -v

# 3. 取得當前使用者資訊（受保護端點）
curl http://localhost:8000/api/v1/users/me -b cookies.txt

# 4. 刷新 Token
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -b cookies.txt -c cookies.txt

# 5. 登出
curl -X POST http://localhost:8000/api/v1/auth/logout -b cookies.txt
```

### 測試 Rate Limiting

```bash
# 快速連續嘗試登入 6 次（超過 5/min 限制）
for i in {1..6}; do
  curl -X POST http://localhost:8000/api/v1/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test@example.com&password=wrong" \
    -w "\nStatus: %{http_code}\n"
done
# 第 6 次應返回 429 Too Many Requests
```

### 前端測試

1. 開啟 http://localhost:5173
2. 點擊「註冊」建立帳號
3. 登入後會自動跳轉到 Dashboard
4. 開多個 Tab 測試多分頁同步
5. 等待 15 分鐘測試 Token 自動刷新

---

## 📚 API 端點

### Authentication (`/api/v1/auth`)

| 方法 | 端點        | 說明         | Rate Limit |
| ---- | ----------- | ------------ | ---------- |
| POST | `/register` | 註冊新使用者 | 3/min      |
| POST | `/login`    | 登入         | 5/min      |
| POST | `/logout`   | 登出         | -          |
| POST | `/refresh`  | 刷新 Token   | 20/min     |

### Users (`/api/v1/users`)

| 方法 | 端點  | 說明           | 需認證 |
| ---- | ----- | -------------- | ------ |
| GET  | `/me` | 取得當前使用者 | ✅     |

---

## 🔒 安全特性

- ✅ HttpOnly Cookie（防 XSS）
- ✅ Token Rotation（防重放攻擊）
- ✅ Rate Limiting（防暴力破解）
- ✅ bcrypt 密碼雜湊
- ✅ SameSite Cookie（防 CSRF）
- ✅ SELECT FOR UPDATE（防 Race Condition）

---

## 📖 延伸閱讀

- [AUTH_TUTORIAL.md](docs/AUTH_TUTORIAL.md) - 詳細教學文件
- [CLAUDE.md](CLAUDE.md) - 開發指南
- [ROADMAP.md](ROADMAP.md) - 開發路線圖
