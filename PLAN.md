# 登入系統樣板專案開發計畫

## 專案目標

建立一個最小化但完整的使用者認證系統樣板，包含：
- 使用者註冊與登入功能
- 基於 JWT 的無狀態認證機制
- 前後端分離架構
- Docker 容器化部署

## 技術堆疊

### 後端
- **框架**：FastAPI (Python 3.12+)
- **認證**：JWT (HS256 演算法，24 小時有效期)
- **密碼雜湊**：bcrypt
- **資料庫**：PostgreSQL 15+
- **ORM**：SQLAlchemy 2.0+
- **遷移工具**：Alembic
- **ASGI 伺服器**：Uvicorn

### 前端
- **框架**：React 18+
- **語言**：TypeScript
- **建構工具**：Vite
- **路由**：React Router v6
- **狀態管理**：Context API (AuthContext)
- **HTTP 客戶端**：Axios
- **表單處理**：手動處理（無額外函式庫）

### 基礎設施
- **容器化**：Docker + Docker Compose
- **環境變數管理**：.env 檔案

## 專案架構

### Monorepo 結構

```
auth_test/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI 應用程式入口
│   │   ├── config.py            # 配置管理（環境變數）
│   │   ├── database.py          # 資料庫連線設定
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── user.py          # User SQLAlchemy 模型
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── user.py          # Pydantic schemas (UserCreate, UserResponse)
│   │   │   └── auth.py          # Token schemas (Token, TokenData)
│   │   ├── routers/
│   │   │   ├── __init__.py
│   │   │   └── auth.py          # 認證端點 (註冊、登入)
│   │   ├── dependencies/
│   │   │   ├── __init__.py
│   │   │   └── auth.py          # JWT 驗證依賴
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── security.py      # 密碼雜湊、JWT 工具
│   │       └── exceptions.py    # 自訂例外類別
│   ├── alembic/
│   │   ├── versions/            # 資料庫遷移腳本
│   │   └── env.py
│   ├── alembic.ini
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── main.tsx             # 應用程式入口
│   │   ├── App.tsx              # 根元件
│   │   ├── contexts/
│   │   │   └── AuthContext.tsx # 認證狀態管理
│   │   ├── components/
│   │   │   ├── PrivateRoute.tsx    # 路由保護元件
│   │   │   ├── LoginForm.tsx       # 登入表單
│   │   │   └── RegisterForm.tsx    # 註冊表單
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx       # 登入頁面
│   │   │   ├── RegisterPage.tsx    # 註冊頁面
│   │   │   ├── DashboardPage.tsx   # 受保護的儀表板
│   │   │   └── HomePage.tsx        # 首頁
│   │   ├── services/
│   │   │   └── api.ts              # Axios 實例與 API 呼叫
│   │   ├── types/
│   │   │   └── auth.ts             # TypeScript 型別定義
│   │   └── utils/
│   │       └── token.ts            # Token 儲存與取得工具
│   ├── public/
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   ├── Dockerfile
│   └── .env.example
├── docker-compose.yml
├── .gitignore
├── PLAN.md                      # 本文件
└── README.md
```

## 詳細實作步驟

### 步驟 1：專案基礎設定

#### 1.1 建立專案結構
```bash
mkdir -p backend/app/{models,schemas,routers,dependencies,utils}
mkdir -p backend/alembic/versions
mkdir -p frontend/src/{contexts,components,pages,services,types,utils}
mkdir -p frontend/public
```

#### 1.2 建立 .gitignore
```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
.env
venv/
*.db

# Node
node_modules/
dist/
.env.local

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
```

### 步驟 2：後端實作

#### 2.1 設定依賴 (backend/requirements.txt)
```
fastapi==0.109.0
uvicorn[standard]==0.27.0
sqlalchemy==2.0.25
alembic==1.13.1
psycopg2-binary==2.9.9
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
pydantic-settings==2.1.0
python-dotenv==1.0.0
```

#### 2.2 配置管理 (backend/app/config.py)
- 使用 Pydantic Settings
- 環境變數：
  - `DATABASE_URL`: PostgreSQL 連線字串
  - `SECRET_KEY`: JWT 簽名金鑰
  - `ALGORITHM`: "HS256"
  - `ACCESS_TOKEN_EXPIRE_HOURS`: 24
  - `CORS_ORIGINS`: "http://localhost:5173"

#### 2.3 資料庫設定 (backend/app/database.py)
- SQLAlchemy engine 和 session 工廠
- Base declarative class
- `get_db()` 依賴函數

#### 2.4 User 模型 (backend/app/models/user.py)
```python
class User(Base):
    __tablename__ = "users"

    id: int (主鍵，自動遞增)
    email: str (唯一，索引)
    username: str (唯一，索引)
    hashed_password: str
    created_at: datetime (預設為當前時間)
    is_active: bool (預設為 True)
```

#### 2.5 Pydantic Schemas
- **user.py**: `UserCreate`, `UserResponse`
- **auth.py**: `Token`, `TokenData`, `LoginRequest`

#### 2.6 安全工具 (backend/app/utils/security.py)
- `hash_password(password: str) -> str`: 使用 bcrypt
- `verify_password(plain: str, hashed: str) -> bool`
- `create_access_token(data: dict) -> str`: 建立 JWT
- `decode_access_token(token: str) -> TokenData`: 驗證並解碼 JWT

#### 2.7 認證依賴 (backend/app/dependencies/auth.py)
- `get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User`
- 從 Authorization header 取得 token
- 驗證 token 並從資料庫載入使用者

#### 2.8 認證路由 (backend/app/routers/auth.py)

**端點清單：**

| 方法 | 路徑 | 描述 | 請求 Body | 回應 |
|------|------|------|-----------|------|
| POST | `/auth/register` | 註冊新使用者 | `UserCreate` | `UserResponse` |
| POST | `/auth/login` | 使用者登入 | `LoginRequest` | `Token` |
| GET | `/auth/me` | 取得當前使用者資訊 | - | `UserResponse` |

**商業邏輯：**
- **註冊**：
  - 驗證 email 和 username 唯一性
  - 雜湊密碼
  - 建立使用者記錄
  - 回傳使用者資訊（不含密碼）

- **登入**：
  - 驗證 email/username 存在
  - 驗證密碼
  - 產生 JWT token
  - 回傳 `{"access_token": "...", "token_type": "bearer"}`

- **取得當前使用者**：
  - 需要有效的 JWT token
  - 回傳已認證使用者的資訊

#### 2.9 FastAPI 主應用程式 (backend/app/main.py)
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Auth API")

# CORS 設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 註冊路由
app.include_router(auth_router, prefix="/auth", tags=["auth"])

# 健康檢查端點
@app.get("/health")
def health_check():
    return {"status": "ok"}
```

#### 2.10 Alembic 設定
- 初始化：`alembic init alembic`
- 修改 `alembic.ini` 和 `alembic/env.py` 以使用環境變數中的 DATABASE_URL
- 建立初始遷移：`alembic revision --autogenerate -m "Create users table"`
- 執行遷移：`alembic upgrade head`

#### 2.11 Dockerfile (backend/Dockerfile)
```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

### 步驟 3：前端實作

#### 3.1 初始化專案
```bash
cd frontend
npm create vite@latest . -- --template react-ts
npm install
npm install react-router-dom axios
npm install -D @types/react-router-dom
```

#### 3.2 TypeScript 型別定義 (src/types/auth.ts)
```typescript
export interface User {
  id: number;
  email: string;
  username: string;
  created_at: string;
  is_active: boolean;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  register: (data: RegisterRequest) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  loading: boolean;
}
```

#### 3.3 Token 工具 (src/utils/token.ts)
```typescript
export const setToken = (token: string) => {
  localStorage.setItem('access_token', token);
};

export const getToken = (): string | null => {
  return localStorage.getItem('access_token');
};

export const removeToken = () => {
  localStorage.removeItem('access_token');
};
```

#### 3.4 API 服務 (src/services/api.ts)
```typescript
import axios from 'axios';
import { getToken } from '../utils/token';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
});

// 請求攔截器：自動附加 token
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authAPI = {
  register: (data: RegisterRequest) => api.post('/auth/register', data),
  login: (data: LoginRequest) => api.post('/auth/login', data),
  getCurrentUser: () => api.get('/auth/me'),
};

export default api;
```

#### 3.5 AuthContext (src/contexts/AuthContext.tsx)
- 使用 `createContext` 和 `useContext`
- 狀態：`user`, `loading`
- 方法：`login`, `register`, `logout`
- 初始化時從 localStorage 檢查 token 並載入使用者資訊
- Provider 包裝整個應用程式

#### 3.6 PrivateRoute 元件 (src/components/PrivateRoute.tsx)
```typescript
const PrivateRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) return <div>載入中...</div>;

  return isAuthenticated ? children : <Navigate to="/login" />;
};
```

#### 3.7 表單元件
- **RegisterForm.tsx**: email, username, password 欄位
- **LoginForm.tsx**: email, password 欄位
- 兩者都包含基本的客戶端驗證和錯誤處理

#### 3.8 頁面元件
- **HomePage.tsx**: 公開首頁，顯示登入/註冊連結
- **LoginPage.tsx**: 包含 LoginForm
- **RegisterPage.tsx**: 包含 RegisterForm
- **DashboardPage.tsx**: 受保護頁面，顯示使用者資訊和登出按鈕

#### 3.9 路由設定 (src/App.tsx)
```typescript
<BrowserRouter>
  <Routes>
    <Route path="/" element={<HomePage />} />
    <Route path="/login" element={<LoginPage />} />
    <Route path="/register" element={<RegisterPage />} />
    <Route
      path="/dashboard"
      element={
        <PrivateRoute>
          <DashboardPage />
        </PrivateRoute>
      }
    />
  </Routes>
</BrowserRouter>
```

#### 3.10 環境變數 (frontend/.env.example)
```
VITE_API_URL=http://localhost:8000
```

#### 3.11 Dockerfile (frontend/Dockerfile)
```dockerfile
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
```

#### 3.12 Vite 設定 (vite.config.ts)
```typescript
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    watch: {
      usePolling: true, // Docker 環境下需要
    },
  },
});
```

### 步驟 4：Docker 配置

#### 4.1 docker-compose.yml
```yaml
version: '3.8'

services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: authuser
      POSTGRES_PASSWORD: authpass
      POSTGRES_DB: authdb
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authuser"]
      interval: 5s
      timeout: 5s
      retries: 5

  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://authuser:authpass@db:5432/authdb
      SECRET_KEY: your-secret-key-change-in-production
      ALGORITHM: HS256
      ACCESS_TOKEN_EXPIRE_HOURS: 24
      CORS_ORIGINS: http://localhost:5173
    volumes:
      - ./backend:/app
    depends_on:
      db:
        condition: service_healthy
    command: >
      sh -c "alembic upgrade head &&
             uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

  frontend:
    build: ./frontend
    ports:
      - "5173:5173"
    environment:
      VITE_API_URL: http://localhost:8000
    volumes:
      - ./frontend:/app
      - /app/node_modules
    depends_on:
      - backend

volumes:
  postgres_data:
```

#### 4.2 啟動與停止
```bash
# 啟動所有服務
docker-compose up -d

# 查看日誌
docker-compose logs -f

# 停止所有服務
docker-compose down

# 停止並移除資料庫資料
docker-compose down -v
```

## 驗證步驟

### 1. 後端 API 測試

#### 使用 curl 或 Postman 測試：

```bash
# 健康檢查
curl http://localhost:8000/health

# 註冊新使用者
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "SecurePass123"
  }'

# 登入
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123"
  }'

# 取得當前使用者 (需替換 YOUR_TOKEN)
curl http://localhost:8000/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**預期結果：**
- 註冊成功回傳使用者資訊（不含密碼）
- 登入成功回傳 JWT token
- `/auth/me` 使用有效 token 可取得使用者資訊
- `/auth/me` 使用無效 token 回傳 401 錯誤

### 2. 前端功能測試

1. **訪問首頁** (`http://localhost:5173`)
   - 應顯示登入和註冊連結

2. **註冊流程**
   - 點擊註冊連結
   - 填寫 email, username, password
   - 送出表單
   - 應自動登入並導向儀表板

3. **登入流程**
   - 登出後返回登入頁面
   - 使用已註冊的帳號登入
   - 應導向儀表板

4. **受保護路由**
   - 未登入狀態訪問 `/dashboard` 應導向登入頁
   - 登入後可正常訪問儀表板
   - 儀表板顯示使用者資訊

5. **登出功能**
   - 點擊登出按鈕
   - Token 應從 localStorage 移除
   - 應導向首頁或登入頁

6. **Token 持久化**
   - 登入後重新整理頁面
   - 應保持登入狀態
   - 關閉瀏覽器後重新開啟，24 小時內應仍為登入狀態

### 3. 資料庫驗證

```bash
# 連線到資料庫容器
docker-compose exec db psql -U authuser -d authdb

# 查看使用者表
\dt
SELECT * FROM users;

# 確認密碼已雜湊
# 確認 email 和 username 唯一性約束
```

### 4. 錯誤處理驗證

- 重複 email 註冊應回傳 400 錯誤
- 重複 username 註冊應回傳 400 錯誤
- 錯誤密碼登入應回傳 401 錯誤
- 無效 token 訪問 `/auth/me` 應回傳 401 錯誤
- 過期 token 應回傳 401 錯誤（需等待 24 小時或手動修改有效期測試）

## 安全性注意事項

### 開發環境

1. **環境變數**
   - 絕不將 `.env` 檔案提交到版本控制
   - 使用 `.env.example` 作為模板
   - `SECRET_KEY` 使用強隨機字串（建議 32 bytes）

2. **CORS 設定**
   - 開發環境限制為 `http://localhost:5173`
   - 生產環境應設定為實際前端域名

3. **密碼政策**
   - 後端應加入密碼強度驗證（最小長度、複雜度）
   - 前端提供即時密碼強度反饋

4. **資料庫**
   - 開發環境可使用簡單密碼
   - 生產環境必須使用強密碼
   - 使用專用資料庫使用者，僅授予必要權限

### 生產環境建議

1. **HTTPS**
   - 強制使用 HTTPS
   - 設定 HSTS header
   - Token 僅在 HTTPS 下傳輸

2. **Token 安全**
   - 縮短 token 有效期（建議 15 分鐘）
   - 實作 refresh token 機制
   - 考慮使用 httpOnly cookies 而非 localStorage

3. **Rate Limiting**
   - 登入端點限制嘗試次數（如 5 次/分鐘）
   - 註冊端點防止大量建立帳號
   - 使用 slowapi 或 nginx rate limiting

4. **輸入驗證**
   - 後端完整驗證所有輸入
   - 防止 SQL injection（使用 ORM 已大幅降低風險）
   - 防止 XSS 攻擊（前端適當 escape）

5. **監控與日誌**
   - 記錄所有認證嘗試
   - 監控異常登入行為
   - 定期審計安全日誌

## 常見問題與解決方案

### 1. CORS 錯誤
**症狀**：前端無法呼叫後端 API，瀏覽器 console 顯示 CORS 錯誤

**解決**：
- 確認 `backend/app/main.py` 中 CORS 設定包含前端 URL
- 確認 `allow_credentials=True`
- 檢查 `allow_methods` 和 `allow_headers` 設定

### 2. Token 無法通過驗證
**症狀**：`/auth/me` 回傳 401 錯誤

**解決**：
- 確認 `SECRET_KEY` 前後端一致
- 檢查 token 格式是否為 `Bearer <token>`
- 使用 jwt.io 解碼 token 檢查內容和有效期
- 確認時區設定正確（token 過期時間）

### 3. 資料庫連線失敗
**症狀**：後端無法啟動，錯誤訊息顯示無法連線資料庫

**解決**：
- 確認 `docker-compose.yml` 中 `depends_on` 設定包含 healthcheck
- 檢查 `DATABASE_URL` 環境變數正確
- 使用 `docker-compose logs db` 查看資料庫日誌
- 確認資料庫容器已完全啟動

### 4. Alembic 遷移失敗
**症狀**：後端啟動時 `alembic upgrade head` 失敗

**解決**：
- 檢查 `alembic/env.py` 中 `target_metadata` 設定
- 確認 `alembic.ini` 中資料庫 URL 設定
- 手動執行 `docker-compose exec backend alembic upgrade head` 查看詳細錯誤
- 必要時重置資料庫：`docker-compose down -v` 後重新啟動

### 5. 前端 Hot Reload 在 Docker 中不工作
**症狀**：修改前端程式碼後瀏覽器不自動更新

**解決**：
- 確認 `vite.config.ts` 中設定 `watch.usePolling: true`
- 確認 `docker-compose.yml` 中正確掛載 volumes
- 排除 `node_modules` 避免衝突：`- /app/node_modules`

## 擴展建議

### 短期擴展（1-2 週內可實作）

1. **Refresh Token 機制**
   - 縮短 access token 有效期至 15 分鐘
   - 實作 refresh token（有效期 7 天）
   - 新增 `/auth/refresh` 端點
   - 前端自動刷新 token 機制

2. **密碼重置功能**
   - 新增「忘記密碼」流程
   - 產生重置 token（email 或 SMS）
   - 實作重置密碼端點
   - 前端重置密碼頁面

3. **Email 驗證**
   - 註冊後發送驗證信
   - 新增 `email_verified` 欄位
   - 未驗證使用者功能限制
   - 重新發送驗證信功能

4. **使用者個人資料管理**
   - 新增個人資料欄位（姓名、頭像等）
   - 實作更新個人資料端點
   - 修改密碼功能
   - 刪除帳號功能

### 中期擴展（1-2 個月）

5. **角色與權限系統**
   - 新增 `Role` 和 `Permission` 模型
   - 實作 RBAC（Role-Based Access Control）
   - 管理員後台介面
   - 權限檢查裝飾器

6. **OAuth2 社群登入**
   - Google OAuth2 整合
   - GitHub OAuth2 整合
   - Facebook/Twitter 登入
   - 帳號綁定功能

7. **進階安全功能**
   - 雙因素認證（2FA/TOTP）
   - 登入歷史記錄
   - 裝置管理（記住此裝置）
   - 可疑活動通知

8. **API Rate Limiting**
   - 使用 slowapi 或 Redis
   - 不同端點不同限制
   - IP-based 和 user-based 限制
   - 超限回傳 429 錯誤

### 長期擴展（3+ 個月）

9. **微服務架構**
   - 拆分認證服務
   - 使用 Redis 作為 session store
   - 服務間認證（API Gateway）
   - 分散式追蹤（OpenTelemetry）

10. **測試覆蓋**
    - 後端單元測試（pytest）
    - 前端單元測試（Vitest）
    - E2E 測試（Playwright/Cypress）
    - CI/CD 整合

11. **效能優化**
    - Redis 快取使用者資訊
    - 資料庫查詢優化（索引）
    - CDN 整合
    - 負載平衡

12. **監控與日誌**
    - 結構化日誌（JSON format）
    - 集中式日誌管理（ELK/Loki）
    - 效能監控（Prometheus + Grafana）
    - 錯誤追蹤（Sentry）

## 開發時程建議

| 階段 | 時間 | 任務 |
|------|------|------|
| 第 1 天 | 2-4 小時 | 專案結構建立、後端基礎設定、資料庫模型 |
| 第 2 天 | 3-5 小時 | 後端認證邏輯、JWT 實作、API 端點 |
| 第 3 天 | 2-3 小時 | Alembic 遷移、Docker 配置、後端測試 |
| 第 4 天 | 3-5 小時 | 前端專案初始化、AuthContext、API 服務 |
| 第 5 天 | 3-5 小時 | 前端表單、頁面、路由設定 |
| 第 6 天 | 2-4 小時 | 前端 Docker 配置、整合測試、錯誤處理 |
| 第 7 天 | 2-3 小時 | 文件撰寫、程式碼清理、最終驗證 |

**總計**：約 17-29 小時（依經驗程度而定）

## 參考資源

### 官方文件
- [FastAPI 文件](https://fastapi.tiangolo.com/)
- [SQLAlchemy 2.0 文件](https://docs.sqlalchemy.org/en/20/)
- [Alembic 文件](https://alembic.sqlalchemy.org/)
- [React 文件](https://react.dev/)
- [Vite 文件](https://vitejs.dev/)
- [React Router 文件](https://reactrouter.com/)

### 安全性資源
- [OWASP 認證備忘單](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT 最佳實踐](https://datatracker.ietf.org/doc/html/rfc8725)
- [bcrypt 密碼雜湊](https://github.com/pyca/bcrypt/)

### Docker
- [Docker Compose 文件](https://docs.docker.com/compose/)
- [Multi-stage builds 最佳實踐](https://docs.docker.com/build/building/multi-stage/)

## 授權

本樣板專案建議使用 MIT License，允許自由使用、修改和分發。

---

**文件版本**：1.0
**最後更新**：2026-01-22
**維護者**：開發團隊
