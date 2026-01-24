# 🔐 帳號登入系統開發教學

> **目標讀者**：Junior Engineer，想從零開始理解並實作一個安全的認證系統
> **使用專案**：`auth_test` — 一個採用業界最佳實踐的 Full-stack 認證系統

---

## 📚 目錄

1. [系統架構概覽](#1-系統架構概覽)
2. [核心概念](#2-核心概念)
3. [後端實作詳解](#3-後端實作詳解)
4. [前端實作詳解](#4-前端實作詳解)
5. [安全機制深入](#5-安全機制深入)
6. [實作流程圖](#6-實作流程圖)
7. [動手練習](#7-動手練習)
8. [常見錯誤與除錯](#8-常見錯誤與除錯)
9. [延伸學習](#9-延伸學習)

---

## 1. 系統架構概覽

### 技術棧

| 層級         | 技術選擇              | 用途                   |
| ------------ | --------------------- | ---------------------- |
| **後端 API** | FastAPI               | 高效能 Python Web 框架 |
| **資料庫**   | PostgreSQL            | 關聯式資料庫           |
| **ORM**      | SQLAlchemy 2.0        | 資料庫物件映射         |
| **遷移工具** | Alembic               | 資料庫版本控制         |
| **前端框架** | React 18 + TypeScript | UI 層                  |
| **建置工具** | Vite                  | 快速開發伺服器         |
| **路由**     | React Router          | 前端路由               |

### 專案結構

```mermaid
graph TB
    subgraph Frontend["🎨 Frontend (React + TypeScript)"]
        UI[UI Components]
        Context[AuthContext]
        Services[API Services]
    end

    subgraph Backend["⚙️ Backend (FastAPI)"]
        Router[Routers]
        Auth[Auth Module]
        DB[Database Layer]
    end

    subgraph Storage["💾 Storage"]
        PG[(PostgreSQL)]
    end

    UI --> Context
    Context --> Services
    Services -->|HTTP + Cookie| Router
    Router --> Auth
    Auth --> DB
    DB --> PG
```

---

## 2. 核心概念

### 2.1 認證 (Authentication) vs 授權 (Authorization)

| 概念     | 說明               | 例子               |
| -------- | ------------------ | ------------------ |
| **認證** | 確認「你是誰」     | 登入帳號密碼驗證   |
| **授權** | 確認「你能做什麼」 | 管理員可以刪除用戶 |

> [!IMPORTANT]
> 本專案專注於**認證**，授權 (RBAC) 是進階主題，之後可以擴展。

### 2.2 JWT (JSON Web Token)

JWT 是一種**自包含的 Token**，包含三個部分：

```
Header.Payload.Signature
```

**範例**：

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZXhwIjoxNzA2MTIzNDU2fQ.xxxxx
```

**解碼後的 Payload**：

```json
{
  "sub": "test@example.com",
  "exp": 1706123456,
  "type": "access"
}
```

### 2.3 Access Token vs Refresh Token

```mermaid
sequenceDiagram
    participant U as 使用者
    participant F as Frontend
    participant B as Backend
    participant DB as Database

    U->>F: 輸入帳密
    F->>B: POST /login
    B->>DB: 驗證使用者
    DB-->>B: 使用者資料
    B->>B: 生成 Access Token (15分鐘)
    B->>DB: 儲存 Refresh Token (7天)
    B-->>F: Set-Cookie: access_token, refresh_token

    Note over F,B: 15分鐘後 Access Token 過期

    F->>B: 任何 API 請求
    B-->>F: 401 Unauthorized
    F->>B: POST /refresh (帶 refresh_token)
    B->>DB: 驗證並撤銷舊 Refresh Token
    B->>DB: 儲存新 Refresh Token
    B-->>F: Set-Cookie: 新的 tokens
```

| Token 類型    | 有效期  | 儲存位置             | 用途                |
| ------------- | ------- | -------------------- | ------------------- |
| Access Token  | 15 分鐘 | HttpOnly Cookie      | 驗證 API 請求       |
| Refresh Token | 7 天    | HttpOnly Cookie + DB | 取得新 Access Token |

---

## 3. 後端實作詳解

### 3.1 專案結構

```
backend/
├── app/
│   ├── main.py              # FastAPI 入口點
│   ├── config.py            # 環境變數設定
│   ├── database.py          # SQLAlchemy 設定
│   ├── models.py            # ORM 模型
│   ├── schemas.py           # Pydantic 驗證
│   ├── auth.py              # 認證邏輯
│   ├── dependencies.py      # 依賴注入
│   └── routers/
│       ├── auth.py          # 認證 API
│       └── users.py         # 使用者 API
├── alembic/                 # 資料庫遷移
└── pyproject.toml           # 相依套件
```

### 3.2 資料模型 (ORM)

#### User 模型

📁 [models.py](file:///home/aipe-tester/Projects/auth_test/backend/app/models.py#L9-L24)

```python
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )
```

> [!TIP]
> **關鍵設計**：
>
> - `hashed_password`：永遠不要儲存明文密碼！
> - `index=True`：加速 Email 查詢
> - `server_default`：讓資料庫處理預設值，更可靠

#### RefreshToken 模型

📁 [models.py](file:///home/aipe-tester/Projects/auth_test/backend/app/models.py#L27-L39)

```python
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(String(500), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False)
```

> [!IMPORTANT]
> **為什麼 Refresh Token 要存資料庫？**
>
> 1. 可以撤銷已發出的 token（登出時）
> 2. 可以實作 Token Rotation（每次刷新都發新的）
> 3. 可以檢測 token 重放攻擊

### 3.3 密碼處理

📁 [auth.py](file:///home/aipe-tester/Projects/auth_test/backend/app/auth.py#L18-L40)

```python
from passlib.context import CryptContext

# bcrypt 是目前最推薦的密碼雜湊演算法
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """雜湊密碼使用 bcrypt。"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """驗證密碼是否正確。"""
    return pwd_context.verify(plain_password, hashed_password)
```

> [!CAUTION]
> **永遠不要這樣做**：
>
> - ❌ 使用 MD5, SHA1 雜湊密碼
> - ❌ 自己實作加密演算法
> - ❌ 在任何地方儲存或記錄明文密碼

### 3.4 JWT Token 管理

📁 [auth.py](file:///home/aipe-tester/Projects/auth_test/backend/app/auth.py#L43-L72)

```python
from jose import jwt

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

def create_access_token(data: dict) -> str:
    """生成 JWT access token。"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> dict:
    """解碼並驗證 JWT token。"""
    payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    return payload
```

### 3.5 Refresh Token 與 Token Rotation

📁 [auth.py](file:///home/aipe-tester/Projects/auth_test/backend/app/auth.py#L75-L108)

```python
def create_refresh_token(user_id: int, db: Session) -> str:
    """生成並儲存 refresh token。"""
    from app.models import RefreshToken

    # 🧹 懶刪除：清理該使用者的過期或已撤銷 token
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        (RefreshToken.expires_at < datetime.now(timezone.utc)) | (RefreshToken.is_revoked == True)
    ).delete(synchronize_session=False)

    # 🔐 生成安全隨機 token
    token_value = secrets.token_urlsafe(64)
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    # 💾 儲存至資料庫
    refresh_token = RefreshToken(
        token=token_value,
        user_id=user_id,
        expires_at=expires_at
    )
    db.add(refresh_token)
    db.commit()

    return token_value
```

#### Token Rotation（防止重放攻擊）

📁 [auth.py](file:///home/aipe-tester/Projects/auth_test/backend/app/auth.py#L153-L187)

```python
def verify_and_revoke_refresh_token(token: str, db: Session):
    """原子性地驗證並撤銷 refresh token（避免競態條件）。"""
    from app.models import RefreshToken

    # 🔒 使用 SELECT FOR UPDATE 鎖定該行
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token == token,
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > datetime.now(timezone.utc)
    ).with_for_update().first()

    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # ✅ 在同一個 transaction 中撤銷
    db_token.is_revoked = True
    db.commit()

    return db_token.user
```

> [!NOTE]
> **`with_for_update()` 的作用**：
> 確保在多個請求同時嘗試使用同一個 Refresh Token 時，只有第一個請求能成功，其他請求會等待並發現 token 已被撤銷。

### 3.6 API 端點實作

📁 [routers/auth.py](file:///home/aipe-tester/Projects/auth_test/backend/app/routers/auth.py)

#### 註冊端點

```python
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")  # 🛡️ 速率限制
def register(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    # 1️⃣ 檢查 Email 是否已存在
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # 2️⃣ 雜湊密碼
    hashed_password = hash_password(user_data.password)

    # 3️⃣ 建立使用者
    new_user = User(email=user_data.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user
```

#### 登入端點

```python
@router.post("/login")
@limiter.limit("5/minute")
def login(request: Request, response: Response,
          form_data: OAuth2PasswordRequestForm = Depends(),
          db: Session = Depends(get_db)):
    # 1️⃣ 驗證使用者
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    # 2️⃣ 建立 Tokens
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(user.id, db)

    # 3️⃣ 設定 HttpOnly Cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,           # 🛡️ JavaScript 無法存取
        secure=settings.cookie_secure,  # 🔒 生產環境使用 HTTPS
        samesite=settings.cookie_samesite,  # 🛡️ CSRF 防護
        max_age=900  # 15 分鐘
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=604800  # 7 天
    )

    return {"message": "Login successful"}
```

### 3.7 依賴注入：取得當前使用者

📁 [dependencies.py](file:///home/aipe-tester/Projects/auth_test/backend/app/dependencies.py)

```python
def get_current_user(
    access_token: str = Cookie(None),
    db: Session = Depends(get_db)
) -> User:
    """從 Cookie 中的 JWT token 取得當前使用者。"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )

    if not access_token:
        raise credentials_exception

    try:
        payload = decode_access_token(access_token)
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception

    return user
```

**使用方式**：

```python
@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
```

---

## 4. 前端實作詳解

### 4.1 專案結構

```
frontend/src/
├── main.tsx             # React 入口
├── App.tsx              # 路由設定
├── context/
│   └── AuthContext.tsx  # 認證狀態管理
├── services/
│   ├── api.ts           # Axios 設定 + Interceptor
│   └── auth.ts          # 認證 API 封裝
├── components/
│   ├── LoginForm.tsx    # 登入表單
│   └── ProtectedRoute.tsx  # 路由守衛
├── pages/
│   ├── LoginPage.tsx
│   ├── RegisterPage.tsx
│   └── DashboardPage.tsx
├── types/
│   └── auth.ts          # TypeScript 類型定義
└── utils/
    └── errorHandler.ts  # 錯誤處理
```

### 4.2 API 服務層

📁 [api.ts](file:///home/aipe-tester/Projects/auth_test/frontend/src/services/api.ts)

```typescript
import axios from "axios";

const api = axios.create({
  baseURL: "/api/v1",
  headers: {
    "Content-Type": "application/json",
  },
  withCredentials: true, // 🔑 啟用 Cookie 傳遞
});
```

> [!IMPORTANT]
> **`withCredentials: true` 是必須的！**
> 這告訴 Axios 在跨域請求時也要攜帶 Cookie，否則後端收不到 Token。

### 4.3 自動 Token 刷新 (Axios Interceptor)

📁 [api.ts](file:///home/aipe-tester/Projects/auth_test/frontend/src/services/api.ts#L64-L119)

```typescript
// Response interceptor: 自動刷新 Access Token
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // 如果是 401 且不是 refresh 端點，嘗試刷新 token
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url?.includes("/auth/refresh")
    ) {
      if (isRefreshing) {
        // 等待 token 刷新完成（其他請求排隊）
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(() => api(originalRequest));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        await api.post("/auth/refresh"); // 刷新 token
        processQueue(null, "success");
        return api(originalRequest); // 重試原請求
      } catch (refreshError) {
        processQueue(refreshError as Error, null);
        window.location.href = "/login"; // 刷新失敗，導向登入頁
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  },
);
```

```mermaid
flowchart TD
    A[API 請求] --> B{收到 401?}
    B -->|否| C[正常回傳]
    B -->|是| D{正在刷新中?}
    D -->|是| E[加入等待隊列]
    D -->|否| F[呼叫 /refresh]
    F --> G{刷新成功?}
    G -->|是| H[重試原請求]
    G -->|否| I[導向登入頁]
    E --> J{刷新完成}
    J -->|成功| H
    J -->|失敗| I
```

### 4.4 多 Tab 同步 (BroadcastChannel)

📁 [api.ts](file:///home/aipe-tester/Projects/auth_test/frontend/src/services/api.ts#L30-L61)

```typescript
// BroadcastChannel for cross-tab token refresh synchronization
const refreshChannel =
  typeof BroadcastChannel !== "undefined"
    ? new BroadcastChannel("auth-refresh")
    : null;

if (refreshChannel) {
  refreshChannel.onmessage = (event) => {
    const { type } = event.data;

    switch (type) {
      case "REFRESH_START":
        // 其他 tab 開始刷新，本 tab 進入等待模式
        if (!isRefreshing) isRefreshing = true;
        break;

      case "REFRESH_SUCCESS":
        // 其他 tab 刷新成功，本 tab 的 pending 請求可以重試
        processQueue(null, "success");
        isRefreshing = false;
        break;

      case "REFRESH_FAILED":
        // 其他 tab 刷新失敗，本 tab 也需要重導向
        processQueue(new Error("Token refresh failed"), null);
        isRefreshing = false;
        window.location.href = "/login";
        break;
    }
  };
}
```

```mermaid
sequenceDiagram
    participant Tab1 as Tab 1
    participant Tab2 as Tab 2
    participant BC as BroadcastChannel
    participant API as Backend

    Tab1->>API: 請求（Access Token 過期）
    API-->>Tab1: 401
    Tab1->>BC: REFRESH_START
    BC->>Tab2: REFRESH_START
    Tab2->>Tab2: isRefreshing = true

    Tab1->>API: POST /refresh
    API-->>Tab1: 新 Token (Cookie)

    Tab1->>BC: REFRESH_SUCCESS
    BC->>Tab2: REFRESH_SUCCESS
    Tab2->>Tab2: 重試等待中的請求
```

### 4.5 React Context (認證狀態管理)

📁 [AuthContext.tsx](file:///home/aipe-tester/Projects/auth_test/frontend/src/context/AuthContext.tsx)

```typescript
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const initAuth = async () => {
      try {
        // 🔄 頁面載入時嘗試取得當前使用者
        const currentUser = await authService.getCurrentUser();
        setUser(currentUser);
      } catch (error) {
        // 如果失敗（401），代表未登入或 token 過期
        setUser(null);
      } finally {
        setLoading(false);
      }
    };
    initAuth();
  }, []);

  const login = async (email: string, password: string): Promise<void> => {
    await authService.login(email, password);
    const currentUser = await authService.getCurrentUser();
    setUser(currentUser);
  };

  const logout = async (): Promise<void> => {
    try {
      await authService.logout();
    } finally {
      setUser(null);  // 無論後端成功與否，前端都要清除狀態
    }
  };

  return <AuthContext.Provider value={{ user, loading, login, register, logout }}>{children}</AuthContext.Provider>;
};
```

### 4.6 路由守衛 (ProtectedRoute)

📁 [ProtectedRoute.tsx](file:///home/aipe-tester/Projects/auth_test/frontend/src/components/ProtectedRoute.tsx)

```typescript
export const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return <div>載入中...</div>;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};
```

**使用方式**：

```tsx
<Route
  path="/dashboard"
  element={
    <ProtectedRoute>
      <DashboardPage />
    </ProtectedRoute>
  }
/>
```

---

## 5. 安全機制深入

### 5.1 安全檢查清單

| 威脅               | 防護機制          | 本專案實作                      |
| ------------------ | ----------------- | ------------------------------- |
| **XSS**            | HttpOnly Cookie   | ✅ Token 儲存於 HttpOnly Cookie |
| **CSRF**           | SameSite Cookie   | ✅ 生產環境使用 `strict`        |
| **暴力破解**       | Rate Limiting     | ✅ 登入 5/min, 註冊 3/min       |
| **密碼洩露**       | bcrypt 雜湊       | ✅ 使用 bcrypt (2^12 rounds)    |
| **Token 竊取**     | Token Rotation    | ✅ 每次刷新發新 token           |
| **重放攻擊**       | 一次性 Token      | ✅ Refresh Token 用完即撤銷     |
| **SQL Injection**  | ORM               | ✅ 使用 SQLAlchemy              |
| **Race Condition** | SELECT FOR UPDATE | ✅ Token 驗證使用行鎖           |

### 5.2 HttpOnly vs LocalStorage

```mermaid
graph LR
    subgraph "❌ LocalStorage（不安全）"
        A[Token 在 LocalStorage] --> B[XSS 攻擊]
        B --> C[惡意腳本讀取 Token]
        C --> D[Token 被盜]
    end

    subgraph "✅ HttpOnly Cookie（安全）"
        E[Token 在 HttpOnly Cookie] --> F[XSS 攻擊]
        F --> G[JavaScript 無法存取]
        G --> H[Token 安全]
    end
```

> [!CAUTION]
> **永遠不要把 Token 存在 localStorage！**
> 任何 XSS 漏洞都能直接讀取並竊取使用者的 Token。

### 5.3 環境變數設定

📁 [config.py](file:///home/aipe-tester/Projects/auth_test/backend/app/config.py)

```python
class Settings(BaseSettings):
    database_url: str = "postgresql://postgres:postgres@localhost:5432/auth_test"
    secret_key: str = "dev-secret-key-change-in-production"  # ⚠️ 開發用預設值
    cors_origins: str = "http://localhost:5173"
    environment: str = "development"
    trust_proxy: bool = False

    @property
    def cookie_secure(self) -> bool:
        """生產環境自動啟用 HTTPS-only Cookie"""
        return self.is_production

    @property
    def cookie_samesite(self) -> str:
        """生產環境使用 strict，開發環境使用 lax"""
        return "strict" if self.is_production else "lax"
```

> [!WARNING]
> **生產環境必須**：
>
> 1. 使用 `openssl rand -hex 32` 生成隨機 SECRET_KEY
> 2. 設定 `ENVIRONMENT=production`
> 3. 使用 HTTPS（Cookie Secure 會自動啟用）

---

## 6. 實作流程圖

### 完整登入流程

```mermaid
sequenceDiagram
    autonumber
    participant U as 使用者
    participant F as Frontend
    participant B as Backend
    participant DB as Database

    rect rgb(240, 248, 255)
        Note over U,DB: 🔐 登入流程
        U->>F: 輸入 email + password
        F->>B: POST /api/v1/auth/login
        B->>DB: SELECT * FROM users WHERE email = ?
        DB-->>B: User record
        B->>B: verify_password(input, hashed)
        alt 密碼正確
            B->>B: create_access_token()
            B->>DB: INSERT INTO refresh_tokens
            B-->>F: Set-Cookie: access_token, refresh_token
            F-->>U: 導向 Dashboard
        else 密碼錯誤
            B-->>F: 401 Unauthorized
            F-->>U: 顯示錯誤訊息
        end
    end

    rect rgb(255, 250, 240)
        Note over U,DB: 📡 請求受保護資源
        U->>F: 訪問 Dashboard
        F->>B: GET /api/v1/users/me (Cookie: access_token)
        B->>B: decode_access_token()
        B->>DB: SELECT * FROM users WHERE email = ?
        B-->>F: User data
        F-->>U: 顯示 Dashboard
    end

    rect rgb(255, 245, 245)
        Note over U,DB: 🔄 Token 過期刷新
        F->>B: GET /api/v1/users/me (expired token)
        B-->>F: 401 Unauthorized
        F->>B: POST /api/v1/auth/refresh (Cookie: refresh_token)
        B->>DB: SELECT FOR UPDATE ... WHERE token = ?
        B->>DB: UPDATE ... SET is_revoked = true
        B->>DB: INSERT INTO refresh_tokens (new token)
        B-->>F: Set-Cookie: new tokens
        F->>B: GET /api/v1/users/me (retry)
        B-->>F: User data
    end
```

---

## 7. 動手練習

### 練習 1：理解資料流

1. 在 `backend/app/routers/auth.py` 的 `login` 函式加入 `print` 語句，觀察登入流程
2. 使用瀏覽器開發者工具 (F12) → Application → Cookies 查看 Token

### 練習 2：實作新功能

嘗試新增「密碼強度驗證」：

📁 `backend/app/schemas.py`

```python
from pydantic import field_validator

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

    @field_validator('password')
    def validate_password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('密碼必須包含至少一個大寫字母')
        if not any(c.isdigit() for c in v):
            raise ValueError('密碼必須包含至少一個數字')
        return v
```

### 練習 3：測試 Rate Limiting

```bash
# 快速連續呼叫 6 次登入
for i in {1..6}; do
  curl -X POST http://localhost:8000/api/v1/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test@example.com&password=wrong" \
    -w "\nStatus: %{http_code}\n"
done
# 第 6 次應返回 429 Too Many Requests
```

---

## 8. 常見錯誤與除錯

### 8.1 前端無法存取後端 API

**症狀**：Console 顯示 CORS 錯誤

**解法**：

1. 檢查 `backend/.env` 的 `CORS_ORIGINS` 是否包含前端 URL
2. 確認 `withCredentials: true` 已設定

### 8.2 登入後 Cookie 沒有設定

**症狀**：登入成功但 Cookie 為空

**解法**：

1. 確認後端 `response.set_cookie()` 有被呼叫
2. 開發環境不要使用 `secure=True`
3. 確認前端請求有 `withCredentials: true`

### 8.3 Token 刷新無限迴圈

**症狀**：瀏覽器卡住或無限 401

**解法**：

1. 確認 Interceptor 有排除 `/auth/refresh` 端點
2. 確認 `_retry` 標記有正確設定

---

## 9. 延伸學習

### 本專案尚未實作（適合練習）

| 功能        | 難度   | 說明               |
| ----------- | ------ | ------------------ |
| Email 驗證  | ⭐⭐   | 註冊後發送驗證信   |
| 密碼重設    | ⭐⭐   | 忘記密碼流程       |
| 2FA/TOTP    | ⭐⭐⭐ | 雙因素認證         |
| OAuth2 登入 | ⭐⭐⭐ | Google/GitHub 登入 |
| RBAC 授權   | ⭐⭐⭐ | 角色權限控制       |
| 單元測試    | ⭐⭐   | pytest + httpx     |

### 推薦資源

- [FastAPI 官方文件](https://fastapi.tiangolo.com/)
- [SQLAlchemy 2.0 教學](https://docs.sqlalchemy.org/en/20/)
- [JWT 最佳實踐 (RFC 8725)](https://datatracker.ietf.org/doc/html/rfc8725)
- [OWASP 認證指南](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

> [!TIP]
> **學習建議**：先完整跑一次專案，再回來對照程式碼理解每個部分。實際動手修改比單純閱讀更有效！
