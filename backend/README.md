# 認證系統後端

FastAPI 認證系統後端服務

## 環境需求

- Python 3.12+
- PostgreSQL 16
- uv (套件管理器)

## 快速開始

### 1. 安裝依賴

```bash
cd backend
uv venv
uv pip install -e .
```

### 2. 配置環境變數

複製 `.env.example` 到 `.env` 並修改配置：

```bash
cp .env.example .env
```

必要的環境變數：
- `DATABASE_URL`: PostgreSQL 連線字串
- `SECRET_KEY`: JWT 加密金鑰
- `CORS_ORIGINS`: 允許的前端來源（逗號分隔）
- `DEBUG`: 除錯模式（true/false）

### 3. 啟動開發伺服器

```bash
source .venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

或使用 uv 直接執行：

```bash
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 4. 驗證服務

訪問以下端點：
- http://localhost:8000/ - 根路徑健康檢查
- http://localhost:8000/health - 詳細健康檢查
- http://localhost:8000/docs - API 文件（Swagger UI）
- http://localhost:8000/redoc - API 文件（ReDoc）

## 專案結構

```
backend/
├── app/
│   ├── __init__.py      # 套件初始化
│   ├── main.py          # FastAPI 應用程式主入口
│   ├── config.py        # Pydantic Settings 環境配置
│   └── database.py      # SQLAlchemy 引擎和 session 設定
├── .env.example         # 環境變數範本
├── pyproject.toml       # 專案依賴配置
└── README.md            # 本文件
```

## 技術棧

- **FastAPI**: 現代化 Python Web 框架
- **SQLAlchemy 2.0+**: ORM 資料庫操作
- **Pydantic Settings**: 環境變數管理
- **PostgreSQL**: 主要資料庫
- **uvicorn**: ASGI 伺服器
