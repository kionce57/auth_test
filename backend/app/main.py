"""
FastAPI 應用程式主入口

初始化 FastAPI 應用，配置 CORS 中介軟體
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings

# 建立 FastAPI 應用實例
app = FastAPI(
    title="認證系統 API",
    description="FastAPI 認證系統後端服務",
    version="0.1.0",
    debug=settings.debug,
)

# 配置 CORS 中介軟體
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """根路徑健康檢查"""
    return {"status": "ok", "message": "認證系統 API 運行中"}


@app.get("/health")
async def health_check():
    """健康檢查端點"""
    return {
        "status": "healthy",
        "debug": settings.debug,
    }
