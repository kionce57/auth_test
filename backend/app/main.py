from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.routers import auth, users

app = FastAPI()

# 設定 Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from fastapi import APIRouter

# 建立 v1 路由群組
api_v1 = APIRouter(prefix="/api/v1")

# 註冊路由至 v1
api_v1.include_router(auth.router, prefix="", tags=["Authentication"])
api_v1.include_router(users.router, prefix="", tags=["Users"])

app.include_router(api_v1)

# 保留舊端點以維持向後相容（標記為 deprecated）
app.include_router(auth.router, deprecated=True)
app.include_router(users.router, deprecated=True)


@app.get("/health")
def health_check():
    """健康檢查端點。"""
    return {"status": "healthy"}
