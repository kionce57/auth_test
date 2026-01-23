from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.routers import auth, users

app = FastAPI()


def get_client_ip(request: Request) -> str:
    """安全地取得客戶端 IP，處理反向代理情況。

    Args:
        request: FastAPI Request 物件

    Returns:
        客戶端 IP 位址
    """
    # 如果啟用 trust_proxy 且有 X-Forwarded-For header
    if settings.trust_proxy:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # X-Forwarded-For 格式: client, proxy1, proxy2
            # 取第一個 IP（真實客戶端 IP）
            return forwarded.split(",")[0].strip()

    # 否則使用直接連線 IP
    return request.client.host if request.client else "unknown"


# 設定 Rate Limiter（使用安全的 IP 取得函式）
limiter = Limiter(key_func=get_client_ip)
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
