from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from sqlalchemy.orm import Session

from app.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
    revoke_refresh_token,
    verify_and_revoke_refresh_token,
    verify_password,
    verify_refresh_token,
)
from app.config import settings
from app.database import get_db
from app.models import User
from app.schemas import SessionCreate, SessionResponse, Token, UserCreate, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


def get_client_ip(request: Request) -> str:
    """安全地取得客戶端 IP，處理反向代理情況。"""
    if settings.trust_proxy:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=get_client_ip)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
def register(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    """註冊新使用者。

    Args:
        user_data: 使用者註冊資料（email + password）
        db: 資料庫 session

    Returns:
        建立的使用者資訊

    Raises:
        HTTPException: Email 已存在時返回 400 錯誤
    """
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    hashed_password = hash_password(user_data.password)
    new_user = User(email=user_data.email, hashed_password=hashed_password)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login")
@limiter.limit("5/minute")
def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """使用者登入，設定 HttpOnly Cookie。

    Args:
        response: FastAPI Response 物件
        form_data: OAuth2 表單資料（username 欄位存放 email）
        db: 資料庫 session

    Returns:
        登入成功訊息

    Raises:
        HTTPException: 認證失敗時返回 401 錯誤
    """
    user = db.query(User).filter(User.email == form_data.username).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 建立 Access Token（15 分鐘）
    access_token = create_access_token(data={"sub": user.email})

    # 建立 Refresh Token（7 天）
    refresh_token = create_refresh_token(user.id, db)

    # 設定 Access Token Cookie（HttpOnly）
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.cookie_secure,  # 生產環境自動啟用
        samesite=settings.cookie_samesite,
        max_age=900  # 15 分鐘（秒）
    )

    # 設定 Refresh Token Cookie（HttpOnly）
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.cookie_secure,  # 生產環境自動啟用
        samesite=settings.cookie_samesite,
        max_age=604800  # 7 天（秒）
    )

    return {"message": "Login successful"}


@router.post("/logout")
def logout(
    response: Response,
    refresh_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    """使用者登出，清除 Cookie 並撤銷 refresh token。

    Args:
        response: FastAPI Response 物件
        refresh_token: Refresh Token（從 Cookie 讀取）
        db: 資料庫 session

    Returns:
        登出成功訊息
    """
    # 撤銷資料庫中的 refresh token
    if refresh_token:
        try:
            revoke_refresh_token(refresh_token, db)
        except Exception:
            # 即使撤銷失敗也要清除 Cookie（避免使用者無法登出）
            pass

    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Logout successful"}


@router.post("/refresh")
@limiter.limit("20/minute")
def refresh_token(
    request: Request,
    response: Response,
    refresh_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    """使用 Refresh Token 取得新的 Access Token（Token Rotation）。

    Args:
        response: FastAPI Response 物件
        refresh_token: Refresh Token（從 Cookie 讀取）
        db: 資料庫 session

    Returns:
        Token 刷新成功訊息

    Raises:
        HTTPException: Refresh Token 無效、已撤銷或過期時返回 401 錯誤
    """
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    # 原子性驗證並撤銷（避免 race condition）
    user = verify_and_revoke_refresh_token(refresh_token, db)

    # 發放新的 Access Token + Refresh Token
    new_access_token = create_access_token(data={"sub": user.email})
    new_refresh_token = create_refresh_token(user.id, db)

    # 設定新的 Access Token Cookie
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=settings.cookie_secure,  # 生產環境自動啟用
        samesite=settings.cookie_samesite,
        max_age=900
    )

    # 設定新的 Refresh Token Cookie
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=settings.cookie_secure,  # 生產環境自動啟用
        samesite=settings.cookie_samesite,
        max_age=604800
    )

    return {"message": "Token refreshed"}


# ============= API v2 =============
router_v2 = APIRouter()


@router_v2.post("", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def create_session(
    request: Request,
    response: Response,
    credentials: SessionCreate,
    db: Session = Depends(get_db)
):
    """建立 session (v2 login) - 使用 JSON body"""
    user = db.query(User).filter(User.email == credentials.email).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    # 建立 tokens（邏輯與 v1 相同）
    access_token = create_access_token(data={"sub": user.email})
    refresh_token_value = create_refresh_token(user.id, db)

    # 設定 cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=900
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token_value,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=604800
    )

    return SessionResponse(
        message="Session created",
        user=UserResponse.model_validate(user)
    )


@router_v2.delete("")
def delete_session(
    response: Response,
    refresh_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    """刪除 session (v2 logout)"""
    if refresh_token:
        try:
            revoke_refresh_token(refresh_token, db)
        except Exception:
            pass

    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Session deleted"}


@router_v2.post("/refresh")
@limiter.limit("20/minute")
def refresh_session(
    request: Request,
    response: Response,
    refresh_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    """刷新 session (v2 token refresh)"""
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    user = verify_and_revoke_refresh_token(refresh_token, db)

    new_access_token = create_access_token(data={"sub": user.email})
    new_refresh_token = create_refresh_token(user.id, db)

    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=900
    )
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=604800
    )

    return {"message": "Session refreshed"}
