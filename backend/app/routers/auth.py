from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
    revoke_refresh_token,
    verify_password,
    verify_refresh_token,
)
from app.database import get_db
from app.models import User
from app.schemas import Token, UserCreate, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
async def register(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
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
async def login(
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
        secure=False,  # 開發環境使用 False，生產環境改為 True（需 HTTPS）
        samesite="lax",
        max_age=900  # 15 分鐘（秒）
    )

    # 設定 Refresh Token Cookie（HttpOnly）
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=604800  # 7 天（秒）
    )

    return {"message": "Login successful"}


@router.post("/logout")
def logout(response: Response):
    """使用者登出，清除 Cookie。

    Args:
        response: FastAPI Response 物件

    Returns:
        登出成功訊息
    """
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Logout successful"}


@router.post("/refresh")
@limiter.limit("20/minute")
async def refresh_token(
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

    # 驗證舊 Refresh Token
    user = verify_refresh_token(refresh_token, db)

    # Token Rotation：撤銷舊 token
    revoke_refresh_token(refresh_token, db)

    # 發放新的 Access Token + Refresh Token
    new_access_token = create_access_token(data={"sub": user.email})
    new_refresh_token = create_refresh_token(user.id, db)

    # 設定新的 Access Token Cookie
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=900
    )

    # 設定新的 Refresh Token Cookie
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=604800
    )

    return {"message": "Token refreshed"}
