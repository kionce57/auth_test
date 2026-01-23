from fastapi import Cookie, Depends, HTTPException, status
from jose import JWTError
from sqlalchemy.orm import Session

from app.auth import decode_access_token
from app.database import get_db
from app.models import User


def get_current_user(
    access_token: str = Cookie(None), db: Session = Depends(get_db)
) -> User:
    """從 Cookie 中的 JWT token 取得當前使用者。

    Args:
        access_token: JWT token（從 Cookie 讀取）
        db: 資料庫 session

    Returns:
        當前使用者物件

    Raises:
        HTTPException: Token 無效、缺失或使用者不存在時拋出 401 錯誤
    """
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
