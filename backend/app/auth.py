import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # 改為 15 分鐘
REFRESH_TOKEN_EXPIRE_DAYS = 7  # 7 天


def hash_password(password: str) -> str:
    """雜湊密碼使用 bcrypt。

    Args:
        password: 明文密碼

    Returns:
        雜湊後的密碼
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """驗證密碼是否正確。

    Args:
        plain_password: 明文密碼
        hashed_password: 雜湊後的密碼

    Returns:
        密碼是否匹配
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict) -> str:
    """生成 JWT access token。

    Args:
        data: 要編碼進 token 的資料，應包含 "sub" 鍵（通常是 email）

    Returns:
        JWT token 字串
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """解碼並驗證 JWT token。

    Args:
        token: JWT token 字串

    Returns:
        Token payload 字典

    Raises:
        JWTError: Token 無效或過期
    """
    payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    return payload


def create_refresh_token(user_id: int, db: Session) -> str:
    """生成並儲存 refresh token。

    Args:
        user_id: 使用者 ID
        db: 資料庫 session

    Returns:
        Refresh token 字串
    """
    from app.models import RefreshToken

    # 生成安全隨機 token
    token_value = secrets.token_urlsafe(64)
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    # 儲存至資料庫
    refresh_token = RefreshToken(
        token=token_value,
        user_id=user_id,
        expires_at=expires_at
    )
    db.add(refresh_token)
    db.commit()

    return token_value


def verify_refresh_token(token: str, db: Session):
    """驗證 refresh token 並返回 User。

    Args:
        token: Refresh token 字串
        db: 資料庫 session

    Returns:
        User 物件

    Raises:
        HTTPException: Token 無效、已撤銷或過期
    """
    from app.models import RefreshToken

    db_token = db.query(RefreshToken).filter(
        RefreshToken.token == token,
        RefreshToken.is_revoked == False,  # noqa: E712
        RefreshToken.expires_at > datetime.now(timezone.utc)
    ).first()

    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    return db_token.user


def revoke_refresh_token(token: str, db: Session) -> None:
    """撤銷 refresh token（用於 Token Rotation）。

    Args:
        token: Refresh token 字串
        db: 資料庫 session
    """
    from app.models import RefreshToken

    db.query(RefreshToken).filter(RefreshToken.token == token).update(
        {"is_revoked": True}
    )
    db.commit()
