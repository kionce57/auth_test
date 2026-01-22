from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24


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
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
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
