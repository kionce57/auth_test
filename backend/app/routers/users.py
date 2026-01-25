from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth import hash_password
from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.routers.auth import get_client_ip, limiter
from app.schemas import UserCreate, UserResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """取得當前使用者資訊（需要認證）。

    Args:
        current_user: 從 JWT token 解析出的當前使用者

    Returns:
        當前使用者的詳細資訊
    """
    return current_user


# ============= API v2 =============
router_v2 = APIRouter()


@router_v2.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
def create_user(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    """建立使用者 (v2 register)"""
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


@router_v2.get("/me", response_model=UserResponse)
def get_current_user_v2(current_user: User = Depends(get_current_user)):
    """取得當前使用者 (v2)"""
    return current_user
