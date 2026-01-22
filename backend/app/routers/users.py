from fastapi import APIRouter, Depends

from app.dependencies import get_current_user
from app.models import User
from app.schemas import UserResponse

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
