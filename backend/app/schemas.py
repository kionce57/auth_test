from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str


class SessionCreate(BaseModel):
    """建立 session（v2 login）"""
    email: EmailStr
    password: str


class SessionResponse(BaseModel):
    """Session 建立回應"""
    message: str
    user: UserResponse
