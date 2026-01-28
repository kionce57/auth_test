from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # 修改：改為 nullable（Google 使用者沒有密碼）
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # 新增：Google OAuth 欄位
    google_id: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True, index=True
    )
    auth_provider: Mapped[str] = mapped_column(
        String(20), server_default="local", nullable=False
    )
    # auth_provider 可能值: "local", "google", "both"

    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationship
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(String(500), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    # Relationship
    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")
