"""
資料庫連線設定

使用 SQLAlchemy 2.0+ 管理 PostgreSQL 連線
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

# 建立資料庫引擎
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,  # 連線前檢查連線是否有效
    pool_size=5,  # 連線池大小
    max_overflow=10,  # 最大溢出連線數
    echo=settings.debug,  # 除錯模式下印出 SQL 語句
)

# Session 工廠
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# ORM 模型基底類別
Base = declarative_base()


def get_db():
    """
    依賴注入用的資料庫 session 生成器

    使用範例：
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
