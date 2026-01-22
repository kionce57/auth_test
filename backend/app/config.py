"""
應用程式配置管理

使用 Pydantic Settings 從環境變數載入配置
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """應用程式設定"""

    database_url: str
    secret_key: str
    cors_origins: str = "http://localhost:5173"
    debug: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


settings = Settings()
