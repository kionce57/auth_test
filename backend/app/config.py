"""
應用程式配置管理

使用 Pydantic Settings 從環境變數載入配置
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """應用程式設定"""

    # 資料庫配置
    database_url: str

    # 安全配置
    secret_key: str

    # CORS 配置
    cors_origins: str = "http://localhost:5173"

    # 應用程式配置
    debug: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """將 CORS 來源字串轉換為列表"""
        return [origin.strip() for origin in self.cors_origins.split(",")]


# 全域設定實例
settings = Settings()
