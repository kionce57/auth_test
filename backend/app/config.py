from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql://postgres:postgres@localhost:5432/auth_test"
    secret_key: str = "dev-secret-key-change-in-production"
    cors_origins: str = "http://localhost:5173"
    environment: str = "development"  # development 或 production
    trust_proxy: bool = False  # 是否信任反向代理的 X-Forwarded-For header（僅在有 Nginx 等代理時設為 True）

    # Google OAuth 設定
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/api/v2/sessions/google/callback"

    model_config = SettingsConfigDict(case_sensitive=False, env_file=".env")

    @property
    def is_production(self) -> bool:
        """判斷是否為生產環境。"""
        return self.environment.lower() == "production"

    @property
    def cookie_secure(self) -> bool:
        """Cookie Secure flag（生產環境自動啟用）。"""
        return self.is_production

    @property
    def cookie_samesite(self) -> str:
        """Cookie SameSite 設定（生產環境使用 strict）。"""
        return "strict" if self.is_production else "lax"


settings = Settings()
