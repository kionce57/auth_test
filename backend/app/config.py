from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql://postgres:postgres@localhost:5432/auth_test"
    secret_key: str = "dev-secret-key-change-in-production"
    cors_origins: str = "http://localhost:5173"

    model_config = SettingsConfigDict(case_sensitive=False, env_file=".env")


settings = Settings()
