from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    secret_key: str
    cors_origins: str = "http://localhost:5173"

    model_config = SettingsConfigDict(case_sensitive=False)


settings = Settings()
