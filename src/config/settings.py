from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseAppSettings(BaseSettings):
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    TEMPLATE_FOLDER: Path = BASE_DIR / "notifications/templates/"

    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env")


class Settings(BaseAppSettings):
    POSTGRES_USER: str = "test_user"
    POSTGRES_PASSWORD: str = "test_password"
    POSTGRES_HOST: str = "test_host"
    POSTGRES_DB_PORT: int = 5432
    POSTGRES_DB: str = "test_db"
    CELERY_BROKER_URL: str = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/1"
    SECRET_KEY_ACCESS: str
    SECRET_KEY_REFRESH: str
    JWT_SIGNING_ALGORITHM: str = "HS256",
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
