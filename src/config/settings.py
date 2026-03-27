from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseAppSettings(BaseSettings):
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    TEMPLATE_FOLDER: Path = BASE_DIR / "notifications/templates/"
    MAIL_HOST: str = "mailhog_theater"
    MAIL_PORT: str = "1025"
    MAIL_USERNAME: str = "user"
    MAIL_PASSWORD: str = "password"
    MAIL_FROM: str = "noreply@test.com"
    LOGIN_TIME_DAYS: int = 7

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
    JWT_SIGNING_ALGORITHM: str = "HS256"


class TestingSettings(BaseAppSettings):
    MAILHOG_API_PORT: str = "8025"
    MAILHOG_USER: str = "admin"
    MAILHOG_PASSWORD: str = "password"
    SECRET_KEY_ACCESS: str
    SECRET_KEY_REFRESH: str
    JWT_SIGNING_ALGORITHM: str = "HS256"
