from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from typing import AsyncGenerator

from config import get_settings

settings = get_settings()


POSTGRESQL_DATABASE_URL = (
    f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@"
    f"{settings.POSTGRES_HOST}:{settings.POSTGRES_DB_PORT}/{settings.POSTGRES_DB}"
)

postgresql_engine = create_async_engine(POSTGRESQL_DATABASE_URL, echo=False)

AsyncPostgresqlSession = sessionmaker(  # type: ignore
    bind=postgresql_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

sync_database_url = POSTGRESQL_DATABASE_URL.replace("postgresql+asyncpg", "postgresql")
sync_postgresql_engine = create_engine(sync_database_url, echo=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency that provides an asynchronous database session.
    The session is automatically closed after use.

    Returns:
        AsyncGenerator[AsyncSession, None]: An asynchronous generator yielding an AsyncSession.
    """
    async with AsyncPostgresqlSession() as session:
        yield session
