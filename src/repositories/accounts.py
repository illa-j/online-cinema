from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from database import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    RefreshTokenModel,
)
from schemas import UserCreateSchema
from config import get_settings

settings = get_settings()


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    stmt = select(UserModel).where(UserModel.email == email)
    result = await db.execute(stmt)
    return result.scalars().first()


async def get_user_by_id(db: AsyncSession, user_id: int) -> UserModel | None:
    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    return result.scalars().first()


async def get_default_user_group(db: AsyncSession) -> UserGroupModel | None:
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db.execute(stmt)
    return result.scalars().first()


async def create_user(db: AsyncSession, user_data: UserCreateSchema) -> UserModel:
    new_user = UserModel(
        email=user_data.email, password=user_data.password, group_id=user_data.group_id
    )
    db.add(new_user)
    await db.flush()
    return new_user


async def create_activation_token(
    db: AsyncSession, user_id: int, token: str
) -> ActivationTokenModel:
    activation_token = ActivationTokenModel(user_id=user_id)
    activation_token.token = token
    db.add(activation_token)
    await db.flush()
    return activation_token


async def create_refresh_token(
    db: AsyncSession, user_id: int, token: str
) -> RefreshTokenModel:
    refresh_token = RefreshTokenModel.create(
        user_id=user_id, days_valid=settings.LOGIN_TIME_DAYS, token=token
    )
    db.add(refresh_token)
    await db.flush()
    return refresh_token


async def get_user_with_activation_tokens_by_email(
    db: AsyncSession, email: str
) -> UserModel | None:
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_tokens))
        .join(ActivationTokenModel)
        .where(UserModel.email == email)
    )
    result = await db.execute(stmt)
    return result.scalars().first()


async def get_refresh_token_by_user_id(db: AsyncSession, user_id: int) -> RefreshTokenModel | None:
    stmt = select(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id)
    result = await db.execute(stmt)
    return result.scalars().first()


async def delete_activation_token_by_user_id(db: AsyncSession, user_id: int) -> None:
    stmt = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user_id)
    result = await db.execute(stmt)
    token = result.scalars().first()
    if token:
        await db.delete(token)
        await db.flush()


async def delete_refresh_tokens_by_user_id(db: AsyncSession, user_id: int) -> None:
    stmt = select(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id)
    result = await db.execute(stmt)
    token = result.scalars().first()
    if token:
        await db.delete(token)
        await db.flush()
