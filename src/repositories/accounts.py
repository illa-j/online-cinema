from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from database import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel
from schemas import UserCreateSchema


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    stmt = select(UserModel).where(UserModel.email == email)
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


async def get_user_with_activation_tokens(
    db: AsyncSession,
    email: str
) -> UserModel | None:
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_tokens))
        .join(ActivationTokenModel)
        .where(UserModel.email == email)
    )
    result = await db.execute(stmt)
    return result.scalars().first()


async def delete_activation_token_by_user_id(db: AsyncSession, user_id: int) -> None:
    stmt = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user_id)
    result = await db.execute(stmt)
    token = result.scalar_one_or_none()
    if token:
        await db.delete(token)
        await db.flush()
