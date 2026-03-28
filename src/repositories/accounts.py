from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel
from schemas import UserCreateSchema


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    stmt = select(UserModel).where(UserModel.email == email)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_default_user_group(db: AsyncSession) -> UserGroupModel | None:
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


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
