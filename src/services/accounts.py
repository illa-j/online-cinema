from fastapi import HTTPException, status, BackgroundTasks

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel
from notifications.emails import send_activation_email
from schemas import UserRegistrationRequestSchema
from repositories.accounts import (
    get_user_by_email,
    get_default_user_group,
    create_user,
    create_activation_token,
)
from schemas.accounts import UserCreateSchema, UserRegistrationResponseSchema
from security.utils import generate_secure_token


async def register_user_service(
    db: AsyncSession,
    user_data: UserRegistrationRequestSchema,
    background_tasks: BackgroundTasks,
) -> UserModel:
    user = await get_user_by_email(db, user_data.email)
    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    user_group = await get_default_user_group(db)
    if user_group is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not found.",
        )
    try:
        new_user = await create_user(
            db,
            UserCreateSchema(
                email=user_data.email,
                password=user_data.password,
                group_id=user_group.id,
            ),
        )

        activation_token = generate_secure_token()

        await create_activation_token(db, new_user.id, activation_token)
        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        ) from e

    background_tasks.add_task(
        send_activation_email,
        new_user.email,
        activation_token,
        f"http://127.0.0.1:8000/api/v1/accounts/activate/",
    )
    return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)
