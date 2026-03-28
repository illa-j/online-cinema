from datetime import datetime, timezone

from fastapi import HTTPException, status, BackgroundTasks

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel, ActivationTokenModel
from notifications import send_activation_complete_email, send_activation_email
from schemas import (
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    UserCreateSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema
)
from repositories.accounts import (
    get_user_by_email,
    get_default_user_group,
    create_user,
    create_activation_token,
    get_user_with_activation_tokens,
    delete_activation_token_by_user_id
)
from security.utils import generate_secure_token


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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


async def activate_user_service(
    activation_data: UserActivationRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession
) -> MessageResponseSchema:
    user = await get_user_with_activation_tokens(db, activation_data.email)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User is already activated."
        )
    user_activation_token = (
        user.activation_tokens[0] if user.activation_tokens else None
    )

    if not user_activation_token or not user_activation_token.verify_token(
        activation_data.token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or activation token.",
        )

    if _as_utc(user_activation_token.expires_at) < datetime.now(timezone.utc):
        await delete_activation_token_by_user_id(db, user.id)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has been expired. Try to renew token.",
        )

    try:
        await delete_activation_token_by_user_id(db, user.id)

        user.is_active = True
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        ) from e

    background_tasks.add_task(
        send_activation_complete_email,
        user.email,
        "http://127.0.0.1:8000/api/v1/accounts/login",
    )
    return MessageResponseSchema(message="Account activated successfully.")
