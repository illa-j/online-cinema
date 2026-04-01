from datetime import datetime, timezone

from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel
from exceptions.security import BaseSecurityError
from notifications import send_activation_complete_email, send_activation_email
from schemas import (
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    UserCreateSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    ActivationTokenRenewalRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserLogoutRequestSchema,
    AccessTokenRenewalRequestSchema,
    TokenRefreshResponseSchema
)
from repositories.accounts import (
    create_refresh_token,
    get_refresh_token_by_user_id,
    get_user_by_email,
    get_default_user_group,
    create_user,
    create_activation_token,
    get_user_by_id,
    get_user_with_activation_tokens_by_email,
    delete_activation_token_by_user_id,
    delete_refresh_tokens_by_user_id,
)
from security.interfaces import JWTAuthManagerInterface
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
    db: AsyncSession,
) -> MessageResponseSchema:
    user = await get_user_with_activation_tokens_by_email(db, activation_data.email)

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


async def renew_activation_token_service(
    data: ActivationTokenRenewalRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession,
) -> MessageResponseSchema:
    user = await get_user_by_email(db, data.email)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email not found.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="User is already activated."
        )
    try:
        await delete_activation_token_by_user_id(db, user.id)

        activation_token = generate_secure_token()

        await create_activation_token(db, user.id, activation_token)

        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during activation token renewal.",
        ) from e

    background_tasks.add_task(
        send_activation_email,
        user.email,
        activation_token,
        f"http://127.0.0.1:8000/api/v1/accounts/activate/",
    )
    return MessageResponseSchema(message="New activation token has been sent.")


async def login_user_service(
    login_data: UserLoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface,
    db: AsyncSession,
) -> UserLoginResponseSchema:
    user = await get_user_by_email(db, login_data.email)
    if user is None or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        await delete_refresh_tokens_by_user_id(db, user.id)
        await create_refresh_token(db, user.id, jwt_refresh_token)
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        ) from e

    jwt_access_token = jwt_manager.create_access_token({"user_id": user.id})
    return UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token,
    )


async def logout_user_service(
    data: UserLogoutRequestSchema,
    jwt_manager: JWTAuthManagerInterface,
    db: AsyncSession
) -> MessageResponseSchema:
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token or expired.",
            )
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token or expired."
        ) from e

    user_refresh_token = await get_refresh_token_by_user_id(db, user_id)
    if user_refresh_token is None or not user_refresh_token.verify_token(
        data.refresh_token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token or expired.",
        )

    if _as_utc(user_refresh_token.expires_at) < datetime.now(timezone.utc):
        await delete_refresh_tokens_by_user_id(db, user_id)

        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token or expired.",
        )

    try:
        await delete_refresh_tokens_by_user_id(db, user_id)

        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        ) from e

    return MessageResponseSchema(message="Successfully logged out.")


async def renew_access_token_service(
    data: AccessTokenRenewalRequestSchema,
    jwt_manager: JWTAuthManagerInterface,
    db: AsyncSession
) -> TokenRefreshResponseSchema:
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("user_id")
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token or expired."
        ) from e

    user_refresh_token = await get_refresh_token_by_user_id(db, user_id)
    if user_refresh_token is None or not user_refresh_token.verify_token(
        data.refresh_token
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token or expired.",
        )

    user = await get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if _as_utc(user_refresh_token.expires_at) < datetime.now(timezone.utc):
        await delete_refresh_tokens_by_user_id(db, user_id)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token or expired.",
        )

    await delete_refresh_tokens_by_user_id(db, user_id)
    await db.commit()

    jwt_access_token = jwt_manager.create_access_token({"user_id": user_id})
    return TokenRefreshResponseSchema(access_token=jwt_access_token)
