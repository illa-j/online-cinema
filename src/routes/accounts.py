from datetime import datetime, timezone

from sqlalchemy import select, delete
from sqlalchemy.orm import joinedload, selectinload
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks

from database.models.accounts import (
    ActivationTokenModel,
    RefreshTokenModel,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    PasswordResetTokenModel,
)
from database.session_postgresql import get_db
from exceptions.security import BaseSecurityError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshResponseSchema,
    ActivationTokenRenewalRequestSchema,
    UserLogoutRequestSchema,
    AccessTokenRenewalRequestSchema,
    ChangeUserGroupRequestSchema,
    UserResetPasswordRequestSchema,
)
from notifications import (
    send_activation_email,
    send_activation_complete_email,
    send_password_reset_email,
    send_password_reset_complete_email,
)
from security.interfaces import JWTAuthManagerInterface
from config import get_jwt_auth_manager, get_settings, get_current_user
from security.utils import generate_secure_token

settings = get_settings()
router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = stmt.scalars().first()
    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    stmt = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = stmt.scalars().first()
    if user_group is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not found.",
        )
    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()

        activation_token = generate_secure_token()

        token = ActivationTokenModel(user_id=new_user.id)
        token.token = activation_token
        db.add(token)

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


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_tokens))
        .join(ActivationTokenModel)
        .where(UserModel.email == activation_data.email)
    )
    user = stmt.scalars().first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="User is already activated."
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

    if user_activation_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has been expired. Try to renew token.",
        )
    try:
        await db.execute(
            delete(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
        )

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
    return MessageResponseSchema(message="Account has been successfully activated.")


@router.post("/renew-activation-token/", response_model=MessageResponseSchema)
async def renew_activation_token(
    data: ActivationTokenRenewalRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = stmt.scalars().first()

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
        await db.execute(
            delete(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
        )

        activation_token = generate_secure_token()

        new_token = ActivationTokenModel(user_id=user.id)
        new_token.token = activation_token
        db.add(new_token)

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


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login_user(
    login_data: UserLoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(
        select(UserModel).where(UserModel.email == login_data.email)
    )
    user = stmt.scalars().first()
    if user is None or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not activated.",
        )

    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        await db.execute(
            delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id)
        )

        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token,
        )
        db.add(refresh_token)
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


@router.post("/logout/", response_model=MessageResponseSchema)
async def logout_user(
    data: UserLogoutRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token or expired.",
            )
    except BaseSecurityError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token or expired."
        ) from e

    stmt = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id)
    )
    user_refresh_token = stmt.scalars().first()
    if user_refresh_token is None or not user_refresh_token.verify_token(
        data.refresh_token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token or expired.",
        )
    if user_refresh_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token or expired.",
        )

    try:
        await db.execute(
            delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id)
        )

        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        ) from e

    return MessageResponseSchema(message="Successfully logged out.")


@router.post("/renew-access-token/", response_model=TokenRefreshResponseSchema)
async def renew_access_token(
    data: AccessTokenRenewalRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("user_id")
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token or expired."
        ) from e

    stmt = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id)
    )
    user_refresh_token = stmt.scalars().first()
    if user_refresh_token is None or not user_refresh_token.verify_token(
        data.refresh_token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token or expired.",
        )

    if user_refresh_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token or expired.",
        )

    jwt_access_token = jwt_manager.create_access_token({"user_id": user_id})
    return TokenRefreshResponseSchema(access_token=jwt_access_token)


@router.post("/password-reset/", response_model=MessageResponseSchema)
async def password_reset_request(
    data: UserResetPasswordRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = stmt.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password or email.",
        )

    if not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password or email.",
        )

    try:
        user.password = data.new_password
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        ) from e

    return MessageResponseSchema(message="User password was updated succesfully.")


@router.post("/password-reset-request/", response_model=MessageResponseSchema)
async def password_reset_request(
    data: PasswordResetRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    GENERIC_RESPONSE = MessageResponseSchema(
        message="If an account with this email exists, password reset instructions have been sent."
    )

    stmt = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = stmt.scalars().first()

    if user is None or not user.is_active:
        return GENERIC_RESPONSE

    try:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        reset_token = generate_secure_token()

        new_token = PasswordResetTokenModel(user_id=user.id)
        new_token.token = reset_token
        db.add(new_token)

        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during password reset token generation.",
        ) from e

    background_tasks.add_task(
        send_password_reset_email,
        user.email,
        reset_token,
        f"http://127.0.0.1:8000/reset-password/",
    )
    return GENERIC_RESPONSE


@router.post("/password-reset-complete/", response_model=MessageResponseSchema)
async def password_reset_complete(
    data: PasswordResetCompleteRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_tokens))
        .join(PasswordResetTokenModel)
        .where(
            UserModel.email == data.email,
        )
    )
    user = stmt.scalars().first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password reset token.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not activated.",
        )
    password_reset_token = (
        user.password_reset_tokens[0] if user.password_reset_tokens else None
    )

    if not password_reset_token or not password_reset_token.verify_token(data.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password reset token.",
        )

    if password_reset_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has been expired. Try to renew token.",
        )
    try:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        user.password = data.password

        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during password reset.",
        ) from e

    background_tasks.add_task(
        send_password_reset_complete_email,
        user.email,
        "http://127.0.0.1:8000/api/v1/accounts/login",
    )
    return MessageResponseSchema(message="Password has been successfully reset.")


@router.patch("/{user_id}/change-group/", response_model=MessageResponseSchema)
async def change_user_group(
    user_id: int,
    data: ChangeUserGroupRequestSchema,
    current_user_id: int = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.group))
        .where(UserModel.id == current_user_id)
    )
    current_user = stmt.scalar_one_or_none()

    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User was not found."
        )

    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive."
        )

    if current_user.group.name != UserGroupEnum.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions."
        )

    stmt = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.group))
        .where(UserModel.id == user_id)
    )
    user = stmt.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    stmt = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == data.group)
    )
    user_group = stmt.scalars().first()
    if user_group is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User group not found.",
        )

    try:
        user.group = user_group
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during password reset.",
        ) from e

    return MessageResponseSchema(message="User group was updated succefully.")


@router.patch("/{user_id}/activate/", response_model=MessageResponseSchema)
async def activate_user_manually(
    user_id: int,
    current_user_id: int = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.group))
        .where(UserModel.id == current_user_id)
    )
    current_user = stmt.scalar_one_or_none()

    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User was not found."
        )

    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive."
        )

    if current_user.group.name != UserGroupEnum.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions."
        )

    stmt = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = stmt.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User was not found."
        )

    if user.is_active:
        return MessageResponseSchema(message="User has already been activated.")

    try:
        user.is_active = True
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during password reset.",
        ) from e

    return MessageResponseSchema(message="User was activated succefully.")
