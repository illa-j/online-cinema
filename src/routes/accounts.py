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
from database import get_db
from exceptions.security import BaseSecurityError, TokenExpiredError
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


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    summary="User Registration",
    description="Register a new user with an email and password.",
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "description": "Conflict - User with this email already exists.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "A user with this email test@example.com already exists."
                    }
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred during user creation.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            },
        },
    },
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


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activate User Account",
    description=(
        "Activate a user's account using their email and activation token. "
        "The token must be valid and not expired."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": (
                "Bad Request — The activation token is invalid or expired, "
                "the email/token combination is incorrect, "
                "or the user account is already active."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Invalid or Expired Token",
                            "value": {"detail": "Invalid email or activation token."},
                        },
                        "invalid_credentials": {
                            "summary": "Invalid Email or Token",
                            "value": {"detail": "Invalid email or activation token."},
                        },
                        "already_active": {
                            "summary": "Account Already Active",
                            "value": {"detail": "User is already activated."},
                        },
                    }
                }
            },
        },
    },
)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Activate a user account using email and activation token.

    The provided token must match the user and must not be expired.
    If the activation is successful, the user account is marked as active
    and all related activation tokens are removed.

    Raises:
        HTTPException (400):
            - Invalid email or activation token
            - Token is expired
            - User account is already active
        HTTPException (500):
            - An error occurred during account activation

    Returns:
        MessageResponseSchema: Confirmation message indicating successful activation.
    """
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
        await db.execute(
            delete(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
        )
        await db.commit()
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
    return MessageResponseSchema(message="Account activated successfully.")


@router.post(
    "/renew-activation-token/",
    response_model=MessageResponseSchema,
    summary="Renew Activation Token",
    description=(
        "Generate and send a new activation token for a user account. "
        "The user must exist and must not be already activated."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request — The user with the provided email does not exist.",
            "content": {
                "application/json": {
                    "examples": {
                        "user_not_found": {
                            "summary": "User Not Found",
                            "value": {"detail": "User with this email not found."},
                        },
                    }
                }
            },
        },
        409: {
            "description": "Conflict — The user account is already activated.",
            "content": {
                "application/json": {
                    "examples": {
                        "already_active": {
                            "summary": "Account Already Active",
                            "value": {"detail": "User is already activated."},
                        },
                    }
                }
            },
        },
    },
)
async def renew_activation_token(
    data: ActivationTokenRenewalRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate and send a new activation token to the user's email.

    The user must exist and must not be already activated.
    Any existing activation tokens are removed before creating a new one.

    Raises:
        HTTPException (400):
            - User with the provided email does not exist
        HTTPException (409):
            - User account is already activated
        HTTPException (500):
            - An error occurred during activation token renewal

    Returns:
        MessageResponseSchema: Confirmation message indicating that a new activation token was sent.
    """
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


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    summary="User Login",
    description=(
        "Authenticate a user using email and password. "
        "Returns access and refresh tokens if credentials are valid "
        "and the account is activated."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        401: {
            "description": "Unauthorized — Invalid email or password.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_credentials": {
                            "summary": "Invalid Credentials",
                            "value": {"detail": "Invalid email or password."},
                        },
                    }
                }
            },
        },
        403: {
            "description": "Forbidden — The user account is not activated.",
            "content": {
                "application/json": {
                    "examples": {
                        "inactive_account": {
                            "summary": "Account Not Activated",
                            "value": {"detail": "User account is not activated."},
                        },
                    }
                }
            },
        },
    },
)
async def login_user(
    login_data: UserLoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate a user and return JWT tokens.

    Validates user credentials and ensures the account is activated.
    On success, generates a new access token and refresh token.
    Any existing refresh tokens for the user are removed.

    Raises:
        HTTPException (401):
            - Invalid email or password
        HTTPException (403):
            - User account is not activated
        HTTPException (500):
            - An error occurred while processing the login request

    Returns:
        UserLoginResponseSchema: Access and refresh tokens for authenticated user.
    """
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
            detail="User account is not activated.",
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


@router.post(
    "/logout/",
    response_model=MessageResponseSchema,
    summary="User Logout",
    description=(
        "Log out a user by invalidating their refresh token. "
        "The provided token must be valid and not expired."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request — The refresh token is invalid or expired.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Invalid or Expired Token",
                            "value": {"detail": "Invalid token or expired."},
                        },
                    }
                }
            },
        },
    },
)
async def logout_user(
    data: UserLogoutRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
):
    """
    Log out a user by invalidating their refresh token.

    Validates the provided refresh token, ensures it exists in the database
    and is not expired, then removes it to terminate the session.

    Raises:
        HTTPException (400):
            - Invalid or expired refresh token
        HTTPException (500):
            - An error occurred while processing the logout request

    Returns:
        MessageResponseSchema: Confirmation message indicating successful logout.
    """
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

    if _as_utc(user_refresh_token.expires_at) < datetime.now(timezone.utc):
        await db.execute(
            delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id)
        )

        await db.commit()
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


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    summary="Renew Access Token",
    description=(
        "Generate a new access token using a valid refresh token. "
        "The refresh token must be valid, exist in the database, and not be expired."
    ),
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {
            "description": "Bad Request — The refresh token is invalid or expired.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Invalid or Expired Token",
                            "value": {"detail": "Invalid token or expired."},
                        },
                    }
                }
            },
        },
        401: {
            "description": "Unauthorized — The refresh token is missing, invalid, or expired in storage.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Invalid Token",
                            "value": {"detail": "Invalid token or expired."},
                        },
                    }
                }
            },
        },
        404: {
            "description": "Not Found — User from refresh token payload does not exist.",
            "content": {
                "application/json": {
                    "examples": {
                        "user_not_found": {
                            "summary": "User Not Found",
                            "value": {"detail": "User not found."},
                        },
                    }
                }
            },
        },
    },
)
async def renew_access_token(
    data: AccessTokenRenewalRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a new access token using a refresh token.

    Validates the provided refresh token, ensures it exists in the database
    and is not expired, then issues a new access token.

    Raises:
        HTTPException (400):
            - Invalid or expired refresh token
        HTTPException (500):
            - An unexpected error occurred during token renewal

    Returns:
        TokenRefreshResponseSchema: A new access token.
    """
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("user_id")
    except TokenExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token or expired."
        ) from e
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
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token or expired.",
        )

    stmt = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = stmt.scalars().first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if _as_utc(user_refresh_token.expires_at) < datetime.now(timezone.utc):
        await db.execute(
            delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id)
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token or expired.",
        )

    await db.execute(
        delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id)
    )
    await db.commit()

    jwt_access_token = jwt_manager.create_access_token({"user_id": user_id})
    return TokenRefreshResponseSchema(access_token=jwt_access_token)


@router.post(
    "/password-reset/",
    response_model=MessageResponseSchema,
    summary="Reset User Password",
    description=(
        "Update a user's password using their email and current password. "
        "Both email and password must be valid to proceed."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request — Incorrect email or password.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_credentials": {
                            "summary": "Invalid Credentials",
                            "value": {"detail": "Incorrect password or email."},
                        },
                    }
                }
            },
        },
    },
)
async def reset_user_password(
    data: UserResetPasswordRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    """
    Update a user's password using their current credentials.

    Validates the provided email and current password.
    If valid, updates the password to the new value.

    Raises:
        HTTPException (400):
            - Incorrect email or password
        HTTPException (500):
            - An error occurred while updating the password

    Returns:
        MessageResponseSchema: Confirmation message indicating successful password update.
    """
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

    return MessageResponseSchema(message="User password was updated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request Password Reset",
    description=(
        "Initiate a password reset process for a user account. "
        "If the account exists and is active, a password reset token will be generated "
        "and sent to the user's email. "
        "A generic response is always returned to prevent account enumeration."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Success — A generic response is returned regardless of whether the account exists.",
            "content": {
                "application/json": {
                    "examples": {
                        "generic_response": {
                            "summary": "Generic Response",
                            "value": {
                                "message": "If an account with this email exists, password reset instructions have been sent."
                            },
                        },
                    }
                }
            },
        },
    },
)
async def password_reset_request(
    data: PasswordResetRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate a password reset request.

    If a user with the provided email exists and is active, generates a password
    reset token, removes any existing tokens, and sends reset instructions via email.
    Always returns a generic response to prevent account enumeration.

    Raises:
        HTTPException (500):
            - An error occurred during password reset token generation

    Returns:
        MessageResponseSchema: Generic response indicating that reset instructions
        may have been sent if the account exists.
    """
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


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Complete Password Reset",
    description=(
        "Complete the password reset process using email and reset token. "
        "The token must be valid, match the user, and not be expired. "
        "If successful, the user's password is updated and all reset tokens are removed."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": (
                "Bad Request — The email or reset token is invalid, "
                "or the token has expired."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Invalid Token",
                            "value": {
                                "detail": "Invalid email or password reset token."
                            },
                        },
                        "expired_token": {
                            "summary": "Expired Token",
                            "value": {
                                "detail": "Invalid email or password reset token."
                            },
                        },
                    }
                }
            },
        },
        403: {
            "description": "Forbidden — The user account is not activated.",
            "content": {
                "application/json": {
                    "examples": {
                        "inactive_account": {
                            "summary": "Account Not Activated",
                            "value": {"detail": "Account is not activated."},
                        },
                    }
                }
            },
        },
    },
)
async def password_reset_complete(
    data: PasswordResetCompleteRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Complete the password reset process.

    Validates the provided email and reset token, ensures the token exists
    and is not expired, then updates the user's password.
    All existing password reset tokens are removed after successful reset.

    Raises:
        HTTPException (400):
            - Invalid email or password reset token
            - Token is expired
        HTTPException (403):
            - User account is not activated
        HTTPException (500):
            - An error occurred during password reset

    Returns:
        MessageResponseSchema: Confirmation message indicating successful password reset.
    """
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

    if _as_utc(password_reset_token.expires_at) < datetime.now(timezone.utc):
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password reset token.",
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
    return MessageResponseSchema(message="Password reset successfully.")


@router.patch(
    "/{user_id}/change-group/",
    response_model=MessageResponseSchema,
    summary="Change User Group",
    description=(
        "Update the group of a specific user. Only active users with ADMIN privileges "
        "can perform this action. The target user and group must exist."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request — The requested user group is not available in storage.",
            "content": {
                "application/json": {
                    "examples": {
                        "group_not_found": {
                            "summary": "User Group Not Found",
                            "value": {"detail": "User group not found."},
                        },
                    }
                }
            },
        },
        422: {
            "description": "Validation Error — The provided group value is invalid.",
        },
        403: {
            "description": "Forbidden — Current user is inactive or lacks admin permissions.",
            "content": {
                "application/json": {
                    "examples": {
                        "inactive_user": {
                            "summary": "Inactive User",
                            "value": {"detail": "User is inactive."},
                        },
                        "not_admin": {
                            "summary": "Not Enough Permissions",
                            "value": {"detail": "Not enough permissions."},
                        },
                    }
                }
            },
        },
        404: {
            "description": "Not Found — Either the current user or target user was not found.",
            "content": {
                "application/json": {
                    "examples": {
                        "user_not_found": {
                            "summary": "User Not Found",
                            "value": {"detail": "User not found."},
                        },
                    }
                }
            },
        },
    },
)
async def change_user_group(
    user_id: int,
    data: ChangeUserGroupRequestSchema,
    current_user_id: int = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Change the group of a specified user.

    Only active users with ADMIN privileges can update a user's group.
    Validates that both the target user and the new group exist, then updates the user's group.

    Raises:
        HTTPException (400):
            - The specified user group does not exist
        HTTPException (403):
            - Current user is inactive
            - Current user does not have admin permissions
        HTTPException (404):
            - Current user or target user was not found
        HTTPException (500):
            - An error occurred during the update operation

    Returns:
        MessageResponseSchema: Confirmation message indicating successful group update.
    """
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
            detail="An error occurred during user group update.",
        ) from e

    return MessageResponseSchema(message="User group updated successfully.")


@router.patch(
    "/{user_id}/activate/",
    response_model=MessageResponseSchema,
    summary="Manually Activate User",
    description=(
        "Manually activate a user account. Only active users with ADMIN privileges "
        "can perform this action. Returns a message if the user is already active "
        "or confirms successful activation."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        403: {
            "description": "Forbidden — Current user is inactive or lacks admin permissions.",
            "content": {
                "application/json": {
                    "examples": {
                        "inactive_user": {
                            "summary": "Inactive User",
                            "value": {"detail": "User is inactive."},
                        },
                        "not_admin": {
                            "summary": "Not Enough Permissions",
                            "value": {"detail": "Not enough permissions."},
                        },
                    }
                }
            },
        },
        404: {
            "description": "Not Found — Either the current user or target user was not found.",
            "content": {
                "application/json": {
                    "examples": {
                        "user_not_found": {
                            "summary": "User Not Found",
                            "value": {"detail": "User was not found."},
                        },
                    }
                }
            },
        },
        500: {
            "description": "Internal Server Error — An error occurred during activation.",
            "content": {
                "application/json": {
                    "examples": {
                        "activation_error": {
                            "summary": "Activation Error",
                            "value": {"detail": "An error occurred during activation."},
                        },
                    }
                }
            },
        },
    },
)
async def activate_user_manually(
    user_id: int,
    current_user_id: int = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Manually activate a user account.

    Only active users with ADMIN privileges can activate another user.
    If the target user is already active, a message is returned.
    Otherwise, the user's account is activated.

    Raises:
        HTTPException (403):
            - Current user is inactive
            - Current user does not have admin permissions
        HTTPException (404):
            - Current user or target user was not found
        HTTPException (500):
            - An error occurred during activation

    Returns:
        MessageResponseSchema: Confirmation message indicating whether the user
        was already active or successfully activated.
    """
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
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    if user.is_active:
        return MessageResponseSchema(message="User is already active.")

    try:
        user.is_active = True
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during activation.",
        ) from e

    return MessageResponseSchema(message="User was activated successfully.")
