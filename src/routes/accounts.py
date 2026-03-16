from datetime import datetime, timezone

from sqlalchemy import select, delete
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks

from database.models.accounts import (
    ActivationTokenModel,
    RefreshTokenModel,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
)
from database.session_postgresql import get_db
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
)
from notifications import send_activation_email, send_activation_complete_email
from security.interfaces import JWTAuthManagerInterface
from config import get_jwt_auth_manager, get_settings
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
    result = stmt.scalars().first()
    if result is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    stmt = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    result = stmt.scalars().first()
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not found.",
        )
    try:
        new_user = UserModel.create(
            email=user_data.email, raw_password=user_data.password, group_id=result.id
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
        .where(
            UserModel.email == activation_data.email,
        )
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
    user_activation_token = user.activation_tokens[0]

    if not user_activation_token.verify_token(activation_data.token):
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
    email: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(select(UserModel).where(UserModel.email == email))
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
        await db.flush()
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    jwt_access_token = jwt_manager.create_access_token({"user_id": user.id})
    return UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token,
    )
