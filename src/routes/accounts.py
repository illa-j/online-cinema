import asyncio
from datetime import datetime, timezone
from typing import cast

from sqlalchemy import select, delete
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks

from database.models.accounts import (
    ActivationTokenModel,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
)
from database.session_postgresql import get_db
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
)
from notifications import send_activation_email, send_activation_complete_email

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

        token = ActivationTokenModel(user_id=new_user.id)
        db.add(token)

        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        ) from e
    else:
        background_tasks.add_task(
            send_activation_email,
            new_user.email,
            token.token,
            f"http://127.0.0.1:8000/api/v1/accounts/activate/",
        )
        return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)


@router.post("/activate/", response_model=dict[str, str])
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
            ActivationTokenModel.token == activation_data.token,
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

    if user.activation_tokens[0].expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has been expired. Try to renew token.",
        )

    await db.execute(
        delete(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )

    user.is_active = True

    await db.commit()

    background_tasks.add_task(
        send_activation_complete_email,
        user.email,
        "http://127.0.0.1:8000/api/v1/accounts/login",
    )

    return {"message": "Account has been succefully activated."}
