from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks

from database.models.accounts import (
    ActivationTokenModel,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
)
from schemas import UserRegistrationResponseSchema
from database.session_postgresql import get_db
from schemas.accounts import UserRegistrationRequestSchema
from notifications import send_activation_email

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    stmt = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    result = stmt.scalar_one_or_none()
    if result is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    stmt = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    result = stmt.scalar_one_or_none()
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
            f"http://127.0.0.1:8000/api/v1/accounts/activate/{token.token}",
        )
        return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)
