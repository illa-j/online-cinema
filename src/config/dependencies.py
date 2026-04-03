from typing import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import BaseAppSettings, get_settings
from database import get_db, UserModel, UserGroupEnum
from exceptions.security import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager
from repositories.accounts import get_user_with_group_by_id

security = HTTPBearer()


def get_jwt_auth_manager(
    settings: BaseAppSettings = Depends(get_settings),
) -> JWTAuthManagerInterface:
    """
    Create and return a JWT authentication manager instance.

    This function uses the provided application settings to instantiate a JWTAuthManager, which implements
    the JWTAuthManagerInterface. The manager is configured with secret keys for access and refresh tokens
    as well as the JWT signing algorithm specified in the settings.

    Args:
        settings (BaseAppSettings, optional): The application settings instance.
        Defaults to the output of get_settings().

    Returns:
        JWTAuthManagerInterface: An instance of JWTAuthManager configured with
        the appropriate secret keys and algorithm.
    """
    return JWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=settings.JWT_SIGNING_ALGORITHM,
    )


def get_current_user(
    credentials: str = Depends(security),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> int:
    """
    Return the authenticated user's ID from a JWT access token.

    Extracts the token from the request and decodes it via the JWT manager.

    Raises:
        TokenExpiredError: If the token has expired.
        InvalidTokenError: If the token is invalid.
        KeyError: If `user_id` is missing.
    """
    token = credentials.credentials
    try:
        payload = jwt_manager.decode_access_token(token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token."
        )
    return payload["user_id"]


async def get_current_user_with_group(
    current_user_id: int = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserModel:
    user = await get_user_with_group_by_id(db, current_user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User was not found.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive.",
        )
    return user


def require_roles(*allowed_roles: UserGroupEnum) -> Callable:
    async def role_checker(
        current_user: UserModel = Depends(get_current_user_with_group),
    ) -> UserModel:
        if current_user.group.name not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions.",
            )
        return current_user

    return role_checker
