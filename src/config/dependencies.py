from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

from config.settings import BaseAppSettings, Settings
from exceptions.security import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager


security = HTTPBearer()


def get_settings() -> BaseAppSettings:
    """
    Retrieve the application settings based on the current environment.

    This function reads the 'ENVIRONMENT' environment variable (defaulting to 'developing' if not set)
    and returns a corresponding settings instance. If the environment is 'testing', it returns an instance
    of TestingSettings; otherwise, it returns an instance of Settings.

    Returns:
        BaseAppSettings: The settings instance appropriate for the current environment.
    """
    return Settings()


def get_jwt_auth_manager(settings: BaseAppSettings = Depends(get_settings)) -> JWTAuthManagerInterface:
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
        algorithm=settings.JWT_SIGNING_ALGORITHM
    )


def get_current_user(
    credentials: str = Depends(security),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
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
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token."
        )
    return payload["user_id"]
