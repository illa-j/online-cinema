from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=14, deprecated="auto")


def hash_token(token: str) -> str:
    """
    Hash a plain-text token using the configured password context.

    This function takes a plain-text token and returns its bcrypt hash.
    The bcrypt algorithm is used with a specified number of rounds for enhanced security.

    Args:
        token (str): The plain-text token to hash.

    Returns:
        str: The resulting hashed token.
    """
    return pwd_context.hash(token)


def verify_token(plain_token: str, hashed_token: str) -> bool:
    """
    Verify a plain-text token against its hashed version.

    This function compares a plain-text token with a hashed token and returns True
    if they match, and False otherwise.

    Args:
        plain_token (str): The plain-text token provided by the user.
        hashed_token (str): The hashed token stored in the database.

    Returns:
        bool: True if the token is correct, False otherwise.
    """
    return pwd_context.verify(plain_token, hashed_token)
