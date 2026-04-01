import httpx
import pytest

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database import UserModel, ActivationTokenModel
from database.models.accounts import (
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
)
from tests.extract_html import get_email_soup

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_create_user(
    client: AsyncClient, db_session: AsyncSession, seed_user_groups: None
):
    """
    Test successful user registration.

    Validates that a new user and an activation token are created in the database.
    """
    payload = {"email": "testuser@example.com", "password": "StrongPassword123!"}

    response = await client.post("/api/v1/accounts/register/", json=payload)
    assert response.status_code == 201, "Expected status code 201 Created."
    response_data = response.json()
    assert response_data["email"] == payload["email"], "Returned email does not match."
    assert "id" in response_data, "Response does not contain user ID."

    stmt_user = select(UserModel).where(UserModel.email == payload["email"])
    result = await db_session.execute(stmt_user)
    created_user = result.scalars().first()
    assert created_user is not None, "User was not created in the database."
    assert (
        created_user.email == payload["email"]
    ), "Created user's email does not match."

    stmt_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == created_user.id
    )
    result = await db_session.execute(stmt_token)
    activation_token = result.scalars().first()
    assert (
        activation_token is not None
    ), "Activation token was not created in the database."
    assert (
        activation_token.user_id == created_user.id
    ), "Activation token's user_id does not match."
    assert (
        activation_token._hashed_token is not None
    ), "Activation token has no token value."

    expires_at = activation_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    assert expires_at > datetime.now(
        timezone.utc
    ), "Activation token is already expired."


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_password, expected_error",
    [
        ("short", "Password must contain at least 8 characters."),
        ("NoDigitHere!", "Password must contain at least one digit."),
        ("nodigitnorupper@", "Password must contain at least one uppercase letter."),
        ("NOLOWERCASE1@", "Password must contain at least one lower letter."),
        (
            "NoSpecial123",
            "Password must contain at least one special character: @, $, !, %, *, ?, #, &.",
        ),
    ],
)
async def test_register_user_password_validation(
    client, seed_user_groups, invalid_password, expected_error
):
    """
    Test password strength validation in the user registration endpoint.

    Ensures that when an invalid password is provided, the endpoint returns the appropriate
    error message and a 422 status code.

    Args:
        client: The asynchronous HTTP client fixture.
        seed_user_groups: Fixture that seeds the default user groups.
        invalid_password (str): The password to test.
        expected_error (str): The expected error message substring.
    """
    payload = {"email": "testuser@example.com", "password": invalid_password}

    response = await client.post("/api/v1/accounts/register/", json=payload)
    assert response.status_code == 422, "Expected status code 422 for invalid input."

    response_data = response.json()
    assert expected_error in str(
        response_data
    ), f"Expected error message: {expected_error}"


@pytest.mark.asyncio
async def test_register_user_conflict(client, db_session, seed_user_groups):
    """
    Test user registration conflict.

    Ensures that trying to register a user with an existing email
    returns a 409 Conflict status and the correct error message.

    Args:
        client: The asynchronous HTTP client fixture.
        db_session: The asynchronous database session fixture.
        seed_user_groups: Fixture that seeds default user groups.
    """
    payload = {"email": "conflictuser@example.com", "password": "StrongPassword123!"}

    response_first = await client.post("/api/v1/accounts/register/", json=payload)
    assert (
        response_first.status_code == 201
    ), "Expected status code 201 for the first registration."

    stmt = select(UserModel).where(UserModel.email == payload["email"])
    result = await db_session.execute(stmt)
    created_user = result.scalars().first()
    assert (
        created_user is not None
    ), "User should be created after the first registration."

    response_second = await client.post("/api/v1/accounts/register/", json=payload)
    assert (
        response_second.status_code == 409
    ), "Expected status code 409 for a duplicate registration."

    response_data = response_second.json()
    expected_message = f"A user with this email {payload['email']} already exists."
    assert (
        response_data["detail"] == expected_message
    ), f"Expected error message: {expected_message}"


@pytest.mark.asyncio
async def test_register_user_internal_server_error(client, seed_user_groups):
    """
    Test server error during user registration.

    Ensures that a 500 Internal Server Error is returned when a database operation fails.

    This test patches the commit method of the AsyncSession to simulate a SQLAlchemyError,
    then verifies that the registration endpoint returns the appropriate HTTP 500 error
    with the expected error message.
    """
    payload = {"email": "erroruser@example.com", "password": "StrongPassword123!"}

    with patch("routes.accounts.AsyncSession.commit", side_effect=SQLAlchemyError):
        response = await client.post("/api/v1/accounts/register/", json=payload)

        assert (
            response.status_code == 500
        ), "Expected status code 500 for internal server error."

        response_data = response.json()
        expected_message = "An error occurred during user creation."
        assert (
            response_data["detail"] == expected_message
        ), f"Expected error message: {expected_message}"


@pytest.mark.asyncio
async def test_activate_account_success(client, db_session, settings, seed_user_groups):
    """
    Test successful activation of a user account.

    Steps:
    - Register a new user.
    - Verify the user is inactive.
    - Activate the user using the activation token.
    - Verify the user is activated and the token is deleted.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }

    registration_response = await client.post(
        "/api/v1/accounts/register/", json=registration_payload
    )
    assert (
        registration_response.status_code == 201
    ), "Expected status code 201 for successful registration."

    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_tokens))
        .where(UserModel.email == registration_payload["email"])
    )
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User was not created in the database."
    assert not user.is_active, "Newly registered user should not be active."

    assert (
        user.activation_tokens and user.activation_tokens[0]._hashed_token is not None
    ), "Activation token was not created in the database."

    token = "test-token-123"
    user.activation_tokens[0].token = token
    await db_session.commit()

    activation_payload = {"email": registration_payload["email"], "token": token}
    activation_response = await client.post(
        "/api/v1/accounts/activate/", json=activation_payload
    )
    assert (
        activation_response.status_code == 200
    ), "Expected status code 200 for successful activation."
    assert activation_response.json()["message"] == "Account activated successfully."

    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_tokens))
        .where(UserModel.email == registration_payload["email"])
    )
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    await db_session.refresh(user)
    assert user.is_active, "User should be active after successful activation."

    stmt = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result = await db_session.execute(stmt)
    token = result.scalars().first()
    assert (
        token is None
    ), "Activation token should be deleted after successful activation."


@pytest.mark.asyncio
async def test_activate_user_with_expired_token(
    client, db_session, settings, seed_user_groups
):
    """
    Test activation with an expired token.

    Ensures that the endpoint returns a 400 error when the activation token is expired.
    Steps:
    - Register a new user.
    - Retrieve the user and their activation token.
    - Manually set the token's expiration to a past date.
    - Attempt to activate the account with the expired token.
    - Verify that the response is a 400 error with the expected error message.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }
    registration_response = await client.post(
        "/api/v1/accounts/register/", json=registration_payload
    )
    assert (
        registration_response.status_code == 201
    ), "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."
    assert not user.is_active, "User should not be active before activation."

    stmt_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id
    )
    result_token = await db_session.execute(stmt_token)
    activation_token = result_token.scalars().first()
    assert activation_token is not None, "Activation token should exist for the user."

    activation_token.expires_at = datetime.now(timezone.utc) - timedelta(days=2)
    await db_session.commit()

    token = "test-token-123"
    activation_token.token = token
    await db_session.commit()

    activation_payload = {"email": registration_payload["email"], "token": token}
    activation_response = await client.post(
        "/api/v1/accounts/activate/", json=activation_payload
    )

    assert (
        activation_response.status_code == 400
    ), "Expected status code 400 for expired token."
    assert (
        activation_response.json()["detail"]
        == "Token has been expired. Try to renew token."
    ), "Expected error message for expired token."


@pytest.mark.asyncio
async def test_activate_user_with_deleted_token(
    client, db_session, settings, seed_user_groups
):
    """
    Test activation with a deleted token.

    Ensures that the endpoint returns a 400 error when the activation token has been deleted.

    Steps:
    - Register a new user.
    - Verify that the user is created and inactive.
    - Delete the activation token from the database.
    - Attempt to activate the account using the deleted token.
    - Verify that a 400 error is returned with the appropriate error message.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }
    registration_response = await client.post(
        "/api/v1/accounts/register/", json=registration_payload
    )
    assert (
        registration_response.status_code == 201
    ), "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."
    assert not user.is_active, "User should not be active before activation."

    stmt_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id
    )
    result_token = await db_session.execute(stmt_token)
    activation_token = result_token.scalars().first()
    assert activation_token is not None, "Activation token should exist for the user."

    token = "test-token-123"
    activation_token.token = token
    await db_session.commit()

    await db_session.execute(
        delete(ActivationTokenModel).where(
            ActivationTokenModel.id == activation_token.id
        )
    )
    await db_session.commit()

    activation_payload = {"email": registration_payload["email"], "token": token}
    activation_response = await client.post(
        "/api/v1/accounts/activate/", json=activation_payload
    )
    assert (
        activation_response.status_code == 400
    ), "Expected status code 400 for deleted token."
    assert (
        activation_response.json()["detail"] == "Invalid email or activation token."
    ), "Expected error message for deleted token."


@pytest.mark.asyncio
async def test_activate_already_active_user(
    client, db_session, settings, seed_user_groups
):
    """
    Test activation of an already active user.

    Ensures that the endpoint returns a 400 error if the user is already active.
    Steps:
    - Register a new user.
    - Mark the user as active in the database.
    - Attempt to activate the user using the activation token.
    - Verify that a 400 error with the expected error message is returned.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }

    registration_response = await client.post(
        "/api/v1/accounts/register/", json=registration_payload
    )
    assert (
        registration_response.status_code == 201
    ), "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."

    user.is_active = True

    stmt_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id
    )
    result_token = await db_session.execute(stmt_token)
    activation_token = result_token.scalars().first()
    assert activation_token is not None, "Activation token should exist for the user."

    token = "test-token-123"
    activation_token.token = token
    await db_session.commit()

    activation_payload = {"email": registration_payload["email"], "token": token}
    activation_response = await client.post(
        "/api/v1/accounts/activate/", json=activation_payload
    )
    assert (
        activation_response.status_code == 400
    ), "Expected status code 400 for already active user."
    assert (
        activation_response.json()["detail"] == "User is already activated."
    ), "Expected error message for already active user."


@pytest.mark.asyncio
async def test_request_password_reset_token_success(
    client, db_session, seed_user_groups
):
    """
    Test successful password reset token request.

    Ensures that a password reset token is created for an active user.

    Steps:
    - Register a new user.
    - Mark the user as active.
    - Request a password reset token.
    - Verify that the endpoint returns status 200 and the expected success message.
    - Query the database to confirm that a PasswordResetTokenModel record was created.
    - Verify that the token's expiration date is in the future.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }
    registration_response = await client.post(
        "/api/v1/accounts/register/", json=registration_payload
    )
    assert (
        registration_response.status_code == 201
    ), "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."

    user.is_active = True
    await db_session.commit()

    reset_payload = {"email": registration_payload["email"]}
    reset_response = await client.post(
        "/api/v1/accounts/password-reset/request/", json=reset_payload
    )
    assert (
        reset_response.status_code == 200
    ), "Expected status code 200 for successful token request."
    assert (
        reset_response.json()["message"]
        == "If an account with this email exists, password reset instructions have been sent."
    ), "Expected success message for password reset token request."

    stmt_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result_token = await db_session.execute(stmt_token)
    reset_token = result_token.scalars().first()
    assert (
        reset_token is not None
    ), "Password reset token should be created for the user."

    expires_at = reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    assert expires_at > datetime.now(
        timezone.utc
    ), "Password reset token should have a future expiration date."


@pytest.mark.asyncio
async def test_reset_password_expired_token(client, db_session, seed_user_groups):
    """
    Test password reset with an expired token.

    Validates that the endpoint returns a 400 status code and an appropriate error message when the password
    reset token is expired, and verifies that the expired token is removed from the database.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }
    registration_response = await client.post(
        "/api/v1/accounts/register/", json=registration_payload
    )
    assert registration_response.status_code == 201, "User registration failed."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."

    user.is_active = True
    await db_session.commit()

    reset_request_payload = {"email": registration_payload["email"]}
    reset_request_response = await client.post(
        "/api/v1/accounts/password-reset/request/", json=reset_request_payload
    )
    assert reset_request_response.status_code == 200, "Password reset request failed."

    stmt_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result_token = await db_session.execute(stmt_token)
    token_record = result_token.scalars().first()
    assert token_record is not None, "Password reset token not created."

    token = "test-reset-token-123"
    token_record.token = token
    token_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    await db_session.commit()

    reset_complete_payload = {
        "email": registration_payload["email"],
        "token": token,
        "password": "NewSecurePassword123!",
    }
    reset_response = await client.post(
        "/api/v1/accounts/reset-password/complete/", json=reset_complete_payload
    )
    assert (
        reset_response.status_code == 400
    ), "Expected status code 400 for expired token."
    assert (
        reset_response.json()["detail"] == "Invalid email or password reset token."
    ), "Unexpected error message."

    stmt_token_check = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result_token_check = await db_session.execute(stmt_token_check)
    expired_token = result_token_check.scalars().first()
    assert expired_token is None, "Expired token was not removed."


@pytest.mark.asyncio
async def test_login_user_success(client, db_session, jwt_manager, seed_user_groups):
    """
    Test successful login.

    Validates that access and refresh tokens are returned, the refresh token is stored in the database,
    and both tokens are valid.
    """
    user_payload = {"email": "testuser@example.com", "password": "StrongPassword123!"}

    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id,
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_payload = {
        "email": user_payload["email"],
        "password": user_payload["password"],
    }
    response = await client.post("/api/v1/accounts/login/", json=login_payload)
    assert response.status_code == 200, "Expected status code 200 for successful login."
    response_data = response.json()
    assert "access_token" in response_data, "Access token is missing in the response."
    assert "refresh_token" in response_data, "Refresh token is missing in the response."
    assert response_data["access_token"], "Access token is empty."
    assert response_data["refresh_token"], "Refresh token is empty."

    access_token_data = jwt_manager.decode_access_token(response_data["access_token"])
    assert (
        access_token_data["user_id"] == user.id
    ), "Access token does not contain correct user ID."

    refresh_token_data = jwt_manager.decode_refresh_token(
        response_data["refresh_token"]
    )
    assert (
        refresh_token_data["user_id"] == user.id
    ), "Refresh token does not contain correct user ID."

    stmt_refresh = select(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id)
    result_refresh = await db_session.execute(stmt_refresh)
    refresh_token_record = result_refresh.scalars().first()
    assert (
        refresh_token_record is not None
    ), "Refresh token was not stored in the database."
    assert refresh_token_record.verify_token(
        response_data["refresh_token"]
    ), "Stored refresh token does not match."

    expires_at = refresh_token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    assert expires_at > datetime.now(timezone.utc), "Refresh token is already expired."


@pytest.mark.asyncio
async def test_login_user_invalid_cases(client, db_session, seed_user_groups):
    """
    Test login with invalid cases:
    1. Non-existent user.
    2. Incorrect password for an existing user.
    """
    login_payload = {"email": "nonexistent@example.com", "password": "SomePassword123!"}
    response = await client.post("/api/v1/accounts/login/", json=login_payload)
    assert (
        response.status_code == 401
    ), "Expected status code 401 for non-existent user."
    assert (
        response.json()["detail"] == "Invalid email or password."
    ), "Unexpected error message for non-existent user."

    user_payload = {"email": "testuser@example.com", "password": "CorrectPassword123!"}
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id,
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_payload_incorrect_password = {
        "email": user_payload["email"],
        "password": "WrongPassword123!",
    }
    response = await client.post(
        "/api/v1/accounts/login/", json=login_payload_incorrect_password
    )
    assert (
        response.status_code == 401
    ), "Expected status code 401 for incorrect password."
    assert (
        response.json()["detail"] == "Invalid email or password."
    ), "Unexpected error message for incorrect password."


@pytest.mark.asyncio
async def test_login_user_inactive_account(client, db_session, seed_user_groups):
    """
    Test login with an inactive user account.

    Validates that the endpoint returns a 403 status code and an appropriate error message
    when attempting to log in with a user whose account is not activated.
    """
    user_payload = {
        "email": "inactiveuser@example.com",
        "password": "StrongPassword123!",
    }

    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "User group not found."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id,
    )
    user.is_active = False
    db_session.add(user)
    await db_session.commit()

    login_payload = {
        "email": user_payload["email"],
        "password": user_payload["password"],
    }
    response = await client.post("/api/v1/accounts/login/", json=login_payload)

    assert response.status_code == 403, "Expected status code 403 for inactive user."
    assert (
        response.json()["detail"] == "User account is not activated."
    ), "Unexpected error message for inactive user."


@pytest.mark.asyncio
async def test_login_user_commit_error(client, db_session, seed_user_groups):
    """
    Test login when a database commit error occurs.

    Validates that the endpoint returns a 500 status code and an appropriate error message.
    """
    user_payload = {"email": "testuser@example.com", "password": "StrongPassword123!"}
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id,
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_payload = {
        "email": user_payload["email"],
        "password": user_payload["password"],
    }

    with patch("routes.accounts.AsyncSession.commit", side_effect=SQLAlchemyError):
        response = await client.post("/api/v1/accounts/login/", json=login_payload)

    assert (
        response.status_code == 500
    ), "Expected status code 500 for database commit error."
    assert (
        response.json()["detail"] == "An error occurred while processing the request."
    ), "Unexpected error message for database commit error."


@pytest.mark.asyncio
async def test_refresh_access_token_success(
    client, db_session, jwt_manager, seed_user_groups
):
    """
    Test successful access token refresh.

    Validates that a new access token is returned when a valid refresh token is provided.
    Steps:
    - Create an active user in the database.
    - Log in the user to obtain a refresh token.
    - Use the refresh token to obtain a new access token.
    - Verify that the new access token contains the correct user ID.
    """
    user_payload = {"email": "testuser@example.com", "password": "StrongPassword123!"}
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id,
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_payload = {
        "email": user_payload["email"],
        "password": user_payload["password"],
    }
    login_response = await client.post("/api/v1/accounts/login/", json=login_payload)
    assert (
        login_response.status_code == 200
    ), "Expected status code 200 for successful login."
    login_data = login_response.json()
    refresh_token = login_data["refresh_token"]

    refresh_payload = {"refresh_token": refresh_token}
    refresh_response = await client.post(
        "/api/v1/accounts/refresh/", json=refresh_payload
    )
    assert (
        refresh_response.status_code == 200
    ), "Expected status code 200 for successful token refresh."
    refresh_data = refresh_response.json()
    assert "access_token" in refresh_data, "Access token is missing in the response."
    assert refresh_data["access_token"], "Access token is empty."

    access_token_data = jwt_manager.decode_access_token(refresh_data["access_token"])
    assert (
        access_token_data["user_id"] == user.id
    ), "Access token does not contain correct user ID."


@pytest.mark.asyncio
async def test_refresh_access_token_expired_token(client, jwt_manager):
    """
    Test refresh token with expired token.

    Validates that a 400 status code and "Token has expired." message are returned
    when the refresh token is expired.
    """
    expired_token = jwt_manager.create_refresh_token(
        {"user_id": 1}, expires_delta=timedelta(days=-1)
    )

    refresh_payload = {"refresh_token": expired_token}
    refresh_response = await client.post(
        "/api/v1/accounts/refresh/", json=refresh_payload
    )

    assert (
        refresh_response.status_code == 400
    ), "Expected status code 400 for expired token."
    assert (
        refresh_response.json()["detail"] == "Invalid token or expired."
    ), "Unexpected error message."


@pytest.mark.asyncio
async def test_refresh_access_token_token_not_found(client, jwt_manager):
    """
    Test refresh token when token is not found in the database.

    Validates that a 401 status code and 'Refresh token not found.' message
    are returned when the refresh token is not stored in the database.
    """
    refresh_token = jwt_manager.create_refresh_token({"user_id": 1})
    refresh_payload = {"refresh_token": refresh_token}
    refresh_response = await client.post(
        "/api/v1/accounts/refresh/", json=refresh_payload
    )

    assert (
        refresh_response.status_code == 401
    ), "Expected status code 401 for token not found."
    assert (
        refresh_response.json()["detail"] == "Invalid token or expired."
    ), "Unexpected error message."


@pytest.mark.asyncio
async def test_refresh_access_token_user_not_found(
    client, db_session, jwt_manager, seed_user_groups
):
    """
    Test refresh token when user ID inside the token does not exist in the database.

    Validates that a 404 status code and "User not found." message
    are returned when the user ID in the token is invalid.

    Steps:
    - Create a new active user.
    - Generate a refresh token with an invalid user ID.
    - Store the refresh token in the database.
    - Attempt to refresh the access token using the invalid refresh token.
    - Verify that the endpoint returns a 404 error with the expected message.
    """
    user_payload = {"email": "testuser@example.com", "password": "StrongPassword123!"}

    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id,
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    invalid_user_id = 9999
    refresh_token = jwt_manager.create_refresh_token({"user_id": invalid_user_id})

    refresh_token_record = RefreshTokenModel.create(
        user_id=invalid_user_id, days_valid=7, token=refresh_token
    )
    db_session.add(refresh_token_record)
    await db_session.commit()

    refresh_payload = {"refresh_token": refresh_token}
    refresh_response = await client.post(
        "/api/v1/accounts/refresh/", json=refresh_payload
    )

    assert (
        refresh_response.status_code == 404
    ), "Expected status code 404 for non-existent user."
    assert (
        refresh_response.json()["detail"] == "User not found."
    ), "Unexpected error message."


@pytest.mark.asyncio
async def test_logout_user_success(client, db_session, jwt_manager, seed_user_groups):
    """
    Test successful logout.

    Validates that a refresh token is revoked and removed from the database.
    """
    user_payload = {"email": "testuser@example.com", "password": "StrongPassword123!"}

    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id,
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
    refresh_token_record = RefreshTokenModel.create(
        user_id=user.id, days_valid=7, token=refresh_token
    )
    db_session.add(refresh_token_record)
    await db_session.commit()

    logout_response = await client.post(
        "/api/v1/accounts/logout/", json={"refresh_token": refresh_token}
    )
    assert (
        logout_response.status_code == 200
    ), "Expected status code 200 for successful logout."

    assert (
        logout_response.json()["message"] == "Successfully logged out."
    ), "Unexpected logout success message."
    stmt_check = select(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id)
    result_check = await db_session.execute(stmt_check)
    token_record = result_check.scalars().first()
    assert token_record is None, "Refresh token should be deleted after logout."


async def test_logout_user_invalid_token(
    client, db_session, jwt_manager, seed_user_groups
):
    """
    Test logout with an invalid refresh token.

    Ensures the endpoint rejects malformed or expired tokens.
    """
    user_payload = {"email": "testuser@example.com", "password": "StrongPassword123!"}

    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id,
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
    refresh_token_record = RefreshTokenModel.create(
        user_id=user.id, days_valid=7, token=refresh_token
    )
    db_session.add(refresh_token_record)
    await db_session.commit()

    invalid_refresh_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJpYXQiOjE1MTYyMzkwMjJ9.m3dwiZen61lzDEFBOdhGjFrnRlBe5aq6aqAyu2ZHVk0"
    logout_response = await client.post(
        "/api/v1/accounts/logout/", json={"refresh_token": invalid_refresh_token}
    )
    assert (
        logout_response.status_code == 400
    ), "Expected status code 400 for invalid token."
    assert (
        logout_response.json()["detail"] == "Invalid token or expired."
    ), "Unexpected error message for invalid token."


async def test_logout_for_nonexistent_user(client, jwt_manager, seed_user_groups):
    """
    Test logout when the token belongs to a non-existent user.

    Ensures the endpoint returns a generic token error.
    """
    invalid_user_id = 9999
    refresh_token = jwt_manager.create_refresh_token({"user_id": invalid_user_id})

    logout_response = await client.post(
        "/api/v1/accounts/logout/", json={"refresh_token": refresh_token}
    )
    assert (
        logout_response.status_code == 400
    ), "Expected status code 400 for non-existent user."
    assert (
        logout_response.json()["detail"] == "Invalid token or expired."
    ), "Unexpected error message for non-existent user."


async def test_change_user_group_success(client, db_session, seed_user_groups):
    """
    Test successful user group change.

    Validates that an admin can update another user's group.
    """
    user_data = {"email": "admin@gmail.com", "password": "AdminPassword123!"}
    user_admin = UserModel.create(
        email=user_data["email"], raw_password=user_data["password"], group_id=3
    )
    user_admin.is_active = True
    db_session.add(user_admin)
    await db_session.commit()

    login_response = await client.post(
        "/api/v1/accounts/login/",
        json={"email": user_data["email"], "password": user_data["password"]},
    )
    client.headers.update(
        {"Authorization": f"Bearer {login_response.json()["access_token"]}"}
    )
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.ADMIN)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    stmt = await db_session.execute(select(UserModel))
    user = stmt.scalars().first()
    assert user is not None, "User should exist in the database."

    response = await client.patch(
        f"/api/v1/accounts/change-user-group/", json={"email": user.email, "group": "admin"}
    )
    assert (
        response.status_code == 200
    ), "Expected status code 200 for successful group change."
    assert (
        response.json()["message"] == "User group updated successfully."
    ), "Unexpected success message for group change."
    await db_session.refresh(user)

    assert user.group_id == user_group.id, "User group was not updated correctly."


async def test_change_user_group_invalid_group(client, db_session, seed_user_groups):
    """
    Test changing a user group to an invalid value.

    Ensures the request is rejected and the group stays unchanged.
    """
    user_data = {"email": "admin@gmail.com", "password": "AdminPassword123!"}
    user_admin = UserModel.create(
        email=user_data["email"], raw_password=user_data["password"], group_id=3
    )
    user_admin.is_active = True
    db_session.add(user_admin)
    await db_session.commit()

    login_response = await client.post(
        "/api/v1/accounts/login/",
        json={"email": user_data["email"], "password": user_data["password"]},
    )
    client.headers.update(
        {"Authorization": f"Bearer {login_response.json()["access_token"]}"}
    )
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.ADMIN)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    stmt = await db_session.execute(select(UserModel))
    user = stmt.scalars().first()
    assert user is not None, "User should exist in the database."

    response = await client.patch(
        f"/api/v1/accounts/change-user-group/",
        json={"email": user.email, "group": "nonexistent"}
    )
    assert response.status_code == 422, "Expected status code 422 for invalid group."
    await db_session.refresh(user)

    assert (
        user.group_id == user_group.id
    ), "User group should not be changed when an invalid group is provided."


async def test_change_user_group_nonexistent_user(client, db_session, seed_user_groups):
    """
    Test changing the group of a non-existent user.

    Ensures the endpoint returns a not found response.
    """
    user_data = {"email": "admin@gmail.com", "password": "AdminPassword123!"}
    user_admin = UserModel.create(
        email=user_data["email"], raw_password=user_data["password"], group_id=3
    )
    user_admin.is_active = True
    db_session.add(user_admin)
    await db_session.commit()

    login_response = await client.post(
        "/api/v1/accounts/login/",
        json={"email": user_data["email"], "password": user_data["password"]},
    )
    client.headers.update(
        {"Authorization": f"Bearer {login_response.json()["access_token"]}"}
    )
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.ADMIN)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()
    assert user_group is not None, "Default user group should exist."

    response = await client.patch(
        f"/api/v1/accounts/change-user-group/", json={"email": "nonexistent@gmail.com", "group": "admin"}
    )
    assert (
        response.status_code == 404
    ), "Expected status code 404 for non-existent user."
    assert (
        response.json()["detail"] == "User not found."
    ), "Unexpected error message for non-existent user."


async def test_change_user_group_unauthorized(client, db_session, seed_user_groups):
    """
    Test changing a user group without authentication.

    Ensures the endpoint rejects unauthenticated requests.
    """
    response = await client.patch(
        f"/api/v1/accounts/change-user-group/", json={"email": "user@gmail.com", "group": "admin"}
    )
    assert (
        response.status_code == 401
    ), "Expected status code 401 for unauthorized access."
    assert (
        response.json()["detail"] == "Not authenticated"
    ), "Unexpected error message for unauthorized access."


async def test_change_user_group_forbidden(client, db_session, seed_user_groups):
    """
    Test changing a user group without sufficient permissions.

    Ensures a non-admin user cannot modify group assignments.
    """
    user_data = {"email": "user@gmail.com", "password": "UserPassword123!"}
    user = UserModel.create(
        email=user_data["email"], raw_password=user_data["password"], group_id=1
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_response = await client.post(
        "/api/v1/accounts/login/",
        json={"email": user_data["email"], "password": user_data["password"]},
    )
    client.headers.update(
        {"Authorization": f"Bearer {login_response.json()["access_token"]}"}
    )
    response = await client.patch(
        f"/api/v1/accounts/change-user-group/", json={"email": user.email, "group": "admin"}
    )
    assert response.status_code == 403, "Expected status code 403 for forbidden access."
    assert (
        response.json()["detail"] == "Not enough permissions."
    ), "Unexpected error message for forbidden access."


async def test_activate_user_manually_successfully(
    client, db_session, seed_user_groups
):
    """
    Test manual activation of a newly registered user.

    Validates that an admin can activate an inactive account.
    """
    admin_payload = {"email": "admin@gmail.com", "password": "StrongPassword123!"}
    user = UserModel.create(
        email=admin_payload["email"], raw_password=admin_payload["password"], group_id=3
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_response = await client.post(
        "/api/v1/accounts/login/",
        json={"email": admin_payload["email"], "password": admin_payload["password"]},
    )

    user_registration_payload = {
        "email": "test@gmail.com",
        "password": "StrongPassword123!",
    }
    registration_response = await client.post(
        "/api/v1/accounts/register/", json=user_registration_payload
    )
    assert (
        registration_response.status_code == 201
    ), "Expected status code 201 for successful registration."

    stmt = await db_session.execute(
        select(UserModel).where(UserModel.email == user_registration_payload["email"])
    )
    user = stmt.scalars().first()
    assert user is not None, "User should exist in the database."
    assert not user.is_active, "User should not be active before activation."

    client.headers.update(
        {"Authorization": f"Bearer {login_response.json()['access_token']}"}
    )
    activation_response = await client.patch(f"/api/v1/accounts/{user.id}/activate/")
    assert (
        activation_response.status_code == 200
    ), "Expected status code 200 for successful activation."
    assert (
        activation_response.json()["message"] == "User was activated successfully."
    ), "Unexpected success message for user activation."
    await db_session.refresh(user)
    assert user.is_active, "User should be active after activation."


async def test_activate_user_manually_nonexistent_user(
    client, db_session, seed_user_groups
):
    """
    Test manual activation for a non-existent user.

    Ensures the endpoint returns a not found response.
    """
    admin_payload = {"email": "admin@gmail.com", "password": "StrongPassword123!"}
    user = UserModel.create(
        email=admin_payload["email"], raw_password=admin_payload["password"], group_id=3
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_response = await client.post(
        "/api/v1/accounts/login/",
        json={"email": admin_payload["email"], "password": admin_payload["password"]},
    )
    client.headers.update(
        {"Authorization": f"Bearer {login_response.json()['access_token']}"}
    )
    activation_response = await client.patch(f"/api/v1/accounts/9999/activate/")
    assert (
        activation_response.status_code == 404
    ), "Expected status code 404 for non-existent user."
    assert (
        activation_response.json()["detail"] == "User not found."
    ), "Unexpected error message for non-existent user."


async def test_activate_user_manually_unauthorized(
    client, db_session, seed_user_groups
):
    """
    Test manual activation without authentication.

    Ensures unauthenticated requests are rejected.
    """
    activation_response = await client.patch(f"/api/v1/accounts/1/activate/")
    assert (
        activation_response.status_code == 401
    ), "Expected status code 401 for unauthorized access."
    assert (
        activation_response.json()["detail"] == "Not authenticated"
    ), "Unexpected error message for unauthorized access."


async def test_activate_user_manually_forbidden(client, db_session, seed_user_groups):
    """
    Test manual activation without enough permissions.

    Ensures a regular user cannot activate another account.
    """
    payload = {"email": "user@gmail.com", "password": "UserPassword123!"}
    user = UserModel.create(
        email=payload["email"], raw_password=payload["password"], group_id=1
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_response = await client.post(
        "/api/v1/accounts/login/",
        json={"email": payload["email"], "password": payload["password"]},
    )
    client.headers.update(
        {"Authorization": f"Bearer {login_response.json()['access_token']}"}
    )
    activation_response = await client.patch(f"/api/v1/accounts/{user.id}/activate/")
    assert (
        activation_response.status_code == 403
    ), "Expected status code 403 for forbidden access."
    assert (
        activation_response.json()["detail"] == "Not enough permissions."
    ), "Unexpected error message for forbidden access."


async def test_activate_user_manually_already_active(
    client, db_session, seed_user_groups
):
    """
    Test manual activation for an already active user.

    Ensures the endpoint responds successfully without changing state.
    """
    payload = {"email": "admin@gmail.com", "password": "StrongPassword123!"}
    user = UserModel.create(
        email=payload["email"], raw_password=payload["password"], group_id=3
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_response = await client.post(
        "/api/v1/accounts/login/",
        json={"email": payload["email"], "password": payload["password"]},
    )
    client.headers.update(
        {"Authorization": f"Bearer {login_response.json()['access_token']}"}
    )
    activation_response = await client.patch(f"/api/v1/accounts/{user.id}/activate/")
    assert (
        activation_response.status_code == 200
    ), "Expected status code 200 for already active user."
    assert (
        activation_response.json()["message"] == "User is already active."
    ), "Unexpected error message for already active user."
