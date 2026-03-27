import httpx
import pytest

from email.utils import parseaddr
from sqlalchemy import select
from sqlalchemy.orm import selectinload, joinedload
from validators import url as validate_url
from email_validator import EmailNotValidError, validate_email

from tests.extract_html import get_email_soup
from database import (
    ActivationTokenModel,
    UserModel,
    RefreshTokenModel,
    PasswordResetTokenModel,
)

pytestmark = pytest.mark.e2e


@pytest.mark.order(1)
@pytest.mark.asyncio
async def test_registration(
    e2e_client, reset_db_once_for_e2e, settings, seed_user_groups, e2e_db_session
):
    """
    End-to-end test for user registration.

    This test verifies the following:
    1. A user can successfully register with valid credentials.
    2. An activation email is sent to the provided email address.
    3. The email contains the correct activation link.

    Steps:
    - Send a POST request to the registration endpoint with user data.
    - Assert the response status code and returned user data.
    - Fetch the list of emails from MailHog via its API.
    - Verify that an email was sent to the expected recipient.
    - Ensure the email body contains the activation link.
    """
    user_data = {"email": "test@gmail.com", "password": "StrongPassword123!"}

    response = await e2e_client.post("/api/v1/accounts/register/", json=user_data)
    assert response.status_code == 201, f"Expected 201, got {response.status_code}"

    response_data = response.json()
    assert response_data["email"] == user_data["email"]

    mailhog_url = (
        f"http://{settings.MAIL_HOST}:{settings.MAILHOG_API_PORT}/api/v2/messages"
    )

    async with httpx.AsyncClient() as mailhog_client:
        mailhog_response = await mailhog_client.get(mailhog_url)
    await e2e_db_session.commit()
    e2e_db_session.expire_all()

    assert (
        mailhog_response.status_code == 200
    ), f"MailHog API returned {mailhog_response.status_code}"
    messages = mailhog_response.json()["items"]
    assert len(messages) > 0, "No emails were sent!"

    email = messages[0]

    user_email = parseaddr(email["Content"]["Headers"]["To"][0])[1]
    assert user_email == user_data["email"], "Email recipient does not match."

    email_subject = email["Content"]["Headers"].get("Subject", [None])[0]
    assert (
        email_subject == "Account Activation"
    ), f"Expected subject 'Account Activation', but got '{email_subject}'"

    try:
        email_soup = await get_email_soup(
            messages=messages, email=user_data["email"], subject=email_subject
        )
    except ValueError as e:
        pytest.fail(str(e))

    token = email_soup.find("div", id="token")
    assert token is not None, "Email element with id 'token' not found!"

    token_value = token.text.strip()
    assert token_value, "Token value is empty!"

    stmt = await e2e_db_session.execute(
        select(UserModel)
        .options(selectinload(UserModel.activation_tokens))
        .where(
            UserModel.email == user_data["email"],
            ActivationTokenModel.user_id == UserModel.id,
        )
    )
    user = stmt.scalars().first()
    assert user is not None, "User not found in database!"
    assert len(user.activation_tokens) > 0, "Activation token not found for user!"
    assert user.activation_tokens[0].verify_token(
        token_value
    ), "Token value in email does not match database!"


@pytest.mark.order(2)
@pytest.mark.asyncio
async def test_account_activation(e2e_client, settings, e2e_db_session):
    """
    End-to-end test for account activation.

    This test verifies the following:
    1. The activation token is valid.
    2. The account can be activated using the token.
    3. The account's status is updated to active in the database.
    4. An email confirming activation is sent to the user.

    Steps:
    - Retrieve the activation token from the database.
    - Send a POST request to the activation endpoint with the token.
    - Assert the response status code and verify the account is activated.
    - Fetch the list of emails from MailHog via its API.
    - Verify the email sent confirms the activation and contains the expected details.
    """
    stmt = await e2e_db_session.execute(
        select(ActivationTokenModel).options(joinedload(ActivationTokenModel.user))
    )
    activation_token = stmt.scalars().first()
    assert activation_token is not None, "No activation token found in database!"

    token_value = "token_value"
    activation_token.token = token_value
    await e2e_db_session.commit()

    payload = {"email": activation_token.user.email, "token": token_value}
    response = await e2e_client.post("/api/v1/accounts/activate/", json=payload)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    response_data = response.json()
    assert (
        response_data["message"] == "Account activated successfully."
    ), f"Unexpected response message: {response_data['message']}"

    await e2e_db_session.refresh(activation_token.user)
    assert (
        activation_token.user.is_active
    ), "User account was not activated in the database!"

    mailhog_url = (
        f"http://{settings.MAIL_HOST}:{settings.MAILHOG_API_PORT}/api/v2/messages"
    )

    async with httpx.AsyncClient() as mailhog_client:
        mailhog_response = await mailhog_client.get(mailhog_url)
    assert (
        mailhog_response.status_code == 200
    ), f"MailHog API returned {mailhog_response.status_code}"

    messages = mailhog_response.json()["items"]
    assert len(messages) > 0, "No emails were sent after activation!"

    email = messages[0]
    user_email = parseaddr(email["Content"]["Headers"]["To"][0])[1]
    assert (
        user_email == activation_token.user.email
    ), "Email recipient does not match after activation."

    email_subject = email["Content"]["Headers"].get("Subject", [None])[0]
    assert (
        email_subject == "Activation Complete"
    ), f"Expected subject 'Activation Complete', but got '{email_subject}'"

    try:
        email_soup = await get_email_soup(
            messages=messages, email=payload["email"], subject=email_subject
        )
    except ValueError as e:
        pytest.fail(str(e))

    confirmation_message = email_soup.find("h2", id="confirmation")
    assert (
        confirmation_message is not None
    ), "Confirmation message element with id 'confirmation' not found in email!"
    assert (
        confirmation_message.text.strip() == "Your Account Has Been Activated!"
    ), "Confirmation message text does not match expected value!"

    email_element = email_soup.find("strong", id="email")
    assert email_element is not None, "Email element with id 'email' not found!"

    try:
        validate_email(email_element.text)
    except EmailNotValidError as e:
        pytest.fail(f"The email link {email_element.text} is not valid: {e}")
    assert (
        email_element.text == user_email
    ), "Email content does not match the user's email!"

    link_element = email_soup.find("a", id="link")
    assert link_element is not None, "Activation link element with id 'link' not found!"
    activation_url = link_element["href"]
    assert validate_url(activation_url), f"The URL '{activation_url}' is not valid!"


@pytest.mark.order(3)
@pytest.mark.asyncio
async def test_user_login(e2e_client, e2e_db_session):
    """
    End-to-end test for user login (async version).

    This test verifies the following:
    1. A user can log in with valid credentials.
    2. The API returns an access token and a refresh token.
    3. The refresh token is stored in the database.

    Steps:
    - Send a POST request to the login endpoint with the user's credentials.
    - Assert the response status code and verify the returned access and refresh tokens.
    - Validate that the refresh token is stored in the database.
    """
    user_data = {"email": "test@gmail.com", "password": "StrongPassword123!"}

    login_url = "/api/v1/accounts/login/"
    response = await e2e_client.post(login_url, json=user_data)

    assert (
        response.status_code == 200
    ), f"Expected status code 200, got {response.status_code}"
    response_data = response.json()

    assert "access_token" in response_data, "Access token is missing in the response!"
    assert "refresh_token" in response_data, "Refresh token is missing in the response!"

    refresh_token = response_data["refresh_token"]

    stmt = await e2e_db_session.execute(
        select(UserModel)
        .options(selectinload(UserModel.refresh_tokens))
        .where(UserModel.email == user_data["email"])
    )
    user = stmt.scalars().first()
    assert user is not None, "User not found in database!"

    assert len(user.refresh_tokens) > 0, "Refresh token was not stored in the database!"
    assert user.refresh_tokens[0].verify_token(
        refresh_token
    ), "Refresh token in response does not match database!"


@pytest.mark.order(4)
@pytest.mark.asyncio
async def test_request_password_reset(e2e_client, e2e_db_session, settings):
    """
    End-to-end test for requesting a password reset (async version).

    This test verifies the following:
    1. If the user exists and is active, a password reset token is generated.
    2. A password reset email is sent to the user.
    3. The email contains the correct reset link.

    Steps:
    - Send a POST request to the password reset request endpoint.
    - Assert the response status code and message.
    - Verify that a password reset token is created for the user.
    - Fetch the list of emails from MailHog via its API.
    - Verify the email was sent and contains the correct information.
    """

    user_email = "test@gmail.com"
    reset_url = "/api/v1/accounts/password-reset/request/"

    response = await e2e_client.post(reset_url, json={"email": user_email})
    assert (
        response.status_code == 200
    ), f"Expected status code 200, got {response.status_code}"
    response_data = response.json()
    assert (
        response_data["message"]
        == "If an account with this email exists, password reset instructions have been sent."
    )

    stmt = await e2e_db_session.execute(
        select(UserModel)
        .options(selectinload(UserModel.password_reset_tokens))
        .where(UserModel.email == user_email)
    )
    user = stmt.scalars().first()
    assert user is not None, "User not found in database!"
    assert (
        len(user.password_reset_tokens) > 0
    ), "Password reset token was not created for the user!"

    mailhog_url = (
        f"http://{settings.MAIL_HOST}:{settings.MAILHOG_API_PORT}/api/v2/messages"
    )
    async with httpx.AsyncClient() as mailhog_client:
        mailhog_response = await mailhog_client.get(mailhog_url)
    assert (
        mailhog_response.status_code == 200
    ), f"MailHog API returned {mailhog_response.status_code}"

    messages = mailhog_response.json()["items"]
    assert len(messages) > 0, "No emails were sent after password reset request!"

    email = messages[0]
    user_email = parseaddr(email["Content"]["Headers"]["To"][0])[1]
    assert user_email == user_email, "Email recipient does not match after activation."

    email_subject = email["Content"]["Headers"].get("Subject", [None])[0]
    assert (
        email_subject == "Password Reset Request"
    ), f"Expected subject 'Password Reset Request', but got '{email_subject}'"

    try:
        email_soup = await get_email_soup(
            messages=messages, email=user_email, subject=email_subject
        )
    except ValueError as e:
        pytest.fail(str(e))

    reset_token = email_soup.find("span", id="token")
    assert reset_token is not None, "Email element with id 'token' not found in email!"

    reset_token_value = reset_token.text.strip()
    assert reset_token_value, "Reset token value is empty!"
    assert user.password_reset_tokens[0].verify_token(
        reset_token_value
    ), "Reset token in email does not match database!"

    email_element = email_soup.find("strong", id="email")
    assert email_element is not None, "Email element with id 'email' not found!"

    try:
        validate_email(email_element.text)
    except EmailNotValidError as e:
        pytest.fail(f"The email link {email_element.text} is not valid: {e}")
    assert (
        email_element.text == user_email
    ), "Email content does not match the user's email!"

    reset_link_element = email_soup.find("a", id="link")
    assert (
        reset_link_element is not None
    ), "Password reset link element with id 'link' not found in email!"
    reset_link = reset_link_element["href"]
    assert validate_url(reset_link), f"The URL '{reset_link}' is not valid!"


@pytest.mark.order(5)
@pytest.mark.asyncio
async def test_reset_password(e2e_client, e2e_db_session, settings):
    """
    End-to-end test for resetting a user's password (async version).

    This test verifies the following:
    1. A valid reset token allows the user to reset their password.
    2. The token is invalidated after use.
    3. The new password is successfully updated in the database.
    4. An email confirmation is sent to the user.

    Steps:
    - Retrieve the password reset token from the database.
    - Send a POST request to the password reset endpoint.
    - Assert the response status code and verify the success message.
    - Check if the password reset token is deleted from the database.
    - Verify that the password has changed.
    - Fetch the list of emails from MailHog via its API.
    - Verify the email was sent and contains the correct information.
    """
    user_email = "test@gmail.com"
    new_password = "NewSecurePassword123!"
    stmt = (
        select(PasswordResetTokenModel)
        .join(UserModel)
        .where(UserModel.email == user_email)
    )
    result = await e2e_db_session.execute(stmt)
    reset_token_record = result.scalars().first()

    assert (
        reset_token_record
    ), f"Password reset token for email {user_email} was not found!"
    reset_token = "reset_token"
    reset_token_record.token = reset_token
    await e2e_db_session.commit()

    reset_url = "/api/v1/accounts/reset-password/complete/"
    response = await e2e_client.post(
        reset_url,
        json={"email": user_email, "password": new_password, "token": reset_token},
    )

    assert (
        response.status_code == 200
    ), f"Expected status code 200, got {response.status_code}"
    response_data = response.json()
    assert (
        response_data["message"] == "Password reset successfully."
    ), "Unexpected password reset message!"

    stmt_deleted = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == reset_token_record.user_id
    )
    deleted_result = await e2e_db_session.execute(stmt_deleted)
    deleted_token = deleted_result.scalars().first()
    assert deleted_token is None, "Password reset token was not deleted after use!"

    stmt_user = select(UserModel).where(UserModel.email == user_email)
    user_result = await e2e_db_session.execute(stmt_user)
    updated_user = user_result.scalars().first()
    assert updated_user is not None, f"User with email {user_email} not found!"
    assert updated_user.verify_password(
        new_password
    ), "Password was not updated successfully!"

    await e2e_db_session.commit()
    mailhog_url = (
        f"http://{settings.MAIL_HOST}:{settings.MAILHOG_API_PORT}/api/v2/messages"
    )
    async with httpx.AsyncClient() as mailhog_client:
        mailhog_response = await mailhog_client.get(mailhog_url)
    assert (
        mailhog_response.status_code == 200
    ), f"MailHog API returned {mailhog_response.status_code}"

    messages = mailhog_response.json()["items"]
    assert len(messages) > 0, "No emails were sent after password reset request!"

    email = messages[0]
    user_email = parseaddr(email["Content"]["Headers"]["To"][0])[1]
    assert user_email == user_email, "Email recipient does not match."

    email_subject = email["Content"]["Headers"].get("Subject", [None])[0]
    assert (
        email_subject == "Password Reset Complete"
    ), f"Expected subject 'Password Reset Complete', but got '{email_subject}'"

    try:
        email_soup = await get_email_soup(
            messages=messages, email=user_email, subject=email_subject
        )
    except ValueError as e:
        pytest.fail(str(e))

    email_element = email_soup.find("strong", id="email")
    assert email_element is not None, "Email element with id 'email' not found!"

    try:
        validate_email(email_element.text)
    except EmailNotValidError as e:
        pytest.fail(f"The email link {email_element.text} is not valid: {e}")
    assert (
        email_element.text == user_email
    ), "Email content does not match the user's email!"

    link_element = email_soup.find("a", id="link")
    assert link_element is not None, "Login link element with id 'link' not found!"
    login_url = link_element["href"]
    assert validate_url(login_url), f"The URL '{login_url}' is not valid!"


@pytest.mark.order(6)
@pytest.mark.asyncio
async def test_user_login_with_new_password(e2e_client, e2e_db_session):
    """
    End-to-end test for user login after password reset (async version).

    This test verifies the following:
    1. A user can log in with the new password after resetting it.
    2. The API returns an access token and a refresh token.
    3. The refresh token is stored in the database.

    Steps:
    - Send a POST request to the login endpoint with the new credentials.
    - Assert the response status code and verify the returned access and refresh tokens.
    - Validate that the refresh token is stored in the database.
    """

    user_data = {"email": "test@gmail.com", "password": "NewSecurePassword123!"}

    login_url = "/api/v1/accounts/login/"
    response = await e2e_client.post(login_url, json=user_data)
    assert (
        response.status_code == 200
    ), f"Expected status code 200, got {response.status_code}"

    response_data = response.json()
    assert "access_token" in response_data, "Access token is missing in response!"
    assert "refresh_token" in response_data, "Refresh token is missing in response!"

    stmt = await e2e_db_session.execute(
        select(RefreshTokenModel)
        .options(joinedload(RefreshTokenModel.user))
        .join(UserModel)
        .where(UserModel.email == user_data["email"])
    )
    stored_token = stmt.scalars().first()

    assert stored_token is not None, "Refresh token was not stored in the database!"
    assert (
        stored_token.user.email == user_data["email"]
    ), "Refresh token is linked to the wrong user!"
