from pydantic import BaseModel, EmailStr, field_validator

from database import validate_password_strength, validate_email
from database.models.accounts import UserGroupEnum


class BaseEmailPasswordSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {"from_attributes": True}

    @field_validator("email")
    @classmethod
    def normalize_email_address(cls, value):
        return validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return validate_password_strength(value)


class UserRegistrationRequestSchema(BaseEmailPasswordSchema):
    pass


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class ActivationTokenRenewalRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseEmailPasswordSchema):
    token: str


class UserLoginRequestSchema(BaseEmailPasswordSchema):
    pass


class UserResetPasswordRequestSchema(BaseEmailPasswordSchema):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value):
        return validate_password_strength(value)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {"from_attributes": True}


class UserLogoutRequestSchema(BaseModel):
    refresh_token: str


class AccessTokenRenewalRequestSchema(BaseModel):
    refresh_token: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ChangeUserGroupRequestSchema(BaseModel):
    group: UserGroupEnum
