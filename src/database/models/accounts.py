import enum

from datetime import datetime, date, timedelta, timezone
from typing import List, Optional

from sqlalchemy.orm import Mapped, mapped_column, relationship, validates
from sqlalchemy import (
    Date,
    ForeignKey,
    Integer,
    String,
    Boolean,
    DateTime,
    UniqueConstraint,
    func,
    Text,
    Enum,
)

from database.validators import accounts as validators
from database.models.base import Base
from security.tokens import hash_token, verify_token
from security.passwords import hash_password, verify_password


class UserGroupEnum(str, enum.Enum):
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"


class GenderEnum(str, enum.Enum):
    MAN = "man"
    WOMAN = "woman"


class UserGroupModel(Base):
    __tablename__ = "user_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[UserGroupEnum] = mapped_column(
        Enum(UserGroupEnum), nullable=False, unique=True
    )

    users: Mapped[List["UserModel"]] = relationship("UserModel", back_populates="group")


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    _hashed_password: Mapped[str] = mapped_column(
        "hashed_password", String(255), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    group_id: Mapped[int] = mapped_column(
        ForeignKey("user_groups.id", ondelete="RESTRICT"), nullable=False
    )
    group: Mapped[UserGroupModel] = relationship(
        "UserGroupModel", back_populates="users"
    )

    user_profiles: Mapped[List["UserProfileModel"]] = relationship(
        "UserProfileModel", back_populates="user", cascade="all, delete-orphan"
    )

    activation_tokens: Mapped[List["ActivationTokenModel"]] = relationship(
        "ActivationTokenModel", back_populates="user", cascade="all, delete-orphan"
    )
    password_reset_tokens: Mapped[List["PasswordResetTokenModel"]] = relationship(
        "PasswordResetTokenModel", back_populates="user", cascade="all, delete-orphan"
    )
    refresh_tokens: Mapped[List["RefreshTokenModel"]] = relationship(
        "RefreshTokenModel", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return (
            f"<UserModel(id={self.id}, email={self.email}, is_active={self.is_active})>"
        )

    def has_group(self, group_name: UserGroupEnum) -> bool:
        return self.group.name == group_name

    @classmethod
    def create(
        cls, email: str, raw_password: str, group_id: int | Mapped[int]
    ) -> "UserModel":
        """
        Factory method to create a new UserModel instance.

        This method simplifies the creation of a new user by handling
        password hashing and setting required attributes.
        """
        user = cls(email=email, group_id=group_id)
        user.password = raw_password
        return user

    @property
    def password(self) -> None:
        raise AttributeError(
            "Password is write-only. Use the setter to set the password."
        )

    @password.setter
    def password(self, raw_password: str) -> None:
        """
        Set the user's password after validating its strength and hashing it.
        """
        validators.validate_password_strength(raw_password)
        self._hashed_password = hash_password(raw_password)

    def verify_password(self, raw_password: str) -> bool:
        """
        Verify the provided password against the stored hashed password.
        """
        return verify_password(raw_password, self._hashed_password)

    @validates("email")
    def validate_email(self, key, value):
        return validators.validate_email(value.lower())


class UserProfileModel(Base):
    __tablename__ = "user_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    user: Mapped["UserModel"] = relationship(
        "UserModel", back_populates="user_profiles"
    )

    first_name: Mapped[Optional[str]] = mapped_column(String(100))
    last_name: Mapped[Optional[str]] = mapped_column(String(100))
    avatar: Mapped[str] = mapped_column(String(255), nullable=False)
    gender: Mapped["GenderEnum"] = mapped_column(Enum(GenderEnum), nullable=False)
    date_of_birth: Mapped[Optional[date]] = mapped_column(Date)
    info: Mapped[Optional[str]] = mapped_column(Text)


class TokenBaseModel(Base):
    __abstract__ = True

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    _hashed_token: Mapped[str] = mapped_column(String(60), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc) + timedelta(days=1),
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    @property
    def token(self) -> str:
        raise AttributeError("Token is write-only. Use the setter to set the token.")

    @token.setter
    def token(self, value: str) -> None:
        self._hashed_token = hash_token(value)

    def verify_token(self, plain_token: str) -> bool:
        """
        Verify a plain-text token against the stored hashed token.

        This method compares a plain-text token with the stored hashed token and returns True
        if they match, and False otherwise.
        """
        return verify_token(plain_token, self._hashed_token)


class ActivationTokenModel(TokenBaseModel):
    __tablename__ = "activation_tokens"

    user: Mapped["UserModel"] = relationship(
        "UserModel", back_populates="activation_tokens"
    )

    __table_args__ = (UniqueConstraint("user_id"),)

    def __repr__(self):
        return f"<ActivationTokenModel(id={self.id}, expires_at={self.expires_at})>"


class PasswordResetTokenModel(TokenBaseModel):
    __tablename__ = "password_reset_tokens"

    user: Mapped["UserModel"] = relationship(
        "UserModel", back_populates="password_reset_tokens"
    )

    __table_args__ = (UniqueConstraint("user_id"),)

    def __repr__(self):
        return f"<PasswordResetTokenModel(id={self.id}, expires_at={self.expires_at})>"


class RefreshTokenModel(TokenBaseModel):
    __tablename__ = "refresh_tokens"

    user: Mapped[UserModel] = relationship("UserModel", back_populates="refresh_tokens")

    @classmethod
    def create(cls, user_id: int, days_valid: int, token: str) -> "RefreshTokenModel":
        """
        Factory method to create a new RefreshTokenModel instance.

        This method simplifies the creation of a new refresh token by calculating
        the expiration date based on the provided number of valid days and setting
        the required attributes.
        """
        expires_at = datetime.now(timezone.utc) + timedelta(days=days_valid)
        instance = cls(user_id=user_id, expires_at=expires_at)
        instance.token = token
        return instance

    def __repr__(self):
        return f"<RefreshTokenModel(id={self.id}, expires_at={self.expires_at})>"
