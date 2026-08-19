import os

from database.validators.accounts import validate_email, validate_password_strength
from database.models.base import Base
from database.models.accounts import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserProfileModel,
)
from database.models.movies import (
    MovieModel,
    GenreModel,
    StarModel,
    DirectorModel,
    CertificationModel,
    MoviesGenresModel,
    MovieStarsModel,
    MoviesDirectorsModel,
)

environment = os.getenv("ENVIRONMENT", "developing")

if environment == "testing":
    from database.session_sqlite import (
        get_sqlite_db as get_db,
        get_sqlite_db_contextmanager as get_db_contextmanager,
        reset_database,
    )
else:
    from database.session_postgresql import (
        get_postgresql_db as get_db,
        sync_postgresql_engine,
    )
