from celery import shared_task
from sqlalchemy import delete, func

from database import ActivationTokenModel, PasswordResetTokenModel, RefreshTokenModel
from database import sync_postgresql_engine

MODELS = [
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
]


@shared_task
def clean_up_expired_tokens():
    """
    Celery task that cleans up expired activation tokens from Postgres
    using synchronous SQLAlchemy session.
    """

    with sync_postgresql_engine.begin() as db:
        for model in MODELS:
            db.execute(delete(model).where(model.expires_at < func.now()))
