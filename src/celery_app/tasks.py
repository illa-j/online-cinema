from celery import shared_task
from sqlalchemy import delete, func

from database import ActivationTokenModel
from database.session_postgresql import sync_postgresql_engine


@shared_task
def clean_up_activation_tokens():
    """
    Celery task that cleans up expired activation tokens from Postgres
    using synchronous SQLAlchemy session.
    """
    with sync_postgresql_engine.connect() as db:
        db.execute(
            delete(ActivationTokenModel).where(
                ActivationTokenModel.expires_at < func.now()
            )
        )
        db.commit()
