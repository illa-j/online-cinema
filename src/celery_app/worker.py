from celery import Celery
from celery.schedules import crontab

from config import get_settings

settings = get_settings()

celery = Celery(
    "worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["celery_app.tasks"]
)

celery.conf.beat_schedule = {
    "cleanup-every-10-minutes": {
        "task": "celery_app.tasks.clean_up_activation_tokens",
        "schedule": 600.0,
    },
}
