import asyncio

from fastapi_mail import FastMail, MessageSchema

from jinja2 import Environment, FileSystemLoader

from config import get_settings
from notifications.conf import conf

settings = get_settings()

env = Environment(loader=FileSystemLoader(settings.TEMPLATE_FOLDER))
fast_mail = FastMail(conf)


async def send_activation_email(email, activation_link):
    template = env.get_template("activation_request.html")
    html_body = template.render(email=email, activation_link=activation_link)
    message = MessageSchema(
        subject="Account Activation", recipients=[email], subtype="html", body=html_body
    )
    await fast_mail.send_message(message)
