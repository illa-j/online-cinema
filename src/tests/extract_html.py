import base64
from bs4 import BeautifulSoup


async def get_email_soup(
    messages: list, email: str, subject: str = None
) -> BeautifulSoup:
    user_messages = [
        msg
        for msg in messages
        if any(f"{r['Mailbox']}@{r['Domain']}" == email for r in msg["To"])
    ]

    if subject:
        user_messages = [
            msg
            for msg in user_messages
            if msg["Content"]["Headers"]["Subject"][0] == subject
        ]

    if not user_messages:
        raise ValueError(f"No email found for {email}")

    raw_body = user_messages[0]["MIME"]["Parts"][0]["Body"]
    html = base64.b64decode(raw_body).decode("utf-8")

    return BeautifulSoup(html, "html.parser")
