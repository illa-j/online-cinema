from fastapi import FastAPI
from routes.accounts import router as accounts_router


app = FastAPI(
    title="Online Cinema",
    description="An online cinema is a digital platform that allows users to select, watch, and purchase access to movies and other video materials via the internet. These services have become popular due to their convenience, a wide selection of content, and the ability to personalize the user experience."
)

api_version_prefix = "/api/v1"

app.include_router(accounts_router, prefix=f"{api_version_prefix}/accounts", tags=["accounts"])
