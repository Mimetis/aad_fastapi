import os
import pathlib
from os import environ
from typing import cast
from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from aad.aad_options import AzureAdSettings
from routers import engines
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request

from aad import (
    AadBearerBackend,
    AadUser,
    authorize,
    oauth2_scheme,
)

dir = pathlib.Path(__file__).parent.parent.absolute()
localenv = os.path.join(dir, "local.env")
if os.path.exists(localenv):
    load_dotenv(localenv, override=True)

# App Registration settings for protecting all the APIs.
api_options = AzureAdSettings()
api_options.client_id = environ.get("API_CLIENT_ID")
api_options.domain = environ.get("DOMAIN")
api_options.scopes = environ.get("SCOPES")

# App Registration setting for authentication SWAGGER WEB UI AUTHENTICATION.
web_ui_client_id = environ.get("CLIENT_ID")  # Client ID
web_ui_scopes = environ.get("SCOPES")  # Client ID

# pre fill client id
swagger_ui_init_oauth = {
    "usePkceWithAuthorizationCodeGrant": "true",
    "clientId": web_ui_client_id,
    "appName": "B-ID",
    "scopes": web_ui_scopes,
}

# Create a FasAPI instance
app = FastAPI(swagger_ui_init_oauth=swagger_ui_init_oauth)

# Add the bearer middleware, protected with Api App Registration
app.add_middleware(AuthenticationMiddleware, backend=AadBearerBackend(api_options))

# These routers needs an authentication for all its routes using Web App Registration
app.include_router(
    engines.router, dependencies=[Depends(oauth2_scheme(options=api_options))]
)


@app.get("/")
async def hello_world():
    try:
        return {"hello": "world"}
    except Exception as ex:
        return ex


@app.get("/user")
async def user(request: Request, token=Depends(oauth2_scheme(options=api_options))):

    try:
        return request.user
    except Exception as ex:
        return ex


@app.get("/user_with_scope")
@authorize("user_impersonation")
async def user_with_scope(
    request: Request, token=Depends(oauth2_scheme(options=api_options))
):

    user = cast(AadUser, request.user)

    try:
        return user
    except Exception as ex:
        return ex


@app.get("/user_with_scope_and_roles")
@authorize("user_impersonation", "security-administrator")
async def user_with_scope_and_roles(
    request: Request, token=Depends(oauth2_scheme(options=api_options))
):

    user = cast(AadUser, request.user)

    try:
        return user
    except Exception as ex:
        return ex
