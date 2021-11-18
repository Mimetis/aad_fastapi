import os
import pathlib
from os import environ
from typing import cast

import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from routers import engines, users
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request

from aad import (
    AadClient,
    AadBearerBackend,
    AadUser,
    authorize,
    oauth2_scheme,
)

dir = pathlib.Path(__file__).parent.parent.absolute()
localenv = os.path.join(dir, "local.env")
if os.path.exists(localenv):
    load_dotenv(localenv, override=True)

client_id = environ.get("CLIENT_ID")

# pre fill client id
swagger_ui_init_oauth = {
    "usePkceWithAuthorizationCodeGrant": "true",
    "clientId": client_id,
    "appName": "B-ID",
}

# Create a FasAPI instance
app = FastAPI(swagger_ui_init_oauth=swagger_ui_init_oauth)

# Add the bearer middleware
app.add_middleware(AuthenticationMiddleware, backend=AadBearerBackend())


# These routers needs an authentication for all its routes
app.include_router(engines.router, dependencies=[Depends(oauth2_scheme())])
app.include_router(users.router, dependencies=[Depends(oauth2_scheme())])


@app.get("/")
async def hello_world():

    try:
        return {"hello": "world"}
    except Exception as ex:
        return ex


@app.get("/user")
async def user(request: Request, token=Depends(oauth2_scheme())):

    try:
        return request.user
    except Exception as ex:
        return ex


@app.get("/user_with_scope")
@authorize("user_impersonation")
async def user_with_scope(request: Request, token=Depends(oauth2_scheme())):

    user = cast(AadUser, request.user)

    try:
        return user
    except Exception as ex:
        return ex


@app.get("/user_with_scope_and_roles")
@authorize("user_impersonation", "security-administrator")
async def user_with_scope_and_roles(request: Request, token=Depends(oauth2_scheme())):

    user = cast(AadUser, request.user)

    try:
        return user
    except Exception as ex:
        return ex


@app.get("/user_from_graph")
@authorize("user_impersonation")
async def user_from_graph(
    request: Request, criteria: str = None, token=Depends(oauth2_scheme())
):

    try:
        aad_client = AadClient()

        # Get a new token on behalf of the user, with new scopes
        auth_token_obo = await aad_client.acquire_user_token(request.user, "User.Read")

        headers = {"ConsistencyLevel": "eventual"}

        params = {
            "$count": "true",
            "$orderBy": "displayName",
            "$top": "50",
            "$search": f'"displayName:{criteria}" '
            + f'OR "mail:{criteria}" '
            + f'OR "userPrincipalName:{criteria}"',
            "$select": "id,displayName,mail,companyName,department,jobTitle,givenName",
        }

        # We may want to use the graph package,
        # but for understanding meaning, we stick with a simple request
        response = requests.get(
            "https://graph.microsoft.com/beta/users",
            params=params,
            auth=auth_token_obo,
            headers=headers,
        )

        jsonvalue = response.json()

        return jsonvalue
    except Exception as ex:
        return ex
