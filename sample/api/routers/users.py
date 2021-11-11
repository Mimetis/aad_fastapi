import requests
from fastapi import APIRouter
from starlette.requests import Request

from aad import AadAuthenticationClient
from aad.aad_authentication_client import ScopeType
from aad.aad_decorators import authorize

router = APIRouter()


@router.get("/users/me", tags=["users"])
@authorize("user_impersonation")
async def read_user_me(request: Request):

    aad_client = AadAuthenticationClient()

    # Get a new token on behalf of the user, with new scopes for graph
    auth_token_obo = await aad_client.acquire_user_token(
        ScopeType.Graph, user=request.user
    )

    # We may want to use the graph package,
    # but for understanding meaning, we stick with a simple request
    response = requests.get(
        "https://graph.microsoft.com/beta/me",
        auth=auth_token_obo,
    )

    jsonvalue = response.json()

    return jsonvalue
