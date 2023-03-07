import inspect
import typing
from fastapi.openapi.models import OAuthFlowAuthorizationCode, OAuthFlows
from fastapi.security import OAuth2
from functools import wraps
from starlette.authentication import requires
from starlette.exceptions import HTTPException
from starlette.requests import Request
from typing import Optional

from .aad_options import AzureAdSettings
from .aad_user import AadUser


def authorize(
    scopes: typing.Union[str, typing.Sequence[str]] = None,
    roles: typing.Union[str, typing.Sequence[str]] = None,
):
    """authorize decorator. you can specify scopes and (or) roles"""

    def wrapper(endpoint):
        @wraps(endpoint)
        @requires(scopes)
        async def require_auth_endpoint(request: Request, *args, **kwargs):
            def has_required_roles(user_roles: typing.Sequence[str]) -> bool:
                for mandatory_role in mandatory_roles_list:
                    if mandatory_role not in user_roles:
                        return False
                return True

            # Check args
            mandatory_roles_list = []
            if roles is not None:
                mandatory_roles_list = [roles] if isinstance(roles, str) else list(roles)

            # Since we used @requires and the caller has
            # the Depends(aad.oauth2), the request.user exists.
            user: AadUser = request.user
            user_roles_list = user.roles_id or []

            if len(mandatory_roles_list) > 0 and not has_required_roles(user_roles_list):
                raise HTTPException(status_code=403, detail="Unauthorized role")

            if inspect.iscoroutinefunction(endpoint):
                result = await endpoint(request, *args, **kwargs)
            else:
                result = endpoint(request, *args, **kwargs)

            return result

        return require_auth_endpoint

    return wrapper


def oauth2_scheme(
    options: AzureAdSettings = None, env_path: Optional[str] = None, **kwargs
):
    """get the OAUTH2 schema used for API Authentication"""

    if options is None:
        options = AzureAdSettings(_env_file=env_path)

    scopes_dictionary = {}
    if options.scopes_list is not None:
        for ls in options.scopes_list:
            scopes_dictionary[ls] = ls

    return OAuth2(
        flows=OAuthFlows(
            authorizationCode=OAuthFlowAuthorizationCode(
                authorizationUrl=options.authorization_url,
                tokenUrl=options.token_url,
                scopes=scopes_dictionary,
            ),
        )
    )
