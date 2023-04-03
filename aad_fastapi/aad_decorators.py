import inspect
import typing
from functools import wraps
from typing import Optional

from fastapi.openapi.models import OAuthFlowAuthorizationCode, OAuthFlows
from fastapi.security import OAuth2
from starlette.authentication import requires
from starlette.exceptions import HTTPException
from starlette.requests import Request

from .aad_options import AzureAdSettings
from .aad_user import AadUser
from .roles.role_requirement import RoleRequirement
from .roles.role_validator import RoleValidator


def authorize(
    scopes: typing.Union[str, typing.Sequence[str]] = None,
    roles: typing.Union[str, typing.Sequence[str]] = None,
    role_requirement: RoleRequirement = RoleRequirement.ALL,
):
    """
    Decorator to authorize a route
    :param scopes: list of scopes
    :param roles: list of roles to validate
    :param role_requirement: role requirement (RoleRequirement.ALL or RoleRequirement.ANY)
    """

    def wrapper(endpoint):
        @wraps(endpoint)
        @requires(scopes)
        async def require_auth_endpoint(request: Request, *args, **kwargs):
            # Check args
            mandatory_roles_list = []
            if roles is not None:
                mandatory_roles_list = [roles] if isinstance(roles, str) else list(roles)

            # Since we used @requires and the caller has
            # the Depends(aad.oauth2), the request.user exists.
            user: AadUser = request.user
            user_roles_list = user.roles_id or []

            role_validator = RoleValidator(mandatory_roles_list, role_requirement)
            if len(mandatory_roles_list) > 0 and not role_validator.validate_roles(
                user_roles_list
            ):
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
    """get the OAuth2 schema used for API Authentication"""

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
