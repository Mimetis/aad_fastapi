import inspect
from typing import List, Optional, Sequence, Union

from fastapi import HTTPException, Security
from fastapi.security import OAuth2
from starlette.requests import Request

from .aad_user import AadUser
from .roles.role_requirement import RoleRequirement
from .roles.role_validator import RoleValidator


def _to_list(values: Optional[Union[str, Sequence[str]]]) -> List[str]:
    if values is None:
        return []
    return [values] if isinstance(values, str) else list(values)


class Authorize:
    """FastAPI dependency authorizing a route, the FastAPI-native alternative to
    the @authorize decorator. The token is validated by AadBearerBackend.

        @app.get("/me")
        async def me(user: AadUser = Depends(Authorize("user_impersonation"))):
            ...

        router = APIRouter(dependencies=[Depends(Authorize(roles=["Data.Read"]))])

    :param scopes: scopes the token must all contain. If not set, any token accepted
        by AadBearerBackend is authorized
    :param roles: roles to validate
    :param role_requirement: RoleRequirement.ALL (default) or RoleRequirement.ANY
    :param scheme: the oauth2_scheme() of the API, to document the route security
        and its scopes in OpenAPI
    """

    def __init__(
        self,
        scopes: Optional[Union[str, Sequence[str]]] = None,
        roles: Optional[Union[str, Sequence[str]]] = None,
        role_requirement: RoleRequirement = RoleRequirement.ALL,
        scheme: Optional[OAuth2] = None,
    ):
        self.scopes = _to_list(scopes)
        self.roles = _to_list(roles)
        self.role_validator = RoleValidator(self.roles, role_requirement)

        # FastAPI resolves the dependency parameters from this signature: the
        # scheme, when given, adds the OAuth2 security (and scopes) to OpenAPI
        parameters = [
            inspect.Parameter(
                "request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request
            )
        ]
        if scheme is not None:
            parameters.append(
                inspect.Parameter(
                    "token",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=str,
                    default=Security(scheme, scopes=self.scopes),
                )
            )
        self.__signature__ = inspect.Signature(parameters, return_annotation=AadUser)

    async def __call__(self, request: Request, token: Optional[str] = None) -> AadUser:
        if "user" not in request.scope:
            raise RuntimeError(
                "Authorize requires the AuthenticationMiddleware, with AadBearerBackend"
            )

        user = request.scope["user"]
        if not isinstance(user, AadUser) or not user.is_authenticated:
            raise HTTPException(
                status_code=401,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_scopes = user.scopes or []
        if not all(scope in user_scopes for scope in self.scopes):
            raise HTTPException(
                status_code=403,
                detail="Insufficient scope",
                headers={
                    "WWW-Authenticate": 'Bearer error="insufficient_scope", '
                    f'scope="{" ".join(self.scopes)}"'
                },
            )

        if self.roles and not self.role_validator.validate_roles(user.roles_id or []):
            raise HTTPException(status_code=403, detail="Unauthorized role")

        return user
