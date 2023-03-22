from typing import Optional

from fastapi.security.utils import get_authorization_scheme_param
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
)
from starlette.requests import Request

from .aad_auth_error import AuthError
from .aad_helpers import _validate_claims, ensure_user_from_token
from .aad_options import AzureAdSettings
from .aad_token import AuthToken


class AadBearerBackend(AuthenticationBackend):
    _discovery_keys = None

    def __init__(
        self, options: AzureAdSettings = None, env_path: Optional[str] = None, **kwargs
    ):
        if options is None:
            options = AzureAdSettings(_env_file=env_path)

        self.options = options

        # options to decode bearer with another certificate then azure
        # (useful for Tests)
        self.public_key = kwargs.pop("public_key", None)

    # Implementation for middleware for scarlette AuthenticationBackend
    async def authenticate(self, request):
        """Authenticate a request.
        If authentication is successful, defining a user instance
        """

        if "Authorization" not in request.headers:
            return

        try:
            # get token from header
            auth_token = self.get_token_from_header(request)

            # decode token
            user = ensure_user_from_token(
                auth_token, public_key=self.public_key, options=self.options
            )

            # validate the claims
            _validate_claims(
                user.claims,
                audiences=self.options.audiences,
                issuers=self.options.get_available_issuers(),
            )
            return AuthCredentials(user.scopes), user

        except Exception as ex:
            raise AuthenticationError("Invalid auth credentials", ex)

    @staticmethod
    def get_token_from_header(request: Request):
        """Get the bearer token from the request header."""

        # get authorization header
        authorization = request.headers.get("Authorization")

        # If not bearer, return None
        if not authorization:
            raise AuthError(
                "authorization_header_missing",
                "Authorization header is expected",
            )

        # get schema from header
        scheme, bearer = get_authorization_scheme_param(authorization)

        if scheme.lower() != "bearer":
            raise AuthError(
                "authorization_invalid_header",
                "Authorization header must start with" " Bearer",
            )

        if not bearer:
            raise AuthError(
                "authorization_token_not_found",
                "Token not found in the authorization header",
            )
        return AuthToken(bearer)
