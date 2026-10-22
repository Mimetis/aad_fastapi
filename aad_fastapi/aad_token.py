from typing import Dict, Optional, cast

from aiohttp.helpers import BasicAuth
from fastapi.security.utils import get_authorization_scheme_param
from requests.auth import AuthBase

from .aad_auth_error import AuthError


class AuthToken(AuthBase, BasicAuth):
    def __init__(
        self,
        access_token: Optional[str] = None,
        id_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        client_info: Optional[str] = None,
        token: Optional[Dict[str, str]] = None,
    ):
        if token:
            access_token = token.get("access_token", None)
            id_token = token.get("id_token", None)
            client_info = token.get("client_info", None)
            refresh_token = token.get("refresh_token", None)

        if access_token is None:
            raise AuthError(
                "access_token_empty",
                "No access token in the BearerAuth instance",
            )

        if access_token.lower().startswith("bearer"):
            _, access_token = get_authorization_scheme_param(access_token)

        self.access_token: str = access_token
        self.id_token = id_token
        self.client_info = client_info
        self.refresh_token = refresh_token

    # Used by BasicAuth
    def __new__(
        cls,
        login: str = "",
        password: str = "",
        encoding: str = "latin1",
        *args,
        **kwargs,
    ) -> "AuthToken":
        # even if not used, mandatory to be sure instance is not returning False
        login = login if login is not None and login != "" else "unused"
        return cast("AuthToken", super().__new__(cls, login, password, encoding))

    # Used by BasicAuth
    def encode(self) -> str:
        return f"Bearer {self.access_token}"

    # User by AuthBase
    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.access_token
        return r
