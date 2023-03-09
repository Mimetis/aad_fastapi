from typing import List, Optional

from authlib.jose.rfc7519.claims import JWTClaims
from starlette.authentication import SimpleUser

from .aad_token import AuthToken


class AadUser(SimpleUser):
    """User object for Azure AD authentication."""

    id: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    auth_token: Optional[AuthToken] = None
    roles_id: Optional[List[str]] = None
    groups: Optional[List[str]] = None
    scopes: Optional[List[str]] = None
    claims: Optional[JWTClaims] = None
    company: Optional[any] = None
    is_interactive: bool = True
