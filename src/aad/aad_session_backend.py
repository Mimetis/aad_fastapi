from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    UnauthenticatedUser,
)

from .aad_authentication_client import AadAuthenticationClient


class AadSessionBackend(AuthenticationBackend):
    async def authenticate(self, request):
        """Authenticate a request.
        If authentication is successful, defining a user instance
        """
        try:

            if not request.session or not request.session.get("aad_id"):
                return AuthCredentials(None), UnauthenticatedUser()

            aad_client = AadAuthenticationClient(session=request.session)

            # Do not validate signature, since we may have here a
            # microsoft graph token, that we can't validate
            # but it's fine since we are not on the web api side
            user = await aad_client.get_user(False)

            if user is None:
                return AuthCredentials(None), UnauthenticatedUser()

            return AuthCredentials(user.scopes), user

        except Exception:
            return AuthCredentials(None), UnauthenticatedUser()
