import typing
from typing import Optional

from authlib.jose import JsonWebKey
from authlib.jose import errors as jwt_errors
from authlib.jose import jwt
from authlib.jose.rfc7519.claims import JWTClaims
from authlib.jose.util import extract_header
from msal.oauth2cli.oidc import decode_id_token

from .aad_auth_error import AuthError
from .aad_discover_keys import AadDiscoverKey
from .aad_options import AzureAdSettings
from .aad_token import AuthToken
from .aad_user import AadUser


def _decode_token_without_validating_signature(
    auth_token: typing.Union[AuthToken, str]
) -> JWTClaims:
    auth_token = AuthToken(auth_token) if isinstance(auth_token, str) else auth_token

    token = auth_token.access_token

    decoded = decode_id_token(token)
    # this Guid is the Microsoft Graph audience identifier
    c = JWTClaims(decoded, None)
    return c


def _decode_token(
    auth_token: typing.Union[AuthToken, str], keys_url=None, **kwargs
) -> JWTClaims:
    """Decode an access token using public key or key to retrieve the public key"""

    try:
        public_key = kwargs.pop("public_key", None)

        if keys_url is None and public_key is None:
            raise AuthError(
                "invalid_public_key",
                "public_key or key_url must be specified to be able to get the "
                "public key to decode the token",
            )

        jwkey = None

        auth_token = AuthToken(auth_token) if isinstance(auth_token, str) else auth_token

        # if id token exists, gets it
        # in that cicumstances, we are sure we can validate the token
        token = (
            auth_token.access_token
            if auth_token.id_token is None
            else auth_token.id_token
        )

        if public_key is not None:
            jwkey = public_key
        else:
            # get keys
            token_header = token.split(".")[0].encode()
            jwks = AadDiscoverKey.get_discovery_key_json(keys_url)
            unverified_header = extract_header(token_header, jwt_errors.DecodeError)

            # get signing keys, to be able to decode token
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    jwkey = JsonWebKey.import_key(key)

        claims = jwt.decode(token, jwkey)

        return claims

    # If the token is coming from Graph, we can't validate the signature
    # https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validating-tokens
    except jwt_errors.BadSignatureError as bse:
        raise AuthError(exception=bse)
    except AuthError as aex:
        raise aex
    except Exception as ex:
        raise AuthError(exception=ex)


def _validate_claims(
    claims: JWTClaims,
    audiences: typing.Union[str, typing.List[str]] = None,
    issuers: typing.Union[str, typing.List[str]] = None,
):
    """Validate a claims."""

    claims_options = {}

    if audiences is not None and isinstance(audiences, str):
        aud_list = [audiences]
    else:
        aud_list = audiences

    if aud_list is not None and isinstance(aud_list, typing.List):
        claims_options["aud"] = {
            "essential": True,
            "values": aud_list,
        }

    # You can get a list of issuers for the various Azure AD deployments
    # (global & sovereign) from the following endpoint :
    # https://login.microsoftonline.com/common/discovery/instance
    # ?authorization_endpoint=
    # https://login.microsoftonline.com/common/oauth2/v2.0/authorize&api-version=1.1

    if issuers is not None and isinstance(issuers, str):
        issuers = [
            f"https://login.microsoftonline.com/{issuers}/",
            f"https://login.microsoftonline.com/{issuers}/v2.0",
            f"https://login.windows.net/{issuers}/",
            f"https://login.microsoft.com/{issuers}/",
            f"https://sts.windows.net/{issuers}/",
        ]

    if issuers is not None and isinstance(issuers, typing.List):
        claims_options["iss"] = {"essential": True, "values": issuers}

    claims.options = claims_options

    claims.validate()


def ensure_user_from_token(
    auth_token: AuthToken,
    validate: bool = True,
    options: AzureAdSettings = None,
    env_path: Optional[str] = None,
    **kwargs,
):
    if options is None:
        options = AzureAdSettings(_env_file=env_path)

    if validate:
        claims = _decode_token(
            auth_token,
            keys_url=options.keys_url,
            **kwargs,
        )
    else:
        claims = _decode_token_without_validating_signature(auth_token)

    user = _get_user_from_claims(claims)
    user.auth_token = auth_token
    return user


def _get_user_from_claims(claims: JWTClaims) -> AadUser:
    """Get an AadUser from claims"""

    # get scopes and add the "authenticated"
    scopes = ["authenticated"]

    # scopes can be a list or an array
    if claims.get("scp") is not None:
        scp = claims.get("scp")
        if isinstance(scp, typing.List):
            scopes.extend(scp)
        else:
            for _scp in str.split(scp, " "):
                scopes.append(_scp)

    username_key = "preferred_username"
    name_key = "name"
    is_sp = False

    if username_key not in claims:
        username_key = "unique_name"

    if "name" not in claims:
        appid = "appid" if "appid" in claims else "azp"
        is_sp = True
        name_key = appid
        username_key = appid

    user = AadUser(claims[username_key])
    user.id = claims.get("oid", None)

    if user.id is None:
        raise AuthError("oid_is_missing" "Property oid is mandatory")

    user.name = claims[name_key]
    user.email = claims[username_key] if not is_sp else ""
    user.groups = claims.get("groups", None)
    user.roles_id = claims.get("roles", None)
    user.scopes = scopes
    user.claims = claims
    user.is_interactive = not is_sp
    return user
