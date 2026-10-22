import time
import typing
from typing import Any, Dict, Optional

import jwt

from .aad_auth_error import AuthError
from .aad_discover_keys import AadDiscoverKey
from .aad_options import AzureAdSettings
from .aad_token import AuthToken
from .aad_user import AadUser

# Azure AD signs its tokens with RS256 only. Restricting the accepted
# algorithms prevents "alg" confusion attacks (e.g. "none" or HS256).
ALGORITHMS = ["RS256"]

# error codes kept identical to the ones previously raised by authlib.jose
_ERROR_CODES = {
    jwt.ExpiredSignatureError: "expired_token",
    jwt.InvalidSignatureError: "bad_signature",
    jwt.MissingRequiredClaimError: "missing_claim",
    jwt.InvalidAudienceError: "invalid_claim",
    jwt.InvalidIssuerError: "invalid_claim",
    jwt.DecodeError: "decode_error",
}


def _to_auth_error(ex: jwt.PyJWTError) -> AuthError:
    code = next(
        (c for t, c in _ERROR_CODES.items() if isinstance(ex, t)), "invalid_token"
    )
    return AuthError(code, str(ex), exception=ex)


def _decode_token_without_validating_signature(
    auth_token: typing.Union[AuthToken, str]
) -> Dict[str, Any]:
    auth_token = AuthToken(auth_token) if isinstance(auth_token, str) else auth_token

    token = auth_token.access_token

    # Microsoft Graph tokens can't be validated (signed for Graph only)
    return jwt.decode(token, options={"verify_signature": False})


def _decode_token(
    auth_token: typing.Union[AuthToken, str], keys_url=None, **kwargs
) -> Dict[str, Any]:
    """Decode an access token using public key or key to retrieve the public key"""

    try:
        public_key = kwargs.pop("public_key", None)

        if keys_url is None and public_key is None:
            raise AuthError(
                "invalid_public_key",
                "public_key or key_url must be specified to be able to get the "
                "public key to decode the token",
            )

        auth_token = AuthToken(auth_token) if isinstance(auth_token, str) else auth_token

        # if id token exists, gets it
        # in that cicumstances, we are sure we can validate the token
        token = (
            auth_token.access_token
            if auth_token.id_token is None
            else auth_token.id_token
        )

        if public_key is not None:
            # public_key can be a PEM string, a cryptography key or a JWK dict
            jwkey = (
                jwt.PyJWK(public_key).key if isinstance(public_key, dict) else public_key
            )
        else:
            # get the signing key matching the token "kid" header
            jwkey = AadDiscoverKey.get_signing_key(keys_url, token).key

        # signature, exp, nbf and iat are verified here.
        # aud and iss are verified by _validate_claims
        return jwt.decode(
            token, jwkey, algorithms=ALGORITHMS, options={"verify_aud": False}
        )

    # If the token is coming from Graph, we can't validate the signature
    # https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validating-tokens
    except jwt.PyJWTError as jex:
        raise _to_auth_error(jex)
    except AuthError as aex:
        raise aex
    except Exception as ex:
        raise AuthError(exception=ex)


def _require_claim(claims: Dict[str, Any], name: str):
    if name not in claims:
        raise jwt.MissingRequiredClaimError(name)
    if not claims[name]:
        raise jwt.InvalidTokenError(f'Invalid claim "{name}"')


def _validate_claims(
    claims: Dict[str, Any],
    audiences: typing.Union[str, typing.List[str]] = None,
    issuers: typing.Union[str, typing.List[str]] = None,
):
    """Validate a claims."""

    if audiences is not None and isinstance(audiences, str):
        aud_list = [audiences]
    else:
        aud_list = audiences

    if aud_list is not None and isinstance(aud_list, typing.List):
        _require_claim(claims, "aud")
        token_aud = claims["aud"]
        token_aud = token_aud if isinstance(token_aud, list) else [token_aud]
        if aud_list and not any(aud in token_aud for aud in aud_list):
            raise jwt.InvalidAudienceError("Audience doesn't match")

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
        _require_claim(claims, "iss")
        if issuers and claims["iss"] not in issuers:
            raise jwt.InvalidIssuerError("Invalid issuer")

    # already checked when decoding a signed token, but claims may come from
    # _decode_token_without_validating_signature
    now = time.time()
    if "exp" in claims and claims["exp"] < now:
        raise jwt.ExpiredSignatureError("Signature has expired")
    if "nbf" in claims and claims["nbf"] > now:
        raise jwt.ImmatureSignatureError("The token is not yet valid (nbf)")


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


def _get_user_from_claims(claims: Dict[str, Any]) -> AadUser:
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
