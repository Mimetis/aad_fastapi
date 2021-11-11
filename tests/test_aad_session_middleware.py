import json
from collections import namedtuple

import pytest
from helpers import gen_payload
from starlette.authentication import AuthCredentials, UnauthenticatedUser

from aad import AadSessionBackend, AadUser, AzureAdSettings
from aad.aad_cache_manager import CacheManager


@pytest.mark.asyncio
async def test_aad_session_backend_no_session():

    aad_session_backend = AadSessionBackend()
    request = namedtuple("request", ["session"])
    request.session = None

    cred, user = await aad_session_backend.authenticate(request=request)

    assert isinstance(cred, AuthCredentials)
    assert isinstance(user, UnauthenticatedUser)


@pytest.mark.asyncio
async def test_aad_session_backend_no_aad_id():

    aad_session_backend = AadSessionBackend()
    request = namedtuple("request", ["session"])
    request.session = {}
    request.session["something"] = "somewhere"

    cred, user = await aad_session_backend.authenticate(request=request)

    assert isinstance(cred, AuthCredentials)
    assert isinstance(user, UnauthenticatedUser)


@pytest.mark.asyncio
async def test_aad_session_backend_no_token_cache():

    aad_session_backend = AadSessionBackend()
    request = namedtuple("request", ["session"])
    request.session = {}
    request.session["aad_id"] = "123456"

    cred, user = await aad_session_backend.authenticate(request=request)

    assert isinstance(cred, AuthCredentials)
    assert isinstance(user, UnauthenticatedUser)


@pytest.mark.asyncio
async def test_aad_session_backend_token_cache(client_credential):

    aad_session_backend = AadSessionBackend()
    request = namedtuple("request", ["session"])
    request.session = {}
    request.session["aad_id"] = "123456"

    options = AzureAdSettings()
    scopes_identifiers = options.api_scopes_identifiers

    payload = gen_payload(
        options, client_credential.private_key, scp=scopes_identifiers
    )

    token = json.loads(payload)
    access_token = token["access_token"]
    id_token = token["access_token"]

    token_cache = (
        '{\n "AccessToken": '
        '  {\n "id": '
        '    {\n  "credential_type": "AccessToken", '
        '        \n  "secret": "' + access_token + '",'
        '        \n  "home_account_id": "A",'
        '        \n  "environment": "login.microsoftonline.com", '
        '        \n  "client_id": "client_id", '
        '        \n  "target": "https://contoso.com/client_id/user_impersonation", '
        '        \n  "realm": "1ca8bd94-3c97-4fc6-8955-bad266b43f0b", '
        '        \n  "token_type": "Bearer", '
        '        \n  "cached_at": "1631724977", '
        '        \n  "expires_on": "1631728575", '
        '        \n  "extended_expires_on": "1631728575" '
        "        \n        }\n    }, "
        '  \n "Account": '
        '    { \n "account_id": '
        '      {\n "home_account_id": "a-a", '
        '        \n "environment": "login.microsoftonline.com",'
        '        \n "realm": "1ca8bd94-3c97-4fc6-8955-bad266b43f0b", '
        '        \n "local_account_id": "c6b74d2d-f41e-4bc4-8cdf-29b6c28d4038", '
        '        \n "username": "johndoe@contoso.com",'
        '        \n "authority_type": "MSSTS" '
        "        \n   }\n    }, "
        '   \n "IdToken": '
        '      {\n "id": '
        '        {\n "credential_type": "IdToken", '
        '         \n "secret": "' + id_token + '", '
        '         \n "home_account_id": "A", '
        '         \n "environment": "login.microsoftonline.com", '
        '         \n "realm": "1ca8bd94-3c97-4fc6-8955-bad266b43f0b", '
        '         \n "client_id": "client_id" '
        "         \n        }\n    },"
        '    \n "RefreshToken": '
        '       {\n "id": '
        '        {\n "credential_type": "RefreshToken", '
        '         \n "secret": "' + id_token + '", '
        '         \n "home_account_id": "A", '
        '         \n "environment": "login.microsoftonline.com", '
        '         \n "client_id": "client_id", '
        '         \n "target": "https://contoso.com/client_id/user_impersonation", '
        '         \n "last_modification_time": "1631724977"\n        }\n    },'
        '    \n "AppMetadata": '
        '       {\n  "appmetadata-id": '
        '        {\n  "client_id": "client_id", '
        '         \n  "environment": "login.microsoftonline.com"\n        }\n    }\n}'
    )

    cache_session = await CacheManager.get(request.session["aad_id"])
    cache_session["token_cache"] = token_cache
    await CacheManager.set(request.session["aad_id"], cache_session)

    cred, user = await aad_session_backend.authenticate(request=request)

    assert isinstance(cred, AuthCredentials)
    assert isinstance(user, AadUser)
