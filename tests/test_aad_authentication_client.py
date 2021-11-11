import json
from collections import namedtuple

import pytest
from azure.identity._credentials.chained import ChainedTokenCredential
from helpers import gen_payload
from http_client import MinimalResponse

from aad import (
    AadAuthenticationClient,
    AuthError,
    AuthToken,
    ScopeType,
    ensure_user_from_token,
)


def test_aad_client_options_is_set():
    """Test case for AadAuthenticationClient ctor

    Ensures that options are set correctly
    """
    aad_test = AadAuthenticationClient()
    assert aad_test.options is not None


@pytest.mark.asyncio
async def test_aad_client_options_is_not_set(client_credential):
    """Test case for AadAuthenticationClient ctor

    Ensures that options not set will fail correctly
    """
    aad_client = AadAuthenticationClient(options={})

    with pytest.raises(Exception) as auth_error:
        await aad_client.build_msal_confidential_app(
            client_credential=client_credential.__dict__
        )

    assert auth_error is not None
    assert isinstance(auth_error.value, AuthError)
    assert auth_error.value.code == "options_client_id_missing"


@pytest.mark.asyncio
async def test_construct_flow(client_credential):
    """Test case for aad_client.build_auth_code_flow(scopes, redirect_uri)

    Ensures that flow is correctly constructed and return redirect_uri
    """

    # azure aad client
    aad_client = AadAuthenticationClient()

    scopes_identifiers = aad_client.options.api_scopes_identifiers
    redirect_uri = "https://localhost/oauth-redirect.html"

    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, redirect_uri, client_credential=client_credential.__dict__
    )

    assert flow is not None
    assert "redirect_uri" in flow
    assert flow["redirect_uri"] == redirect_uri
    assert "auth_uri" in flow
    assert "state" in flow
    assert "code_verifier" in flow
    assert "scope" in flow
    for scope in scopes_identifiers:
        assert scope in flow["scope"]


@pytest.mark.asyncio
async def test_acquire_token_by_auth_code_flow(client_credential):
    """Test case for aad_client.acquire_token_by_auth_code_flow using a user credential

    Ensures that user can acquire a valid token
    and get the session user filled with correct values
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options, client_credential.private_key, scp=scopes_identifiers
        )
        return MinimalResponse(status_code=200, text=payload)

    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    assert user is not None
    assert user.name == "John Doe"
    assert user.auth_token is not None
    assert user.auth_token.access_token is not None
    assert user.auth_token.client_info is not None
    assert aad_client.session is not None


@pytest.mark.asyncio
async def test_acquire_token_by_auth_code_flow_through_general_method(
    client_credential,
):
    """Test case for aad_client.acquire_token_by_auth_code_flow using a user credential

    Ensures that user can acquire a valid token
    and get the session user filled with correct values
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options, client_credential.private_key, scp=scopes_identifiers
        )
        return MinimalResponse(status_code=200, text=payload)

    user = await aad_client.acquire_user_token(
        ScopeType.WebApi,
        scopes_identifiers,
        auth_response=auth_response,  # fake auth response from flow
        flow=flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    assert user is not None
    assert user.name == "John Doe"
    assert user.auth_token is not None
    assert user.auth_token.access_token is not None
    assert user.auth_token.client_info is not None
    assert aad_client.session is not None


@pytest.mark.asyncio
async def test_acquire_token_by_auth_code_flow_with_roles(client_credential):
    """Test case for aad_client.acquire_token_by_auth_code_flow
    using a user credential and roles

    Ensures that roles are correctly retrieved from token
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options,
            client_credential.private_key,
            roles=["Admin", "User"],
            scp=scopes_identifiers,
        )
        return MinimalResponse(status_code=200, text=payload)

    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )
    assert user is not None
    assert user.auth_token is not None
    assert user.auth_token.client_info is not None
    assert user.auth_token.access_token is not None
    assert user.roles_id is not None
    assert len(user.roles_id) == 2
    assert "Admin" in user.roles_id
    assert "User" in user.roles_id


@pytest.mark.asyncio
async def test_acquire_token_by_auth_code_flow_with_scopes(client_credential):
    """Test case for aad_client.acquire_token_by_auth_code_flow
    using a user credential and scopes

    Ensures that scopes are correctly retrieved from token
    """

    # azure aad client
    aad_client = AadAuthenticationClient()
    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options, client_credential.private_key, scp=scopes_identifiers
        )
        return MinimalResponse(status_code=200, text=payload)

    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    assert user.scopes is not None
    assert len(user.scopes) == len(scopes_identifiers) + 1
    for scope in aad_client.options.api_scopes:
        assert scope in user.scopes


@pytest.mark.asyncio
async def test_acquire_token_by_auth_code_flow_with_scope(client_credential):
    """Test case for aad_client.acquire_token_by_auth_code_flow
    using a user credential and one scope

    Ensures that one scope is correctly retrieved from token (if only 1 scope)
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scope_identifier = aad_client.options.api_scopes_identifiers[0]

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scope_identifier, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options, client_credential.private_key, scp=scope_identifier
        )
        return MinimalResponse(status_code=200, text=payload)

    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scope_identifier,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    assert user.scopes is not None
    assert len(user.scopes) == 2
    assert aad_client.options.api_scopes[0] in user.scopes


@pytest.mark.asyncio
async def test_acquire_token_by_auth_code_flow_with_scope_then_acquire_on_behalf_of(
    client_credential,
):
    """Test case for aad_client.acquire_token_by_auth_code_flow
    using a user credential and one scope

    Ensures that one scope is correctly retrieved from token (if only 1 scope)
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scope_identifier = aad_client.options.api_scopes_identifiers[0]

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scope_identifier, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options, client_credential.private_key, scp=scope_identifier
        )
        return MinimalResponse(status_code=200, text=payload)

    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scope_identifier,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    def mock_post_2(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options, client_credential.private_key, scp=["User.Read"]
        )
        return MinimalResponse(status_code=200, text=payload)

    token2 = await aad_client._acquire_token_on_behalf_of(
        user.auth_token,
        ["User.Read"],
        post=mock_post_2,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    assert token2 is not None
    from aad.aad_helpers import _decode_token

    decoded_token = _decode_token(token2, public_key=client_credential.public_key)
    assert decoded_token is not None
    assert "scp" in decoded_token
    assert len(decoded_token["scp"]) > 0
    assert decoded_token["scp"][0] == "User.Read"


@pytest.mark.asyncio
async def test_acquire_token_by_auth_code_flow_with_wrong_public_key(client_credential):
    """Test case for aad_client.acquire_token using a user credential

    Ensures that decoding the token with an incorrect public key will fail
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(aad_client.options, client_credential.private_key)
        return MinimalResponse(status_code=200, text=payload)

    public_key = client_credential.public_key.replace("DwIDAQAB", "DwIDAQAA")

    with pytest.raises(Exception) as auth_error:
        await aad_client._acquire_token_and_user_by_auth_code_flow(
            scopes_identifiers,
            auth_response,  # fake auth response from flow
            flow,  # correct flow from azure ad
            post=mock_post,
            public_key=public_key,
            client_credential=client_credential.__dict__,
        )

    assert auth_error is not None
    assert isinstance(auth_error.value, AuthError)
    assert auth_error.value.code == "bad_signature"


@pytest.mark.asyncio
async def test_acquire_token_for_service_principal(client_credential):
    """Test case for aad_client.acquire_token using a service principal

    Ensures that service principal can acquire a valid token and
    get the session user filled with correct values
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    # build confidential app
    scopes_identifiers = aad_client.options.api_scopes_identifiers_default

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(aad_client.options, client_credential.private_key, True)
        return MinimalResponse(status_code=200, text=payload)

    token = await aad_client._acquire_token_for_client(
        scopes_identifiers,
        post=mock_post,
        public_key=client_credential.public_key,
        client_credential=client_credential.__dict__,
    )

    assert token is not None
    assert token.client_info is None
    assert token.access_token is not None


@pytest.mark.asyncio
async def test_acquire_token_for_service_principal_through_general_method(
    client_credential, monkeypatch: pytest.MonkeyPatch
):
    """Test case for aad_client.acquire_token using a service principal

    Ensures that service principal can acquire a valid token and
    get the session user filled with correct values
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    # build confidential app
    scopes_identifiers = aad_client.options.api_scopes_identifiers_default

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(aad_client.options, client_credential.private_key, True)
        return MinimalResponse(status_code=200, text=payload)

    # def mock_get_token(self, scopes, **kwargs):
    #     payload = gen_payload(aad_client.options, client_credential.private_key, True)
    #     auth_token = json.loads(payload)
    #     AccessToken = namedtuple("AccessToken", ["token", "expires_on"])
    #     accessToken = AccessToken(token=auth_token["access_token"], expires_on=None)
    #     return accessToken

    # monkeypatch.setattr(ChainedTokenCredential, "get_token", mock_get_token)

    user = await aad_client.acquire_user_token(
        ScopeType.WebApi,
        scopes=scopes_identifiers,
        post=mock_post,
        public_key=client_credential.public_key,
        client_credential=client_credential.__dict__,
    )

    assert user is not None
    assert user.auth_token is not None
    assert user.auth_token.access_token is not None


@pytest.mark.asyncio
async def test_acquire_token_on_behalf_of(client_credential, private_key):
    """Test case for aad_client.acquire_token using a service principal

    Ensures that service principal can acquire a valid token and
    get the session user filled with correct values
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    payload = gen_payload(aad_client.options, private_key)
    token = json.loads(payload)
    auth_token = AuthToken(token=token)

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(aad_client.options, client_credential.private_key, True)
        return MinimalResponse(status_code=200, text=payload)

    token = await aad_client._acquire_token_on_behalf_of(
        auth_token,
        ["User.Read"],
        post=mock_post,
        public_key=client_credential.public_key,
        client_credential=client_credential.__dict__,
    )

    assert token is not None
    assert token.client_info is None
    assert token.access_token is not None


@pytest.mark.asyncio
async def test_acquire_token_on_behalf_of_through_general_method(
    client_credential, private_key
):
    """Test case for aad_client.acquire_token using a service principal

    Ensures that service principal can acquire a valid token and
    get the session user filled with correct values
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    payload = gen_payload(aad_client.options, private_key, scp="bjiu-123")
    token = json.loads(payload)
    auth_token = AuthToken(token=token)
    user = ensure_user_from_token(auth_token, public_key=client_credential.public_key)

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options, client_credential.private_key, scp="User.Read"
        )
        return MinimalResponse(status_code=200, text=payload)

    user = await aad_client.acquire_user_token(
        ScopeType.Graph,
        user=user,
        scopes=["User.Read"],
        post=mock_post,
        public_key=client_credential.public_key,
        client_credential=client_credential.__dict__,
    )

    assert user is not None
    assert user.auth_token is not None
    assert user.auth_token.access_token is not None


@pytest.mark.asyncio
async def test_acquire_token_for_graph_api(client_credential):
    """Test case for aad_client.acquire_token using a service principal

    Ensures that service principal can acquire a valid token and
    get the session user filled with correct values
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(aad_client.options, client_credential.private_key, True)
        return MinimalResponse(status_code=200, text=payload)

    token = await aad_client._acquire_token_for_graph_api(
        post=mock_post,
        public_key=client_credential.public_key,
        client_credential=client_credential.__dict__,
    )

    assert token is not None
    assert token.client_info is None
    assert token.access_token is not None


@pytest.mark.asyncio
async def test_acquire_token_for_managed_identity(
    client_credential, monkeypatch: pytest.MonkeyPatch
):

    # azure aad client
    aad_client = AadAuthenticationClient()

    def mock_get_token(self, scopes, **kwargs):
        payload = gen_payload(aad_client.options, client_credential.private_key, True)
        auth_token = json.loads(payload)
        AccessToken = namedtuple("AccessToken", ["token", "expires_on"])
        accessToken = AccessToken(token=auth_token["access_token"], expires_on=None)
        return accessToken

    monkeypatch.setattr(ChainedTokenCredential, "get_token", mock_get_token)

    token = await aad_client._acquire_token_for_managed_identity()

    assert token is not None
    assert token.client_info is None
    assert token.access_token is not None


@pytest.mark.asyncio
async def test_acquire_token_for_web_api(client_credential):
    """Test case for aad_client.acquire_token using a service principal

    Ensures that service principal can acquire a valid token and
    get the session user filled with correct values
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(aad_client.options, client_credential.private_key, True)
        return MinimalResponse(status_code=200, text=payload)

    token = await aad_client._acquire_token_for_service_principal(
        post=mock_post,
        public_key=client_credential.public_key,
        client_credential=client_credential.__dict__,
    )

    assert token is not None
    assert token.client_info is None
    assert token.access_token is not None


@pytest.mark.asyncio
async def test_acquire_token_from_cache(client_credential):
    """Test case for aad_client.acquire_token using a user credential

    Ensures that user can acquire a valid token from AD,
    then acquiring this token from cache if valid
    """
    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(aad_client.options, client_credential.private_key)
        return MinimalResponse(status_code=200, text=payload)

    await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    # 2nd call should it the cache
    # no need to set flow and auth_response since everything should happen from cache
    await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    # 3nd call should it the cache
    # no need to set flow and auth_response since everything should happen from cache
    user_3 = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    assert user_3 is not None
    assert user_3.name == "John Doe"
    assert user_3.auth_token is not None
    assert user_3.auth_token.access_token is not None
    assert aad_client.session is not None


@pytest.mark.asyncio
async def test_acquire_token_from_flow_works_without_session_set(client_credential):

    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(aad_client.options, client_credential.private_key)
        return MinimalResponse(status_code=200, text=payload)

    #
    # flow is not explicitely set, so should be in a session object
    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )
    assert user is not None
    assert user.name == "John Doe"
    assert user.auth_token is not None
    assert user.auth_token.access_token is not None
    assert user.auth_token.client_info is not None
    assert aad_client.session is not None


@pytest.mark.asyncio
async def test_build_msal_public():
    # azure aad client
    aad_client = AadAuthenticationClient()

    msal_public = await aad_client.build_msal_public_app()

    assert msal_public is not None


@pytest.mark.asyncio
async def test_get_client(client_credential):

    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options, client_credential.private_key, scp=scopes_identifiers
        )
        return MinimalResponse(status_code=200, text=payload)

    await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    user = await aad_client.get_user(False)

    assert user is not None
    assert user.name == "John Doe"
    assert user.auth_token is not None
    assert user.auth_token.access_token is not None
    assert aad_client.session is not None


@pytest.mark.asyncio
async def test_remove_account(client_credential):

    # azure aad client
    aad_client = AadAuthenticationClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # constructing flow to have the auth uri
    flow = await aad_client.build_auth_code_flow(
        scopes_identifiers, client_credential=client_credential.__dict__
    )

    # build fake response from azure ad with good state / fake code
    auth_response = {"state": flow["state"], "code": "012"}

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options, client_credential.private_key, scp=scopes_identifiers
        )
        return MinimalResponse(status_code=200, text=payload)

    await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    aad_id = aad_client.session.get("aad_id")
    assert aad_id is not None
    session_cache = await aad_client.cache_manager.get(aad_id)
    assert session_cache is not None

    await aad_client.remove_account(
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    aad_id = aad_client.session.get("aad_id")
    assert aad_id is None
    session_cache = await aad_client.cache_manager.get(aad_id)
    assert isinstance(session_cache, dict)
    assert len(list(session_cache)) == 0
