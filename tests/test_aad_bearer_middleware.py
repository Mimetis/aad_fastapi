import pytest
from helpers import gen_payload
from http_client import MinimalResponse
from requests.models import CaseInsensitiveDict
from starlette.testclient import TestClient

from aad import AadClient, AadBearerBackend, AadUser


def test_aad_server_options_is_set():
    """Test case for AadBearerMiddleware(app)

    Ensures that options can be set automatically
    """
    aad_server_options = AadBearerBackend()
    assert aad_server_options.options is not None
    assert aad_server_options.options.client_id is not None


@pytest.mark.asyncio
async def test_is_not_authorized_if_no_bearer_token(client: TestClient):
    """Test case for token=Depends(oauth2_scheme())

    Ensures we can't access an api with authorization set
    """

    response = await client.get("/isauth")
    assert response.status_code == 403
    response_details = response.json()
    assert response_details["detail"] == "Not authenticated"


@pytest.mark.asyncio
async def test_user_is_authorized_from_authenticated_request(
    client: TestClient, client_credential
):
    """Test case for token=Depends(oauth2_scheme())

    Ensures that we can send a request and get a response
    if authenticated with a user credential
    """
    # azure aad client
    aad_client = AadClient()

    # get a confidential app
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

    # this method is alrady tested
    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {user.auth_token.access_token}"

    response = await client.get("/isauth", headers=headers)
    assert response.status_code == 200
    assert response.content is not None

    user = AadUser.create_user(**response.json())
    assert user.is_authenticated is True


@pytest.mark.asyncio
async def test_service_principal_is_authorized_from_authenticated_request(
    client: TestClient, client_credential
):
    """Test case for token=Depends(oauth2_scheme())

    Ensures that we can send a request and get a response if
    authenticated with a service principal
    """

    # azure aad client
    aad_client = AadClient()

    # build confidential app
    scopes_identifiers = aad_client.options.api_scopes_identifiers_default

    def mock_post(url, headers=None, *args, **kwargs):
        payload = gen_payload(
            aad_client.options,
            client_credential.private_key,
            True,
            scp=scopes_identifiers,
        )
        return MinimalResponse(status_code=200, text=payload)

    token = await aad_client._acquire_token_for_client(
        scopes_identifiers,
        post=mock_post,
        public_key=client_credential.public_key,
        client_credential=client_credential.__dict__,
    )

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {token.access_token}"
    response = await client.get("/isauth", headers=headers)

    assert response.status_code == 200
    assert response.content is not None

    user_from_api = AadUser.create_user(**response.json())
    assert user_from_api.is_authenticated is True


@pytest.mark.asyncio
async def test_service_principal_is_unauthorized_if_scopes_are_needed(
    client: TestClient, client_credential
):
    """Test case for token=Depends(oauth2_scheme())

    Test case for @authorize("user_impersonation")

    Ensures that a service principal can't access an api with scopes
    """

    # azure aad client
    aad_client = AadClient()

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

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {token.access_token}"
    response = await client.get("/isauth_impersonation", headers=headers)
    assert response.status_code == 403
    detail_response = response.json()
    assert detail_response["detail"] == "Forbidden"


@pytest.mark.asyncio
async def test_user_is_authorized_from_authenticated_request_with_scopes(
    client: TestClient, client_credential
):
    """Test case for token=Depends(oauth2_scheme())

    Test case for @authorize("user_impersonation")

    Ensures that we can send a user token with scopes
    and get a response if scopes are matching
    """

    # azure aad client
    aad_client = AadClient()

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

    # this method is alrady tested
    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {user.auth_token.access_token}"
    response = await client.get("/isauth_impersonation", headers=headers)
    assert response.status_code == 200
    assert response.content is not None

    user = AadUser.create_user(**response.json())
    assert user.is_authenticated is True
    assert len(user.scopes) == len(aad_client.options.scopes_str) + 1
    assert "authenticated" in user.scopes
    for scope in aad_client.options.scopes_str:
        assert scope in user.scopes


@pytest.mark.asyncio
async def test_user_is_unauthorized_from_authenticated_request_if_scopes_mismatch(
    client: TestClient, client_credential
):
    """Test case for token=Depends(oauth2_scheme())

    Test case for @authorize("user_impersonation")

    Ensures that a user token with bad scopes is
    not authorized to acces an api with scopes specified
    """

    # azure aad client
    aad_client = AadClient()

    # build code flow
    # fake scopes that should fail
    scopes_identifiers = "other_scope_not_good"

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

    # this method is alrady tested
    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {user.auth_token.access_token}"

    response = await client.get("/isauth_impersonation", headers=headers)

    assert response.content is not None
    assert response.status_code == 403
    detail_response = response.json()
    assert detail_response["detail"] == "Forbidden"


@pytest.mark.asyncio
async def test_user_is_authorized_from_authenticated_request_with_roles(
    client: TestClient, client_credential
):
    """Test case for token=Depends(oauth2_scheme())

    Test for @authorize("user_impersonation", ["Admin", "Contributor"])

    Ensures that a user token with scopes and roles is
    authorized to acces an api with scopes / roles specified
    """

    # azure aad client
    aad_client = AadClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # fake roles
    roles = ["Admin", "Contributor"]

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
            scp=scopes_identifiers,
            roles=roles,
        )
        return MinimalResponse(status_code=200, text=payload)

    # this method is alrady tested
    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {user.auth_token.access_token}"

    response = await client.get("/isauth_impersonation_roles", headers=headers)

    assert response.status_code == 200
    assert response.content is not None

    user = AadUser.create_user(**response.json())
    assert user.is_authenticated is True
    assert len(user.roles_id) == len(roles)
    for role in roles:
        assert role in user.roles_id


@pytest.mark.asyncio
async def test_user_is_unauthorized_from_authenticated_request_if_roles_mismatch(
    client: TestClient, client_credential
):
    """Test case for token=Depends(oauth2_scheme())

    Test case for @authorize("user_impersonation", ["Admin", "Contributor"])

    Ensures that a user token with bad roles
    is not authorized to acces an api with scopes / roles specified
    """

    # azure aad client
    aad_client = AadClient()

    # build code flow
    scopes_identifiers = aad_client.options.api_scopes_identifiers

    # fake roles
    # we miss the "Admin" role here, and the API needs it
    roles = ["Contributor"]

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
            scp=scopes_identifiers,
            roles=roles,
        )
        return MinimalResponse(status_code=200, text=payload)

    # this method is alrady tested
    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {user.auth_token.access_token}"

    response = await client.get("/isauth_impersonation_roles", headers=headers)

    assert response.status_code == 403
    detail_response = response.json()
    assert detail_response["detail"] == "Unauthorized role"


@pytest.mark.asyncio
async def test_user_is_unauthorized_from_authenticated_request_if_no_roles(
    client: TestClient, client_credential
):
    """Test case for token=Depends(oauth2_scheme())

    Test case for @authorize("user_impersonation", ["Admin", "Contributor"])

    Ensures that a user token without roles
    is not authorized to acces an api with scopes / roles specified
    """
    # azure aad client
    aad_client = AadClient()

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

    # this method is alrady tested
    user = await aad_client._acquire_token_and_user_by_auth_code_flow(
        scopes_identifiers,
        auth_response,  # fake auth response from flow
        flow,  # correct flow from azure ad
        post=mock_post,  # fake response
        public_key=client_credential.public_key,  # public key to decrypt fake response
        client_credential=client_credential.__dict__,
    )

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {user.auth_token.access_token}"

    response = await client.get("/isauth_impersonation_roles", headers=headers)

    assert response.status_code == 403
    detail_response = response.json()
    assert detail_response["detail"] == "Unauthorized role"
