import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from helpers import gen_payload
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request

from aad_fastapi import AadBearerBackend, AzureAdSettings, authorize


@pytest.mark.parametrize(
    "roles, expected_status_code",
    [
        (["Admin", "Contributor"], 200),
        (["Admin"], 403),
        (["Contributor"], 403),
        ([], 403),
    ],
)
def test_isauth_with_impersonation_and_all_roles(
    mock_test_client, private_key, roles, expected_status_code
):
    options = AzureAdSettings()
    payload = gen_payload(options, private_key, roles=roles, scp=["user_impersonation"])
    token = json.loads(payload)["access_token"]
    response = mock_test_client.get(
        "/isauth_impersonation_all_roles", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == expected_status_code


@pytest.mark.parametrize(
    "roles,expected_status_code",
    [
        (["Admin", "Contributor"], 200),
        (["Admin"], 200),
        (["Contributor"], 200),
        ([], 403),
    ],
)
def test_valid_access_token_with_any_roles(
    mock_test_client, private_key, roles, expected_status_code
):
    options = AzureAdSettings()
    payload = gen_payload(options, private_key, roles=roles, scp=["user_impersonation"])
    token = json.loads(payload)["access_token"]
    response = mock_test_client.get(
        "/isauth_impersonation_any_roles", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == expected_status_code


def test_authorize_without_scopes_requires_authenticated_user(
    mock_test_client, private_key
):
    options = AzureAdSettings()
    payload = gen_payload(options, private_key, scp=["user_impersonation"])
    token = json.loads(payload)["access_token"]

    response = mock_test_client.get(
        "/isauth_authenticated", headers={"Authorization": "Bearer " + token}
    )
    assert response.status_code == 200

    response = mock_test_client.get("/isauth_authenticated")
    assert response.status_code == 403


@pytest.mark.parametrize("route", ["/isauth_authenticated", "/isauth"])
def test_app_token_without_permissions_is_rejected(mock_test_client, private_key, route):
    """App-only token without any granted app role (no "roles" nor "scp" claim)"""

    options = AzureAdSettings()
    payload = gen_payload(options, private_key, use_service_principal=True)
    token = json.loads(payload)["access_token"]

    response = mock_test_client.get(route, headers={"Authorization": "Bearer " + token})
    assert response.status_code == 400


def test_app_token_with_roles_is_accepted(mock_test_client, private_key):
    options = AzureAdSettings()
    payload = gen_payload(
        options, private_key, use_service_principal=True, roles=["Data.Read"]
    )
    token = json.loads(payload)["access_token"]

    response = mock_test_client.get(
        "/isauth_authenticated", headers={"Authorization": "Bearer " + token}
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "authority_host, tenant_token_accepted",
    [
        ("login.microsoftonline.com", True),
        ("login.windows.net", True),
        ("sts.windows.net", True),
        ("login.microsoft.com", True),
        # the test tokens are issued by the public cloud (sts.windows.net)
        ("login.chinacloudapi.cn", False),
    ],
)
def test_other_tenant_token_is_rejected_whatever_the_authority_host(
    public_key, private_key, authority_host, tenant_token_accepted
):
    options = AzureAdSettings(authority=f"https://{authority_host}/common")
    app = FastAPI()
    app.add_middleware(
        AuthenticationMiddleware,
        backend=AadBearerBackend(options, public_key=public_key),
    )

    @app.get("/protected")
    @authorize("user_impersonation")
    async def protected(request: Request):
        return {"ok": True}

    client = TestClient(app)

    def get_status(**token_kwargs):
        payload = gen_payload(
            options, private_key, scp="user_impersonation", **token_kwargs
        )
        token = json.loads(payload)["access_token"]
        response = client.get("/protected", headers={"Authorization": "Bearer " + token})
        return response.status_code

    other_tenant = "03030303-aaaa-bbbb-cccc-030303030303"
    assert (
        get_status(iss=f"https://sts.windows.net/{other_tenant}/", tid=other_tenant)
        == 400
    )
    assert get_status() == (200 if tenant_token_accepted else 400)
