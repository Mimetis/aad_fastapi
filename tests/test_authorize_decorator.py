import json

import pytest

from aad_fastapi import AzureAdSettings
from tests.helpers import gen_payload


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
