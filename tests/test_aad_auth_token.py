import json

import pytest
import requests
from helpers import gen_payload
from requests.models import Response

from src.aad_fastapi import AadDiscoverKey, AuthError, AuthToken, AzureAdSettings


def test_discover_keys(monkeypatch: pytest.MonkeyPatch):

    keys = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "nOo3ZDrODXEK1jKWhXslHR_KXEg",
                "x5t": "nOo3ZDrODXEK1jKWhXslHR_KXEg",
                "n": "oaLLT9hkcSj2tGfZsjbu7Xz1Krs0",
                "e": "AQAB",
                "x5c": ["MIIDBTCCAe"],
                "issuer": "https://login.microsoftonline.com/aaaaaaa-/v2.0",
            }
        ]
    }
    data = json.dumps(keys)
    response = Response()
    response.status_code = 200
    response._content = data.encode()
    response.reason = "OK"
    monkeypatch.setattr(requests, "get", lambda url: response)

    keys = AadDiscoverKey.get_discovery_key_json("https://keys_url")

    assert keys is not None


def test_aad_error_status():
    err = AuthError(code="CODE", description="DESCRIPTION")

    assert err is not None
    assert err.status_code == 401

    err = AuthError(code="CODE", description="DESCRIPTION", status_code=403)

    assert err is not None
    assert err.status_code == 403


def test_aad_error_with_exception():
    class MyException(Exception):
        def __init__(self, error, message):
            self.error = error
            self.message = message

    err = AuthError(exception=MyException("ERROR", "MESSAGE"))

    assert err is not None
    assert err.code == "ERROR"
    assert err.description == "MESSAGE"

    class MyException2(Exception):
        def __init__(self, code, description):
            self.code = code
            self.description = description

    err = AuthError(exception=MyException("ERROR", "DESCRIPTION"))

    assert err is not None
    assert err.code == "ERROR"
    assert err.description == "DESCRIPTION"

    err = AuthError(exception=Exception("ERROR_DESCRIPTION"))

    assert err is not None
    assert err.code is None
    assert err.description == "ERROR_DESCRIPTION"


def test_auth_token_from_token(private_key):
    """Test case for auth_token

    Ensures we can decode a valid token
    """
    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    token = json.loads(payload)
    # add random values for id_token and refresh_token that
    # are not generated by the helper
    token["id_token"] = "ejy....id_token"
    token["refresh_token"] = "ejy....refresh_token"

    auth_token = AuthToken(token=token)

    assert auth_token.access_token is not None
    assert auth_token.id_token is not None
    assert auth_token.refresh_token is not None
    assert auth_token.client_info is not None
    assert auth_token.access_token == token["access_token"]
    assert auth_token.id_token == token["id_token"]
    assert auth_token.refresh_token == token["refresh_token"]
    assert auth_token.client_info == token["client_info"]


def test_auth_token_from_args(private_key):
    """Test case for auth_token

    Ensures we can decode a valid token
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    token = json.loads(payload)
    # add random values for id_token and refresh_token that
    # are not generated by the helper
    token["id_token"] = "ejy....id_token"
    token["refresh_token"] = "ejy....refresh_token"

    auth_token = AuthToken(
        token["access_token"],
        token["id_token"],
        token["refresh_token"],
        token["client_info"],
    )

    assert auth_token.access_token is not None
    assert auth_token.id_token is not None
    assert auth_token.refresh_token is not None
    assert auth_token.client_info is not None
    assert auth_token.access_token == token["access_token"]
    assert auth_token.id_token == token["id_token"]
    assert auth_token.refresh_token == token["refresh_token"]
    assert auth_token.client_info == token["client_info"]


def test_auth_token_fail_if_no_access_token():
    """Test case for AuthToken

    Ensures we can decode a valid token
    """

    # generate a valid payload
    with pytest.raises(Exception) as auth_error:
        AuthToken(id_token="ejy...")

    assert auth_error is not None
    assert isinstance(auth_error.value, AuthError)
    assert auth_error.value.code == "access_token_empty"


def test_auth_token_access_token_overrided_by_token(private_key):
    """Test case for AuthToken

    Ensures we can decode a valid token
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    token = json.loads(payload)

    auth_token = AuthToken(access_token="aaaaa", token=token)

    assert auth_token.access_token is not None
    assert auth_token.access_token == token["access_token"]
