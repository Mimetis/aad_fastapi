import json

import pytest
from authlib.jose.rfc7519.claims import JWTClaims
from helpers import gen_payload

from aad_fastapi import AadUser, AuthError, AzureAdSettings
from aad_fastapi.aad_helpers import (
    _decode_token,
    _get_user_from_claims,
    _validate_claims,
)


def test_decode_token(private_key, public_key):
    """Test case for aad_helpers._decode_token

    Ensures we can decode a valid token
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    token = json.loads(payload)
    claims = _decode_token(token["access_token"], public_key=public_key)

    assert isinstance(claims, JWTClaims)


def test_decode_token_fail_if_no_key(private_key, public_key):
    """Test case for aad_helpers._decode_token

    Ensures that we have a correct error raised if key is invalid
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    token = json.loads(payload)
    access_token = token["access_token"]

    with pytest.raises(Exception) as auth_error:
        _decode_token(access_token)

    assert auth_error is not None
    assert isinstance(auth_error.value, AuthError)
    assert auth_error.value.code == "invalid_public_key"


def test_validate_claims_with_tenant_id(private_key, public_key):
    """Test case for aad_helpers._validate_claims

    Ensures we have valid claims, and that issuer is validated
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    token = json.loads(payload)
    claims = _decode_token(token["access_token"], public_key=public_key)

    _validate_claims(claims, issuers=options.tenant_id)

    assert True


def test_validate_claims(private_key, public_key):
    """Test case for aad_helpers._validate_claims

    Ensures we have valid claims, and that issuer is validated
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    token = json.loads(payload)
    claims = _decode_token(token["access_token"], public_key=public_key)

    _validate_claims(claims, issuers=claims.get("tid"))

    assert True


def test_validate_claims_multi_audiences(private_key, public_key):
    """Test case for aad_helpers._validate_claims

    Ensures we have valid claims, and that issuer is validated
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    token = json.loads(payload)
    claims = _decode_token(token["access_token"], public_key=public_key)

    aud = claims.get("aud")
    aud_list = [aud, "client_id"]
    _validate_claims(claims, issuers=claims.get("tid"), audiences=aud_list)

    assert True


def test_validate_claims_with_issuers_list(private_key, public_key):
    """Test case for aad_helpers._validate_claims

    Ensures we have valid claims, and that issuer is validated
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(
        options, private_key, iss="http://a_valid_issuer/a_valid_host_name"
    )
    token = json.loads(payload)
    claims = _decode_token(token["access_token"], public_key=public_key)

    issuers = [
        "http://a_valid_issuer/a_valid_host_name",
        "http://a_valid_issuer/a_valid_host_name/v2.0",
    ]

    _validate_claims(claims, issuers=issuers)

    assert True


def test_validate_claims_should_fail(private_key, public_key):
    """Test case for aad_helpers._validate_claims

    Ensures we are rejecting claims is issuer is not valid
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(
        options, private_key, iss="http://not_the_same_issuer_than_token"
    )
    token = json.loads(payload)
    claims = _decode_token(token["access_token"], public_key=public_key)

    with pytest.raises(Exception):
        _validate_claims(claims, issuer_tenant_id=options.tenant_id)


def test_get_user_from_claims(private_key, public_key):
    """Test case for aad_helpers._decode_token

    Ensures we have a valid user from claims
    """

    # generate a valid payload
    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    token = json.loads(payload)
    claims = _decode_token(token["access_token"], public_key=public_key)
    user = _get_user_from_claims(claims)

    assert isinstance(user, AadUser)
    assert user.username == f"John.Doe@{options.domain}"
