import json
import time
import warnings

import jwt
import pytest
from helpers import gen_payload

from aad_fastapi import AadUser, AuthError, AzureAdSettings
from aad_fastapi.aad_helpers import (
    _decode_token,
    _decode_token_without_validating_signature,
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

    assert isinstance(claims, dict)
    assert claims["oid"] == "jdoe1"


def test_decode_token_with_keys_url(private_key, jwks_endpoint):
    """Ensures the signing key is retrieved from the keys url, and cached"""

    options = AzureAdSettings()
    access_token = json.loads(gen_payload(options, private_key))["access_token"]

    claims = _decode_token(access_token, keys_url=jwks_endpoint["url"])
    claims = _decode_token(access_token, keys_url=jwks_endpoint["url"])

    assert claims["oid"] == "jdoe1"
    assert jwks_endpoint["calls"] == 1


def test_decode_token_with_unknown_kid(private_key, jwks_endpoint):
    """Ensures a token signed with an unknown key is rejected"""

    options = AzureAdSettings()
    access_token = json.loads(gen_payload(options, private_key, kid="unknown"))[
        "access_token"
    ]

    with pytest.raises(AuthError):
        _decode_token(access_token, keys_url=jwks_endpoint["url"])


def test_decode_token_with_bad_signature(public_key):
    """Ensures a token signed with another private key is rejected"""

    from cryptography.hazmat.primitives.asymmetric import rsa

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payload = gen_payload(AzureAdSettings(), other_key)
    access_token = json.loads(payload)["access_token"]

    with pytest.raises(AuthError) as auth_error:
        _decode_token(access_token, public_key=public_key)

    assert auth_error.value.code == "bad_signature"


def test_decode_token_expired(private_key, public_key):
    """Ensures an expired token is rejected"""

    now = int(time.time())
    payload = gen_payload(AzureAdSettings(), private_key, iat=now - 7200, exp=now - 3600)
    access_token = json.loads(payload)["access_token"]

    with pytest.raises(AuthError) as auth_error:
        _decode_token(access_token, public_key=public_key)

    assert auth_error.value.code == "expired_token"


def test_decode_token_rejects_unsigned_token(public_key):
    """Ensures the "none" algorithm (unsigned token) is rejected"""

    access_token = jwt.encode({"oid": "jdoe1"}, None, algorithm="none")

    with pytest.raises(AuthError):
        _decode_token(access_token, public_key=public_key)


def test_decode_token_without_validating_signature(private_key):
    """Ensures we can read the claims without the public key, and without
    deprecation warnings"""

    options = AzureAdSettings()
    access_token = json.loads(gen_payload(options, private_key))["access_token"]

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        claims = _decode_token_without_validating_signature(access_token)

    assert claims["oid"] == "jdoe1"


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

    with pytest.raises(jwt.InvalidIssuerError):
        _validate_claims(claims, issuers=options.tenant_id)


def test_validate_claims_should_fail_on_audience(private_key, public_key):
    """Ensures we are rejecting claims if audience is not valid"""

    options = AzureAdSettings()
    payload = gen_payload(options, private_key)
    claims = _decode_token(json.loads(payload)["access_token"], public_key=public_key)

    with pytest.raises(jwt.InvalidAudienceError):
        _validate_claims(claims, audiences=["another_audience"])


def test_validate_claims_should_fail_if_expired(private_key):
    """Ensures expiration is checked on claims decoded without signature"""

    now = int(time.time())
    payload = gen_payload(AzureAdSettings(), private_key, iat=now - 7200, exp=now - 3600)
    claims = _decode_token_without_validating_signature(
        json.loads(payload)["access_token"]
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        _validate_claims(claims)


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
