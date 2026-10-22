# Tests

## Mocking the requests / responses

Since the tests are automated and we can't use a user token, the tests are _mocking_ the calls to **Azure AD**.

Token validation relies on [PyJWT](https://pyjwt.readthedocs.io/). The Azure AD signing keys endpoint (`keys_url`) is queried by a `jwt.PyJWKClient`, managed by `AadDiscoverKey`.

The `jwks_endpoint` fixture (see `/tests/conftest.py`) mocks this endpoint, serving the public key of the local test certificate, without sending any request:

``` py
def test_decode_token_with_keys_url(private_key, jwks_endpoint):
    ...
    claims = _decode_token(access_token, keys_url=jwks_endpoint["url"])
```

## Access Token

All tokens acquired from Azure AD are mocked using a local certificate (private and public keys)

This allows the tests to run locally, but using a real token, using a self signed local certificate to encode and decode the token

Looking at the `/tests/helpers.py`, we have a function using the private key to create an access_token:

``` py
def gen_access_token(
    options: AzureAdSettings, private_key: str, use_service_principal=False, **kwargs
):  
    ...
    ...
    return jwt.encode(payload, private_key, algorithm="RS256", headers=header)
```

and the `_decode_token` function is able to take an optional `public_key` argument to decode a token:

``` py
if public_key is not None:
    jwkey = public_key
...
return jwt.decode(token, jwkey, algorithms=ALGORITHMS, options={"verify_aud": False})
```
