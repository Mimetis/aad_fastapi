# Tests

## Mocking the requests / responses

Since the tests are automated and we can't use a user token, the tests are _mocking_ the call to **Azure AD**.

Internally, the **aad** objects are using the `oauth2` object from the **msal** package.

This object is able to take an optional paramter called `post`, to mock any post response without having to send the request.

``` python
def _obtain_token(  # The verb "obtain" is influenced by OAUTH2 RFC 6749
        self, grant_type,
        params=None,  # a dict to be sent as query string to the endpoint
        data=None,  # All relevant data, which will go into the http body
        headers=None,  # a dict to be sent as request headers
        post=None,  # A callable to replace requests.post(), for testing.
                    # Such as: lambda url, **kwargs:
                    #   Mock(status_code=200, text='{}')
        **kwargs  # Relay all extra parameters to underlying requests
        ):
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
    dump_bytes = jwt.encode(header, payload, private_key)
    ...
```

and the `_decode_token` function is able to take an optional `public_key` argument to decode a token:

``` py
if public_key is not None:
    jwkey = public_key

claims = jwt.decode(token, jwkey)
```
