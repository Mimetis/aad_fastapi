import base64
import json
from datetime import datetime, timedelta
from typing import List, Union

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from aad_fastapi.aad_options import AzureAdSettings

# kid used to sign all the generated test tokens
TEST_KEY_ID = "nOo3ZDrODXEK1jKWhXslHR_KXEg"

# Extract of the Azure AD instance discovery response (INSTANCE_DISCOVERY_URL)
INSTANCE_DISCOVERY = {
    "tenant_discovery_endpoint": "https://login.microsoftonline.com/common/v2.0/"
    ".well-known/openid-configuration",
    "api-version": "1.1",
    "metadata": [
        {
            "preferred_network": "login.microsoftonline.com",
            "aliases": [
                "login.microsoftonline.com",
                "login.windows.net",
                "login.microsoft.com",
                "sts.windows.net",
            ],
        },
        {
            "preferred_network": "login.partner.microsoftonline.cn",
            "aliases": ["login.partner.microsoftonline.cn", "login.chinacloudapi.cn"],
        },
        {
            "preferred_network": "login.microsoftonline.us",
            "aliases": ["login.microsoftonline.us", "login.usgovcloudapi.net"],
        },
    ],
}


def gen_client_info(options: AzureAdSettings, **kwargs):
    """
    Generate a fake client_info payload to ensure cache will work correctly
    """

    uid = kwargs.pop("uid", "jdoe1")
    utid = kwargs.pop("utid", options.tenant_id)

    header = {"uid": uid, "utid": utid}

    dump = json.dumps(header, separators=(",", ":"))
    dump_bytes = base64.urlsafe_b64encode(dump.encode()).rstrip(b"=")

    return dump_bytes.decode("utf-8")


def gen_access_token(
    options: AzureAdSettings,
    private_key: Union[str, RSAPrivateKey],
    use_service_principal=False,
    **kwargs,
):
    """
    Generate a fake token to ensure the validation is correctly done on server side
     with a valid token
    """

    # Generate a due date for the token
    now = datetime.now()
    iat = kwargs.pop("iat", int(datetime.timestamp(now)))
    nbf = kwargs.pop("nbf", iat)
    exp = kwargs.pop("exp", int(datetime.timestamp(now + timedelta(minutes=60))))

    # identifier
    oid = kwargs.pop("oid", "jdoe1")
    tid = kwargs.pop("tid", options.tenant_id)

    # Generate audience and issuer to validate token issuer
    client_id = kwargs.pop("client_id", options.client_id)
    tenant_id = kwargs.pop("tenant_id", options.tenant_id)
    domain = kwargs.pop("domain", options.domain)
    iss = kwargs.pop("iss", f"https://sts.windows.net/{tenant_id}/")
    aud = kwargs.pop("aud", f"https://{domain}/{client_id}")
    scp = kwargs.pop("scp", None)
    roles = kwargs.pop("roles", None)

    # Generate payload without user information
    payload = {
        "iss": iss,
        "aud": aud,
        "iat": iat,
        "exp": exp,
        "nbf": nbf,
        "appid": client_id,
        "oid": oid,
        "tid": tid,
    }

    # app roles can be granted to users and to applications (service principals)
    if roles is not None:
        payload["roles"] = roles

    # Generate user payload if token is issued from a user authentication
    if not use_service_principal:
        family_name = kwargs.pop("family_name", "Doe")
        given_name = kwargs.pop("given_name", "John")
        name = f"{given_name} {family_name}"
        email = kwargs.pop("email", f"{given_name}.{family_name}@{domain}")

        payload["unique_name"] = email
        payload["family_name"] = family_name
        payload["given name"] = given_name
        payload["name"] = name

        if scp is not None:
            if not isinstance(scp, List):
                scp = [scp]

            new_scp = []
            for scope in scp:
                scope_array = scope.split("/")
                if len(scope_array) >= 1:
                    scope = scope_array[len(scope_array) - 1]
                new_scp.append(scope)
            scp = new_scp

            payload["scp"] = scp

    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": kwargs.pop("kid", TEST_KEY_ID),
    }

    return jwt.encode(payload, private_key, algorithm="RS256", headers=header)


def gen_payload(
    options: AzureAdSettings,
    private_key: Union[str, RSAPrivateKey],
    use_service_principal=False,
    **kwargs,
):
    """Generate a fake payload with an access_token and client_info if
    user credentials"""

    access_token = gen_access_token(
        options=options,
        private_key=private_key,
        use_service_principal=use_service_principal,
        **kwargs,
    )

    if use_service_principal:
        return json.dumps({"access_token": access_token})
    else:
        client_info = gen_client_info(options, **kwargs)
        return json.dumps({"access_token": access_token, "client_info": client_info})
