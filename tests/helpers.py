import json
from datetime import datetime, timedelta
from typing import List

from authlib.common import encoding
from authlib.jose import jwt

from aad_fastapi.aad_options import AzureAdSettings


def gen_client_info(options: AzureAdSettings, **kwargs):
    """
    Generate a fake client_info payload to ensure cache will work correctly
    """

    uid = kwargs.pop("uid", "jdoe1")
    utid = kwargs.pop("utid", options.tenant_id)

    header = {"uid": uid, "utid": utid}

    dump = encoding.json_dumps(header)
    dump_bytes = encoding.json_b64encode(dump)

    return dump_bytes.decode("utf-8")


def gen_access_token(
    options: AzureAdSettings,
    private_key: str,
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

    # Generate user payload if token is issued from a user authentication
    if not use_service_principal:
        family_name = kwargs.pop("family_name", "Doe")
        given_name = kwargs.pop("given_name", "John")
        name = f"{given_name} {family_name}"
        roles = kwargs.pop("roles", None)
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

        if roles is not None:
            payload["roles"] = roles

    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "nOo3ZDrODXEK1jKWhXslHR_KXEg",
    }

    dump_bytes = jwt.encode(header, payload, private_key)

    return dump_bytes.decode("utf-8")


def gen_payload(
    options: AzureAdSettings,
    private_key: str,
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
