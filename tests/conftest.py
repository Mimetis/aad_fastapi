import os
import pathlib
import sys

import pytest
from async_asgi_testclient import TestClient
from fastapi import FastAPI
from fastapi.param_functions import Depends
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request

from aad_fastapi import AadBearerBackend, authorize, oauth2_scheme

os.environ["CLIENT_ID"] = "01010101-aaaa-bbbb-acdf-020202020202"
os.environ["TENANT_ID"] = "02020202-aaaa-erty-olki-020202020202"
os.environ["DOMAIN"] = "contoso.onmicrosoft.com"
os.environ["API_SCOPES"] = "user_impersonation"
os.environ["AUTHORITY"] = "https://login.microsoftonline.com/common"
os.environ["VAULT_URL"] = "https://your_key_vault_name.vault.azure.net/"
os.environ["VAULT_CERTIFICATE_NAME"] = "certificate_name_from_your_key_vault"


# each test runs on cwd to its temp dir
@pytest.fixture(autouse=True)
def go_to_tmpdir(request):
    # Get the fixture dynamically by its name.
    tmpdir = request.getfixturevalue("tmpdir")
    # ensure local test created packages can be imported
    sys.path.insert(0, str(tmpdir))
    # Chdir only for the duration of the test.
    with tmpdir.as_cwd():
        yield


@pytest.fixture(scope="module")
def public_key(cert):
    return cert["public_key"]


@pytest.fixture(scope="module")
def private_key(cert):
    return cert["private_key"]


@pytest.fixture(scope="module")
def thumbprint():
    return "ce496c5eff03728f9fd01b106874245ffc31058b".encode()


@pytest.fixture(scope="module")
def client_credential(private_key, public_key, thumbprint):
    class client_certificate:
        def __init__(self, private_key, public_key, thumbprint):
            self.private_key = private_key
            self.thumbprint = thumbprint
            self.public_key = public_key

    return client_certificate(private_key, public_key, thumbprint)


@pytest.fixture(scope="module")
def cert():
    # Get certificate private and public keys to create access_token
    aad_tests_dir = pathlib.Path(__file__).parent.absolute()

    public_key_file = os.path.join(aad_tests_dir, "public.pem")
    public_key = open(public_key_file, "r").read()

    private_key_file = os.path.join(aad_tests_dir, "private.pem")
    private_key = open(private_key_file, "r").read()

    return {"public_key": public_key, "private_key": private_key}


@pytest.fixture(scope="module")
def client(public_key):
    # pre fill client id
    swagger_ui_init_oauth = {
        "clientId": os.environ.get("CLIENT_ID"),
        "appName": "B-ID",
    }

    app = FastAPI(swagger_ui_init_oauth=swagger_ui_init_oauth)

    aad_bearer_backend = AadBearerBackend(public_key=public_key)
    # Add the bearer middleware
    app.add_middleware(AuthenticationMiddleware, backend=aad_bearer_backend)

    @app.get("/test")
    async def get_test(request: Request):
        return {"test": True}

    @app.get("/isauth")
    async def get_isauth(request: Request, token=Depends(oauth2_scheme())):
        return request.user

    @app.get("/isauth_impersonation")
    @authorize("user_impersonation")
    async def get_isauth_with_impersonation(
        request: Request, token=Depends(oauth2_scheme())
    ):
        return request.user

    @app.get("/isauth_impersonation_roles")
    @authorize("user_impersonation", ["Admin", "Contributor"])
    async def get_isauth_with_impersonation_and_roles(
        request: Request, token=Depends(oauth2_scheme())
    ):
        return request.user

    return TestClient(app)
