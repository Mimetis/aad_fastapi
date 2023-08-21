import os
import sys

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.param_functions import Depends
from fastapi.testclient import TestClient
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request

from aad_fastapi import AadBearerBackend, authorize, oauth2_scheme
from aad_fastapi.roles.role_requirement import RoleRequirement

os.environ["CLIENT_ID"] = "01010101-aaaa-bbbb-acdf-020202020202"
os.environ["TENANT_ID"] = "02020202-aaaa-erty-olki-020202020202"
os.environ["DOMAIN"] = "contoso.onmicrosoft.com"
os.environ["API_SCOPES"] = "user_impersonation"
os.environ["AUTHORITY"] = "https://login.microsoftonline.com/common"
os.environ["VAULT_URL"] = "https://your_key_vault_name.vault.azure.net/"
os.environ["VAULT_CERTIFICATE_NAME"] = "certificate_name_from_your_key_vault"


@pytest.fixture(autouse=True)
def run_test_in_temporary_directory(request):
    tmpdir = request.getfixturevalue("tmpdir")
    sys.path.insert(0, str(tmpdir))
    with tmpdir.as_cwd():
        yield


@pytest.fixture(scope="module")
def public_key(cert):
    return cert["public_key"]


@pytest.fixture(scope="module")
def private_key(cert):
    return cert["private_key"]


@pytest.fixture(scope="module")
def cert():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    return {"public_key": public_key, "private_key": private_key}


@pytest.fixture(scope="module")
def mock_test_client(public_key):
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

    @app.get("/isauth_impersonation_all_roles")
    @authorize("user_impersonation", ["Admin", "Contributor"])
    async def get_isauth_with_impersonation_and_all_roles(
        request: Request, token=Depends(oauth2_scheme())
    ):
        return request.user

    @app.get("/isauth_impersonation_any_roles")
    @authorize(
        "user_impersonation",
        ["Admin", "Contributor"],
        role_requirement=RoleRequirement.ANY,
    )
    async def get_isauth_with_impersonation_and_any_roles(
        request: Request, token=Depends(oauth2_scheme())
    ):
        return request.user

    return TestClient(app)
