import io
import json
import os
import sys
import urllib.request

import pytest
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.param_functions import Depends
from fastapi.testclient import TestClient
from helpers import INSTANCE_DISCOVERY, TEST_KEY_ID
from jwt.algorithms import RSAAlgorithm
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request

from aad_fastapi import AadBearerBackend, AadDiscoverKey, authorize, oauth2_scheme
from aad_fastapi.aad_options import INSTANCE_DISCOVERY_URL
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


@pytest.fixture(autouse=True)
def instance_discovery(monkeypatch: pytest.MonkeyPatch):
    """Mock the Azure AD instance discovery endpoint, used to compute the issuers.

    Returns the list of the kwargs of each discovery request.
    """
    calls = []
    real_get = requests.get

    def fake_get(url, *args, **kwargs):
        if url != INSTANCE_DISCOVERY_URL:
            return real_get(url, *args, **kwargs)
        calls.append(kwargs)
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(INSTANCE_DISCOVERY).encode()
        return response

    monkeypatch.setattr(requests, "get", fake_get)
    return calls


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


@pytest.fixture
def jwks_endpoint(monkeypatch: pytest.MonkeyPatch, public_key):
    """Mock the Azure AD keys endpoint, serving the test public key.

    Returns a dict with the keys url, the served jwks and the requests count.
    """
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk.update({"kid": TEST_KEY_ID, "use": "sig", "alg": "RS256"})
    endpoint = {"url": "https://keys_url", "jwks": {"keys": [jwk]}, "calls": 0}

    class FakeOpener:
        def open(self, request, timeout=None):
            endpoint["calls"] += 1
            return io.BytesIO(json.dumps(endpoint["jwks"]).encode())

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_: FakeOpener())
    monkeypatch.setattr(AadDiscoverKey, "_clients", {})
    return endpoint


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

    @app.get("/isauth_authenticated")
    @authorize()
    async def get_isauth_authenticated(request: Request):
        return {"authenticated": True}

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
