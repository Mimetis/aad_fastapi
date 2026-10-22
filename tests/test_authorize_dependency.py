import json

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from helpers import gen_payload
from starlette.middleware.authentication import AuthenticationMiddleware

from aad_fastapi import (
    AadBearerBackend,
    AadUser,
    Authorize,
    AzureAdSettings,
    oauth2_scheme,
)
from aad_fastapi.roles.role_requirement import RoleRequirement


@pytest.fixture(scope="module")
def client(public_key):
    app = FastAPI()
    app.add_middleware(
        AuthenticationMiddleware, backend=AadBearerBackend(public_key=public_key)
    )
    oauth2 = oauth2_scheme()

    @app.get("/me")
    async def me(user: AadUser = Depends(Authorize())):
        return {"id": user.id}

    @app.get("/scoped")
    async def scoped(user: AadUser = Depends(Authorize("user_impersonation"))):
        return {"id": user.id}

    @app.get(
        "/all_roles",
        dependencies=[Depends(Authorize("user_impersonation", ["Admin", "Contributor"]))],
    )
    async def all_roles():
        return {}

    @app.get(
        "/any_roles",
        dependencies=[
            Depends(
                Authorize(
                    roles=["Admin", "Contributor"], role_requirement=RoleRequirement.ANY
                )
            )
        ],
    )
    async def any_roles():
        return {}

    @app.get("/documented")
    async def documented(
        user: AadUser = Depends(Authorize("user_impersonation", scheme=oauth2)),
    ):
        return {"id": user.id}

    router = APIRouter(
        prefix="/data", dependencies=[Depends(Authorize(roles="Data.Read"))]
    )

    @router.get("/items")
    async def items():
        return []

    app.include_router(router)

    return TestClient(app)


def get(client, private_key, route, **token_kwargs):
    payload = gen_payload(AzureAdSettings(), private_key, **token_kwargs)
    token = json.loads(payload)["access_token"]
    return client.get(route, headers={"Authorization": "Bearer " + token})


def test_no_token_is_unauthenticated(client):
    response = client.get("/me")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_valid_token(client, private_key):
    response = get(client, private_key, "/me", scp="user_impersonation")

    assert response.status_code == 200
    assert response.json() == {"id": "jdoe1"}


def test_missing_scope(client, private_key):
    response = get(client, private_key, "/scoped", roles=["Admin"])

    assert response.status_code == 403
    assert response.headers["WWW-Authenticate"] == (
        'Bearer error="insufficient_scope", scope="user_impersonation"'
    )
    assert (
        get(client, private_key, "/scoped", scp="user_impersonation").status_code == 200
    )


@pytest.mark.parametrize(
    "route, roles, expected_status_code",
    [
        ("/all_roles", ["Admin", "Contributor"], 200),
        ("/all_roles", ["Admin"], 403),
        ("/any_roles", ["Admin"], 200),
        ("/any_roles", ["Reader"], 403),
        ("/any_roles", None, 403),
    ],
)
def test_roles(client, private_key, route, roles, expected_status_code):
    response = get(client, private_key, route, scp="user_impersonation", roles=roles)

    assert response.status_code == expected_status_code


def test_router_dependency_with_app_token(client, private_key):
    """App-only token, granted the Data.Read app role"""

    response = get(
        client,
        private_key,
        "/data/items",
        use_service_principal=True,
        roles=["Data.Read"],
    )
    assert response.status_code == 200

    response = get(
        client, private_key, "/data/items", use_service_principal=True, roles=["Other"]
    )
    assert response.status_code == 403


def test_openapi_documents_the_security_only_with_a_scheme(client):
    paths = client.get("/openapi.json").json()["paths"]

    assert paths["/documented"]["get"]["security"] == [{"OAuth2": ["user_impersonation"]}]
    # the dependency doesn't add any parameter to the routes
    assert "parameters" not in paths["/documented"]["get"]
    assert "parameters" not in paths["/me"]["get"]
    assert "security" not in paths["/me"]["get"]


def test_invalid_role_requirement():
    with pytest.raises(ValueError):
        Authorize(
            roles="Admin",
            role_requirement="invalid",  # pyright: ignore[reportArgumentType]
        )


def test_requires_the_authentication_middleware():
    app = FastAPI()

    @app.get("/me")
    async def me(user: AadUser = Depends(Authorize())):
        return {}

    with pytest.raises(RuntimeError):
        TestClient(app).get("/me")
