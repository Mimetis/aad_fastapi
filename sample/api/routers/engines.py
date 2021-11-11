from fastapi import APIRouter
from starlette.requests import Request

router = APIRouter(
    prefix="/engines",
    tags=["engines"],
    responses={404: {"description": "Not found"}},
)

fake_items_db = {"plumbus": {"name": "Plumbus"}, "gun": {"name": "Portal Gun"}}

company = {
    "company_id": "000ABC",
    "company_name": "One Two Three",
    "id": "601BBA98-677A-49E8-B677-6905C62D521C",
    "webapis_oids": [
        {
            "id": "36AA308B-5B0F-447A-BABC-40330B004F16",
            "app_name": "OneTwoThreeWebAppService",
            "roles_id": ["data-provider", "data-browser"],
        }
    ],
}


# Always check scopes for API auth
@router.get("")
async def get_engines(request: Request):
    return company


# Always check scopes for API auth
@router.get("/admin")
async def get_engines_admin(request: Request):
    return fake_items_db
