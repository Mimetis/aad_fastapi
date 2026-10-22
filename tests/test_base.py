from aad_fastapi import base


def test_app_name():
    assert base.NAME == "aad_fastapi"


def test_star_import():
    namespace = {}
    exec("from aad_fastapi import *", namespace)

    assert "AzureAdSettings" in namespace
    assert "AadBearerBackend" in namespace
