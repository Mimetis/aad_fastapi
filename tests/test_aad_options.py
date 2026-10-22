import pytest

from aad_fastapi import AuthError, AzureAdSettings
from aad_fastapi.aad_options import INSTANCE_DISCOVERY_TIMEOUT


@pytest.mark.parametrize(
    "host",
    [
        "login.microsoftonline.com",
        "login.windows.net",
        "login.microsoft.com",
        "sts.windows.net",
    ],
)
def test_issuers_for_every_host_of_the_cloud(host):
    """Every valid host of the public cloud gives the issuers of all its aliases"""

    options = AzureAdSettings(authority=f"https://{host}/common")
    tenant_id = options.tenant_id
    assert tenant_id is not None
    issuers = options.get_available_issuers()

    assert f"https://sts.windows.net/{tenant_id}/" in issuers
    assert f"https://login.microsoftonline.com/{tenant_id}/v2.0" in issuers
    assert all(tenant_id in issuer for issuer in issuers)
    assert not any("chinacloudapi" in issuer for issuer in issuers)


def test_issuers_for_sovereign_cloud():
    options = AzureAdSettings(authority="https://login.chinacloudapi.cn/common")
    tenant_id = options.tenant_id

    issuers = options.get_available_issuers()

    assert f"https://login.partner.microsoftonline.cn/{tenant_id}/v2.0" in issuers
    assert not any("microsoftonline.com" in issuer for issuer in issuers)


def test_issuers_unknown_authority_host_raises():
    """An empty issuers list would disable the issuer validation"""

    options = AzureAdSettings(authority="https://contoso.b2clogin.com/common")

    with pytest.raises(AuthError) as auth_error:
        options.get_available_issuers()

    assert auth_error.value.code == "invalid_configuration"


def test_issuers_missing_configuration_raises():
    for options in (AzureAdSettings(tenant_id=None), AzureAdSettings(authority=None)):
        with pytest.raises(AuthError) as auth_error:
            options.get_available_issuers()

        assert auth_error.value.code == "invalid_configuration"


def test_issuers_are_cached(instance_discovery):
    options = AzureAdSettings()

    options.get_available_issuers()
    options.get_available_issuers()

    assert len(instance_discovery) == 1
    assert instance_discovery[0]["timeout"] == INSTANCE_DISCOVERY_TIMEOUT


def test_issuers_list_can_be_configured(instance_discovery):
    options = AzureAdSettings(aad_issuers_list=["https://my_issuer/"])

    assert options.get_available_issuers() == ["https://my_issuer/"]
    assert instance_discovery == []


def test_audiences():
    options = AzureAdSettings(client_id="cid", domain="contoso.com")
    assert options.audiences == ["https://contoso.com/cid", "api://cid", "cid"]

    options = AzureAdSettings(client_id="cid", domain=None)
    assert options.audiences == ["api://cid", "cid"]

    # no client_id: no valid audience, every token is rejected
    assert AzureAdSettings(client_id=None).audiences == []
