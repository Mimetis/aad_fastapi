from aad import oauth2_scheme
from aad.aad_options import AzureAdSettings


def test_oauth2_scheme_options_is_set():
    """Test case for AadBearerMiddleware(app)

    Ensures that options can be set automatically
    """
    oauth2 = oauth2_scheme()

    assert oauth2 is not None
    assert oauth2.scheme_name == "OAuth2"
    assert oauth2.model is not None
    assert oauth2.model.flows is not None
    assert oauth2.model.flows.authorizationCode is not None


def test_oauth2_scheme_custom_options_is_set():
    """Test case for AadBearerMiddleware(app)

    Ensures that options can be set automatically
    """
    options = AzureAdSettings()
    options.authority = "https://login.microsoftonline.com/tenant_id"
    options.api_scopes_str = "scope1 scope2"
    options.domain = "contoso.com"
    options.client_id = "A0A1A2-B0B1B2"

    oauth2 = oauth2_scheme(options=options)

    assert oauth2 is not None
    assert oauth2.scheme_name == "OAuth2"
    assert oauth2.model is not None
    assert oauth2.model.flows is not None
    assert oauth2.model.flows.authorizationCode is not None
    assert (
        oauth2.model.flows.authorizationCode.authorizationUrl
        == "https://login.microsoftonline.com/tenant_id/oauth2/v2.0/authorize"
    )
    assert len(oauth2.model.flows.authorizationCode.scopes) == 2
    assert (
        list(oauth2.model.flows.authorizationCode.scopes)[0]
        == "https://contoso.com/A0A1A2-B0B1B2/scope1"
    )
    assert (
        list(oauth2.model.flows.authorizationCode.scopes)[1]
        == "https://contoso.com/A0A1A2-B0B1B2/scope2"
    )
