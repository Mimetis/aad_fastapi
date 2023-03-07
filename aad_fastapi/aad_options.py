import typing
from typing import List
from urllib.parse import urlparse

import requests
from pydantic.env_settings import BaseSettings
from pydantic.fields import Field


class AzureAdSettings(BaseSettings):
    """
    Represents the Azure AD Settings.
    client_id       : Application Resgistration app id (GUID)
    authority       : Authority url.
        ex: "https://login.microsoftonline.com/{client_id}"
    domain          : Azure tenant domain. "ex:microsoft.onmicrosoft.com"
    tenant_id       : Azure tenant id. (GUID)
    api_scopes      : API scopes list (separated by a blank space).
        ex:"user_impersonation"
    vault_url : vault url, containing the certificate to use.
        ex:"https://rgbertkvd10.vault.azure.net/"
    vault_certificate_name : certificate name, contained in vault. ex:"mycert"

    if not present, each value will be retrieved from environment variables:
    "CLIENT_ID", "AUTHORITY", "DOMAIN", "TENANT_ID", "API_SCOPES",
    "VAULT_URL", "VAULT_CERTIFICATE_NAME"

    """

    client_id: str = Field(None, description="Client id", env="CLIENT_ID")
    client_secret: str = Field(None, description="Client Secret", env="CLIENT_SECRET")
    authority: str = Field(None, description="login authority", env="AUTHORITY")
    domain: str = Field(None, description="Domain name", env="DOMAIN")
    tenant_id: str = Field(None, description="Tenant Id", env="TENANT_ID")
    scopes: str = Field(None, description="Scopes", env="SCOPES")
    vault_name: str = Field(None, description="Global Vault Url", env="VAULT_NAME")
    vault_certificate_key: str = Field(
        None, description="Certificate name", env="VAULT_CERTIFICATE_KEY"
    )
    vault_secret_key: str = Field(
        None, description="Certificate name", env="VAULT_SECRET_KEY"
    )
    aad_issuers_list: List[str] = []

    @property
    def authorization_url(self):
        return f"{self.authority}/oauth2/v2.0/authorize"

    @property
    def token_url(self):
        return f"{self.authority}/oauth2/v2.0/token"

    @property
    def keys_url(self):
        return f"{self.authority}/discovery/v2.0/keys"

    @property
    def vault_url(self):
        return f"https://{self.vault_name}.vault.azure.net"

    def get_available_issuers(self):
        if self.aad_issuers_list is not None and len(self.aad_issuers_list) > 0:
            return self.aad_issuers_list

        issuers_list_url = (
            "https://login.microsoftonline.com/common/discovery/instance"
            + "?authorization_endpoint="
            + "https://login.microsoftonline.com/common/oauth2/v2.0/"
            + "authorize&api-version=1.1"
        )

        _issuers_list = requests.get(issuers_list_url).json()
        _metadatas = _issuers_list["metadata"]

        _authority_parser = urlparse(self.authority)
        _authority_domain = _authority_parser.hostname

        for _metadata in _metadatas:
            if _authority_domain in _metadata["preferred_network"]:
                for alias in _metadata["aliases"]:
                    self.aad_issuers_list.append(f"https://{alias}/{self.tenant_id}/")
                    self.aad_issuers_list.append(f"https://{alias}/{self.tenant_id}/v2.0")

        return self.aad_issuers_list

    @property
    def audiences(self):
        """
        Returns the audiences that are valid for a client_id
        """
        return [
            f"https://{self.domain}/{self.client_id}",
            f"api://{self.client_id}",
            self.client_id,
        ]

    @property
    def scopes_list(self):
        _scopes = []

        if self.scopes is not None:
            if isinstance(self.scopes, typing.List):
                _scopes.extend(self.scopes)
            else:
                for _scp in str.split(self.scopes, " "):
                    _scopes.append(_scp)

        return _scopes

    class Config:
        env_file = ".env"
