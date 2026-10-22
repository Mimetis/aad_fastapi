import typing
from typing import List, Optional
from urllib.parse import urlparse

import requests
from pydantic.fields import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .aad_auth_error import AuthError

# Lists the hosts (aliases) of every Microsoft cloud, used to build the issuers
INSTANCE_DISCOVERY_URL = (
    "https://login.microsoftonline.com/common/discovery/instance"
    "?authorization_endpoint="
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize&api-version=1.1"
)
INSTANCE_DISCOVERY_TIMEOUT = 10


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
    allow_tokens_without_permissions : accept tokens with neither a "scp" nor a
        "roles" claim (default False). See README, "Token validation".

    if not present, each value will be retrieved from environment variables:
    "CLIENT_ID", "AUTHORITY", "DOMAIN", "TENANT_ID", "API_SCOPES",
    "VAULT_URL", "VAULT_CERTIFICATE_NAME", "ALLOW_TOKENS_WITHOUT_PERMISSIONS"
    """

    model_config = SettingsConfigDict(
        env_file=".env", validate_default=False, extra="allow"
    )

    client_id: Optional[str] = Field(default=None, description="Client id")
    client_secret: Optional[str] = Field(default=None, description="Client Secret")
    authority: Optional[str] = Field(default=None, description="login authority")
    domain: Optional[str] = Field(default=None, description="Domain name")
    tenant_id: Optional[str] = Field(default=None, description="Tenant Id")
    scopes: Optional[str] = Field(default=None, description="Scopes")
    vault_name: Optional[str] = Field(default=None, description="Global Vault Url")
    vault_certificate_key: Optional[str] = Field(
        default=None, description="Certificate name"
    )
    vault_secret_key: Optional[str] = Field(default=None, description="Certificate name")
    aad_issuers_list: List[str] = []
    allow_tokens_without_permissions: bool = Field(
        default=False,
        description="Accept tokens with neither a 'scp' nor a 'roles' claim, like "
        "app-only tokens without any granted permission. Enable it only if you "
        "authorize the callers yourself.",
    )

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

    def get_available_issuers(self) -> List[str]:
        """Get the issuers accepted for tenant_id, on every host of the authority's
        cloud (ex: login.microsoftonline.com, sts.windows.net, ...).

        Raises an AuthError if they can't be computed: an empty list would disable
        the issuer validation, accepting tokens issued for any tenant.
        """
        if self.aad_issuers_list:
            return self.aad_issuers_list

        authority_host = urlparse(self.authority).hostname if self.authority else None

        if not self.tenant_id or not authority_host:
            raise AuthError(
                "invalid_configuration",
                "tenant_id and authority must be set to validate the token issuer",
                status_code=500,
            )

        response = requests.get(
            INSTANCE_DISCOVERY_URL, timeout=INSTANCE_DISCOVERY_TIMEOUT
        )
        response.raise_for_status()

        issuers = []
        for metadata in response.json().get("metadata", []):
            aliases = metadata.get("aliases", [])
            if authority_host in aliases:
                for alias in aliases:
                    issuers.append(f"https://{alias}/{self.tenant_id}/")
                    issuers.append(f"https://{alias}/{self.tenant_id}/v2.0")

        if not issuers:
            raise AuthError(
                "invalid_configuration",
                f"Unable to find the issuers of the authority host '{authority_host}'. "
                "Set aad_issuers_list to configure them explicitly.",
                status_code=500,
            )

        self.aad_issuers_list = issuers
        return issuers

    @property
    def audiences(self) -> List[str]:
        """
        Returns the audiences that are valid for a client_id
        """
        if not self.client_id:
            return []

        audiences = [f"api://{self.client_id}", self.client_id]
        if self.domain:
            audiences.insert(0, f"https://{self.domain}/{self.client_id}")
        return audiences

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
