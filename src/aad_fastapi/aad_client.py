import json
from typing import Dict, List, Optional, Union
from uuid import uuid4

import msal
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import (
    AzureCliCredential,
    ChainedTokenCredential,
    ManagedIdentityCredential,
)

from .aad_autherror import AuthError
from .aad_cache_manager import CacheManager
from .aad_helpers import ensure_user_from_token
from .aad_options import AzureAdSettings
from .aad_token import AuthToken
from .aad_user import AadUser
from .aad_vault import AadVault


class AadClient:
    def __init__(
        self,
        session: dict = None,
        options: AzureAdSettings = None,
        env_path: str = None,
    ):

        if options is None:
            options = AzureAdSettings(_env_file=env_path)

        self.options = options
        self.session = session if session is not None else {}
        self.cache_manager = CacheManager

        # Session ID, representing the token STATE ID
        self.aad_id: str = self.session.get("aad_id", None)

        # On first auth, no token is cached, so no STATE ID
        if self.aad_id is None:
            self.aad_id = str(uuid4())

        self.session["aad_id"] = self.aad_id
        self.cache = msal.SerializableTokenCache()

    async def _load_cache(self):

        # get session cache
        cache_session = await self.cache_manager.get(self.aad_id)

        if "token_cache" in cache_session:
            self.cache.deserialize(cache_session["token_cache"])

        return self.cache

    async def _save_cache(self):
        if self.cache.has_state_changed:
            cache_session = await self.cache_manager.get(self.aad_id)
            cache_session["token_cache"] = self.cache.serialize()
            await self.cache_manager.set(self.aad_id, cache_session)

    def _ensure_options(self):
        if self.options is None:
            raise AuthError(
                "options_missing", "options are missing from aad authentication client"
            )

        def _ensure_options_property(property):
            if not hasattr(self.options, property):
                raise AuthError(
                    f"options_{property}_missing",
                    f"{property} is missing from options in aad authentication client",
                )

        _ensure_options_property("client_id")
        _ensure_options_property("authority")

        if not hasattr(self.options, "client_secret"):
            _ensure_options_property("vault_name")
            _ensure_options_property("vault_certificate_name")

    async def build_msal_public_app(self, **kwargs) -> msal.PublicClientApplication:
        self._ensure_options()
        token_cache = await self._load_cache()

        return msal.PublicClientApplication(
            client_id=self.options.client_id,
            authority=self.options.authority,
            token_cache=token_cache,
            **kwargs,
        )

    def _extract_access_token_from_msal_token(self, token: dict = None):

        if token is None:
            return None

        # extract token for web api scope only:
        target = self.options.scopes_list[0]

        token_values = list(token.values())
        for tok in token_values:
            if "target" in tok and tok["target"] == target:
                return tok["secret"]

        return token_values[0].get("secret", None) if len(token_values) > 0 else None

    async def get_user(self, validate: bool = False) -> Optional[AadUser]:

        cache_session = await self.cache_manager.get(self.aad_id)
        if not cache_session:
            return None

        token_cache = cache_session.get("token_cache", None)

        if not token_cache:
            return None

        msal_token = json.loads(token_cache)

        access_token = self._extract_access_token_from_msal_token(
            msal_token.get("AccessToken", None)
        )

        # Invalid. Gracefuly return
        if access_token is None:
            return None

        id_token = self._extract_access_token_from_msal_token(
            msal_token.get("IdToken", None)
        )
        refresh_token = self._extract_access_token_from_msal_token(
            msal_token.get("RefreshToken", None)
        )

        auth_token = AuthToken(
            access_token=access_token,
            id_token=id_token,
            refresh_token=refresh_token,
        )
        user = ensure_user_from_token(auth_token=auth_token, validate=validate)

        return user

    async def acquire_user_token(
        self,
        user: AadUser = None,
        scopes: Union[List[str], str] = None,
        **kwargs,
    ) -> Optional[AadUser]:

        try:
            self._ensure_options()

            authentication_token: AuthToken = None
            exception: Exception = None

            # Get scopes
            scopes = self.options.scopes_list if scopes is None else scopes
            scopes = scopes if isinstance(scopes, List) else [scopes]

            # ---------------------------------------------------
            # Case 0: Login fallback, only for login UI
            # ---------------------------------------------------
            # hiddens parameters to ensure simplicity of usage
            # these parameters are only used on user login, through web ui
            auth_response = kwargs.pop("auth_response", None)
            flow = kwargs.pop("flow", None)

            # particular case on login identication
            if auth_response is not None:
                aad_user = await self._acquire_token_and_user_by_auth_code_flow(
                    scopes, auth_response=auth_response, flow=flow, **kwargs
                )
                return aad_user

            # try to get a valid user from cache
            if user is None:
                user = await self.get_user(validate=False)

            # ---------------------------------------------------
            # Case 1: user is knwon
            # ---------------------------------------------------
            # we have a valid user in parameter with an existing token
            # if the audience from this issuer is the good one,
            # we can keep the token
            if user is not None and user.auth_token is not None:
                try:
                    authentication_token = await self._acquire_token_on_behalf_of(
                        user.auth_token, scopes, **kwargs
                    )
                except Exception as ex:
                    authentication_token = None
                    exception = Exception(ex, exception)

            # ---------------------------------------------------
            # Case 2: Try Managed Identity first or Azure CLI
            # ---------------------------------------------------
            if authentication_token is None:
                try:
                    authentication_token = (
                        await self._acquire_token_for_managed_identity(**kwargs)
                    )
                except Exception as ex:
                    authentication_token = None
                    exception = Exception(ex, exception)

            # ---------------------------------------------------
            # Case 3: Try to reach Service Principal directly
            # ---------------------------------------------------
            if authentication_token is None:
                try:
                    authentication_token = await self._acquire_token_for_client(
                        scopes, **kwargs
                    )
                except Exception as ex:
                    exception = Exception(ex, exception)
                    authentication_token = None

            if authentication_token is None:
                raise AuthError(exception=exception)

            # We can't validate the signature for Graph, since only Microsoft Graph can
            aad_user = ensure_user_from_token(
                auth_token=authentication_token, validate=True, **kwargs
            )

            return aad_user
        except AuthError as aex:
            raise aex
        except Exception as ex:
            raise AuthError(exception=ex)

    async def _acquire_token_and_user_by_auth_code_flow(
        self,
        scopes: Union[List[str], str],
        auth_response=None,
        flow=None,
        **kwargs,
    ) -> AadUser:
        try:
            self._ensure_options()

            cache_session = await self.cache_manager.get(self.aad_id)

            scopes = scopes if isinstance(scopes, List) else [scopes]

            cca = await self.build_msal_confidential_app(**kwargs)

            token = await self._get_token_from_cache(cca, scopes, **kwargs)

            if token:
                return ensure_user_from_token(auth_token=token, **kwargs)

            if flow:
                auth_code_flow = flow
            else:
                auth_code_flow = cache_session.get("flow", None)

            if auth_code_flow is None:
                raise AuthError(
                    "no_auth_code_flow",
                    (
                        "no auth code flow has been provided. Please be sure you have "
                        "a session set."
                    ),
                )

            token = cca.acquire_token_by_auth_code_flow(
                auth_code_flow=auth_code_flow, auth_response=auth_response, **kwargs
            )

            if not token or "access_token" not in token:
                error_code = "no_token_provided_from_acquire_token"
                error_desc = (
                    "can't get token from acquire token interactively "
                    "or from client browser"
                )
                error_code = (
                    error_code if token is None else token.get("error", error_code)
                )
                error_desc = (
                    error_desc
                    if token is None
                    else token.get("error_description", error_desc)
                )
                raise AuthError(error_code, error_desc)

            user = ensure_user_from_token(auth_token=AuthToken(token=token), **kwargs)

            await self._save_cache()

            return user

        except AuthError as aex:
            raise aex
        except Exception as ex:
            raise AuthError(exception=ex)

    async def _acquire_token_for_managed_identity(self, scope: str, **kwargs):
        try:
            # Managed identity when deployed,
            managed_identity = ManagedIdentityCredential()
            # Fallback on Azure CLI if running locally
            # The Azure CLI should be added to App Registration
            azure_cli = AzureCliCredential()

            credential = ChainedTokenCredential(managed_identity, azure_cli)

            # resource = (
            #     self.options.api_scopes_identifiers_root[0]
            #     if self.options.api_scopes_identifiers_root is not None
            #     and len(self.options.api_scopes_identifiers_root) >= 1
            #     else None
            # )

            # access_token = credential.get_token(resource)

            access_token = credential.get_token(scope)

            if access_token is None or access_token.token is None:
                raise AuthError(
                    "no_token_acquired_from_managed_identity",
                    "Can't get a token for the managed identity",
                )

            auth_token = AuthToken(access_token=access_token.token)

            return auth_token
        except ClientAuthenticationError as cae:
            raise AuthError(cae.error, cae.message)
        except AuthError as aex:
            raise aex
        except Exception as ex:
            raise AuthError(exception=ex)

    async def _acquire_token_for_client(
        self,
        scopes: Union[List[str], str],
        **kwargs,
    ):
        """Acquire a tocken to access a ressource from the application
        for specific scopes"""

        try:

            self._ensure_options()

            cca = await self.build_msal_confidential_app(**kwargs)

            scopes = scopes if isinstance(scopes, List) else [scopes]

            auth_token_from_cache = await self._get_token_from_cache(
                cca, scopes, **kwargs
            )

            if auth_token_from_cache:
                return auth_token_from_cache

            token = cca.acquire_token_for_client(scopes=scopes, **kwargs)

            if not token or "access_token" not in token:
                error_code = "no_token_provided_from_acquire_token_for_client"
                error_desc = "can't get token directly from application identity"
                error_code = (
                    error_code if token is None else token.get("error", error_code)
                )
                error_desc = (
                    error_desc
                    if token is None
                    else token.get("error_description", error_desc)
                )
                raise AuthError(error_code, error_desc)

            auth_token = AuthToken(token=token)

            await self._save_cache()

            return auth_token

        except AuthError as aex:
            raise aex
        except Exception as ex:
            raise AuthError(exception=ex)

    async def _acquire_token_on_behalf_of(
        self,
        auth_token: AuthToken,
        scopes: Union[List[str], str],
        **kwargs,
    ):
        try:

            self._ensure_options()

            cca = await self.build_msal_confidential_app(**kwargs)

            scopes = scopes if isinstance(scopes, List) else [scopes]
            auth_token_from_cache = await self._get_token_from_cache(
                cca, scopes, **kwargs
            )

            if auth_token_from_cache:
                return auth_token_from_cache

            token = cca.acquire_token_on_behalf_of(
                user_assertion=auth_token.access_token, scopes=scopes, **kwargs
            )

            if not token or "access_token" not in token:
                error_code = "no_token_provided_from_acquire_token_on_behalf_of"
                error_desc = "can't get token from acquire token on behalf of user"
                error_code = (
                    error_code if token is None else token.get("error", error_code)
                )
                error_desc = (
                    error_desc
                    if token is None
                    else token.get("error_description", error_desc)
                )
                raise AuthError(error_code, error_desc)

            auth_token_on_behalf_of = AuthToken(token=token)

            await self._save_cache()

            return auth_token_on_behalf_of

        except AuthError as aex:
            raise aex
        except Exception as ex:
            raise AuthError(exception=ex)

    async def build_msal_confidential_app(
        self, **kwargs
    ) -> msal.ConfidentialClientApplication:

        """Get an msal instance
        :return:
            The msal instance configured to use a certificate from the
            general Key Vault.
        """

        try:
            self._ensure_options()

            # get the client secret of any compatible client_credential from kwargs
            client_credential = kwargs.get(
                "client_credential", self.options.client_secret
            )

            # if no client secret, load a certificate
            if not client_credential:

                cache_session = await self.cache_manager.get("azure_ad")

                if cache_session is None or "certificate" not in cache_session:

                    aadVault = AadVault(self.options.vault_url)
                    certificate = await aadVault.get_certificate(
                        self.options.vault_certificate_key
                    )

                    cache_session = await self.cache_manager.get("azure_ad")
                    cache_session["certificate"] = certificate

                    await self.cache_manager.set("azure_ad", cache_session)

                # cache_session = self.cache_manager.read(self.aad_id)
                cache_session = await self.cache_manager.get("azure_ad")

                client_credential = aadVault.get_msal_client_credential(
                    cache_session["certificate"]
                )

            token_cache = await self._load_cache()

            # Create tha msal app from that
            return msal.ConfidentialClientApplication(
                client_id=self.options.client_id,
                authority=self.options.authority,
                client_credential=client_credential,
                token_cache=token_cache,
            )

        except AuthError as aex:
            raise aex
        except Exception as ex:
            raise AuthError(exception=ex)

    async def build_auth_code_flow(
        self,
        scopes: Union[List[str], str],
        redirect_uri=None,
        **kwargs,
    ):

        """Initiate an auth code flow.
        :return:
            The auth code flow containing the auth_uri you need to specify in
            your login uri
        """

        try:
            self._ensure_options()

            cache_session = await self.cache_manager.get(self.aad_id)

            scopes = scopes if isinstance(scopes, List) else [scopes]

            cca = await self.build_msal_confidential_app(**kwargs)

            flow: Dict[str, str] = cca.initiate_auth_code_flow(
                scopes, redirect_uri=redirect_uri
            )

            cache_session["flow"] = flow

            if self.session is not None:
                # save session
                self.session["aad_id"] = self.aad_id
                # save to cache
                await self.cache_manager.set(self.aad_id, cache_session)

            return flow

        except AuthError as aex:
            raise aex
        except Exception as ex:
            raise AuthError(exception=ex)

    async def _get_token_from_cache(
        self, cca: msal.ClientApplication, scopes: List[str], **kwargs
    ):
        accounts = cca.get_accounts()
        token = None
        auth_token = None

        if accounts:  # So all account(s) belong to the current signed-in user
            token = cca.acquire_token_silent(scopes, account=accounts[0], **kwargs)

            if not token or "access_token" not in token:
                return None

            auth_token = AuthToken(token=token)

            await self._save_cache()

        return auth_token

    def get_logout_uri(self, logout_page_uri):
        return (
            self.options.authority
            + "/oauth2/v2.0/logout"
            + "?post_logout_redirect_uri="
            + logout_page_uri
        )

    async def remove_account(self, **kwargs):

        try:
            self._ensure_options()
            # remove account from msal cache
            cca = await self.build_msal_confidential_app(**kwargs)

            accounts = cca.get_accounts()

            if accounts:
                cca.remove_account(accounts[0])

            await self._save_cache()

            # remove account from cache
            await self.cache_manager.remove(self.aad_id)

            # remove session id, stored in the cookie
            self.session.pop("aad_id")

        except Exception:
            pass  # do not raise any error here. just kindly exit the function
