from typing import Any, Dict

from jwt import PyJWK, PyJWKClient


class AadDiscoverKey:
    # Azure AD rotates its signing keys: cached key sets expire after this many
    # seconds, and an unknown "kid" triggers an immediate refresh.
    KEYS_CACHE_LIFESPAN = 3600

    # one JWKS client (and cache) per keys url
    _clients: Dict[str, PyJWKClient] = {}

    @staticmethod
    def get_jwks_client(key_url: str) -> PyJWKClient:
        client = AadDiscoverKey._clients.get(key_url)
        if client is None:
            client = PyJWKClient(
                key_url,
                cache_jwk_set=True,
                lifespan=AadDiscoverKey.KEYS_CACHE_LIFESPAN,
            )
            AadDiscoverKey._clients[key_url] = client
        return client

    @staticmethod
    def get_discovery_key_json(key_url: str) -> Dict[str, Any]:
        """Fetch the raw JWKS document (also refreshes the signing keys cache)"""
        return AadDiscoverKey.get_jwks_client(key_url).fetch_data()

    @staticmethod
    def get_signing_key(key_url: str, token: str) -> PyJWK:
        """Get the public key matching the "kid" header of the token"""
        return AadDiscoverKey.get_jwks_client(key_url).get_signing_key_from_jwt(token)
