import json
import urllib.request
from functools import lru_cache
from ssl import SSLContext
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError
from .jwk_set_cache import JWKSetCache

class PyJWKClient:

    def __init__(self, uri: str, cache_keys: bool=False, max_cached_keys: int=16, cache_jwk_set: bool=True, lifespan: int=300, headers: Optional[Dict[str, Any]]=None, timeout: int=30, ssl_context: Optional[SSLContext]=None):
        if headers is None:
            headers = {}
        self.uri = uri
        self.jwk_set_cache: Optional[JWKSetCache] = None
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        if cache_jwk_set:
            if lifespan <= 0:
                raise PyJWKClientError(f'Lifespan must be greater than 0, the input is "{lifespan}"')
            self.jwk_set_cache = JWKSetCache(lifespan)
        else:
            self.jwk_set_cache = None
        if cache_keys:
            self.get_signing_key = lru_cache(maxsize=max_cached_keys)(self.get_signing_key)

    def fetch_data(self) -> str:
        """Fetch the JWKS data from the uri provided during instantiation."""
        try:
            request = urllib.request.Request(self.uri, headers=self.headers)
            if self.ssl_context:
                response = urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context)
            else:
                response = urllib.request.urlopen(request, timeout=self.timeout)
            return response.read().decode('utf-8')
        except URLError as e:
            raise PyJWKClientConnectionError(f'Failed to fetch JWKS from {self.uri}. Error: {str(e)}')

    def get_jwk_set(self, refresh: bool=False) -> PyJWKSet:
        """Return the fetched PyJWKSet.
        
        Args:
            refresh: Force a refetch of the JWKS.
        """
        if not refresh and self.jwk_set_cache and not self.jwk_set_cache.is_expired():
            return self.jwk_set_cache.jwk_set

        data = self.fetch_data()
        try:
            jwk_set = PyJWKSet.from_json(data)
        except Exception as e:
            if self.jwk_set_cache:
                self.jwk_set_cache.delete()
            raise PyJWKClientError(f'Failed to parse JWKS: {str(e)}')

        if self.jwk_set_cache:
            self.jwk_set_cache.jwk_set = jwk_set

        return jwk_set

    def get_signing_keys(self) -> List[PyJWK]:
        """Return a list of signing keys from the JWKS."""
        jwk_set = self.get_jwk_set()
        signing_keys = []

        for jwk_key in jwk_set.keys:
            if jwk_key.public_key_use == 'sig' or not jwk_key.public_key_use:
                signing_keys.append(jwk_key)

        if not signing_keys:
            raise PyJWKClientError('No signing keys found in JWKS')

        return signing_keys

    def get_signing_key(self, kid: str) -> PyJWK:
        """Return the signing key from the JWKS that matches the provided kid.
        
        Args:
            kid: The key ID to search for.
        """
        signing_keys = self.get_signing_keys()
        for key in signing_keys:
            if key.key_id == kid:
                return key

        # If no key is found, try refreshing the JWKS once
        signing_keys = self.get_signing_keys()
        for key in signing_keys:
            if key.key_id == kid:
                return key

        raise PyJWKClientError(f'Unable to find a signing key that matches: {kid}')

    def get_signing_key_from_jwt(self, token: str, refresh_jwks: bool=True) -> PyJWK:
        """Return the signing key from the JWKS that matches the kid in the token header.
        
        Args:
            token: The JWT token to get the key for.
            refresh_jwks: Whether to refresh the JWKS if the key is not found.
        """
        try:
            headers = decode_token(token, options={'verify_signature': False})['header']
        except Exception as e:
            raise PyJWKClientError(f'Failed to decode JWT headers: {str(e)}')

        kid = headers.get('kid')
        if not kid:
            signing_keys = self.get_signing_keys()
            if len(signing_keys) == 1:
                return signing_keys[0]
            raise PyJWKClientError('Token headers must include a key ID ("kid")')

        try:
            return self.get_signing_key(kid)
        except PyJWKClientError:
            if refresh_jwks:
                self.get_jwk_set(refresh=True)
                return self.get_signing_key(kid)
            raise