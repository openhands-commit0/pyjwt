from __future__ import annotations
import json
import time
from typing import Any
from .algorithms import get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import InvalidKeyError, PyJWKError, PyJWKSetError, PyJWTError
from .types import JWKDict

class PyJWK:

    def __init__(self, jwk_data: JWKDict, algorithm: str | None=None) -> None:
        self._algorithms = get_default_algorithms()
        self._jwk_data = jwk_data
        kty = self._jwk_data.get('kty', None)
        if not kty:
            raise InvalidKeyError(f'kty is not found: {self._jwk_data}')
        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get('alg', None)
        if not algorithm:
            crv = self._jwk_data.get('crv', None)
            if kty == 'EC':
                if crv == 'P-256' or not crv:
                    algorithm = 'ES256'
                elif crv == 'P-384':
                    algorithm = 'ES384'
                elif crv == 'P-521':
                    algorithm = 'ES512'
                elif crv == 'secp256k1':
                    algorithm = 'ES256K'
                else:
                    raise InvalidKeyError(f'Unsupported crv: {crv}')
            elif kty == 'RSA':
                algorithm = 'RS256'
            elif kty == 'oct':
                algorithm = 'HS256'
            elif kty == 'OKP':
                if not crv:
                    raise InvalidKeyError(f'crv is not found: {self._jwk_data}')
                if crv == 'Ed25519':
                    algorithm = 'EdDSA'
                else:
                    raise InvalidKeyError(f'Unsupported crv: {crv}')
            else:
                raise InvalidKeyError(f'Unsupported kty: {kty}')
        if not has_crypto and algorithm in requires_cryptography:
            raise PyJWKError(f"{algorithm} requires 'cryptography' to be installed.")
        self.Algorithm = self._algorithms.get(algorithm)
        if not self.Algorithm:
            raise PyJWKError(f'Unable to find an algorithm for key: {self._jwk_data}')
        self.key = self.Algorithm.from_jwk(self._jwk_data)

    @property
    def key_id(self) -> str | None:
        return self._jwk_data.get('kid')

    @property
    def public_key_use(self) -> str | None:
        return self._jwk_data.get('use')

    @property
    def key_type(self) -> str:
        return self._jwk_data.get('kty')

    @classmethod
    def from_dict(cls, obj: JWKDict, algorithm: str | None=None) -> 'PyJWK':
        """Creates a PyJWK from a dict object."""
        if not isinstance(obj, dict):
            raise InvalidKeyError('Invalid JWK format')
        return cls(obj, algorithm)

    @classmethod
    def from_json(cls, data: str, algorithm: str | None=None) -> 'PyJWK':
        """Creates a PyJWK from a JSON-encoded string."""
        try:
            obj = json.loads(data)
        except ValueError as e:
            raise InvalidKeyError(f'Invalid JWK format: {str(e)}')
        return cls.from_dict(obj, algorithm)

class PyJWKSet:

    def __init__(self, keys: list[JWKDict]) -> None:
        self.keys = []
        if not keys:
            raise PyJWKSetError('The JWK Set did not contain any keys')
        if not isinstance(keys, list):
            raise PyJWKSetError('Invalid JWK Set value')
        for key in keys:
            try:
                self.keys.append(PyJWK(key))
            except PyJWTError:
                continue
        if len(self.keys) == 0:
            raise PyJWKSetError("The JWK Set did not contain any usable keys. Perhaps 'cryptography' is not installed?")

    def __getitem__(self, kid: str) -> 'PyJWK':
        for key in self.keys:
            if key.key_id == kid:
                return key
        raise KeyError(f'keyset has no key for kid: {kid}')

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> 'PyJWKSet':
        """Creates a PyJWKSet from a dict object."""
        if not isinstance(obj, dict):
            raise PyJWKSetError('Invalid JWK Set value')
        keys = obj.get('keys', [])
        return cls(keys)

    @classmethod
    def from_json(cls, data: str) -> 'PyJWKSet':
        """Creates a PyJWKSet from a JSON-encoded string."""
        try:
            obj = json.loads(data)
        except ValueError as e:
            raise PyJWKSetError(f'Invalid JWK Set value: {str(e)}')
        return cls.from_dict(obj)

class PyJWTSetWithTimestamp:

    def __init__(self, jwk_set: PyJWKSet, timestamp: float | None=None):
        self.jwk_set = jwk_set
        self.timestamp = timestamp if timestamp is not None else time.monotonic()