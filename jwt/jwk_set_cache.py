import time
from typing import Optional
from .api_jwk import PyJWKSet, PyJWTSetWithTimestamp

class JWKSetCache:

    def __init__(self, lifespan: int) -> None:
        self.jwk_set_with_timestamp: Optional[PyJWTSetWithTimestamp] = None
        self.lifespan = lifespan

    @property
    def jwk_set(self) -> PyJWKSet:
        if self.jwk_set_with_timestamp is None:
            raise ValueError('No JWK set has been cached')
        return self.jwk_set_with_timestamp.jwk_set

    @jwk_set.setter
    def jwk_set(self, value: PyJWKSet) -> None:
        self.jwk_set_with_timestamp = PyJWTSetWithTimestamp(value, int(time.time()))

    def is_expired(self) -> bool:
        if self.jwk_set_with_timestamp is None:
            return True
        return int(time.time()) - self.jwk_set_with_timestamp.timestamp > self.lifespan

    def delete(self) -> None:
        self.jwk_set_with_timestamp = None