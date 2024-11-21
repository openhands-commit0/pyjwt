from __future__ import annotations
import json
import warnings
from calendar import timegm
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any
from . import api_jws
from .exceptions import DecodeError, ExpiredSignatureError, ImmatureSignatureError, InvalidAudienceError, InvalidIssuedAtError, InvalidIssuerError, MissingRequiredClaimError
from .warnings import RemovedInPyjwt3Warning
if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys

class PyJWT:

    def __init__(self, options: dict[str, Any] | None=None) -> None:
        if options is None:
            options = {}
        self.options: dict[str, Any] = {**self._get_default_options(), **options}

    def _get_default_options(self) -> dict[str, Any]:
        """Returns the default options for this instance."""
        return {
            'verify_signature': True,
            'verify_exp': True,
            'verify_nbf': True,
            'verify_iat': True,
            'verify_aud': True,
            'verify_iss': True,
            'require': []
        }

    def _encode_payload(self, payload: dict[str, Any], headers: dict[str, Any] | None=None, json_encoder: type[json.JSONEncoder] | None=None) -> bytes:
        """
        Encode a given payload to the bytes to be signed.

        This method is intended to be overridden by subclasses that need to
        encode the payload in a different way, e.g. compress the payload.
        """
        json_str = json.dumps(payload, separators=(',', ':'), cls=json_encoder).encode('utf-8')
        return json_str

    def _decode_payload(self, decoded: dict[str, Any]) -> Any:
        """
        Decode the payload from a JWS dictionary (payload, signature, header).

        This method is intended to be overridden by subclasses that need to
        decode the payload in a different way, e.g. decompress compressed
        payloads.
        """
        try:
            payload = json.loads(decoded['payload'].decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid payload string: %s' % e)
        if not isinstance(payload, dict):
            raise DecodeError('Invalid payload string: must be a json object')
        return payload

    def encode(self, payload: dict[str, Any], key: str | bytes | AllowedPrivateKeys, algorithm: str | None=None, headers: dict[str, Any] | None=None, json_encoder: type[json.JSONEncoder] | None=None) -> str:
        """
        Encode a JWT from a payload and optional headers.

        Takes a payload and signs it using the specified algorithm.

        Arguments:
            payload: A dict of claims for the JWT.
            key: The key to use for signing the claim. Note: if the algorithm is None, the key is not used.
            algorithm: The signing algorithm to use. If none is specified then 'none' is used.
            headers: A dict of additional headers to use.
            json_encoder: A custom JSON encoder to use for encoding the JWT.
        """
        # Check that we have a mapping
        if not isinstance(payload, dict):
            raise TypeError('Payload must be a dict')

        # Add reserved claims
        if 'exp' in payload and not isinstance(payload['exp'], (int, float)):
            payload['exp'] = timegm(payload['exp'].utctimetuple())
        if 'iat' in payload and not isinstance(payload['iat'], (int, float)):
            payload['iat'] = timegm(payload['iat'].utctimetuple())
        if 'nbf' in payload and not isinstance(payload['nbf'], (int, float)):
            payload['nbf'] = timegm(payload['nbf'].utctimetuple())

        json_payload = self._encode_payload(payload, headers, json_encoder)
        return api_jws.encode(json_payload, key, algorithm, headers)

    def decode_complete(self, jwt: str | bytes, key: str | bytes | AllowedPublicKeys | None=None, algorithms: list[str] | None=None, options: dict[str, Any] | None=None, **kwargs: Any) -> dict[str, Any]:
        """
        Decodes a JWT and returns a dict of the token contents.

        Args:
            jwt: The JWT to decode.
            key: The key to use for verifying the claim. Note: if the algorithm is 'none', the key is not used.
            algorithms: A list of allowed algorithms. If None, default to the algorithms registered.
            options: A dict of options for decoding. If None, use default options.
            **kwargs: Additional options for decoding.

        Returns:
            A dict including:
                - header: A dict of the JWT header
                - payload: The decoded payload
                - signature: The signature of the JWT
        """
        merged_options = {**self.options, **(options or {})}
        decoded = api_jws.decode_complete(jwt, key, algorithms, merged_options)
        payload = self._decode_payload(decoded)

        if merged_options['verify_exp'] and 'exp' in payload:
            now = kwargs.get('now', datetime.now(timezone.utc))
            exp = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
            if now > exp:
                raise ExpiredSignatureError('Signature has expired')

        if merged_options['verify_nbf'] and 'nbf' in payload:
            now = kwargs.get('now', datetime.now(timezone.utc))
            nbf = datetime.fromtimestamp(payload['nbf'], tz=timezone.utc)
            if now < nbf:
                raise ImmatureSignatureError('The token is not yet valid (nbf)')

        if merged_options['verify_iat'] and 'iat' in payload:
            now = kwargs.get('now', datetime.now(timezone.utc))
            iat = datetime.fromtimestamp(payload['iat'], tz=timezone.utc)
            if now < iat:
                raise InvalidIssuedAtError('Issued at claim (iat) cannot be in the future')

        if merged_options['verify_iss']:
            expected_issuer = kwargs.get('issuer', None)
            if expected_issuer is not None:
                if 'iss' not in payload:
                    raise MissingRequiredClaimError('Issuer claim expected but not present')
                if payload['iss'] != expected_issuer:
                    raise InvalidIssuerError('Invalid issuer')

        if merged_options['verify_aud']:
            expected_audience = kwargs.get('audience', None)
            if expected_audience is not None:
                if 'aud' not in payload:
                    raise MissingRequiredClaimError('Audience claim expected but not present')
                audience = payload['aud']
                if isinstance(audience, str):
                    audience = [audience]
                if not isinstance(audience, Iterable):
                    raise InvalidAudienceError('Invalid audience')
                if expected_audience not in audience:
                    raise InvalidAudienceError('Invalid audience')

        if merged_options['require']:
            for claim in merged_options['require']:
                if claim not in payload:
                    raise MissingRequiredClaimError(f'Token is missing the "{claim}" claim')

        decoded['payload'] = payload
        return decoded

    def decode(self, jwt: str | bytes, key: str | bytes | AllowedPublicKeys | None=None, algorithms: list[str] | None=None, options: dict[str, Any] | None=None, **kwargs: Any) -> dict[str, Any]:
        """
        Decodes a JWT and returns the payload.

        This is a shortcut to :meth:`decode_complete()` that returns just the payload.
        """
        decoded = self.decode_complete(jwt, key, algorithms, options, **kwargs)
        return decoded['payload']
_jwt_global_obj = PyJWT()
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode