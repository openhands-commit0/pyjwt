from __future__ import annotations
import binascii
import json
import warnings
from typing import TYPE_CHECKING, Any
from .algorithms import Algorithm, get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import DecodeError, InvalidAlgorithmError, InvalidSignatureError, InvalidTokenError
from .utils import base64url_decode, base64url_encode
from .warnings import RemovedInPyjwt3Warning
if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys

class PyJWS:
    header_typ = 'JWT'

    def __init__(self, algorithms: list[str] | None=None, options: dict[str, Any] | None=None) -> None:
        self._algorithms = get_default_algorithms()
        self._valid_algs = set(algorithms) if algorithms is not None else set(self._algorithms)
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]
        if options is None:
            options = {}
        self.options = {**self._get_default_options(), **options}

    def _get_default_options(self) -> dict[str, Any]:
        """Returns the default options for this instance."""
        return {
            'verify_signature': True
        }

    def register_algorithm(self, alg_id: str, alg_obj: Algorithm) -> None:
        """
        Registers a new Algorithm for use when creating and verifying tokens.
        """
        if not isinstance(alg_obj, Algorithm):
            raise TypeError('Algorithm must be an instance of Algorithm')
        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id: str) -> None:
        """
        Unregisters an Algorithm for use when creating and verifying tokens
        Throws KeyError if algorithm is not registered.
        """
        if alg_id not in self._algorithms:
            raise KeyError(f'Algorithm {alg_id} not found')
        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithms(self) -> list[str]:
        """
        Returns a list of supported values for the 'alg' parameter.
        """
        return list(self._valid_algs)

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        """
        For a given string name, return the matching Algorithm object.

        Example usage:

        >>> jws_obj.get_algorithm_by_name("RS256")
        """
        if alg_name not in self._algorithms:
            raise InvalidAlgorithmError('Algorithm not supported')
        return self._algorithms[alg_name]

    def get_unverified_header(self, jwt: str | bytes) -> dict[str, Any]:
        """Returns back the JWT header parameters as a dict()

        Note: The signature is not verified so the header parameters
        should not be fully trusted until signature verification is complete
        """
        if isinstance(jwt, str):
            jwt = jwt.encode('utf-8')

        try:
            signing_input, crypto_segment = jwt.rsplit(b'.', 1)
            header_segment, payload_segment = signing_input.split(b'.', 1)
        except ValueError:
            raise InvalidTokenError('Not enough segments')

        try:
            header_data = base64url_decode(header_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid header padding')

        try:
            header = json.loads(header_data.decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid header string: %s' % e)

        if not isinstance(header, dict):
            raise DecodeError('Invalid header string: must be a json object')

        return header

    def encode(self, payload: bytes, key: str | bytes | AllowedPrivateKeys | None=None, algorithm: str | None=None, headers: dict[str, Any] | None=None, json_encoder: type[json.JSONEncoder] | None=None, is_payload_detached: bool=False) -> str:
        """Creates a JWT using the given algorithm.

        Args:
            payload: The claims content to sign
            key: The key to use for signing the claim. Note: if the algorithm is None, the key is not used
            algorithm: The signing algorithm to use. If none is specified then 'none' is used.
            headers: A dict of additional headers to use.
            json_encoder: A custom JSON encoder to use for encoding the JWT.
            is_payload_detached: If True, the payload will be detached from the JWS.
        """
        # Check that we have a mapping
        if not isinstance(payload, bytes):
            raise TypeError('Payload must be bytes')

        if algorithm is None:
            algorithm = 'none'

        if algorithm not in self._valid_algs:
            raise InvalidAlgorithmError('Algorithm not supported')

        # Header
        header = {'typ': self.header_typ, 'alg': algorithm}
        if headers:
            header.update(headers)

        if is_payload_detached:
            header['b64'] = False

        json_header = json.dumps(header, separators=(',', ':'), cls=json_encoder).encode('utf-8')
        header_input = base64url_encode(json_header)

        if is_payload_detached:
            payload_input = b''
        else:
            payload_input = base64url_encode(payload)

        signing_input = b'.'.join([header_input, payload_input])

        try:
            alg_obj = self._algorithms[algorithm]
            if algorithm == 'none':
                key = None
            elif key is None:
                raise TypeError('Key is required when algorithm is not "none"')
            else:
                key = alg_obj.prepare_key(key)
            signature = alg_obj.sign(signing_input if not is_payload_detached else payload, key)
        except Exception as e:
            raise TypeError('Unable to encode JWT: %s' % e)

        encoded_signature = base64url_encode(signature)
        encoded_jwt = b'.'.join([signing_input, encoded_signature])

        return encoded_jwt.decode('utf-8')

    def decode_complete(self, jwt: str | bytes, key: str | bytes | AllowedPublicKeys | None=None, algorithms: list[str] | None=None, options: dict[str, Any] | None=None) -> dict[str, Any]:
        """Decodes a JWT and returns a dict of the token contents.

        Args:
            jwt: The JWT to decode.
            key: The key to use for verifying the claim. Note: if the algorithm is 'none', the key is not used.
            algorithms: A list of allowed algorithms. If None, default to the algorithms registered.
            options: A dict of options for decoding. If None, use default options.

        Returns:
            A dict including:
                - header: A dict of the JWT header
                - payload: The decoded payload
                - signature: The signature of the JWT
        """
        if isinstance(jwt, str):
            jwt = jwt.encode('utf-8')

        if not isinstance(jwt, bytes):
            raise DecodeError('Invalid token type')

        try:
            signing_input, crypto_segment = jwt.rsplit(b'.', 1)
            header_segment, payload_segment = signing_input.split(b'.', 1)
        except ValueError:
            raise InvalidTokenError('Not enough segments')

        try:
            header_data = base64url_decode(header_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid header padding')

        try:
            header = json.loads(header_data.decode('utf-8'))
        except ValueError as e:
            raise DecodeError('Invalid header string: %s' % e)

        if not isinstance(header, dict):
            raise DecodeError('Invalid header string: must be a json object')

        try:
            payload = base64url_decode(payload_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid payload padding')

        try:
            signature = base64url_decode(crypto_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid crypto padding')

        if algorithms is None:
            algorithms = list(self._valid_algs)

        if not algorithms and self.options['verify_signature']:
            raise DecodeError('No algorithms were specified')

        try:
            alg = header['alg']
        except KeyError:
            raise InvalidTokenError('Missing algorithm ("alg") in headers')

        if alg not in algorithms:
            raise InvalidAlgorithmError('The specified alg value is not allowed')

        try:
            alg_obj = self._algorithms[alg]
            key = alg_obj.prepare_key(key)
        except KeyError:
            raise InvalidAlgorithmError('Algorithm not supported')
        except Exception as e:
            raise InvalidTokenError('Unable to parse signature key: %s' % e)

        if not alg_obj.verify(signing_input, key, signature):
            raise InvalidSignatureError('Signature verification failed')

        return {
            'header': header,
            'payload': payload,
            'signature': signature
        }

    def decode(self, jwt: str | bytes, key: str | bytes | AllowedPublicKeys | None=None, algorithms: list[str] | None=None, options: dict[str, Any] | None=None) -> bytes:
        """Decodes a JWT and returns the payload.

        This is a shortcut to :meth:`decode_complete()` that returns just the payload.
        """
        decoded = self.decode_complete(jwt, key, algorithms, options)
        return decoded['payload']
_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header