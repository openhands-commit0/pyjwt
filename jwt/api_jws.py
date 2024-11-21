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
        if alg_id in self._algorithms:
            raise ValueError(f'Algorithm {alg_id} is already registered')
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
        if not isinstance(jwt, (str, bytes)):
            raise InvalidTokenError('Invalid token type')

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

    def encode(self, payload: bytes, key: str | bytes | AllowedPrivateKeys | None=None, algorithm: str | None=None, headers: dict[str, Any] | None=None, json_encoder: type[json.JSONEncoder] | None=None, is_payload_detached: bool=False, sort_headers: bool=False) -> str:
        """Creates a JWT using the given algorithm.

        Args:
            payload: The claims content to sign
            key: The key to use for signing the claim. Note: if the algorithm is None, the key is not used
            algorithm: The signing algorithm to use. If none is specified then 'none' is used.
            headers: A dict of additional headers to use.
            json_encoder: A custom JSON encoder to use for encoding the JWT.
            is_payload_detached: If True, the payload will be detached from the JWS.
            sort_headers: If True, sort the header keys.
        """
        # Check that we have a mapping
        if not isinstance(payload, bytes):
            raise TypeError('Payload must be bytes')

        if algorithm is None:
            algorithm = 'none'

        if algorithm not in self._valid_algs:
            raise InvalidAlgorithmError('Algorithm not supported')

        if algorithm != 'none' and key is None:
            raise InvalidKeyError('Key is required when algorithm is not "none"')

        # Header
        header = {'alg': algorithm}
        if self.header_typ is not None and 'typ' not in (headers or {}):
            header['typ'] = self.header_typ

        if headers:
            header.update(headers)
            if header.get('typ') == '':
                del header['typ']
            elif header.get('typ') is None:
                del header['typ']

        if is_payload_detached:
            header['b64'] = False
            if not payload:
                raise InvalidTokenError('Payload cannot be empty when using detached content')

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

    def decode_complete(self, jwt: str | bytes, key: str | bytes | AllowedPublicKeys | None=None, algorithms: list[str] | None=None, options: dict[str, Any] | None=None, detached_payload: bytes | None=None, **kwargs: Any) -> dict[str, Any]:
        """Decodes a JWT and returns a dict of the token contents.

        Args:
            jwt: The JWT to decode.
            key: The key to use for verifying the claim. Note: if the algorithm is 'none', the key is not used.
            algorithms: A list of allowed algorithms. If None, default to the algorithms registered.
            options: A dict of options for decoding. If None, use default options.
            detached_payload: The detached payload to use for verification.
            **kwargs: Additional options for decoding.

        Returns:
            A dict including:
                - header: A dict of the JWT header
                - payload: The decoded payload
                - signature: The signature of the JWT
        """
        if 'verify' in kwargs:
            warnings.warn(
                'The verify parameter is deprecated. '
                'Please use verify_signature in options instead.',
                category=DeprecationWarning,
                stacklevel=2
            )
            options = options or {}
            options['verify_signature'] = kwargs.pop('verify')

        if 'verify_exp' in kwargs:
            warnings.warn(
                'The verify_exp parameter is deprecated. '
                'Please use verify_exp in options instead.',
                category=DeprecationWarning,
                stacklevel=2
            )
            options = options or {}
            options['verify_exp'] = kwargs.pop('verify_exp')

        if 'verify_iat' in kwargs:
            warnings.warn(
                'The verify_iat parameter is deprecated. '
                'Please use verify_iat in options instead.',
                category=DeprecationWarning,
                stacklevel=2
            )
            options = options or {}
            options['verify_iat'] = kwargs.pop('verify_iat')

        if 'verify_nbf' in kwargs:
            warnings.warn(
                'The verify_nbf parameter is deprecated. '
                'Please use verify_nbf in options instead.',
                category=DeprecationWarning,
                stacklevel=2
            )
            options = options or {}
            options['verify_nbf'] = kwargs.pop('verify_nbf')

        if 'verify_aud' in kwargs:
            warnings.warn(
                'The verify_aud parameter is deprecated. '
                'Please use verify_aud in options instead.',
                category=DeprecationWarning,
                stacklevel=2
            )
            options = options or {}
            options['verify_aud'] = kwargs.pop('verify_aud')

        if 'verify_iss' in kwargs:
            warnings.warn(
                'The verify_iss parameter is deprecated. '
                'Please use verify_iss in options instead.',
                category=DeprecationWarning,
                stacklevel=2
            )
            options = options or {}
            options['verify_iss'] = kwargs.pop('verify_iss')

        for kwarg in kwargs:
            warnings.warn(
                f'The "{kwarg}" argument is not supported and will be ignored.',
                category=RemovedInPyjwt3Warning,
                stacklevel=2
            )

        merged_options = {**self.options}
        if options:
            if not isinstance(options, dict):
                raise TypeError('options must be a dict')
            merged_options.update(options)

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

        if header.get('b64', True):
            try:
                payload = base64url_decode(payload_segment)
            except (TypeError, binascii.Error):
                raise DecodeError('Invalid payload padding')
        else:
            if detached_payload is None:
                raise DecodeError('It is required that you pass in a value for the "detached_payload" argument to decode a message using unencoded payload.')
            payload = detached_payload

        try:
            signature = base64url_decode(crypto_segment)
        except (TypeError, binascii.Error):
            raise DecodeError('Invalid crypto padding')

        if algorithms is None:
            algorithms = list(self._valid_algs)

        if not algorithms and merged_options['verify_signature']:
            raise DecodeError('No algorithms were specified')

        try:
            alg = header['alg']
        except KeyError:
            raise InvalidTokenError('Missing algorithm ("alg") in headers')

        if alg not in algorithms:
            raise InvalidAlgorithmError('The specified alg value is not allowed')

        if alg == 'none':
            if merged_options['verify_signature']:
                raise DecodeError('Algorithm "none" not allowed')
            if key not in [None, '', 'none']:
                raise InvalidKeyError('When alg = "none", key must be empty or "none"')
            if signature != b'':
                raise InvalidSignatureError('Signature verification failed')
            return {
                'header': header,
                'payload': payload,
                'signature': signature
            }

        if merged_options['verify_signature']:
            try:
                alg_obj = self._algorithms[alg]
                if key is None:
                    raise InvalidKeyError('Key is required when algorithm is not "none"')
                key = alg_obj.prepare_key(key)
            except KeyError:
                raise InvalidAlgorithmError('Algorithm not supported')
            except InvalidKeyError:
                raise
            except Exception as e:
                raise InvalidTokenError('Unable to parse signature key: %s' % e)

            if not alg_obj.verify(signing_input if header.get('b64', True) else payload, key, signature):
                raise InvalidSignatureError('Signature verification failed')

        return {
            'header': header,
            'payload': payload,
            'signature': signature
        }

    def decode(self, jwt: str | bytes, key: str | bytes | AllowedPublicKeys | None=None, algorithms: list[str] | None=None, options: dict[str, Any] | None=None, detached_payload: bytes | None=None, **kwargs: Any) -> bytes:
        """Decodes a JWT and returns the payload.

        This is a shortcut to :meth:`decode_complete()` that returns just the payload.
        """
        decoded = self.decode_complete(jwt, key, algorithms, options, detached_payload, **kwargs)
        return decoded['payload']
_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header