from __future__ import annotations
import hashlib
import hmac
import json
import sys
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn, Union, cast, overload
from .exceptions import InvalidKeyError
from .types import HashlibHash, JWKDict
from .utils import base64url_decode, base64url_encode, der_to_raw_signature, force_bytes, from_base64url_uint, is_pem_format, is_ssh_key, raw_to_der_signature, to_base64url_uint
if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256K1, SECP256R1, SECP384R1, SECP521R1, EllipticCurve, EllipticCurvePrivateKey, EllipticCurvePrivateNumbers, EllipticCurvePublicKey, EllipticCurvePublicNumbers
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPrivateNumbers, RSAPublicKey, RSAPublicNumbers, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp, rsa_recover_prime_factors
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key, load_pem_public_key, load_ssh_public_key
    has_crypto = True
except ModuleNotFoundError:
    has_crypto = False
if TYPE_CHECKING:
    AllowedRSAKeys = RSAPrivateKey | RSAPublicKey
    AllowedECKeys = EllipticCurvePrivateKey | EllipticCurvePublicKey
    AllowedOKPKeys = Ed25519PrivateKey | Ed25519PublicKey | Ed448PrivateKey | Ed448PublicKey
    AllowedKeys = AllowedRSAKeys | AllowedECKeys | AllowedOKPKeys
    AllowedPrivateKeys = RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey | Ed448PrivateKey
    AllowedPublicKeys = RSAPublicKey | EllipticCurvePublicKey | Ed25519PublicKey | Ed448PublicKey
requires_cryptography = {'RS256', 'RS384', 'RS512', 'ES256', 'ES256K', 'ES384', 'ES521', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA'}

def get_default_algorithms() -> dict[str, Algorithm]:
    """
    Returns the algorithms that are implemented by the library.
    """
    default_algorithms = {
        'none': NoneAlgorithm(),
        'HS256': HMACAlgorithm(HMACAlgorithm.SHA256),
        'HS384': HMACAlgorithm(HMACAlgorithm.SHA384),
        'HS512': HMACAlgorithm(HMACAlgorithm.SHA512),
    }

    if has_crypto:
        default_algorithms.update({
            'RS256': RSAAlgorithm(RSAAlgorithm.SHA256),
            'RS384': RSAAlgorithm(RSAAlgorithm.SHA384),
            'RS512': RSAAlgorithm(RSAAlgorithm.SHA512),
            'ES256': ECAlgorithm(ECAlgorithm.SHA256),
            'ES384': ECAlgorithm(ECAlgorithm.SHA384),
            'ES512': ECAlgorithm(ECAlgorithm.SHA512),
            'PS256': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
            'PS384': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
            'PS512': RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512),
            'EdDSA': OKPAlgorithm(),
        })

    return default_algorithms

class Algorithm(ABC):
    """
    The interface for an algorithm used to sign and verify tokens.
    """

    def compute_hash_digest(self, bytestr: bytes) -> bytes:
        """
        Compute a hash digest using the specified algorithm's hash algorithm.

        If there is no hash algorithm, raises a NotImplementedError.
        """
        if not hasattr(self, 'hash_alg'):
            raise NotImplementedError('Algorithm does not have a hash algorithm')
        
        if has_crypto and isinstance(self.hash_alg, type) and issubclass(self.hash_alg, hashes.HashAlgorithm):
            h = hashes.Hash(self.hash_alg(), backend=default_backend())
            h.update(bytestr)
            return h.finalize()
        else:
            h = self.hash_alg()
            h.update(bytestr)
            return h.digest()

    @abstractmethod
    def prepare_key(self, key: Any) -> Any:
        """
        Performs necessary validation and conversions on the key and returns
        the key value in the proper format for sign() and verify().
        """
        pass

    @abstractmethod
    def sign(self, msg: bytes, key: Any) -> bytes:
        """
        Returns a digital signature for the specified message
        using the specified key value.
        """
        pass

    @abstractmethod
    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        """
        Verifies that the specified digital signature is valid
        for the specified message and key values.
        """
        pass

    @staticmethod
    @abstractmethod
    def to_jwk(key_obj, as_dict: bool=False) -> Union[JWKDict, str]:
        """
        Serializes a given key into a JWK
        """
        pass

    @staticmethod
    @abstractmethod
    def from_jwk(jwk: str | JWKDict) -> Any:
        """
        Deserializes a given key from JWK back into a key object
        """
        pass

class NoneAlgorithm(Algorithm):
    """
    Placeholder for use when no signing or verification
    operations are required.
    """
    def prepare_key(self, key: Any) -> None:
        if key not in [None, '', 'none']:
            raise InvalidKeyError('When alg = "none", key must be empty or "none"')
        return None

    def sign(self, msg: bytes, key: Any) -> bytes:
        return b''

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        return sig == b''

    @staticmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> NoReturn:
        raise NotImplementedError('Algorithm "none" can\'t be exported as JWK')

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> NoReturn:
        raise NotImplementedError('Algorithm "none" can\'t be imported from JWK')

class HMACAlgorithm(Algorithm):
    """
    Performs signing and verification operations using HMAC
    and the specified hash function.
    """
    SHA256: ClassVar[HashlibHash] = hashlib.sha256
    SHA384: ClassVar[HashlibHash] = hashlib.sha384
    SHA512: ClassVar[HashlibHash] = hashlib.sha512

    def __init__(self, hash_alg: HashlibHash) -> None:
        self.hash_alg = hash_alg

    def prepare_key(self, key: Union[str, bytes]) -> bytes:
        key = force_bytes(key)
        return key

    def sign(self, msg: bytes, key: Union[str, bytes]) -> bytes:
        key = self.prepare_key(key)
        h = hmac.new(key, msg, self.hash_alg)
        return h.digest()

    def verify(self, msg: bytes, key: Union[str, bytes], sig: bytes) -> bool:
        key = self.prepare_key(key)
        h = hmac.new(key, msg, self.hash_alg)
        try:
            return hmac.compare_digest(sig, h.digest())
        except TypeError:
            return False

    @staticmethod
    def to_jwk(key_obj: Union[str, bytes], as_dict: bool = False) -> Union[str, JWKDict]:
        key_bytes = force_bytes(key_obj)
        jwk = {
            'kty': 'oct',
            'k': base64url_encode(key_bytes).decode('ascii')
        }
        if as_dict:
            return jwk
        return json.dumps(jwk)

    @staticmethod
    def from_jwk(jwk: Union[str, JWKDict]) -> bytes:
        if isinstance(jwk, str):
            jwk = json.loads(jwk)
        if not isinstance(jwk, dict):
            raise InvalidKeyError('Key must be a dict or a string')
        if jwk.get('kty') != 'oct':
            raise InvalidKeyError('Not an HMAC key')
        k = jwk.get('k')
        if not k:
            raise InvalidKeyError('k parameter is required')
        return base64url_decode(k)
if has_crypto:

    class RSAAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        RSASSA-PKCS-v1_5 and the specified hash function.
        """
        SHA256: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA256
        SHA384: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA384
        SHA512: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA512

        def __init__(self, hash_alg: type[hashes.HashAlgorithm]) -> None:
            self.hash_alg = hash_alg

        def prepare_key(self, key: Union[str, bytes, RSAPrivateKey, RSAPublicKey]) -> Union[RSAPrivateKey, RSAPublicKey]:
            if isinstance(key, (RSAPrivateKey, RSAPublicKey)):
                return key

            key = force_bytes(key)
            if is_pem_format(key):
                try:
                    return load_pem_private_key(key, password=None, backend=default_backend())
                except ValueError:
                    try:
                        return load_pem_public_key(key, backend=default_backend())
                    except ValueError:
                        raise InvalidKeyError('Invalid PEM format')
            elif is_ssh_key(key):
                try:
                    return load_ssh_public_key(key, backend=default_backend())
                except ValueError:
                    raise InvalidKeyError('Invalid SSH key format')
            else:
                raise InvalidKeyError('Invalid key format')

        def sign(self, msg: bytes, key: Union[str, bytes, RSAPrivateKey]) -> bytes:
            key_obj = self.prepare_key(key)
            if not isinstance(key_obj, RSAPrivateKey):
                raise TypeError('Key must be an RSAPrivateKey instance')

            padder = padding.PKCS1v15()
            return key_obj.sign(msg, padder, self.hash_alg())

        def verify(self, msg: bytes, key: Union[str, bytes, RSAPrivateKey, RSAPublicKey], sig: bytes) -> bool:
            key_obj = self.prepare_key(key)
            if not isinstance(key_obj, (RSAPrivateKey, RSAPublicKey)):
                raise TypeError('Key must be an RSA key instance')

            verifier = key_obj if isinstance(key_obj, RSAPublicKey) else key_obj.public_key()
            padder = padding.PKCS1v15()
            try:
                verifier.verify(sig, msg, padder, self.hash_alg())
                return True
            except InvalidSignature:
                return False

        @staticmethod
        def to_jwk(key_obj: Union[RSAPrivateKey, RSAPublicKey], as_dict: bool = False) -> Union[str, JWKDict]:
            if isinstance(key_obj, RSAPrivateKey):
                numbers = key_obj.private_numbers()
                jwk = {
                    'kty': 'RSA',
                    'n': to_base64url_uint(numbers.public_numbers.n).decode('ascii'),
                    'e': to_base64url_uint(numbers.public_numbers.e).decode('ascii'),
                    'd': to_base64url_uint(numbers.d).decode('ascii'),
                    'p': to_base64url_uint(numbers.p).decode('ascii'),
                    'q': to_base64url_uint(numbers.q).decode('ascii'),
                    'dp': to_base64url_uint(numbers.dmp1).decode('ascii'),
                    'dq': to_base64url_uint(numbers.dmq1).decode('ascii'),
                    'qi': to_base64url_uint(numbers.iqmp).decode('ascii')
                }
            else:
                numbers = key_obj.public_numbers()
                jwk = {
                    'kty': 'RSA',
                    'n': to_base64url_uint(numbers.n).decode('ascii'),
                    'e': to_base64url_uint(numbers.e).decode('ascii')
                }

            if as_dict:
                return jwk
            return json.dumps(jwk)

        @staticmethod
        def from_jwk(jwk: Union[str, JWKDict]) -> Union[RSAPrivateKey, RSAPublicKey]:
            if isinstance(jwk, str):
                jwk = json.loads(jwk)
            if not isinstance(jwk, dict):
                raise InvalidKeyError('Key must be a dict or a string')
            if jwk.get('kty') != 'RSA':
                raise InvalidKeyError('Not an RSA key')

            if 'd' in jwk and 'p' in jwk and 'q' in jwk:
                # Private key
                numbers = RSAPrivateNumbers(
                    d=from_base64url_uint(jwk['d']),
                    p=from_base64url_uint(jwk['p']),
                    q=from_base64url_uint(jwk['q']),
                    dmp1=from_base64url_uint(jwk['dp']),
                    dmq1=from_base64url_uint(jwk['dq']),
                    iqmp=from_base64url_uint(jwk['qi']),
                    public_numbers=RSAPublicNumbers(
                        e=from_base64url_uint(jwk['e']),
                        n=from_base64url_uint(jwk['n'])
                    )
                )
                return numbers.private_key(backend=default_backend())
            else:
                # Public key
                numbers = RSAPublicNumbers(
                    e=from_base64url_uint(jwk['e']),
                    n=from_base64url_uint(jwk['n'])
                )
                return numbers.public_key(backend=default_backend())

    class ECAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        ECDSA and the specified hash function
        """
        SHA256: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA256
        SHA384: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA384
        SHA512: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA512

        def __init__(self, hash_alg: type[hashes.HashAlgorithm]) -> None:
            self.hash_alg = hash_alg

        def prepare_key(self, key: Union[str, bytes, EllipticCurvePrivateKey, EllipticCurvePublicKey]) -> Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
            if isinstance(key, (EllipticCurvePrivateKey, EllipticCurvePublicKey)):
                return key

            key = force_bytes(key)
            if is_pem_format(key):
                try:
                    return load_pem_private_key(key, password=None, backend=default_backend())
                except ValueError:
                    try:
                        return load_pem_public_key(key, backend=default_backend())
                    except ValueError:
                        raise InvalidKeyError('Invalid PEM format')
            elif is_ssh_key(key):
                try:
                    return load_ssh_public_key(key, backend=default_backend())
                except ValueError:
                    raise InvalidKeyError('Invalid SSH key format')
            else:
                raise InvalidKeyError('Invalid key format')

        def sign(self, msg: bytes, key: Union[str, bytes, EllipticCurvePrivateKey]) -> bytes:
            key_obj = self.prepare_key(key)
            if not isinstance(key_obj, EllipticCurvePrivateKey):
                raise TypeError('Key must be an EllipticCurvePrivateKey instance')

            signature = key_obj.sign(msg, ECDSA(self.hash_alg()))
            return der_to_raw_signature(signature, key_obj.curve)

        def verify(self, msg: bytes, key: Union[str, bytes, EllipticCurvePrivateKey, EllipticCurvePublicKey], sig: bytes) -> bool:
            key_obj = self.prepare_key(key)
            if not isinstance(key_obj, (EllipticCurvePrivateKey, EllipticCurvePublicKey)):
                raise TypeError('Key must be an EC key instance')

            verifier = key_obj if isinstance(key_obj, EllipticCurvePublicKey) else key_obj.public_key()
            curve = verifier.curve

            try:
                der_sig = raw_to_der_signature(sig, curve)
                verifier.verify(der_sig, msg, ECDSA(self.hash_alg()))
                return True
            except (InvalidSignature, ValueError):
                return False

        @staticmethod
        def to_jwk(key_obj: Union[EllipticCurvePrivateKey, EllipticCurvePublicKey], as_dict: bool = False) -> Union[str, JWKDict]:
            if isinstance(key_obj, EllipticCurvePrivateKey):
                numbers = key_obj.private_numbers()
                jwk = {
                    'kty': 'EC',
                    'crv': {
                        SECP256K1: 'P-256K',
                        SECP256R1: 'P-256',
                        SECP384R1: 'P-384',
                        SECP521R1: 'P-521'
                    }[type(numbers.public_numbers.curve)],
                    'x': to_base64url_uint(numbers.public_numbers.x).decode('ascii'),
                    'y': to_base64url_uint(numbers.public_numbers.y).decode('ascii'),
                    'd': to_base64url_uint(numbers.private_value).decode('ascii')
                }
            else:
                numbers = key_obj.public_numbers()
                jwk = {
                    'kty': 'EC',
                    'crv': {
                        SECP256K1: 'P-256K',
                        SECP256R1: 'P-256',
                        SECP384R1: 'P-384',
                        SECP521R1: 'P-521'
                    }[type(numbers.curve)],
                    'x': to_base64url_uint(numbers.x).decode('ascii'),
                    'y': to_base64url_uint(numbers.y).decode('ascii')
                }

            if as_dict:
                return jwk
            return json.dumps(jwk)

        @staticmethod
        def from_jwk(jwk: Union[str, JWKDict]) -> Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
            if isinstance(jwk, str):
                jwk = json.loads(jwk)
            if not isinstance(jwk, dict):
                raise InvalidKeyError('Key must be a dict or a string')
            if jwk.get('kty') != 'EC':
                raise InvalidKeyError('Not an EC key')

            curve = {
                'P-256K': SECP256K1,
                'P-256': SECP256R1,
                'P-384': SECP384R1,
                'P-521': SECP521R1
            }[jwk['crv']]()

            if 'd' in jwk:
                # Private key
                numbers = EllipticCurvePrivateNumbers(
                    private_value=from_base64url_uint(jwk['d']),
                    public_numbers=EllipticCurvePublicNumbers(
                        x=from_base64url_uint(jwk['x']),
                        y=from_base64url_uint(jwk['y']),
                        curve=curve
                    )
                )
                return numbers.private_key(backend=default_backend())
            else:
                # Public key
                numbers = EllipticCurvePublicNumbers(
                    x=from_base64url_uint(jwk['x']),
                    y=from_base64url_uint(jwk['y']),
                    curve=curve
                )
                return numbers.public_key(backend=default_backend())

    class RSAPSSAlgorithm(RSAAlgorithm):
        """
        Performs a signature using RSASSA-PSS with MGF1
        """
        def sign(self, msg: bytes, key: Union[str, bytes, RSAPrivateKey]) -> bytes:
            key_obj = self.prepare_key(key)
            if not isinstance(key_obj, RSAPrivateKey):
                raise TypeError('Key must be an RSAPrivateKey instance')

            padder = padding.PSS(
                mgf=padding.MGF1(self.hash_alg()),
                salt_length=padding.PSS.MAX_LENGTH
            )
            return key_obj.sign(msg, padder, self.hash_alg())

        def verify(self, msg: bytes, key: Union[str, bytes, RSAPrivateKey, RSAPublicKey], sig: bytes) -> bool:
            key_obj = self.prepare_key(key)
            if not isinstance(key_obj, (RSAPrivateKey, RSAPublicKey)):
                raise TypeError('Key must be an RSA key instance')

            verifier = key_obj if isinstance(key_obj, RSAPublicKey) else key_obj.public_key()
            padder = padding.PSS(
                mgf=padding.MGF1(self.hash_alg()),
                salt_length=padding.PSS.MAX_LENGTH
            )
            try:
                verifier.verify(sig, msg, padder, self.hash_alg())
                return True
            except InvalidSignature:
                return False

    class OKPAlgorithm(Algorithm):
        """
        Performs signing and verification operations using EdDSA

        This class requires ``cryptography>=2.6`` to be installed.
        """

        def __init__(self, **kwargs: Any) -> None:
            pass

        def prepare_key(self, key: Union[str, bytes, AllowedOKPKeys]) -> AllowedOKPKeys:
            if isinstance(key, (Ed25519PrivateKey, Ed25519PublicKey, Ed448PrivateKey, Ed448PublicKey)):
                return key

            key = force_bytes(key)
            if is_pem_format(key):
                try:
                    return load_pem_private_key(key, password=None, backend=default_backend())
                except ValueError:
                    try:
                        return load_pem_public_key(key, backend=default_backend())
                    except ValueError:
                        raise InvalidKeyError('Invalid PEM format')
            elif is_ssh_key(key):
                try:
                    return load_ssh_public_key(key, backend=default_backend())
                except ValueError:
                    raise InvalidKeyError('Invalid SSH key format')
            else:
                raise InvalidKeyError('Invalid key format')

        def sign(self, msg: str | bytes, key: Ed25519PrivateKey | Ed448PrivateKey) -> bytes:
            """
            Sign a message ``msg`` using the EdDSA private key ``key``
            :param str|bytes msg: Message to sign
            :param Ed25519PrivateKey}Ed448PrivateKey key: A :class:`.Ed25519PrivateKey`
                or :class:`.Ed448PrivateKey` isinstance
            :return bytes signature: The signature, as bytes
            """
            msg_bytes = force_bytes(msg)
            key_obj = self.prepare_key(key)
            if not isinstance(key_obj, (Ed25519PrivateKey, Ed448PrivateKey)):
                raise TypeError('Key must be an Ed25519PrivateKey or Ed448PrivateKey instance')
            return key_obj.sign(msg_bytes)

        def verify(self, msg: str | bytes, key: AllowedOKPKeys, sig: str | bytes) -> bool:
            """
            Verify a given ``msg`` against a signature ``sig`` using the EdDSA key ``key``

            :param str|bytes sig: EdDSA signature to check ``msg`` against
            :param str|bytes msg: Message to sign
            :param Ed25519PrivateKey|Ed25519PublicKey|Ed448PrivateKey|Ed448PublicKey key:
                A private or public EdDSA key instance
            :return bool verified: True if signature is valid, False if not.
            """
            msg_bytes = force_bytes(msg)
            sig_bytes = force_bytes(sig)
            key_obj = self.prepare_key(key)

            if isinstance(key_obj, (Ed25519PrivateKey, Ed448PrivateKey)):
                verifier = key_obj.public_key()
            else:
                verifier = key_obj

            try:
                verifier.verify(sig_bytes, msg_bytes)
                return True
            except InvalidSignature:
                return False

        @staticmethod
        def to_jwk(key_obj: AllowedOKPKeys, as_dict: bool = False) -> Union[str, JWKDict]:
            if isinstance(key_obj, (Ed25519PrivateKey, Ed25519PublicKey)):
                crv = 'Ed25519'
            elif isinstance(key_obj, (Ed448PrivateKey, Ed448PublicKey)):
                crv = 'Ed448'
            else:
                raise TypeError('Key must be an EdDSA key instance')

            if isinstance(key_obj, (Ed25519PrivateKey, Ed448PrivateKey)):
                private_bytes = key_obj.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption()
                )
                public_bytes = key_obj.public_key().public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw
                )
                jwk = {
                    'kty': 'OKP',
                    'crv': crv,
                    'x': base64url_encode(public_bytes).decode('ascii'),
                    'd': base64url_encode(private_bytes).decode('ascii')
                }
            else:
                public_bytes = key_obj.public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw
                )
                jwk = {
                    'kty': 'OKP',
                    'crv': crv,
                    'x': base64url_encode(public_bytes).decode('ascii')
                }

            if as_dict:
                return jwk
            return json.dumps(jwk)

        @staticmethod
        def from_jwk(jwk: Union[str, JWKDict]) -> AllowedOKPKeys:
            if isinstance(jwk, str):
                jwk = json.loads(jwk)
            if not isinstance(jwk, dict):
                raise InvalidKeyError('Key must be a dict or a string')
            if jwk.get('kty') != 'OKP':
                raise InvalidKeyError('Not an OKP key')

            curve = jwk.get('crv')
            if curve not in ['Ed25519', 'Ed448']:
                raise InvalidKeyError('Invalid curve')

            x = base64url_decode(jwk['x'])
            if 'd' in jwk:
                # Private key
                d = base64url_decode(jwk['d'])
                if curve == 'Ed25519':
                    return Ed25519PrivateKey.from_private_bytes(d)
                else:
                    return Ed448PrivateKey.from_private_bytes(d)
            else:
                # Public key
                if curve == 'Ed25519':
                    return Ed25519PublicKey.from_public_bytes(x)
                else:
                    return Ed448PublicKey.from_public_bytes(x)