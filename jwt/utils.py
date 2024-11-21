import base64
import binascii
import re
from typing import Union
try:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
except ModuleNotFoundError:
    pass

def force_bytes(value: Union[str, bytes]) -> bytes:
    if isinstance(value, str):
        return value.encode('utf-8')
    elif isinstance(value, bytes):
        return value
    else:
        raise TypeError('Expected string or bytes type')

def base64url_decode(input: Union[str, bytes]) -> bytes:
    if isinstance(input, str):
        input = input.encode('ascii')
    
    rem = len(input) % 4
    if rem > 0:
        input += b'=' * (4 - rem)
    
    return base64.urlsafe_b64decode(input)

def base64url_encode(input: bytes) -> bytes:
    return base64.urlsafe_b64encode(input).rstrip(b'=')

def to_base64url_uint(val: int) -> bytes:
    if val < 0:
        raise ValueError('Must be a positive integer')
    
    if val == 0:
        return b'AA'
    
    int_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64url_encode(int_bytes)

def from_base64url_uint(val: Union[str, bytes]) -> int:
    if isinstance(val, str):
        val = val.encode('ascii')
    
    data = base64url_decode(val)
    return int.from_bytes(data, byteorder='big')

def der_to_raw_signature(der_sig: bytes, curve: EllipticCurve) -> bytes:
    r, s = decode_dss_signature(der_sig)
    key_size = (curve.key_size + 7) // 8
    return r.to_bytes(key_size, byteorder='big') + s.to_bytes(key_size, byteorder='big')

def raw_to_der_signature(raw_sig: bytes, curve: EllipticCurve) -> bytes:
    key_size = (curve.key_size + 7) // 8
    if len(raw_sig) != 2 * key_size:
        raise ValueError('Invalid signature')
    
    r = int.from_bytes(raw_sig[:key_size], byteorder='big')
    s = int.from_bytes(raw_sig[key_size:], byteorder='big')
    return encode_dss_signature(r, s)

def is_pem_format(key: bytes) -> bool:
    return bool(_PEM_RE.search(key))

def is_ssh_key(key: bytes) -> bool:
    if key.startswith(b'ssh-') or key.startswith(b'ecdsa-'):
        return True
    
    match = _SSH_PUBKEY_RC.match(key)
    if not match:
        return False
    
    key_type = match.group(1)
    return (key_type in _SSH_KEY_FORMATS or 
            any(key_type.endswith(suffix) for suffix in [_CERT_SUFFIX]))

_PEMS = {b'CERTIFICATE', b'TRUSTED CERTIFICATE', b'PRIVATE KEY', b'PUBLIC KEY', b'ENCRYPTED PRIVATE KEY', b'OPENSSH PRIVATE KEY', b'DSA PRIVATE KEY', b'RSA PRIVATE KEY', b'RSA PUBLIC KEY', b'EC PRIVATE KEY', b'DH PARAMETERS', b'NEW CERTIFICATE REQUEST', b'CERTIFICATE REQUEST', b'SSH2 PUBLIC KEY', b'SSH2 ENCRYPTED PRIVATE KEY', b'X509 CRL'}
_PEM_RE = re.compile(b'----[- ]BEGIN (' + b'|'.join(_PEMS) + b')[- ]----\r?\n.+?\r?\n----[- ]END \\1[- ]----\r?\n?', re.DOTALL)
_CERT_SUFFIX = b'-cert-v01@openssh.com'
_SSH_PUBKEY_RC = re.compile(b'\\A(\\S+)[ \\t]+(\\S+)')
_SSH_KEY_FORMATS = [b'ssh-ed25519', b'ssh-rsa', b'ssh-dss', b'ecdsa-sha2-nistp256', b'ecdsa-sha2-nistp384', b'ecdsa-sha2-nistp521']