"""Credential key pairs and their COSE (RFC 9053) representation."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ES256 = -7
EDDSA = -8
RS256 = -257

SUPPORTED_ALGORITHMS = (ES256, EDDSA, RS256)
ALGORITHM_NAMES = {ES256: "ES256", EDDSA: "EdDSA", RS256: "RS256"}


def generate_private_key(alg):
    if alg == ES256:
        return ec.generate_private_key(ec.SECP256R1())
    if alg == EDDSA:
        return ed25519.Ed25519PrivateKey.generate()
    if alg == RS256:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raise ValueError(f"unsupported COSE algorithm {alg}")


def private_key_to_bytes(key):
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def private_key_from_bytes(data):
    return serialization.load_der_private_key(data, password=None)


def _int_bytes(value):
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def public_key(key, alg):
    """Return the COSE_Key map for the public half of ``key``."""
    pub = key.public_key()
    if alg == ES256:
        numbers = pub.public_numbers()
        return {
            1: 2,  # kty: EC2
            3: ES256,
            -1: 1,  # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    if alg == EDDSA:
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {1: 1, 3: EDDSA, -1: 6, -2: raw}  # kty: OKP, crv: Ed25519
    if alg == RS256:
        numbers = pub.public_numbers()
        return {1: 3, 3: RS256, -1: _int_bytes(numbers.n), -2: _int_bytes(numbers.e)}
    raise ValueError(f"unsupported COSE algorithm {alg}")


def sign(key, alg, message):
    if alg == ES256:
        return key.sign(message, ec.ECDSA(hashes.SHA256()))
    if alg == EDDSA:
        return key.sign(message)
    if alg == RS256:
        return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    raise ValueError(f"unsupported COSE algorithm {alg}")
