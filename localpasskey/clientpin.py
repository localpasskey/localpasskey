"""Client PIN: the CTAP 2.1 PIN/UV auth protocols and the PIN state behind them.

Browsers set a PIN here (``authenticatorClientPIN``) before they are allowed to
list or delete the passkeys stored on this computer, and hand back the
pinUvAuthToken it produces with every such request. The PIN itself is never
stored: only its 16-byte hash, sealed by the credential store. Both the
authenticator and the control socket use the PinManager the daemon creates, so
a PIN set from a browser and a PIN set from ``localpasskey pin set`` are the
same PIN.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import cose
from .store import CredentialStore, PinState

PIN_INVALID = 0x31
PIN_BLOCKED = 0x32
PIN_AUTH_INVALID = 0x33
PIN_AUTH_BLOCKED = 0x34
PIN_NOT_SET = 0x35
PUAT_REQUIRED = 0x36
PIN_POLICY_VIOLATION = 0x37

# The daemon's in-memory count of consecutive bad PINs; a restart is the
# "power cycle" that CTAP lets an authenticator require to clear the block.
AUTH_BLOCK_AFTER = 3
MAX_PIN_RETRIES = 8
MIN_PIN_LENGTH = 4  # code points
MAX_PIN_BYTES = 63
TOKEN_LIFETIME = 600.0  # shortcut: CTAP 2.1's 30 s initial-use window is not enforced
SUPPORTED_PROTOCOLS = (2, 1)

_P256_KEY_SIZE = 32


class PinError(Exception):
    """A PIN error; ``code`` is the CTAP status byte the browser receives."""

    def __init__(self, code, reason=""):
        super().__init__(f"0x{code:02x} {reason}".strip())
        self.code = code


def pin_hash(pin: bytes) -> bytes:
    """LEFT(SHA-256(PIN), 16): what is stored and what clients send us."""
    return hashlib.sha256(pin).digest()[:16]


def pin_problem(pin: str, repeat: Optional[str] = None) -> Optional[str]:
    """The first reason ``pin`` is not acceptable, or None if it is.

    The daemon and the window both use this, so they cannot disagree. ``repeat``
    is the confirmation field, only compared once something is typed into it.
    """
    if not pin:
        return "Enter a PIN"
    if len(pin) < MIN_PIN_LENGTH:
        return f"At least {MIN_PIN_LENGTH} characters"
    try:
        size = len(pin.encode("utf-8"))
    except UnicodeEncodeError:  # a lone surrogate, which the daemon could never encode
        return "Use valid characters"
    if size > MAX_PIN_BYTES:
        return f"At most {MAX_PIN_BYTES} bytes"
    if "\0" in pin:
        return "No NUL characters"
    if repeat and repeat != pin:
        return "The PINs do not match"
    return None


def _hkdf(secret: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=info
    ).derive(secret)


def _cose_key(key) -> dict:
    # alg -25 per the spec, "although this is NOT the algorithm actually used"
    return {**cose.public_key(key, cose.ES256), 3: -25}


def _peer_key(peer_cose_key) -> ec.EllipticCurvePublicKey:
    """Parse a peer COSE_Key into a P-256 public key (ValueError if it is not one)."""
    if not isinstance(peer_cose_key, dict):
        raise ValueError("keyAgreement is not a COSE_Key map")
    try:
        x, y = peer_cose_key[-2], peer_cose_key[-3]
    except KeyError:
        raise ValueError("keyAgreement has no EC2 coordinates") from None
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        raise ValueError("keyAgreement coordinates are not byte strings")
    if len(x) != _P256_KEY_SIZE or len(y) != _P256_KEY_SIZE:
        raise ValueError("keyAgreement is not a P-256 point")
    point = b"\x04" + x + y
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except ValueError:
        raise ValueError("keyAgreement is not a point on P-256") from None


def _aes_cbc(key: bytes, iv: bytes) -> Cipher:
    return Cipher(algorithms.AES(key), modes.CBC(iv))


def _shared_secret(key, protocol: int, peer_cose_key) -> bytes:
    """The secret both sides derive from ``key`` and the client's key.

    Protocol 1 is plain SHA-256 of the ECDH x-coordinate, used as both the AES
    and the HMAC key; protocol 2 derives each key with its own HKDF.
    """
    peer = _peer_key(peer_cose_key)
    z = key.exchange(ec.ECDH(), peer)
    if protocol == 1:
        return hashlib.sha256(z).digest()
    if protocol == 2:
        return _hkdf(z, b"CTAP2 HMAC key") + _hkdf(z, b"CTAP2 AES key")
    raise ValueError(f"unsupported PIN/UV auth protocol {protocol}")


def encrypt(protocol: int, key: bytes, plaintext: bytes) -> bytes:
    if protocol == 1:
        return _aes_cbc(key, bytes(16)).encryptor().update(plaintext)
    if protocol == 2:
        iv = secrets.token_bytes(16)
        return iv + _aes_cbc(key[32:], iv).encryptor().update(plaintext)
    raise ValueError(f"unsupported PIN/UV auth protocol {protocol}")


def decrypt(protocol: int, key: bytes, ciphertext: bytes) -> bytes:
    if protocol == 1:
        if len(ciphertext) % 16:
            raise ValueError("ciphertext is not a whole number of AES blocks")
        return _aes_cbc(key, bytes(16)).decryptor().update(ciphertext)
    if protocol == 2:
        if len(ciphertext) < 32 or len(ciphertext) % 16:
            raise ValueError("ciphertext is not an IV plus whole AES blocks")
        return _aes_cbc(key[32:], ciphertext[:16]).decryptor().update(ciphertext[16:])
    raise ValueError(f"unsupported PIN/UV auth protocol {protocol}")


def authenticate(protocol: int, key: bytes, message: bytes) -> bytes:
    if protocol == 1:
        return hmac.digest(key, message, "sha256")[:16]
    if protocol == 2:
        return hmac.digest(key[:32], message, "sha256")
    raise ValueError(f"unsupported PIN/UV auth protocol {protocol}")


def verify(protocol: int, key: bytes, message: bytes, signature: bytes) -> bool:
    return hmac.compare_digest(authenticate(protocol, key, message), signature)


class PinManager:
    """One user's PIN state and the key agreement both protocols share."""

    def __init__(self, store: CredentialStore):
        self.store = store
        self._lock = threading.Lock()
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._mismatches = {}  # uid -> consecutive mismatches since daemon start
        self._tokens = []  # (requester, token, expiry); tokens are revoked per requester.uid

    def regenerate(self) -> None:
        """Replace the key agreement key, orphaning the secret clients hold."""
        with self._lock:
            self._key = ec.generate_private_key(ec.SECP256R1())

    def key_agreement(self) -> dict:
        with self._lock:
            return _cose_key(self._key)

    def shared_secret(self, protocol: int, peer_cose_key) -> bytes:
        with self._lock:
            return _shared_secret(self._key, protocol, peer_cose_key)

    def is_set(self, uid: int, username: str) -> bool:
        return self.state(uid, username) is not None

    def retries(self, uid: int, username: str) -> int:
        state = self.state(uid, username)
        return MAX_PIN_RETRIES if state is None else state.retries

    def state(self, uid: int, username: str) -> Optional[PinState]:
        with self._lock:
            return self.store.pin(uid, username)

    def verify(self, uid: int, username: str, digest: bytes) -> None:
        """Check a PIN hash, counting the attempt whether or not it matches."""
        with self._lock:
            state = self.store.pin(uid, username)
            if state is None:
                raise PinError(PIN_NOT_SET, "no PIN is set")
            if state.retries == 0:
                raise PinError(PIN_BLOCKED, "no PIN attempts left")
            if self._mismatches.get(uid, 0) >= AUTH_BLOCK_AFTER:
                raise PinError(PIN_AUTH_BLOCKED, "too many wrong PINs; restart the daemon")
            # Spent before the comparison: a PIN attempt is used even if the
            # process dies in between, which is what the retry count is for.
            state.retries -= 1
            self.store.set_pin(uid, username, state)
            if hmac.compare_digest(state.hash, digest):
                state.retries = MAX_PIN_RETRIES
                self.store.set_pin(uid, username, state)
                self._mismatches[uid] = 0
                return
            mismatches = self._mismatches[uid] = self._mismatches.get(uid, 0) + 1
            if state.retries == 0:
                raise PinError(PIN_BLOCKED, "no PIN attempts left")
            if mismatches >= AUTH_BLOCK_AFTER:
                raise PinError(PIN_AUTH_BLOCKED, "too many wrong PINs; restart the daemon")
            raise PinError(PIN_INVALID, f"wrong PIN, {state.retries} attempt(s) left")

    def set(self, uid: int, username: str, pin: bytes) -> None:
        """Set a UTF-8 PIN, replacing any existing one."""
        try:
            text = pin.decode("utf-8")
        except UnicodeDecodeError:
            raise PinError(PIN_POLICY_VIOLATION, "the PIN must be valid UTF-8") from None
        problem = pin_problem(text)
        if problem is not None:
            raise PinError(PIN_POLICY_VIOLATION, problem)
        with self._lock:
            self.store.set_pin(uid, username, PinState(hash=pin_hash(pin), retries=MAX_PIN_RETRIES))
            self._mismatches[uid] = 0
            self._revoke(uid)

    def remove(self, uid: int, username: str) -> None:
        """Forget the PIN, so the next request sees PIN_NOT_SET."""
        with self._lock:
            self.store.set_pin(uid, username, None)
            self._mismatches[uid] = 0
            self._revoke(uid)

    def _revoke(self, uid: int) -> None:
        self._tokens = [entry for entry in self._tokens if entry[0].uid != uid]

    def issue_token(self, requester) -> bytes:
        """Mint a token for ``requester``, replacing that requester's old one."""
        token = secrets.token_bytes(32)
        with self._lock:
            self._expire()
            self._tokens = [entry for entry in self._tokens if entry[0] != requester]
            self._tokens.append((requester, token, time.monotonic() + TOKEN_LIFETIME))
        return token

    def token_for(self, requester) -> Optional[bytes]:
        """The token of this exact requester, if it is still valid."""
        with self._lock:
            self._expire()
            for candidate, token, _ in self._tokens:
                if candidate == requester:
                    return token
            return None

    def _expire(self) -> None:
        now = time.monotonic()
        self._tokens = [entry for entry in self._tokens if entry[2] > now]
