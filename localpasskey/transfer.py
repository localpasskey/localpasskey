"""Passkey files: LocalPasskey's encrypted backup, CXF and Bitwarden JSON.

This module runs unprivileged, in the CLI and the window. It turns files into
"normalized records" (the dicts the control socket's ``export`` returns and
``import`` takes, private keys as plaintext PKCS#8) and back. The daemon never
sees a file, a passphrase or a KDF; it validates the records again itself.

A LocalPasskey backup is a JSON envelope; the records are encrypted with
AES-256-GCM under a key derived from the passphrase with scrypt, and the
envelope header is the associated data, so its parameters cannot be swapped.
"""

from __future__ import annotations

import binascii
import json
import os
import re
import time
import unicodedata
import uuid
from datetime import datetime
from typing import Callable, List, Optional

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import cose
from .ctap2 import MAX_CREDENTIAL_ID_LENGTH, MAX_LABEL_LENGTH, MAX_USER_ID_LENGTH
from .store import b64decode, b64encode

BACKUP_FORMAT = "localpasskey-backup"
BACKUP_VERSION = 1
BACKUP_SUFFIX = ".lpkbackup"
MIN_PASSPHRASE_LENGTH = 8
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1  # about 0.3 s and 128 MiB
# A hostile file must not make us allocate or compute without bound.
MAX_SCRYPT_N, MAX_SCRYPT_R, MAX_SCRYPT_P = 2**20, 8, 4
MAX_RP_ID_LENGTH = 253
_SALT_SIZE = 16
_NONCE_SIZE = 12
_B64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")


class TransferError(Exception):
    """The file cannot be read or written; the message is for the user."""


class WrongPassphrase(TransferError):
    pass


class _Skip(Exception):
    """One passkey in a file cannot be imported; the message is the reason."""


class Records(list):
    """The normalized records of a file, plus the passkeys that were skipped
    while reading it (``{"credential": describe-like, "reason": str}``)."""

    def __init__(self, records=(), skipped=(), format=""):
        super().__init__(records)
        self.skipped = list(skipped)
        self.format = format


def passphrase_problem(passphrase: str, repeat: Optional[str] = None) -> Optional[str]:
    """The first reason ``passphrase`` is not acceptable, or None if it is.
    ``repeat`` is only compared once something is typed into it."""
    if not passphrase:
        return "Enter a passphrase"
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        return f"At least {MIN_PASSPHRASE_LENGTH} characters"
    if repeat and repeat != passphrase:
        return "The passphrases do not match"
    return None


def describe(record: dict) -> dict:
    """The control socket's ``describe`` view of a normalized record."""
    try:
        cred_id = b64decode(record.get("id") or "").hex()
    except (ValueError, binascii.Error):
        cred_id = ""
    return {
        "id": cred_id,
        "site": record.get("rp_id", ""),
        "site_name": record.get("rp_name", ""),
        "user_name": record.get("user_name", ""),
        "display_name": record.get("user_display_name", ""),
        "algorithm": cose.ALGORITHM_NAMES.get(record.get("alg"), str(record.get("alg"))),
        "discoverable": record.get("discoverable", True),
        "created": record.get("created"),
        "last_used": None,
        "deleted": None,
    }


def _binary(value, name) -> bytes:
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        raise _Skip(f"{name} is not base64url")
    try:
        return b64decode(value.rstrip("="))
    except (ValueError, binascii.Error):
        raise _Skip(f"{name} is not base64url") from None


def _label(value) -> str:
    # Names are cosmetic: shorten them rather than lose the passkey.
    return value[:MAX_LABEL_LENGTH] if isinstance(value, str) else ""


def _alg_of(key) -> int:
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
        return cose.ES256
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return cose.EDDSA
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
        return cose.RS256
    raise _Skip("unsupported key type")


def _record(*, cred_id: bytes, rp_id, user_id: bytes, private_key: bytes, rp_name="",
            user_name="", user_display_name="", discoverable=True, cred_protect=1,
            created=None, alg=None) -> dict:
    """A normalized record, checked like the daemon will so that one bad
    passkey is skipped instead of failing the whole import."""
    if not 1 <= len(cred_id) <= MAX_CREDENTIAL_ID_LENGTH:
        raise _Skip(f"the credential ID must be 1 to {MAX_CREDENTIAL_ID_LENGTH} bytes long")
    if len(user_id) > MAX_USER_ID_LENGTH:
        raise _Skip(f"the user ID is longer than {MAX_USER_ID_LENGTH} bytes")
    if (not isinstance(rp_id, str) or not rp_id or len(rp_id) > MAX_RP_ID_LENGTH
            or any(ch.isspace() or not ch.isprintable() for ch in rp_id)):
        raise _Skip("invalid site")
    try:
        key = cose.private_key_from_bytes(private_key)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise _Skip("the private key cannot be read") from None
    key_alg = _alg_of(key)
    if alg is not None and alg != key_alg:
        raise _Skip("the private key does not match its algorithm")
    if isinstance(cred_protect, bool) or cred_protect not in (1, 2, 3):
        cred_protect = 1
    if isinstance(created, bool) or not isinstance(created, (int, float)) or not created > 0:
        created = 0.0  # the daemon uses the import time
    return {
        "id": b64encode(cred_id),
        "rp_id": rp_id,
        "rp_name": _label(rp_name),
        "user_id": b64encode(user_id),
        "user_name": _label(user_name),
        "user_display_name": _label(user_display_name),
        "alg": key_alg,
        "private_key": b64encode(cose.private_key_to_bytes(key)),
        "discoverable": bool(discoverable),
        "cred_protect": cred_protect,
        "created": float(created),
    }


def _collect(entries, convert, format, peek=None) -> Records:
    """Convert every entry, keeping the ones that fail as skipped."""
    result = Records(format=format)
    for entry in entries:
        try:
            result.append(convert(entry))
        except _Skip as e:
            result.skipped.append({"credential": describe((peek or _peek)(entry)), "reason": str(e)})
    return result


def _peek(entry) -> dict:
    """What can be shown of an entry that failed to convert."""
    return entry if isinstance(entry, dict) else {}


# --- LocalPasskey backup ---------------------------------------------------


def _passphrase_key(passphrase: str, kdf: dict) -> bytes:
    # NFC so the same passphrase typed with another input method still works.
    secret = unicodedata.normalize("NFC", passphrase).encode("utf-8")
    return Scrypt(salt=b64decode(kdf["salt"]), length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(secret)


def _header_aad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def export_backup(records: List[dict], passphrase: str) -> bytes:
    """An encrypted LocalPasskey backup of ``records``."""
    problem = passphrase_problem(passphrase)
    if problem:
        raise TransferError(f"Unsuitable passphrase: {problem}")
    header = {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                "salt": b64encode(os.urandom(_SALT_SIZE))},
        "cipher": "AES-256-GCM",
    }
    nonce = os.urandom(_NONCE_SIZE)
    plaintext = json.dumps({"credentials": list(records)}).encode()
    ciphertext = AESGCM(_passphrase_key(passphrase, header["kdf"])).encrypt(nonce, plaintext, _header_aad(header))
    doc = dict(header, nonce=b64encode(nonce), ciphertext=b64encode(ciphertext))
    return json.dumps(doc, indent=1).encode() + b"\n"


def _int(value, low, high) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _check_header(doc: dict) -> dict:
    if doc.get("version") != BACKUP_VERSION:
        raise TransferError("This backup was made by a newer LocalPasskey; update LocalPasskey to read it")
    kdf = doc.get("kdf")
    if doc.get("cipher") != "AES-256-GCM" or not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
        raise TransferError("This backup uses an unsupported cipher or key derivation")
    n, r, p = kdf.get("n"), kdf.get("r"), kdf.get("p")
    if not (_int(n, 2, MAX_SCRYPT_N) and n & (n - 1) == 0 and _int(r, 1, MAX_SCRYPT_R)
            and _int(p, 1, MAX_SCRYPT_P)):
        raise TransferError("This backup has unsafe key derivation parameters")
    salt = kdf.get("salt")
    if not isinstance(salt, str) or not _B64URL.fullmatch(salt) or len(b64decode(salt.rstrip("="))) < _SALT_SIZE:
        raise TransferError("This backup is damaged (bad salt)")
    return {key: doc[key] for key in ("format", "version", "kdf", "cipher")}


def _load_backup(doc: dict, passphrase_callback: Callable[[], str]) -> Records:
    header = _check_header(doc)
    try:
        nonce = _binary(doc.get("nonce"), "nonce")
        ciphertext = _binary(doc.get("ciphertext"), "ciphertext")
    except _Skip:
        raise TransferError("This backup is damaged") from None
    if len(nonce) != _NONCE_SIZE:
        raise TransferError("This backup is damaged (bad nonce)")
    passphrase = passphrase_callback()
    if not passphrase:
        raise TransferError("No passphrase given")
    try:
        plaintext = AESGCM(_passphrase_key(passphrase, header["kdf"])).decrypt(nonce, ciphertext, _header_aad(header))
    except InvalidTag:
        raise WrongPassphrase("Wrong passphrase, or the file was modified") from None
    try:
        creds = json.loads(plaintext)["credentials"]
        if not isinstance(creds, list):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        raise TransferError("This backup is damaged (bad contents)") from None
    return _collect(creds, _from_backup, "localpasskey")


def _from_backup(data) -> dict:
    if not isinstance(data, dict):
        raise _Skip("not a passkey")
    alg = data.get("alg")
    if alg not in cose.SUPPORTED_ALGORITHMS:
        raise _Skip(f"unsupported algorithm {alg}")
    return _record(
        cred_id=_binary(data.get("id"), "the credential ID"), rp_id=data.get("rp_id"),
        user_id=_binary(data.get("user_id"), "the user ID"),
        private_key=_binary(data.get("private_key"), "the private key"), alg=alg,
        rp_name=data.get("rp_name"), user_name=data.get("user_name"),
        user_display_name=data.get("user_display_name"),
        discoverable=data.get("discoverable", True) is not False,
        cred_protect=data.get("cred_protect"), created=data.get("created"),
    )


# --- FIDO Credential Exchange Format (CXF 1.0) -----------------------------
# Unencrypted by design (CXF leaves confidentiality to its transport, CXP).
# CXF has no algorithm, discoverable or credProtect field: the algorithm comes
# from the key, and imported passkeys are discoverable with credProtect 1.

CXF_EXPORTER_RP_ID = "localpasskey.invalid"


def export_cxf(records: List[dict], now: Optional[float] = None) -> bytes:
    """An unencrypted CXF document holding ``records``."""
    timestamp = int(time.time() if now is None else now)
    items = []
    for rec in records:
        created = int(rec.get("created") or timestamp)
        items.append({
            "id": b64encode(os.urandom(16)),
            "creationAt": created,
            "modifiedAt": created,
            "title": rec.get("rp_name") or rec["rp_id"],
            "credentials": [{
                "type": "passkey",
                "credentialId": rec["id"],
                "rpId": rec["rp_id"],
                "username": rec.get("user_name", ""),
                "userDisplayName": rec.get("user_display_name", ""),
                "userHandle": rec["user_id"],
                "key": rec["private_key"],
            }],
        })
    doc = {
        "version": {"major": 1, "minor": 0},
        "exporterRpId": CXF_EXPORTER_RP_ID,
        "exporterDisplayName": "LocalPasskey",
        "timestamp": timestamp,
        "accounts": [{
            "id": b64encode(os.urandom(16)), "username": "", "email": "",
            "collections": [], "items": items,
        }],
    }
    return json.dumps(doc, indent=1).encode() + b"\n"


def _cxf_passkeys(doc: dict):
    version = doc.get("version")
    if not isinstance(version, dict) or version.get("major") != 1:
        raise TransferError("This CXF file has an unsupported version")
    for account in doc.get("accounts") or []:
        items = account.get("items") if isinstance(account, dict) else None
        for item in items if isinstance(items, list) else []:
            creds = item.get("credentials") if isinstance(item, dict) else None
            for cred in creds if isinstance(creds, list) else []:
                if isinstance(cred, dict) and cred.get("type") == "passkey":
                    yield item, cred


def _from_cxf(entry) -> dict:
    item, cred = entry
    return _record(
        cred_id=_binary(cred.get("credentialId"), "the credential ID"), rp_id=cred.get("rpId"),
        user_id=_binary(cred.get("userHandle"), "the user ID"),
        private_key=_binary(cred.get("key"), "the private key"),
        rp_name=item.get("title"), user_name=cred.get("username"),
        user_display_name=cred.get("userDisplayName"), created=item.get("creationAt"),
    )


def _peek_cxf(entry) -> dict:
    item, cred = entry
    return {"rp_id": cred.get("rpId"), "rp_name": item.get("title"), "user_name": cred.get("username")}


# --- Bitwarden unencrypted JSON export --------------------------------------


def _bitwarden_passkeys(doc: dict):
    if doc.get("encrypted") is True:
        if doc.get("passwordProtected") is True:
            raise TransferError(
                "This Bitwarden export is password protected. Export the vault again "
                "from Bitwarden as unencrypted JSON (.json) and import that file"
            )
        raise TransferError(
            "This Bitwarden export is encrypted with your Bitwarden account. Export the "
            "vault again from Bitwarden as unencrypted JSON (.json) and import that file"
        )
    items = doc.get("items")
    if not isinstance(items, list):
        raise TransferError("This Bitwarden export has no items")
    for item in items:
        login = item.get("login") if isinstance(item, dict) else None
        creds = login.get("fido2Credentials") if isinstance(login, dict) else None
        for cred in creds if isinstance(creds, list) else []:
            if isinstance(cred, dict):
                yield item, cred


def _bitwarden_id(text) -> bytes:
    if isinstance(text, str) and text.startswith("b64."):
        return _binary(text[4:], "the credential ID")
    try:
        return uuid.UUID(text).bytes
    except (TypeError, ValueError, AttributeError):
        raise _Skip("the credential ID is neither a UUID nor b64.-prefixed") from None


def _iso_time(text) -> Optional[float]:
    try:
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _from_bitwarden(entry) -> dict:
    item, cred = entry
    login = item["login"]
    handle = cred.get("userHandle")
    return _record(
        cred_id=_bitwarden_id(cred.get("credentialId")), rp_id=cred.get("rpId"),
        user_id=b"" if handle in (None, "") else _binary(handle, "the user ID"),
        private_key=_binary(cred.get("keyValue"), "the private key"),
        rp_name=cred.get("rpName") or item.get("name"),
        user_name=cred.get("userName") or login.get("username"),
        user_display_name=cred.get("userDisplayName"),
        discoverable=cred.get("discoverable") in ("true", True),
        created=_iso_time(cred.get("creationDate")),
    )


def _peek_bitwarden(entry) -> dict:
    item, cred = entry
    return {"rp_id": cred.get("rpId"), "rp_name": cred.get("rpName") or item.get("name"),
            "user_name": cred.get("userName")}


# --- Reading any supported file --------------------------------------------

_NOT_SUPPORTED = "This is not a LocalPasskey backup, a CXF file or a Bitwarden JSON export"


def _parse(data: bytes) -> dict:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        doc = None
    if not isinstance(doc, dict):
        raise TransferError(_NOT_SUPPORTED)
    return doc


def _format_of(doc: dict) -> str:
    if doc.get("format") == BACKUP_FORMAT:
        return "localpasskey"
    if "exporterRpId" in doc and "accounts" in doc:
        return "cxf"
    if "items" in doc or doc.get("encrypted") is True:
        return "bitwarden"
    raise TransferError(_NOT_SUPPORTED)


def detect_format(data: bytes) -> str:
    """"localpasskey" (encrypted, needs a passphrase), "cxf" or "bitwarden"."""
    return _format_of(_parse(data))


def load(data: bytes, passphrase_callback: Callable[[], str]) -> Records:
    """The passkeys in a file of any supported format. ``passphrase_callback``
    is only called for encrypted backups."""
    doc = _parse(data)
    kind = _format_of(doc)
    if kind == "localpasskey":
        return _load_backup(doc, passphrase_callback)
    if kind == "cxf":
        return _collect(list(_cxf_passkeys(doc)), _from_cxf, kind, _peek_cxf)
    return _collect(list(_bitwarden_passkeys(doc)), _from_bitwarden, kind, _peek_bitwarden)
