"""Per-user passkey storage.

Every Linux user gets their own file, readable by root only:
``<state_dir>/users/<uid>/credentials.json``. The private keys inside it are
also sealed with AES-256-GCM under a machine-local master key and bound to the
owning uid and credential ID. A copy of a user's file is therefore useless
without ``<state_dir>/master.key``, and one user's sealed keys cannot be
replayed into another user's file.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_VERSION = 1
MAX_CREDENTIALS_PER_USER = 4096
_NONCE_SIZE = 12
LAST_USED_RESOLUTION = 60.0  # readers show last_used at minute resolution


class StoreError(Exception):
    """The store cannot be used (corrupt file, wrong owner, ...)."""


class StoreFull(StoreError):
    pass


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass
class Credential:
    id: bytes
    rp_id: str
    user_id: bytes
    alg: int
    sealed_key: bytes
    rp_name: str = ""
    user_name: str = ""
    user_display_name: str = ""
    discoverable: bool = True
    cred_protect: int = 1
    created: float = 0.0
    last_used: Optional[float] = None

    def to_json(self) -> dict:
        return {
            "id": b64encode(self.id),
            "rp_id": self.rp_id,
            "rp_name": self.rp_name,
            "user_id": b64encode(self.user_id),
            "user_name": self.user_name,
            "user_display_name": self.user_display_name,
            "alg": self.alg,
            "key": b64encode(self.sealed_key),
            "discoverable": self.discoverable,
            "cred_protect": self.cred_protect,
            "created": self.created,
            "last_used": self.last_used,
        }

    @classmethod
    def from_json(cls, data: dict) -> "Credential":
        return cls(
            id=b64decode(data["id"]),
            rp_id=data["rp_id"],
            user_id=b64decode(data["user_id"]),
            alg=int(data["alg"]),
            sealed_key=b64decode(data["key"]),
            rp_name=data.get("rp_name", ""),
            user_name=data.get("user_name", ""),
            user_display_name=data.get("user_display_name", ""),
            discoverable=bool(data.get("discoverable", True)),
            cred_protect=int(data.get("cred_protect", 1)),
            created=float(data.get("created", 0.0)),
            last_used=data.get("last_used"),
        )


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_file(path: Path, data: bytes, exclusive: bool = False) -> None:
    target = path if exclusive else path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | (os.O_EXCL if exclusive else os.O_TRUNC)
    with os.fdopen(os.open(target, flags, 0o600), "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    if not exclusive:
        os.replace(target, path)
    _fsync_dir(path.parent)


def _make_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


class CredentialStore:
    def __init__(self, state_dir):
        self.state_dir = Path(state_dir)
        self._lock = threading.RLock()
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._aead = AESGCM(self._master_key())

    def _master_key(self) -> bytes:
        path = self.state_dir / "master.key"
        try:
            key = path.read_bytes()
        except FileNotFoundError:
            key = AESGCM.generate_key(bit_length=256)
            try:
                _write_file(path, key, exclusive=True)
                return key
            except FileExistsError:
                key = path.read_bytes()
        if len(key) != 32:
            raise StoreError(f"{path} is corrupt (expected 32 bytes, found {len(key)})")
        return key

    @staticmethod
    def _aad(uid: int, cred_id: bytes) -> bytes:
        return b"localpasskey/v1\0%d\0" % uid + cred_id

    def seal(self, uid: int, cred_id: bytes, secret: bytes) -> bytes:
        nonce = os.urandom(_NONCE_SIZE)
        return nonce + self._aead.encrypt(nonce, secret, self._aad(uid, cred_id))

    def unseal(self, uid: int, cred: Credential) -> bytes:
        nonce, ciphertext = cred.sealed_key[:_NONCE_SIZE], cred.sealed_key[_NONCE_SIZE:]
        try:
            return self._aead.decrypt(nonce, ciphertext, self._aad(uid, cred.id))
        except (InvalidTag, ValueError):
            raise StoreError(
                f"private key of credential {cred.id.hex()[:12]} (uid {uid}) cannot be "
                "decrypted; was master.key replaced?"
            ) from None

    def _path(self, uid: int) -> Path:
        return self.state_dir / "users" / str(uid) / "credentials.json"

    def _read(self, uid: int, username: str) -> List[Credential]:
        path = self._path(uid)
        try:
            doc = json.loads(path.read_bytes())
        except FileNotFoundError:
            return []
        except ValueError as e:
            raise StoreError(f"{path} is not valid JSON: {e}") from None
        if not isinstance(doc, dict) or doc.get("format") != FORMAT_VERSION or doc.get("uid") != uid:
            raise StoreError(f"{path} has an unexpected format or uid")
        if doc.get("user") != username:
            raise StoreError(
                f"{path} belongs to user {doc.get('user')!r}, not {username!r}. The uid "
                "was reused or the account renamed; move the file away or correct "
                'its "user" field.'
            )
        creds = doc.get("credentials")
        if not isinstance(creds, list):
            raise StoreError(f"{path} has no valid credentials list")
        try:
            return [Credential.from_json(c) for c in creds]
        except (KeyError, TypeError, ValueError) as e:
            raise StoreError(f"{path} contains a malformed credential: {e}") from None

    def _write(self, uid: int, username: str, creds: List[Credential]) -> None:
        path = self._path(uid)
        _make_private_dir(path.parent.parent)
        _make_private_dir(path.parent)
        doc = {
            "format": FORMAT_VERSION,
            "uid": uid,
            "user": username,
            "credentials": [c.to_json() for c in creds],
        }
        _write_file(path, json.dumps(doc, indent=1).encode() + b"\n")

    def credentials(self, uid: int, username: str) -> List[Credential]:
        with self._lock:
            return self._read(uid, username)

    def add(self, uid: int, username: str, cred: Credential) -> None:
        """Store ``cred``; a discoverable credential replaces any older
        discoverable one for the same site and account, as CTAP requires."""
        with self._lock:
            creds = self._read(uid, username)
            if cred.discoverable:
                creds = [
                    c
                    for c in creds
                    if not (c.discoverable and c.rp_id == cred.rp_id and c.user_id == cred.user_id)
                ]
            if len(creds) >= MAX_CREDENTIALS_PER_USER:
                raise StoreFull(f"uid {uid} already has {len(creds)} credentials")
            creds.append(cred)
            self._write(uid, username, creds)

    def record_use(self, uid: int, username: str, cred_id: bytes) -> None:
        """Remember when a credential was last used."""
        with self._lock:
            creds = self._read(uid, username)
            now = time.time()
            for cred in creds:
                if cred.id == cred_id:
                    # Timestamps are only shown to the minute; skip the two-fsync
                    # rewrite while the stored value is still current enough.
                    if cred.last_used is not None and 0 <= now - cred.last_used < LAST_USED_RESOLUTION:
                        return
                    cred.last_used = now
                    self._write(uid, username, creds)
                    return
            raise KeyError(cred_id)

    def remove(self, uid: int, username: str, cred_ids: Iterable[bytes]) -> List[Credential]:
        """Delete the given credentials and return those that were still there."""
        doomed = set(cred_ids)
        with self._lock:
            creds = self._read(uid, username)
            kept = [c for c in creds if c.id not in doomed]
            if len(kept) != len(creds):
                self._write(uid, username, kept)
            return [c for c in creds if c.id in doomed]
