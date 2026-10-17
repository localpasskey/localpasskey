"""Per-user passkey storage.

Every Linux user gets their own file, readable by root only:
``<state_dir>/users/<uid>/credentials.json``. The private keys inside it are
also sealed with AES-256-GCM under a machine-local master key and bound to the
owning uid and credential ID. A copy of a user's file is therefore useless
without ``<state_dir>/master.key``, and one user's sealed keys cannot be
replayed into another user's file.
"""

from __future__ import annotations
import collections

import base64
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Format 2 added the "deleted" key. Reading 1 keeps existing files working,
# while writing only 2 makes a 0.1.1 daemon refuse the file instead of loading
# trashed passkeys as live and dropping the key on its next write.
FORMAT_VERSION = 2
PIN_FORMAT_VERSION = 1
TOTP_FORMAT_VERSION = 1
MAX_CREDENTIALS_PER_USER = 4096
MAX_TOTP_PER_USER = 4096  # separate from passkeys; the trash counts until purged
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


_B64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")


def b64decode_strict(text) -> bytes:
    """Decode untrusted base64url; ValueError if it is anything else."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text):
        raise ValueError("not base64url")
    return b64decode(text.rstrip("="))


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
    deleted: Optional[float] = None

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
            "deleted": self.deleted,
        }

    @classmethod
    def from_json(cls, data: dict) -> "Credential":
        deleted = data.get("deleted")
        if deleted is not None and (isinstance(deleted, bool) or not isinstance(deleted, (int, float))):
            # Fail closed: a corrupt timestamp must not turn a trashed passkey live.
            raise ValueError(f"invalid deleted timestamp {deleted!r}")
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
            deleted=None if deleted is None else float(deleted),
        )


@dataclass
class TotpEntry:
    """An authenticator code (TOTP) setup; the secret is sealed like a key."""

    id: bytes  # 16 random bytes
    sealed_secret: bytes  # seal(uid, b"totp\0" + id, secret)
    site: str = ""  # what the user confirmed, e.g. "github.com"; may be ""
    issuer: str = ""  # from the link; display only
    account: str = ""
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30
    created: float = 0.0
    deleted: Optional[float] = None

    def to_json(self) -> dict:
        return {
            "id": b64encode(self.id),
            "site": self.site,
            "issuer": self.issuer,
            "account": self.account,
            "secret": b64encode(self.sealed_secret),
            "algorithm": self.algorithm,
            "digits": self.digits,
            "period": self.period,
            "created": self.created,
            "deleted": self.deleted,
        }

    @classmethod
    def from_json(cls, data: dict) -> "TotpEntry":
        deleted = data.get("deleted")
        if deleted is not None and (isinstance(deleted, bool) or not isinstance(deleted, (int, float))):
            # Fail closed: a corrupt timestamp must not turn a trashed code live.
            raise ValueError(f"invalid deleted timestamp {deleted!r}")
        from . import totp  # not at the top: totp imports ctap2, which imports this module

        algorithm = data.get("algorithm", totp.DEFAULT_ALGORITHM)
        digits = data.get("digits", totp.DEFAULT_DIGITS)
        period = data.get("period", totp.DEFAULT_PERIOD)
        # Fail closed here too: a code computed with a value the daemon never accepts is no code.
        if algorithm not in totp.ALGORITHMS:
            raise ValueError(f"invalid algorithm {algorithm!r}")
        if isinstance(digits, bool) or not isinstance(digits, int) or digits not in totp.DIGITS:
            raise ValueError(f"invalid digits {digits!r}")
        if (isinstance(period, bool) or not isinstance(period, int)
                or not totp.MIN_PERIOD <= period <= totp.MAX_PERIOD):
            raise ValueError(f"invalid period {period!r}")
        return cls(
            id=b64decode(data["id"]),
            sealed_secret=b64decode(data["secret"]),
            site=str(data.get("site", "")),
            issuer=str(data.get("issuer", "")),
            account=str(data.get("account", "")),
            algorithm=algorithm,
            digits=digits,
            period=period,
            created=float(data.get("created", 0.0)),
            deleted=None if deleted is None else float(deleted),
        )


def _totp_label(entry_id: bytes) -> bytes:
    # The fixed prefix keeps these AADs apart from credential IDs, which are raw.
    return b"totp\0" + entry_id


@dataclass
class PinState:
    hash: bytes  # LEFT(SHA-256(PIN), 16)
    retries: int


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

    def _open(self, uid: int, label: bytes, blob: bytes) -> bytes:
        nonce, ciphertext = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:]
        try:
            return self._aead.decrypt(nonce, ciphertext, self._aad(uid, label))
        except (InvalidTag, ValueError):
            raise StoreError(f"{label.hex()[:12]} (uid {uid}) cannot be decrypted") from None

    def unseal(self, uid: int, cred: Credential) -> bytes:
        try:
            return self._open(uid, cred.id, cred.sealed_key)
        except StoreError:
            raise StoreError(
                f"private key of credential {cred.id.hex()[:12]} (uid {uid}) cannot be "
                "decrypted; was master.key replaced?"
            ) from None

    def _path(self, uid: int) -> Path:
        return self.state_dir / "users" / str(uid) / "credentials.json"

    def _totp_path(self, uid: int) -> Path:
        return self.state_dir / "users" / str(uid) / "totp.json"

    def _pin_path(self, uid: int) -> Path:
        return self.state_dir / "users" / str(uid) / "pin.json"

    def _read(self, uid: int, username: str) -> List[Credential]:
        """Every record in the file, trashed ones included."""
        path = self._path(uid)
        try:
            doc = json.loads(path.read_bytes())
        except FileNotFoundError:
            return []
        except ValueError as e:
            raise StoreError(f"{path} is not valid JSON: {e}") from None
        if not isinstance(doc, dict) or doc.get("format") not in (1, FORMAT_VERSION) or doc.get("uid") != uid:
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
        except (KeyError, TypeError, ValueError, OverflowError) as e:
            raise StoreError(f"{path} contains a malformed credential: {e}") from None

    def _write(self, uid: int, username: str, creds: List[Credential]) -> None:
        """Persist ``creds`` whole; trashed records are only dropped by purge."""
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
        """The LIVE credentials of a user; the trash is hidden here."""
        with self._lock:
            return [c for c in self._read(uid, username) if c.deleted is None]

    def trash(self, uid: int, username: str) -> List[Credential]:
        """The trashed credentials of a user."""
        with self._lock:
            return [c for c in self._read(uid, username) if c.deleted is not None]

    def _matching(self, creds: List[Credential], cred_ids, trashed: bool) -> List[Credential]:
        wanted = set(cred_ids)
        return [
            c for c in creds if c.id in wanted and (c.deleted is not None) == trashed
        ]

    def add(self, uid: int, username: str, cred: Credential) -> None:
        """Store ``cred``; a discoverable credential replaces (moves to the
        trash) any older live discoverable one for the same site and account,
        as CTAP requires."""
        with self._lock:
            creds = self._read(uid, username)
            if cred.discoverable:
                replaced = [
                    c
                    for c in creds
                    if c.discoverable
                    and c.deleted is None
                    and c.rp_id == cred.rp_id
                    and c.user_id == cred.user_id
                ]
                if replaced and len(creds) >= MAX_CREDENTIALS_PER_USER:
                    # No room to keep the old one in the trash: drop it, as CTAP allows.
                    creds = [c for c in creds if all(c is not r for r in replaced)]
                now = time.time()
                for c in replaced:
                    c.deleted = now
            if len(creds) >= MAX_CREDENTIALS_PER_USER:
                raise StoreFull(f"uid {uid} already has {len(creds)} credentials")
            creds.append(cred)
            self._write(uid, username, creds)

    def import_credentials(
        self, uid: int, username: str, creds: Iterable[Credential], dry_run: bool = False
    ) -> Tuple[List[Credential], List[Tuple[Credential, str]]]:
        """Add ``creds`` in one write, skipping each one that would clash.

        Returns ``(imported, skipped)``; skipped entries carry a reason. Unlike
        ``add`` nothing is replaced: an ID already known (live or trashed), a
        live discoverable passkey for the same account, or a duplicate within
        ``creds`` itself is skipped, and so is anything beyond the capacity.
        ``dry_run`` plans without writing."""
        with self._lock:
            stored = self._read(uid, username)
            live_ids = {c.id for c in stored if c.deleted is None}
            trashed_ids = {c.id for c in stored if c.deleted is not None}
            accounts = {(c.rp_id, c.user_id) for c in stored if c.deleted is None and c.discoverable}
            seen_ids, seen_accounts = set(), set()
            imported, skipped = [], []
            for cred in creds:
                account = (cred.rp_id, cred.user_id)
                if cred.id in seen_ids:
                    reason = "duplicate in the file"
                elif cred.id in live_ids:
                    reason = "already on this computer"
                elif cred.id in trashed_ids:
                    reason = "in the trash on this computer"
                elif cred.discoverable and account in accounts:
                    reason = "a passkey for this account already exists"
                elif cred.discoverable and account in seen_accounts:
                    reason = "another passkey in the file is for the same account"
                elif len(stored) + len(imported) >= MAX_CREDENTIALS_PER_USER:
                    reason = "store full"
                else:
                    reason = None
                seen_ids.add(cred.id)
                if reason is not None:
                    skipped.append((cred, reason))
                    continue
                if cred.discoverable:
                    seen_accounts.add(account)
                imported.append(cred)
            if imported and not dry_run:
                self._write(uid, username, stored + imported)
            return imported, skipped

    def record_use(self, uid: int, username: str, cred_id: bytes) -> None:
        """Remember when a live credential was last used."""
        with self._lock:
            creds = self._read(uid, username)
            now = time.time()
            for cred in creds:
                if cred.id == cred_id and cred.deleted is None:
                    # Timestamps are only shown to the minute; skip the two-fsync
                    # rewrite while the stored value is still current enough.
                    if cred.last_used is not None and 0 <= now - cred.last_used < LAST_USED_RESOLUTION:
                        return
                    cred.last_used = now
                    self._write(uid, username, creds)
                    return
            raise KeyError(cred_id)

    def remove(self, uid: int, username: str, cred_ids: Iterable[bytes]) -> List[Credential]:
        """Move the given live credentials to the trash and return them."""
        doomed = set(cred_ids)
        with self._lock:
            creds = self._read(uid, username)
            moved = self._matching(creds, doomed, trashed=False)
            for cred in moved:
                cred.deleted = time.time()
            if moved:
                self._write(uid, username, creds)
            return moved

    def restore(self, uid: int, username: str, cred_ids: Iterable[bytes]) -> List[Credential]:
        """Bring trashed credentials back; refuses as a whole if a selected
        discoverable one would collide with a live passkey for the same account.
        The other selected records count as live: they all come back together."""
        with self._lock:
            creds = self._read(uid, username)
            picked = self._matching(creds, cred_ids, trashed=True)
            returning = {id(c) for c in picked}
            # Count live discoverable passkeys per (rp_id, user_id) — picked ones count as
            # live because they all come back together.
            live_counts = collections.Counter(
                (c.rp_id, c.user_id) for c in creds
                if c.discoverable and (c.deleted is None or id(c) in returning)
            )
            for cred in picked:
                if cred.discoverable and live_counts[(cred.rp_id, cred.user_id)] > 1:
                    raise StoreError(
                        f"a newer passkey for this account on {cred.rp_id} exists; "
                        "delete it first"
                    )
            for cred in picked:
                cred.deleted = None
            if picked:
                self._write(uid, username, creds)
            return picked

    def purge(self, uid: int, username: str, cred_ids: Iterable[bytes]) -> List[Credential]:
        """Permanently delete trashed credentials and return them."""
        doomed = set(cred_ids)
        with self._lock:
            creds = self._read(uid, username)
            purged = self._matching(creds, doomed, trashed=True)
            if purged:
                kept = [c for c in creds if not (c.id in doomed and c.deleted is not None)]
                self._write(uid, username, kept)
            return purged

    def update_user(
        self, uid: int, username: str, cred_id: bytes, user_name: str, display_name: str
    ) -> None:
        """Rename the account of a live credential."""
        with self._lock:
            creds = self._read(uid, username)
            for cred in creds:
                if cred.id == cred_id and cred.deleted is None:
                    cred.user_name = user_name
                    cred.user_display_name = display_name
                    self._write(uid, username, creds)
                    return
            raise KeyError(cred_id)

    def pin(self, uid: int, username: str) -> Optional[PinState]:
        """The stored PIN state, or None when the user has no PIN."""
        with self._lock:
            path = self._pin_path(uid)
            try:
                doc = json.loads(path.read_bytes())
            except FileNotFoundError:
                return None
            except ValueError as e:
                raise StoreError(f"{path} is not valid JSON: {e}") from None
            if not isinstance(doc, dict) or doc.get("format") != PIN_FORMAT_VERSION or doc.get("uid") != uid:
                raise StoreError(f"{path} has an unexpected format or uid")
            if doc.get("user") != username:
                raise StoreError(f"{path} belongs to user {doc.get('user')!r}, not {username!r}")
            try:
                sealed = b64decode(doc["pin"])
                retries = int(doc["retries"])
            except (KeyError, TypeError, ValueError) as e:
                raise StoreError(f"{path} contains malformed password data: {e}") from None
            return PinState(hash=self._open(uid, b"clientPin", sealed), retries=retries)

    def set_pin(self, uid: int, username: str, state: Optional[PinState]) -> None:
        """Store the PIN state, or delete it when ``state`` is None."""
        with self._lock:
            path = self._pin_path(uid)
            if state is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    return
                _fsync_dir(path.parent)
                return
            _make_private_dir(path.parent.parent)
            _make_private_dir(path.parent)
            doc = {
                "format": PIN_FORMAT_VERSION,
                "uid": uid,
                "user": username,
                "pin": b64encode(self.seal(uid, b"clientPin", state.hash)),
                "retries": state.retries,
            }
            _write_file(path, json.dumps(doc, indent=1).encode() + b"\n")

    def _read_totp(self, uid: int, username: str) -> Tuple[bool, List[TotpEntry]]:
        """The require_auth setting and every entry, trashed ones included."""
        path = self._totp_path(uid)
        try:
            doc = json.loads(path.read_bytes())
        except FileNotFoundError:
            return True, []
        except ValueError as e:
            raise StoreError(f"{path} is not valid JSON: {e}") from None
        if not isinstance(doc, dict) or doc.get("format") != TOTP_FORMAT_VERSION or doc.get("uid") != uid:
            raise StoreError(f"{path} has an unexpected format or uid")
        if doc.get("user") != username:
            raise StoreError(f"{path} belongs to user {doc.get('user')!r}, not {username!r}")
        require_auth = doc.get("require_auth", True)
        if not isinstance(require_auth, bool):
            # Fail closed: only an explicit false shows codes without a password.
            raise StoreError(f"{path} has an invalid require_auth value")
        entries = doc.get("entries")
        if not isinstance(entries, list):
            raise StoreError(f"{path} has no valid entries list")
        try:
            return require_auth, [TotpEntry.from_json(e) for e in entries]
        except (KeyError, TypeError, ValueError, OverflowError, AttributeError) as e:
            raise StoreError(f"{path} contains a malformed authenticator code: {e}") from None

    def _write_totp(self, uid: int, username: str, require_auth: bool, entries: List[TotpEntry]) -> None:
        path = self._totp_path(uid)
        _make_private_dir(path.parent.parent)
        _make_private_dir(path.parent)
        doc = {
            "format": TOTP_FORMAT_VERSION,
            "uid": uid,
            "user": username,
            "require_auth": require_auth,
            "entries": [e.to_json() for e in entries],
        }
        _write_file(path, json.dumps(doc, indent=1).encode() + b"\n")

    def totp_entries(self, uid: int, username: str) -> List[TotpEntry]:
        """The LIVE authenticator codes of a user; the trash is hidden here."""
        with self._lock:
            return [e for e in self._read_totp(uid, username)[1] if e.deleted is None]

    def totp_trash(self, uid: int, username: str) -> List[TotpEntry]:
        """The trashed authenticator codes of a user."""
        with self._lock:
            return [e for e in self._read_totp(uid, username)[1] if e.deleted is not None]

    def totp_add(self, uid: int, username: str, entry: TotpEntry) -> None:
        """Store a new authenticator code."""
        with self._lock:
            require_auth, entries = self._read_totp(uid, username)
            if len(entries) >= MAX_TOTP_PER_USER:
                raise StoreFull(f"uid {uid} already has {len(entries)} authenticator codes")
            entries.append(entry)
            self._write_totp(uid, username, require_auth, entries)

    def totp_import(
        self, uid: int, username: str, entries: Iterable[TotpEntry], dry_run: bool = False
    ) -> Tuple[List[TotpEntry], List[Tuple[TotpEntry, str]]]:
        """Add ``entries`` in one write, skipping each one that would clash.

        Returns ``(imported, skipped)``; skipped entries carry a reason. An ID
        already known (live or trashed), a live code with the same secret, site
        and account, a duplicate ID within ``entries`` and anything beyond the
        capacity are skipped. ``dry_run`` plans without writing."""
        with self._lock:
            require_auth, stored = self._read_totp(uid, username)
            live = [e for e in stored if e.deleted is None]
            live_ids = {e.id for e in live}
            trashed_ids = {e.id for e in stored if e.deleted is not None}
            same = {(self.totp_unseal(uid, e), e.site, e.account) for e in live}
            seen_ids = set()
            imported, skipped = [], []
            for entry in entries:
                if entry.id in seen_ids:
                    reason = "duplicate in the file"
                elif entry.id in live_ids or (self.totp_unseal(uid, entry), entry.site, entry.account) in same:
                    reason = "already on this computer"
                elif entry.id in trashed_ids:
                    reason = "in the trash on this computer"
                elif len(stored) + len(imported) >= MAX_TOTP_PER_USER:
                    reason = "store full"
                else:
                    reason = None
                seen_ids.add(entry.id)
                if reason is None:
                    imported.append(entry)
                else:
                    skipped.append((entry, reason))
            if imported and not dry_run:
                self._write_totp(uid, username, require_auth, stored + imported)
            return imported, skipped

    def totp_remove(self, uid: int, username: str, ids: Iterable[bytes]) -> List[TotpEntry]:
        """Move the given live codes to the trash and return them."""
        with self._lock:
            require_auth, entries = self._read_totp(uid, username)
            moved = self._matching(entries, ids, trashed=False)
            now = time.time()
            for entry in moved:
                entry.deleted = now
            if moved:
                self._write_totp(uid, username, require_auth, entries)
            return moved

    def totp_restore(self, uid: int, username: str, ids: Iterable[bytes]) -> List[TotpEntry]:
        """Bring trashed codes back and return them."""
        with self._lock:
            require_auth, entries = self._read_totp(uid, username)
            picked = self._matching(entries, ids, trashed=True)
            for entry in picked:
                entry.deleted = None
            if picked:
                self._write_totp(uid, username, require_auth, entries)
            return picked

    def totp_purge(self, uid: int, username: str, ids: Iterable[bytes]) -> List[TotpEntry]:
        """Permanently delete trashed codes and return them."""
        with self._lock:
            require_auth, entries = self._read_totp(uid, username)
            purged = self._matching(entries, ids, trashed=True)
            if purged:
                kept = [e for e in entries if all(e is not p for p in purged)]
                self._write_totp(uid, username, require_auth, kept)
            return purged

    def totp_update(
        self,
        uid: int,
        username: str,
        entry_id: bytes,
        site: Optional[str] = None,
        issuer: Optional[str] = None,
        account: Optional[str] = None,
    ) -> TotpEntry:
        """Change the labels of a live code; None leaves a field unchanged."""
        with self._lock:
            require_auth, entries = self._read_totp(uid, username)
            for entry in entries:
                if entry.id == entry_id and entry.deleted is None:
                    if site is not None:
                        entry.site = site
                    if issuer is not None:
                        entry.issuer = issuer
                    if account is not None:
                        entry.account = account
                    self._write_totp(uid, username, require_auth, entries)
                    return entry
            raise KeyError(entry_id)

    def totp_unseal(self, uid: int, entry: TotpEntry) -> bytes:
        """The plaintext seed of ``entry``; it never leaves the daemon but in an approved export."""
        try:
            return self._open(uid, _totp_label(entry.id), entry.sealed_secret)
        except StoreError:
            raise StoreError(
                f"secret of authenticator code {entry.id.hex()[:12]} (uid {uid}) cannot be "
                "decrypted; was master.key replaced?"
            ) from None

    def totp_require_auth(self, uid: int, username: str) -> bool:
        """Whether showing this user's codes needs their password (default yes)."""
        with self._lock:
            return self._read_totp(uid, username)[0]

    def set_totp_require_auth(self, uid: int, username: str, value: bool) -> None:
        with self._lock:
            require_auth, entries = self._read_totp(uid, username)
            if require_auth != bool(value):
                self._write_totp(uid, username, bool(value), entries)
