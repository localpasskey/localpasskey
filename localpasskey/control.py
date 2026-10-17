"""Local control socket used by the ``localpasskey`` command.

Each connection carries one JSON request and one JSON reply, one line each.
The kernel tells us the caller's uid (SO_PEERCRED), so users can only see and
manage their own passkeys; root may pass ``"user"`` to manage anyone's.
Deleting moves passkeys to the trash; restoring, purging, the PIN, export and
import ask the caller to authenticate through polkit first.

Authenticator codes (TOTP) live in the same store: ``"totp"`` mirrors the
passkey commands, and showing a code needs an unlock unless the user turned
that setting off. An unlock is kept in memory for the calling process (pid
plus its /proc start time, so a recycled pid does not inherit it) and expires
after ``UNLOCK_IDLE`` seconds without a code request. Root is always unlocked. No reply but export carries a seed.

Export and import exchange "normalized records" (see ``record`` and
``_parse_record``) with plaintext PKCS#8 keys, and code records (``code_record``
and ``_parse_totp``) with Base32 secrets. File formats, passphrases and
encryption are handled by the unprivileged ``transfer`` module; the daemon only
validates records strictly and re-seals imported keys and secrets for the target uid.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import pwd
import socket
import struct
import threading
import time
from types import SimpleNamespace

from cryptography.exceptions import UnsupportedAlgorithm

from . import cose, totp
from .clientpin import MAX_PIN_BYTES, MIN_PIN_LENGTH, PIN_POLICY_VIOLATION, PinError, PinManager, pin_problem
from .ctap2 import (MAX_CREDENTIAL_ID_LENGTH, MAX_LABEL_LENGTH, MAX_RP_ID_LENGTH, MAX_USER_ID_LENGTH,
                    Verdict, _label, valid_rp_id)
from .notify import ACTIVITY
from .polkit import ACTION_EXPORT, ACTION_MANAGE, ACTION_TOTP, process_start_time, process_subject
from .store import (MAX_CREDENTIALS_PER_USER, MAX_TOTP_PER_USER, Credential, StoreError, TotpEntry,
                    b64decode_strict, b64encode)

log = logging.getLogger(__name__)

MAX_REQUEST = 16 * 1024 * 1024  # An import of 4096 RSA passkeys fits in one request.
MIN_ID_PREFIX = 4
UNLOCK_IDLE = 300.0  # seconds a process may keep showing codes after its last code request
READERS_PER_UID = 2  # each reader may hold MAX_REQUEST bytes and their parsed JSON
READER_WAIT = 10.0  # seconds a request waits for a reader slot
CONNECTIONS_PER_UID = 8  # open connections per caller, so one uid cannot exhaust our fds
BUSY = b'{"ok": false, "error": "too many requests in progress"}\n'
PIN_POLICY = (f"the PIN must be at least {MIN_PIN_LENGTH} characters and at most "
              f"{MAX_PIN_BYTES} bytes long, and must not contain NUL")


# _select and _notify_change arguments for authenticator codes.
CODE_WORDS = ("authenticator code", "authenticator codes", "site")
CODE_NOTICE = {"noun": "authenticator code", "name": lambda e: _code_label(e)}


class ControlError(Exception):
    pass


def describe(cred) -> dict:
    return {
        "id": cred.id.hex(),
        "site": cred.rp_id,
        "site_name": cred.rp_name,
        "user_name": cred.user_name,
        "display_name": cred.user_display_name,
        "algorithm": cose.ALGORITHM_NAMES.get(cred.alg, str(cred.alg)),
        "discoverable": cred.discoverable,
        "created": cred.created,
        "last_used": cred.last_used,
        "deleted": cred.deleted,
    }


def record(cred, private_key: bytes) -> dict:
    """The normalized record of a credential, as sent by export."""
    return {
        "id": b64encode(cred.id),
        "rp_id": cred.rp_id,
        "rp_name": cred.rp_name,
        "user_id": b64encode(cred.user_id),
        "user_name": cred.user_name,
        "user_display_name": cred.user_display_name,
        "alg": cred.alg,
        "private_key": b64encode(private_key),
        "discoverable": cred.discoverable,
        "cred_protect": cred.cred_protect,
        "created": cred.created,
    }


def describe_totp(entry) -> dict:
    return {
        "id": entry.id.hex(),
        "site": entry.site,
        "issuer": entry.issuer,
        "account": entry.account,
        "algorithm": entry.algorithm,
        "digits": entry.digits,
        "period": entry.period,
        "created": entry.created,
        "deleted": entry.deleted,
    }


def code_record(entry, secret: bytes) -> dict:
    """One authenticator code, plaintext, as sent by export."""
    return {
        "id": b64encode(entry.id),
        "site": entry.site,
        "issuer": entry.issuer,
        "account": entry.account,
        "secret": totp.encode_secret(secret),
        "algorithm": entry.algorithm,
        "digits": entry.digits,
        "period": entry.period,
        "created": entry.created,
    }


def _code_label(entry) -> str:
    """What a dialog calls a code; its site is what the user was asked to confirm."""
    return _label(entry.site or entry.issuer or entry.account) or "an account"


def _counts(passkeys: int, codes: int) -> str:
    """ "3 passkeys and 2 authenticator codes", omitting an empty part."""
    parts = []
    if passkeys:
        parts.append(f"{passkeys} passkey{'s' if passkeys != 1 else ''}")
    if codes:
        parts.append(f"{codes} authenticator code{'s' if codes != 1 else ''}")
    return " and ".join(parts)


def _totp_labels(data, fail, default=None):
    """site, issuer and account of a code; a missing one is ``default``."""
    labels = []
    for name in ("site", "issuer", "account"):
        text = data.get(name, default)
        if text is not None:
            if not isinstance(text, str):
                fail(f"{name} is missing or not a str")
            if len(text) > MAX_LABEL_LENGTH:
                fail(f"{name} is longer than {MAX_LABEL_LENGTH} characters")
            try:
                text.encode("utf-8")  # a lone surrogate would break every reply naming it
            except UnicodeEncodeError:
                fail(f"{name} is not valid text")
            if name == "site" and text and not valid_rp_id(text):
                fail(f"invalid site {text[:MAX_RP_ID_LENGTH]!r}")
        labels.append(text)
    return labels


def _parse_totp(data, store, uid, index=None) -> TotpEntry:
    """Validate one pasted setup or imported record and seal its secret for ``uid``."""

    def fail(problem):
        prefix = "" if index is None else f"authenticator code {index + 1}: "
        raise ControlError(prefix + problem)

    def field(name, kind, default=None):
        value = data.get(name, default)
        # bool is an int subclass; never accept it for a number.
        if not isinstance(value, kind) or (kind is not bool and isinstance(value, bool)):
            fail(f"{name} is missing or not a {getattr(kind, '__name__', 'number')}")
        return value

    if not isinstance(data, dict):
        fail("not a JSON object")
    try:
        secret = totp.decode_secret(field("secret", str))
    except totp.OtpError as e:
        fail(str(e))
    site, issuer, account = _totp_labels(data, fail, "")
    algorithm = field("algorithm", str, totp.DEFAULT_ALGORITHM).upper()
    if algorithm not in totp.ALGORITHMS:
        fail(f"the algorithm must be one of {', '.join(totp.ALGORITHMS)}")
    digits = field("digits", int, totp.DEFAULT_DIGITS)
    if digits not in totp.DIGITS:
        fail(f"the digits must be {' or '.join(str(d) for d in totp.DIGITS)}")
    period = field("period", int, totp.DEFAULT_PERIOD)
    if not totp.MIN_PERIOD <= period <= totp.MAX_PERIOD:
        fail(f"the period must be {totp.MIN_PERIOD} to {totp.MAX_PERIOD} seconds")
    if index is None:
        entry_id = os.urandom(16)  # clients never pick the ID of a new code
    else:
        try:
            entry_id = b64decode_strict(field("id", str))
        except ValueError:
            fail("id is not base64url")
        if len(entry_id) != 16:
            fail("the id must be 16 bytes long")
    created = data.get("created")
    now = time.time()
    if isinstance(created, bool) or not isinstance(created, (int, float)) or not 0 < created <= now:
        created = now
    return TotpEntry(
        id=entry_id, sealed_secret=store.seal(uid, b"totp\0" + entry_id, secret),
        site=site, issuer=issuer, account=account,
        algorithm=algorithm, digits=digits, period=period, created=float(created),
    )


def _parse_record(index, data, store, uid) -> Credential:
    """Validate one normalized record strictly and seal its key for ``uid``."""

    def fail(problem):
        raise ControlError(f"passkey {index + 1}: {problem}")

    def field(name, kind):
        value = data.get(name)
        # bool is an int subclass; never accept it for a number.
        if not isinstance(value, kind) or (kind is not bool and isinstance(value, bool)):
            fail(f"{name} is missing or not a {getattr(kind, '__name__', 'number')}")
        return value

    def binary(name):
        text = field(name, str)
        try:
            return b64decode_strict(text)
        except ValueError:
            fail(f"{name} is not base64url")

    def label(name):
        text = field(name, str)
        if len(text) > MAX_LABEL_LENGTH:
            fail(f"{name} is longer than {MAX_LABEL_LENGTH} characters")
        try:
            text.encode("utf-8")  # a lone surrogate would break every CBOR reply naming it
        except UnicodeEncodeError:
            fail(f"{name} is not valid text")
        return text

    if not isinstance(data, dict):
        fail("not a JSON object")
    cred_id = binary("id")
    if not 1 <= len(cred_id) <= MAX_CREDENTIAL_ID_LENGTH:
        fail(f"the credential ID must be 1 to {MAX_CREDENTIAL_ID_LENGTH} bytes long")
    user_id = binary("user_id")
    if len(user_id) > MAX_USER_ID_LENGTH:
        fail(f"the user ID is longer than {MAX_USER_ID_LENGTH} bytes")
    rp_id = field("rp_id", str)
    if not valid_rp_id(rp_id):
        fail(f"invalid site {rp_id[:MAX_RP_ID_LENGTH]!r}")
    alg = field("alg", int)
    if alg not in cose.SUPPORTED_ALGORITHMS:
        fail(f"unsupported algorithm {alg}")
    der = binary("private_key")
    try:
        key = cose.private_key_from_bytes(der)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        fail("the private key cannot be read")
    if cose.algorithm_of(key) != alg:
        fail(f"the private key is not a valid {cose.ALGORITHM_NAMES[alg]} key")
    cred_protect = field("cred_protect", int)
    if cred_protect not in (1, 2, 3):
        fail(f"invalid credProtect level {cred_protect}")
    created = field("created", (int, float))
    now = time.time()
    if not 0 < created <= now:  # also catches NaN; Infinity is in the future
        created = now
    return Credential(
        id=cred_id, rp_id=rp_id, user_id=user_id, alg=alg,
        # Re-serialized and sealed here: bound to this uid and this machine.
        sealed_key=store.seal(uid, cred_id, cose.private_key_to_bytes(key)),
        rp_name=label("rp_name"), user_name=label("user_name"),
        user_display_name=label("user_display_name"),
        discoverable=field("discoverable", bool), cred_protect=cred_protect, created=float(created),
    )


class ControlServer:
    def __init__(self, path, store, verifier, status, notifier=None, pins=None):
        self.path = path
        self.store = store
        self.verifier = verifier
        self.status = status
        self.notifier = notifier
        self.pins = pins or PinManager(store)
        self._sock = None
        self._slots = {}  # uid -> limits on that caller's concurrent work
        self._unlocks = {}  # (uid, pid, start time) -> monotonic expiry of that process's unlock
        self._unlocks_lock = threading.Lock()

    def _slot(self, uid):
        # setdefault is atomic, so concurrent connections of one uid share one slot.
        return self._slots.setdefault(uid, SimpleNamespace(
            readers=threading.BoundedSemaphore(READERS_PER_UID),
            connections=threading.BoundedSemaphore(CONNECTIONS_PER_UID), importing=threading.Lock()))

    def start(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        self._sock.bind(self.path)
        os.chmod(self.path, 0o666)
        self._sock.listen(16)
        threading.Thread(target=self._accept_loop, args=(self._sock,), name="control", daemon=True).start()

    def stop(self):
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
            self._sock = None
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass

    def _accept_loop(self, sock):
        while True:
            try:
                conn, _ = sock.accept()
            except OSError as e:
                if e.errno not in (errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ECONNABORTED):
                    return  # stop() closed the socket (EINVAL); anything else is fatal
                log.warning("Control accept failed (%s); retrying", e)
                time.sleep(0.05)  # let a choked fd table drain instead of spinning
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        with conn:
            try:
                pid, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                conn.settimeout(10)  # also bounds the reply: a caller that stops reading is dropped
                slot = self._slot(uid)
                if not slot.connections.acquire(blocking=False):
                    conn.sendall(BUSY)
                    return
                try:
                    # Held until the reply is sent: the parsed request lives through the dialog.
                    # Bounded, so a queued request fails before its client (180 s) gives up.
                    if not slot.readers.acquire(timeout=READER_WAIT):
                        conn.sendall(BUSY)
                        return
                    try:
                        with conn.makefile("rb") as stream:
                            data = stream.readline(MAX_REQUEST + 1)
                        if len(data) > MAX_REQUEST or not data.endswith(b"\n"):
                            return
                        try:
                            request, error = json.loads(data), None
                        except (ValueError, RecursionError) as e:
                            request, error = None, {"ok": False, "error": f"bad request: {e}"}
                        del data
                        try:
                            response = error or self.handle(request, pid, uid)
                        except (ControlError, StoreError) as e:
                            response = {"ok": False, "error": str(e)}
                        except (ValueError, TypeError, AttributeError) as e:
                            response = {"ok": False, "error": f"bad request: {e}"}
                        except Exception as e:
                            log.exception("Control request failed")
                            response = {"ok": False, "error": f"internal error: {e}"}
                        conn.sendall(json.dumps(response).encode() + b"\n")
                    finally:
                        slot.readers.release()
                finally:
                    slot.connections.release()
            except OSError as e:
                log.debug("Control connection failed: %s", e)

    def handle(self, request: dict, pid: int, uid: int) -> dict:
        if not isinstance(request, dict):
            raise ControlError("request must be a JSON object")
        command = request.get("command")
        if command == "status":
            return {"ok": True, **self.status()}
        if command not in ("list", "delete", "restore", "purge", "pin", "export", "import", "totp"):
            raise ControlError(f"unknown command {command!r}")
        target_uid, username = self._target(request.get("user"), uid)
        if command == "pin":
            return self._pin(request, pid, uid, target_uid, username)
        if command == "totp":
            return self._totp(request, pid, uid, target_uid, username)
        if command == "export":
            return self._export(request, pid, uid, target_uid, username)
        if command == "import":
            return self._import(request, pid, uid, target_uid, username)

        if command == "list":
            if "trash" in request and not isinstance(request["trash"], bool):
                raise ControlError("invalid trash selector")
            if request.get("trash"):
                records = self.store.trash(target_uid, username)
            else:
                records = self.store.credentials(target_uid, username)
            return {"ok": True, "user": username, "credentials": [describe(c) for c in records]}

        # delete looks at the live records, restore and purge at the trash.
        if command == "delete":
            records = self.store.credentials(target_uid, username)
        else:
            records = self.store.trash(target_uid, username)
        doomed = self._select(request, records)
        if command == "purge" and len(doomed) != 1:
            raise ControlError("purge permanently deletes one passkey at a time")
        if request.get("dry_run"):
            return {"ok": True, "deleted": [describe(c) for c in doomed]}
        count = len(doomed)
        plural = "s" if count != 1 else ""
        if command == "delete":
            message = (
                f"Move {count} passkey{plural} stored on this computer to the trash? "
                "They stop working until you restore them."
            )
        elif command == "restore":
            message = f"Restore {count} passkey{plural} from the trash?"
        else:
            message = (
                f"Permanently delete the passkey for {_label(doomed[0].rp_id)}? "
                "This cannot be undone."
            )
        self._approve(pid, uid, message, f"not {command}d")
        # Another request may have changed things during the dialog.
        if command == "delete":
            moved = self.store.remove(target_uid, username, (c.id for c in doomed))
            log.info("Moved %d passkey(s) of uid %d to the trash at the request of uid %d",
                     len(moved), target_uid, uid)
            self._notify_change(target_uid, moved, uid, "moved to the trash")
            return {"ok": True, "deleted": [describe(c) for c in moved]}
        if command == "restore":
            restored = self.store.restore(target_uid, username, (c.id for c in doomed))
            log.info("Restored %d passkey(s) of uid %d at the request of uid %d",
                     len(restored), target_uid, uid)
            return {"ok": True, "restored": [describe(c) for c in restored]}
        purged = self.store.purge(target_uid, username, (c.id for c in doomed))
        log.info("Permanently deleted %d passkey(s) of uid %d at the request of uid %d",
                 len(purged), target_uid, uid)
        self._notify_change(target_uid, purged, uid, "permanently deleted")
        return {"ok": True, "purged": [describe(c) for c in purged]}

    def _export(self, request, pid, uid, target_uid, username):
        """Live passkeys and codes only, with their secrets in the clear: the caller encrypts."""
        for field, kind in (("codes", bool), ("code_ids", list)):
            if field in request and not isinstance(request[field], kind):
                raise ControlError(f"invalid {field} selector")
        with_codes = bool(request.get("codes") or request.get("code_ids"))
        # A passkey-only export never reads totp.json, so a damaged one cannot break it.
        live_codes = self.store.totp_entries(target_uid, username) if with_codes else []
        if request.get("code_ids"):
            # The confirmed request of a client: exactly the codes it showed.
            chosen_codes = self._select({"ids": request["code_ids"]}, live_codes, *CODE_WORDS)
        elif request.get("codes") and request.get("all"):
            chosen_codes = live_codes
        elif request.get("codes") and isinstance(request.get("site"), str) and request["site"]:
            chosen_codes = [e for e in live_codes if e.site == request["site"]]
        else:
            chosen_codes = []
        if with_codes and not any(request.get(field) for field in ("all", "site", "ids")):
            chosen = []  # codes only
        else:
            chosen = self._select(request, self.store.credentials(target_uid, username), empty_ok=with_codes)
        if not chosen and not chosen_codes:
            raise ControlError("nothing to export")
        if request.get("dry_run"):
            return {"ok": True, "user": username, "exported": [describe(c) for c in chosen],
                    "exported_codes": [describe_totp(e) for e in chosen_codes]}
        self._approve(
            pid, uid,
            f"Export {_counts(len(chosen), len(chosen_codes))} stored on this computer? Whoever can "
            "open the exported file can sign in as you.",
            "not exported", ACTION_EXPORT,
        )
        # Another request may have changed things during the dialog.
        live = {c.id: c for c in self.store.credentials(target_uid, username)}
        exported = [live[c.id] for c in chosen if c.id in live]
        records = [record(c, self.store.unseal(target_uid, c)) for c in exported]
        exported_codes = []
        if chosen_codes:
            live_codes = {e.id: e for e in self.store.totp_entries(target_uid, username)}
            exported_codes = [live_codes[e.id] for e in chosen_codes if e.id in live_codes]
        codes = [code_record(e, self.store.totp_unseal(target_uid, e)) for e in exported_codes]
        log.info("Exported %d passkey(s) and %d authenticator code(s) of uid %d at the request of uid %d",
                 len(exported), len(exported_codes), target_uid, uid)
        self._notify_change(target_uid, exported, uid, "exported")
        self._notify_change(target_uid, exported_codes, uid, "exported", **CODE_NOTICE)
        return {"ok": True, "user": username, "exported": [describe(c) for c in exported],
                "credentials": records, "exported_codes": [describe_totp(e) for e in exported_codes],
                "codes": codes}

    def _import(self, request, pid, uid, target_uid, username):
        records = request.get("credentials")
        if not isinstance(records, list):
            raise ControlError("credentials must be a list")
        code_records = request.get("codes", [])
        if not isinstance(code_records, list):
            raise ControlError("codes must be a list")
        if "dry_run" in request and not isinstance(request["dry_run"], bool):
            raise ControlError("invalid dry_run flag")
        if len(records) > MAX_CREDENTIALS_PER_USER:
            raise ControlError(f"at most {MAX_CREDENTIALS_PER_USER} passkeys can be imported at once")
        if len(code_records) > MAX_TOTP_PER_USER:
            raise ControlError(f"at most {MAX_TOTP_PER_USER} authenticator codes can be imported at once")
        # Loading keys is CPU-bound and runs before any prompt: one import at a time per caller.
        with self._slot(uid).importing:
            creds = [_parse_record(i, data, self.store, target_uid) for i, data in enumerate(records)]
            entries = [_parse_totp(data, self.store, target_uid, i) for i, data in enumerate(code_records)]
        imported, skipped = self.store.import_credentials(target_uid, username, creds, dry_run=True)
        # Like export, an import without codes leaves totp.json alone.
        imported_codes, skipped_codes = [], []
        if entries:
            imported_codes, skipped_codes = self.store.totp_import(target_uid, username, entries, dry_run=True)
        if (imported or imported_codes) and not request.get("dry_run"):
            self._approve(pid, uid, f"Import {_counts(len(imported), len(imported_codes))} into this computer?",
                          "not imported")
            # The conflict rules are applied again: the store may have changed.
            imported, skipped = self.store.import_credentials(target_uid, username, creds)
            if entries:
                imported_codes, skipped_codes = self.store.totp_import(target_uid, username, entries)
            log.info("Imported %d passkey(s) and %d authenticator code(s) into uid %d at the request of "
                     "uid %d (%d and %d skipped)", len(imported), len(imported_codes), target_uid, uid,
                     len(skipped), len(skipped_codes))
            self._notify_change(target_uid, imported, uid, "imported", "into")
            self._notify_change(target_uid, imported_codes, uid, "imported", "into", **CODE_NOTICE)
        return {
            "ok": True,
            "user": username,
            "imported": [describe(c) for c in imported],
            "skipped": [{"credential": describe(c), "reason": reason} for c, reason in skipped],
            "imported_codes": [describe_totp(e) for e in imported_codes],
            "skipped_codes": [{"code": describe_totp(e), "reason": reason} for e, reason in skipped_codes],
        }

    def _unlock_key(self, pid, uid):
        try:
            return uid, pid, process_start_time(pid)
        except (OSError, ValueError, IndexError):
            return None  # the process is gone

    def _unlocked(self, pid, uid) -> bool:
        """Whether this process may see codes without a prompt; touching it extends the unlock."""
        if uid == 0:
            return True
        key = self._unlock_key(pid, uid)
        with self._unlocks_lock:
            expiry = self._unlocks.get(key)
            if expiry is not None and expiry <= time.monotonic():
                del self._unlocks[key]
                expiry = None
            return expiry is not None

    def _keep_unlocked(self, key):
        """Extend a live unlock; never creates one, so a racing lock request wins."""
        with self._unlocks_lock:
            expiry = self._unlocks.get(key)
            if expiry is not None and expiry > time.monotonic():
                self._unlocks[key] = time.monotonic() + UNLOCK_IDLE

    def _totp(self, request, pid, uid, target_uid, username):
        action = request.get("action")
        if action not in ("status", "list", "unlock", "lock", "code", "add", "update", "delete", "restore",
                          "purge", "settings"):
            raise ControlError(f"unknown authenticator code action {action!r}")
        if "dry_run" in request and not isinstance(request["dry_run"], bool):
            raise ControlError("invalid dry_run flag")
        require_auth = self.store.totp_require_auth(target_uid, username)
        if action == "status":
            return {
                "ok": True,
                "user": username,
                "require_auth": require_auth,
                # Codes can be shown without a prompt, whether by an unlock or the setting.
                "unlocked": not require_auth or self._unlocked(pid, uid),
                "count": len(self.store.totp_entries(target_uid, username)),
                "trash_count": len(self.store.totp_trash(target_uid, username)),
            }
        if action == "list":
            if "trash" in request and not isinstance(request["trash"], bool):
                raise ControlError("invalid trash selector")
            if request.get("trash"):
                entries = self.store.totp_trash(target_uid, username)
            else:
                entries = self.store.totp_entries(target_uid, username)
            return {"ok": True, "user": username, "codes": [describe_totp(e) for e in entries]}
        if action == "unlock":
            if require_auth and uid != 0:
                key = self._unlock_key(pid, uid)
                self._approve(pid, uid, "Show the authenticator codes stored on this computer?",
                              "not unlocked", ACTION_TOTP)
                if key is not None:  # read before the dialog: the approved process, not a successor
                    with self._unlocks_lock:
                        self._unlocks[key] = time.monotonic() + UNLOCK_IDLE
            return {"ok": True, "unlocked": True}
        if action == "lock":
            key = self._unlock_key(pid, uid)
            with self._unlocks_lock:
                self._unlocks.pop(key, None)
            return {"ok": True}
        if action == "code":
            return self._totp_code(request, pid, uid, target_uid, username, require_auth)
        if action == "settings":
            value = request.get("require_auth")
            if not isinstance(value, bool):
                raise ControlError("require_auth must be true or false")
            if require_auth and not value:
                # Always asked, even when unlocked: this unlocks every process for good.
                self._approve(pid, uid, "Show authenticator codes without asking for your password?",
                              "not changed")
            self.store.set_totp_require_auth(target_uid, username, value)
            if value != require_auth:
                log.info("%s the password for authenticator codes of uid %d at the request of uid %d",
                         "Required" if value else "Stopped requiring", target_uid, uid)
            return {"ok": True, "require_auth": value}

        unlocked = self._unlocked(pid, uid)
        if action == "add":
            entry = _parse_totp(request.get("entry"), self.store, target_uid)
            if request.get("dry_run"):
                return {"ok": True, "added": {**describe_totp(entry), "id": ""}}
            if not unlocked:
                self._approve(pid, uid, f"Save an authenticator code for {_code_label(entry)} on this computer?",
                              "not added")
            self.store.totp_add(target_uid, username, entry)
            log.info("Added an authenticator code for uid %d at the request of uid %d", target_uid, uid)
            self._notify_change(target_uid, [entry], uid, "added", "to", **CODE_NOTICE)
            return {"ok": True, "added": describe_totp(entry)}
        if action == "update":
            if not isinstance(request.get("id"), str):
                raise ControlError("the authenticator code ID must be a string")
            [entry] = self._select({"ids": [request["id"]]}, self.store.totp_entries(target_uid, username),
                                   *CODE_WORDS)

            def fail(problem):
                raise ControlError(problem)

            site, issuer, account = _totp_labels(request, fail)
            if site is None and issuer is None and account is None:
                raise ControlError("nothing to change")
            if not unlocked:
                self._approve(pid, uid,
                              f"Change the details of the authenticator code for {_code_label(entry)}?",
                              "not changed")
            try:
                updated = self.store.totp_update(target_uid, username, entry.id, site, issuer, account)
            except KeyError:
                raise ControlError(f"no authenticator code with ID {entry.id.hex()}") from None
            log.info("Changed an authenticator code of uid %d at the request of uid %d", target_uid, uid)
            return {"ok": True, "updated": describe_totp(updated)}

        # delete looks at the live codes, restore and purge at the trash.
        if action == "delete":
            entries = self.store.totp_entries(target_uid, username)
        else:
            entries = self.store.totp_trash(target_uid, username)
        doomed = self._select(request, entries, *CODE_WORDS)
        if action == "purge" and len(doomed) != 1:
            raise ControlError("purge permanently deletes one authenticator code at a time")
        if request.get("dry_run"):
            return {"ok": True, "deleted": [describe_totp(e) for e in doomed]}
        count = len(doomed)
        plural = "s" if count != 1 else ""
        if action == "delete":
            message = f"Move {count} authenticator code{plural} to the trash?"
        elif action == "restore":
            message = f"Restore {count} authenticator code{plural} from the trash?"
        else:
            message = (f"Permanently delete the authenticator code for {_code_label(doomed[0])}? "
                       "You may lose access to that account. This cannot be undone.")
        if action == "purge" or not unlocked:  # an unlock never covers losing a code for good
            self._approve(pid, uid, message, f"not {action}d")
        # Another request may have changed things during the dialog.
        ids = [e.id for e in doomed]
        if action == "delete":
            moved = self.store.totp_remove(target_uid, username, ids)
            log.info("Moved %d authenticator code(s) of uid %d to the trash at the request of uid %d",
                     len(moved), target_uid, uid)
            self._notify_change(target_uid, moved, uid, "moved to the trash", **CODE_NOTICE)
            return {"ok": True, "deleted": [describe_totp(e) for e in moved]}
        if action == "restore":
            restored = self.store.totp_restore(target_uid, username, ids)
            log.info("Restored %d authenticator code(s) of uid %d at the request of uid %d",
                     len(restored), target_uid, uid)
            return {"ok": True, "restored": [describe_totp(e) for e in restored]}
        purged = self.store.totp_purge(target_uid, username, ids)
        log.info("Permanently deleted %d authenticator code(s) of uid %d at the request of uid %d",
                 len(purged), target_uid, uid)
        self._notify_change(target_uid, purged, uid, "permanently deleted", **CODE_NOTICE)
        return {"ok": True, "purged": [describe_totp(e) for e in purged]}

    def _totp_code(self, request, pid, uid, target_uid, username, require_auth):
        if "ask" in request and not isinstance(request["ask"], bool):
            raise ControlError("invalid ask flag")
        if "site" in request:
            raise ControlError("choose codes by ID or all")
        chosen = self._select(request, self.store.totp_entries(target_uid, username), *CODE_WORDS)
        key = self._unlock_key(pid, uid)
        unlocked = not require_auth or self._unlocked(pid, uid)
        if not unlocked:
            if not request.get("ask"):
                raise ControlError("authenticator codes are locked")
            what = (f"the authenticator code for {_code_label(chosen[0])}" if len(chosen) == 1
                    else f"{len(chosen)} authenticator codes")
            # One-shot: no unlock is recorded, the next request asks again.
            self._approve(pid, uid, f"Show {what}?", "not shown", ACTION_TOTP)
            # Another request may have changed things during the dialog.
            live = {e.id: e for e in self.store.totp_entries(target_uid, username)}
            chosen = [live[e.id] for e in chosen if e.id in live]
        now = time.time()  # the daemon's clock, never the client's
        codes = []
        for entry in chosen:
            value, remaining = totp.code(self.store.totp_unseal(target_uid, entry), entry.algorithm,
                                         entry.digits, entry.period, now)
            codes.append({"id": entry.id.hex(), "code": value, "remaining": remaining, "period": entry.period})
        if require_auth and uid != 0 and unlocked:
            self._keep_unlocked(key)
        return {"ok": True, "codes": codes}

    def _pin(self, request, pid, uid, target_uid, username):
        action = request.get("action")
        if action not in ("status", "set", "remove"):
            raise ControlError(f"unknown PIN action {action!r}")
        if action == "status":
            return {
                "ok": True,
                "user": username,
                "set": self.pins.is_set(target_uid, username),
                "retries": self.pins.retries(target_uid, username),
            }
        if action == "set":
            pin = request.get("pin")
            if not isinstance(pin, str):
                raise ControlError("the PIN must be a string")
            if pin_problem(pin):  # before the dialog, not after the user typed their password
                raise ControlError(PIN_POLICY)
            message = "Set a new PIN for the passkeys stored on this computer?"
        else:
            message = "Remove the PIN for the passkeys stored on this computer?"
        self._approve(pid, uid, message, f"not {action}")
        try:
            if action == "set":
                self.pins.set(target_uid, username, pin.encode())
            else:
                self.pins.remove(target_uid, username)
        except PinError as e:
            if e.code == PIN_POLICY_VIOLATION:
                raise ControlError(PIN_POLICY) from None
            raise ControlError(str(e)) from None
        log.info("%s the PIN of uid %d at the request of uid %d",
                 "Set" if action == "set" else "Removed", target_uid, uid)
        return {"ok": True}

    def _approve(self, pid, uid, message, refusal, action=ACTION_MANAGE):
        if uid == 0:
            return
        verdict = self.verifier.check(process_subject(pid, uid), action, message)
        if verdict is not Verdict.APPROVED:
            raise ControlError(f"{refusal}: authentication {verdict.value}")

    def _notify_change(self, target_uid, doomed, caller_uid, what, preposition="from",
                       noun="passkey", name=lambda c: _label(c.rp_id)):
        if self.notifier is None or not doomed:
            return
        if len(doomed) == 1:
            subject = f"The {noun} for {name(doomed[0])} was"
        else:
            sites = sorted({name(c) for c in doomed})
            subject = f"{len(doomed)} {noun}s for {', '.join(sites[:3])}{', …' if len(sites) > 3 else ''} were"
        by = " by the administrator" if caller_uid != target_uid else ""
        try:
            self.notifier.notify(
                SimpleNamespace(uid=target_uid),
                f"{noun.capitalize()}{'' if len(doomed) == 1 else 's'} {what}",
                f"{subject} {what} {preposition} this computer{by}.",
                ACTIVITY,
            )
        except Exception:
            log.exception("Could not show a desktop notification")

    @staticmethod
    def _target(user, caller_uid):
        if user is None:
            return caller_uid, pwd.getpwuid(caller_uid).pw_name
        if caller_uid != 0:
            raise ControlError("only root can manage other users' passkeys")
        try:
            account = pwd.getpwuid(int(user)) if str(user).isdigit() else pwd.getpwnam(str(user))
        except KeyError:
            raise ControlError(f"no such user: {user}") from None
        return account.pw_uid, account.pw_name

    @staticmethod
    def _select(request, creds, noun="passkey", plural="passkeys", attribute="rp_id", empty_ok=False):
        for field, kind in (("all", bool), ("dry_run", bool), ("site", str), ("ids", list)):
            if field in request and not isinstance(request[field], kind):
                raise ControlError(f"invalid {field} selector")
        if any(not isinstance(prefix, str) for prefix in request.get("ids", [])):
            raise ControlError(f"{noun} IDs must be strings")
        if sum(bool(request.get(field)) for field in ("all", "site", "ids")) != 1:
            raise ControlError("choose one selector: IDs, site, or all")
        if request.get("all"):
            selected = list(creds)
        elif request.get("site"):
            selected = [c for c in creds if getattr(c, attribute) == request["site"]]
        else:
            by_hex = {c.id.hex(): c for c in creds}
            prefixes = dict.fromkeys(prefix.lower() for prefix in request["ids"])
            if len(prefixes) > MAX_CREDENTIALS_PER_USER:
                raise ControlError(f"too many {noun} IDs")
            chosen = {}
            for prefix in prefixes:
                # A full ID always wins: clients send back the full IDs they listed.
                if prefix in by_hex:
                    matches = [by_hex[prefix]]
                else:
                    if len(prefix) < MIN_ID_PREFIX:
                        raise ControlError(
                            f"{noun} ID {prefix!r} is too short (use at least {MIN_ID_PREFIX} characters)")
                    matches = [c for h, c in by_hex.items() if h.startswith(prefix)]
                if not matches:
                    raise ControlError(f"no {noun} with ID {prefix}")
                if len(matches) > 1:
                    raise ControlError(f"{noun} ID {prefix} is ambiguous")
                chosen.setdefault(matches[0].id, matches[0])
            selected = list(chosen.values())
        if not selected and not empty_ok:
            raise ControlError(f"no matching {plural}")
        return selected
