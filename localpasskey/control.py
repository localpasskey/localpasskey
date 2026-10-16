"""Local control socket used by the ``localpasskey`` command.

Each connection carries one JSON request and one JSON reply, one line each.
The kernel tells us the caller's uid (SO_PEERCRED), so users can only see and
manage their own passkeys; root may pass ``"user"`` to manage anyone's.
Deleting moves passkeys to the trash; restoring, purging, the PIN, export and
import ask the caller to authenticate through polkit first.

Export and import exchange "normalized records" (see ``record`` and
``_parse_record``) with plaintext PKCS#8 keys. File formats, passphrases and
encryption are handled by the unprivileged ``transfer`` module; the daemon only
validates records strictly and re-seals imported keys for the target uid.
"""

from __future__ import annotations

import binascii
import errno
import json
import logging
import os
import pwd
import re
import socket
import struct
import threading
import time
from types import SimpleNamespace

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from . import cose
from .clientpin import MAX_PIN_BYTES, MIN_PIN_LENGTH, PIN_POLICY_VIOLATION, PinError, PinManager
from .ctap2 import MAX_CREDENTIAL_ID_LENGTH, MAX_LABEL_LENGTH, MAX_USER_ID_LENGTH, Verdict, _label
from .notify import ACTIVITY
from .polkit import ACTION_EXPORT, ACTION_MANAGE, process_subject
from .store import MAX_CREDENTIALS_PER_USER, Credential, StoreError, b64decode, b64encode

log = logging.getLogger(__name__)

MAX_REQUEST = 16 * 1024 * 1024  # An import of 4096 RSA passkeys fits in one request.
MIN_ID_PREFIX = 4
MAX_RP_ID_LENGTH = 253  # the longest DNS name
READERS_PER_UID = 2  # each reader may hold MAX_REQUEST bytes and their parsed JSON
CONNECTIONS_PER_UID = 8  # open connections per caller, so one uid cannot exhaust our fds
MAX_RSA_BITS = 4096  # loading a bigger key costs seconds of CPU with the GIL held
_B64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")


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


def _key_matches(key, alg) -> bool:
    if alg == cose.ES256:
        return isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1)
    if alg == cose.EDDSA:
        return isinstance(key, ed25519.Ed25519PrivateKey)
    return isinstance(key, rsa.RSAPrivateKey) and 2048 <= key.key_size <= MAX_RSA_BITS


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
            if not _B64URL.fullmatch(text):
                raise ValueError
            return b64decode(text.rstrip("="))
        except (ValueError, binascii.Error):
            fail(f"{name} is not base64url")

    def label(name):
        text = field(name, str)
        if len(text) > MAX_LABEL_LENGTH:
            fail(f"{name} is longer than {MAX_LABEL_LENGTH} characters")
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
    if not rp_id or len(rp_id) > MAX_RP_ID_LENGTH or any(ch.isspace() or not ch.isprintable() for ch in rp_id):
        fail(f"invalid site {rp_id[:MAX_RP_ID_LENGTH]!r}")
    alg = field("alg", int)
    if alg not in cose.SUPPORTED_ALGORITHMS:
        fail(f"unsupported algorithm {alg}")
    der = binary("private_key")
    try:
        key = cose.private_key_from_bytes(der)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        fail("the private key cannot be read")
    if not _key_matches(key, alg):
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
                    conn.sendall(b'{"ok": false, "error": "too many requests in progress"}\n')
                    return
                try:
                    # Held until the reply is sent: the parsed request lives through the dialog.
                    with slot.readers:
                        with conn.makefile("rb") as stream:
                            data = stream.readline(MAX_REQUEST + 1)
                        if len(data) > MAX_REQUEST or not data.endswith(b"\n"):
                            return
                        try:
                            request, error = json.loads(data), None
                        except ValueError as e:
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
                    slot.connections.release()
            except OSError as e:
                log.debug("Control connection failed: %s", e)

    def handle(self, request: dict, pid: int, uid: int) -> dict:
        if not isinstance(request, dict):
            raise ControlError("request must be a JSON object")
        command = request.get("command")
        if command == "status":
            return {"ok": True, **self.status()}
        if command not in ("list", "delete", "restore", "purge", "pin", "export", "import"):
            raise ControlError(f"unknown command {command!r}")
        target_uid, username = self._target(request.get("user"), uid)
        if command == "pin":
            return self._pin(request, pid, uid, target_uid, username)
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
        """Live passkeys only, with their keys in the clear: the caller encrypts."""
        chosen = self._select(request, self.store.credentials(target_uid, username))
        if request.get("dry_run"):
            return {"ok": True, "user": username, "exported": [describe(c) for c in chosen]}
        count = len(chosen)
        self._approve(
            pid, uid,
            f"Export {count} passkey{'s' if count != 1 else ''} stored on this computer? Whoever gets "
            "the exported file and its passphrase can sign in as you.",
            "not exported", ACTION_EXPORT,
        )
        # Another request may have changed things during the dialog.
        live = {c.id: c for c in self.store.credentials(target_uid, username)}
        exported = [live[c.id] for c in chosen if c.id in live]
        records = [record(c, self.store.unseal(target_uid, c)) for c in exported]
        log.info("Exported %d passkey(s) of uid %d at the request of uid %d",
                 len(exported), target_uid, uid)
        self._notify_change(target_uid, exported, uid, "exported")
        return {"ok": True, "user": username, "exported": [describe(c) for c in exported],
                "credentials": records}

    def _import(self, request, pid, uid, target_uid, username):
        records = request.get("credentials")
        if not isinstance(records, list):
            raise ControlError("credentials must be a list")
        if "dry_run" in request and not isinstance(request["dry_run"], bool):
            raise ControlError("invalid dry_run flag")
        if len(records) > MAX_CREDENTIALS_PER_USER:
            raise ControlError(f"at most {MAX_CREDENTIALS_PER_USER} passkeys can be imported at once")
        # Loading keys is CPU-bound and runs before any prompt: one import at a time per caller.
        with self._slot(uid).importing:
            creds = [_parse_record(i, data, self.store, target_uid) for i, data in enumerate(records)]
        imported, skipped = self.store.import_credentials(target_uid, username, creds, dry_run=True)
        if imported and not request.get("dry_run"):
            count = len(imported)
            self._approve(pid, uid, f"Import {count} passkey{'s' if count != 1 else ''} into this computer?",
                          "not imported")
            # The conflict rules are applied again: the store may have changed.
            imported, skipped = self.store.import_credentials(target_uid, username, creds)
            log.info("Imported %d passkey(s) into uid %d at the request of uid %d (%d skipped)",
                     len(imported), target_uid, uid, len(skipped))
            self._notify_change(target_uid, imported, uid, "imported", "into")
        return {
            "ok": True,
            "user": username,
            "imported": [describe(c) for c in imported],
            "skipped": [{"credential": describe(c), "reason": reason} for c, reason in skipped],
        }

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
                raise ControlError(
                    f"the PIN must be at least {MIN_PIN_LENGTH} characters and at most "
                    f"{MAX_PIN_BYTES} bytes long, and must not contain NUL"
                ) from None
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

    def _notify_change(self, target_uid, doomed, caller_uid, what, preposition="from"):
        if self.notifier is None or not doomed:
            return
        if len(doomed) == 1:
            subject = f"The passkey for {_label(doomed[0].rp_id)} was"
        else:
            sites = sorted({_label(c.rp_id) for c in doomed})
            subject = f"{len(doomed)} passkeys for {', '.join(sites[:3])}{', …' if len(sites) > 3 else ''} were"
        by = " by the administrator" if caller_uid != target_uid else ""
        try:
            self.notifier.notify(
                SimpleNamespace(uid=target_uid),
                f"Passkey{'' if len(doomed) == 1 else 's'} {what}",
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
    def _select(request, creds):
        for field, kind in (("all", bool), ("dry_run", bool), ("site", str), ("ids", list)):
            if field in request and not isinstance(request[field], kind):
                raise ControlError(f"invalid {field} selector")
        if any(not isinstance(prefix, str) for prefix in request.get("ids", [])):
            raise ControlError("passkey IDs must be strings")
        if sum(bool(request.get(field)) for field in ("all", "site", "ids")) != 1:
            raise ControlError("choose one selector: IDs, site, or all")
        if request.get("all"):
            selected = list(creds)
        elif request.get("site"):
            selected = [c for c in creds if c.rp_id == request["site"]]
        else:
            by_hex = {c.id.hex(): c for c in creds}
            prefixes = dict.fromkeys(prefix.lower() for prefix in request["ids"])
            if len(prefixes) > MAX_CREDENTIALS_PER_USER:
                raise ControlError("too many passkey IDs")
            chosen = {}
            for prefix in prefixes:
                # A full ID always wins: clients send back the full IDs they listed.
                if prefix in by_hex:
                    matches = [by_hex[prefix]]
                else:
                    if len(prefix) < MIN_ID_PREFIX:
                        raise ControlError(
                            f"passkey ID {prefix!r} is too short (use at least {MIN_ID_PREFIX} characters)")
                    matches = [c for h, c in by_hex.items() if h.startswith(prefix)]
                if not matches:
                    raise ControlError(f"no passkey with ID {prefix}")
                if len(matches) > 1:
                    raise ControlError(f"passkey ID {prefix} is ambiguous")
                chosen.setdefault(matches[0].id, matches[0])
            selected = list(chosen.values())
        if not selected:
            raise ControlError("no matching passkeys")
        return selected
