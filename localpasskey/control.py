"""Local control socket used by the ``localpasskey`` command.

Each connection carries one JSON request and one JSON reply, one line each.
The kernel tells us the caller's uid (SO_PEERCRED), so users can only see and
manage their own passkeys; root may pass ``"user"`` to manage anyone's.
Deleting moves passkeys to the trash; restoring, purging and the PIN ask the
caller to authenticate through polkit first.
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

from . import cose
from .clientpin import MAX_PIN_BYTES, MIN_PIN_LENGTH, PIN_POLICY_VIOLATION, PinError, PinManager
from .ctap2 import Verdict, _label
from .notify import ACTIVITY
from .polkit import ACTION_MANAGE, process_subject
from .store import StoreError

log = logging.getLogger(__name__)

MAX_REQUEST = 512 * 1024  # Full IDs for all 4096 stored credentials fit in one deletion.
MIN_ID_PREFIX = 4


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


class ControlServer:
    def __init__(self, path, store, verifier, status, notifier=None, pins=None):
        self.path = path
        self.store = store
        self.verifier = verifier
        self.status = status
        self.notifier = notifier
        self.pins = pins or PinManager(store)
        self._sock = None

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
                conn.settimeout(10)
                with conn.makefile("rb") as stream:
                    data = stream.readline(MAX_REQUEST + 1)
                if len(data) > MAX_REQUEST or not data.endswith(b"\n"):
                    return
                conn.settimeout(None)
                try:
                    response = self.handle(json.loads(data), pid, uid)
                except (ControlError, StoreError) as e:
                    response = {"ok": False, "error": str(e)}
                except (ValueError, TypeError, AttributeError) as e:
                    response = {"ok": False, "error": f"bad request: {e}"}
                except Exception as e:
                    log.exception("Control request failed")
                    response = {"ok": False, "error": f"internal error: {e}"}
                conn.sendall(json.dumps(response).encode() + b"\n")
            except OSError as e:
                log.debug("Control connection failed: %s", e)

    def handle(self, request: dict, pid: int, uid: int) -> dict:
        if not isinstance(request, dict):
            raise ControlError("request must be a JSON object")
        command = request.get("command")
        if command == "status":
            return {"ok": True, **self.status()}
        if command not in ("list", "delete", "restore", "purge", "pin"):
            raise ControlError(f"unknown command {command!r}")
        target_uid, username = self._target(request.get("user"), uid)
        if command == "pin":
            return self._pin(request, pid, uid, target_uid, username)

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
            self._notify_deleted(target_uid, moved, uid, "moved to the trash")
            return {"ok": True, "deleted": [describe(c) for c in moved]}
        if command == "restore":
            restored = self.store.restore(target_uid, username, (c.id for c in doomed))
            log.info("Restored %d passkey(s) of uid %d at the request of uid %d",
                     len(restored), target_uid, uid)
            return {"ok": True, "restored": [describe(c) for c in restored]}
        purged = self.store.purge(target_uid, username, (c.id for c in doomed))
        log.info("Permanently deleted %d passkey(s) of uid %d at the request of uid %d",
                 len(purged), target_uid, uid)
        self._notify_deleted(target_uid, purged, uid, "permanently deleted")
        return {"ok": True, "purged": [describe(c) for c in purged]}

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

    def _approve(self, pid, uid, message, refusal):
        if uid == 0:
            return
        verdict = self.verifier.check(process_subject(pid, uid), ACTION_MANAGE, message)
        if verdict is not Verdict.APPROVED:
            raise ControlError(f"{refusal}: authentication {verdict.value}")

    def _notify_deleted(self, target_uid, doomed, caller_uid, what):
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
                f"{subject} {what} from this computer{by}.",
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
            selected = []
            for prefix in request["ids"]:
                prefix = prefix.lower()
                if len(prefix) < MIN_ID_PREFIX:
                    raise ControlError(f"passkey ID {prefix!r} is too short (use at least {MIN_ID_PREFIX} characters)")
                matches = [c for c in creds if c.id.hex().startswith(prefix)]
                if not matches:
                    raise ControlError(f"no passkey with ID {prefix}")
                if len(matches) > 1:
                    raise ControlError(f"passkey ID {prefix} is ambiguous")
                if matches[0] not in selected:
                    selected.append(matches[0])
        if not selected:
            raise ControlError("no matching passkeys")
        return selected
