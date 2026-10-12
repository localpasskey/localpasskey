"""Local control socket used by the ``localpasskey`` command.

Each connection carries one JSON request and one JSON reply, one line each.
The kernel tells us the caller's uid (SO_PEERCRED), so users can only see and
delete their own passkeys; root may pass ``"user"`` to manage anyone's.
Deleting asks the caller to authenticate through polkit first.
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
    }


class ControlServer:
    def __init__(self, path, store, verifier, status, notifier=None):
        self.path = path
        self.store = store
        self.verifier = verifier
        self.status = status
        self.notifier = notifier
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
        if command not in ("list", "delete"):
            raise ControlError(f"unknown command {command!r}")
        target_uid, username = self._target(request.get("user"), uid)
        creds = self.store.credentials(target_uid, username)
        if command == "list":
            return {"ok": True, "user": username, "credentials": [describe(c) for c in creds]}
        doomed = self._select(request, creds)
        if request.get("dry_run"):
            return {"ok": True, "deleted": [describe(c) for c in doomed]}
        if uid != 0:
            count = len(doomed)
            message = (
                f"Delete {count} passkey{'s' if count != 1 else ''} stored on this computer? "
                "You may no longer be able to sign in with them."
            )
            verdict = self.verifier.check(process_subject(pid, uid), ACTION_MANAGE, message)
            if verdict is not Verdict.APPROVED:
                raise ControlError(f"not deleted: authentication {verdict.value}")
        # Another request may have deleted some of them during the dialog.
        deleted = self.store.remove(target_uid, username, (c.id for c in doomed))
        log.info("Deleted %d passkey(s) of uid %d at the request of uid %d", len(deleted), target_uid, uid)
        self._notify_deleted(target_uid, deleted, uid)
        return {"ok": True, "deleted": [describe(c) for c in deleted]}

    def _notify_deleted(self, target_uid, doomed, caller_uid):
        if self.notifier is None or not doomed:
            return
        if len(doomed) == 1:
            what = f"The passkey for {_label(doomed[0].rp_id)} was"
        else:
            sites = sorted({_label(c.rp_id) for c in doomed})
            what = f"{len(doomed)} passkeys for {', '.join(sites[:3])}{', …' if len(sites) > 3 else ''} were"
        by = " by the administrator" if caller_uid != target_uid else ""
        try:
            self.notifier.notify(
                SimpleNamespace(uid=target_uid),
                "Passkey deleted" if len(doomed) == 1 else "Passkeys deleted",
                f"{what} deleted from this computer{by}.",
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
