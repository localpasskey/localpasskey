"""User verification through polkit.

polkit shows its authentication dialog in the requesting user's session and
asks for that user's own password (``auth_self``), or whatever else PAM is
configured to accept, such as a fingerprint via fprintd. That makes it the
Linux counterpart of the Windows Hello prompt. Requests are cancelled with
CancelCheckAuthorization when the browser gives up, which closes the dialog.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time

from gi.repository import Gio, GLib

from .ctap2 import Verdict

log = logging.getLogger(__name__)

AUTHORITY = "org.freedesktop.PolicyKit1"
AUTHORITY_PATH = "/org/freedesktop/PolicyKit1/Authority"
AUTHORITY_IFACE = "org.freedesktop.PolicyKit1.Authority"
ALLOW_USER_INTERACTION = 0x1

ACTION_AUTHENTICATE = "org.localpasskey.authenticate"
ACTION_MANAGE = "org.localpasskey.manage"
ACTION_EXPORT = "org.localpasskey.export"
ACTION_TOTP = "org.localpasskey.totp"


def process_start_time(pid: int) -> int:
    with open(f"/proc/{pid}/stat") as f:
        stat = f.read()
    return int(stat[stat.rindex(")") + 2 :].split()[19])


def process_subject(pid: int, uid: int):
    return (
        "unix-process",
        {
            "pid": GLib.Variant("u", pid),
            "start-time": GLib.Variant("t", process_start_time(pid)),
            "uid": GLib.Variant("i", uid),
        },
    )


def _clean(message: str) -> str:
    return " ".join("".join(ch if ch.isprintable() else " " for ch in message).split())


class PolkitVerifier:
    def __init__(self, bus: Gio.DBusConnection):
        self.bus = bus

    def verify(self, requester, message, cancelled, timeout) -> Verdict:
        """Ask the user behind a CTAP request to approve it."""
        # Always a unix-process subject: polkitd 126 (Debian 13) aborts on
        # unix-session subjects. polkit maps processes outside any session
        # (apps run as systemd user units) to the user's graphical session.
        try:
            subject = process_subject(requester.pid, requester.uid)
        except (OSError, ValueError):
            log.warning("Process %d went away before it could be verified", requester.pid)
            return Verdict.UNAVAILABLE
        return self.check(subject, ACTION_AUTHENTICATE, message, cancelled, timeout)

    def check(self, subject, action_id, message, cancelled=None, timeout=120.0) -> Verdict:
        cancellation_id = f"localpasskey-{secrets.token_hex(8)}"
        args = GLib.Variant(
            "((sa{sv})sa{ss}us)",
            (subject, action_id, {"polkit.message": _clean(message)}, ALLOW_USER_INTERACTION, cancellation_id),
        )
        finished = threading.Event()
        stopped = []

        def watch():
            deadline = time.monotonic() + timeout
            while not finished.wait(0.05):
                if cancelled is not None and cancelled.is_set():
                    stopped.append(Verdict.CANCELLED)
                elif time.monotonic() >= deadline:
                    stopped.append(Verdict.TIMED_OUT)
                else:
                    continue
                try:
                    self.bus.call_sync(
                        AUTHORITY, AUTHORITY_PATH, AUTHORITY_IFACE, "CancelCheckAuthorization",
                        GLib.Variant("(s)", (cancellation_id,)), None,
                        Gio.DBusCallFlags.NONE, 5000, None,
                    )
                except GLib.Error as e:
                    log.debug("CancelCheckAuthorization failed: %s", e.message)
                return

        watcher = threading.Thread(target=watch, name="polkit-watch", daemon=True)
        watcher.start()
        try:
            reply = self.bus.call_sync(
                AUTHORITY, AUTHORITY_PATH, AUTHORITY_IFACE, "CheckAuthorization", args,
                GLib.VariantType("((bba{ss}))"), Gio.DBusCallFlags.NONE,
                int((timeout + 30) * 1000), None,
            )
        except GLib.Error as e:
            if stopped:
                return stopped[0]
            log.warning("polkit authorization check failed: %s", e.message)
            return Verdict.UNAVAILABLE
        finally:
            finished.set()
            watcher.join()
        if stopped:
            return stopped[0]

        ((authorized, challenge, details),) = reply.unpack()
        if authorized:
            return Verdict.APPROVED
        if details.get("polkit.dismissed"):
            return Verdict.DENIED
        if challenge:
            log.warning(
                "polkit could not ask the user to authenticate; is a polkit "
                "authentication agent running in their session?"
            )
            return Verdict.UNAVAILABLE
        return Verdict.DENIED
