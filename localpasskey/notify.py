"""Desktop notifications in a user's session.

The daemon runs as root, so it starts a small helper as the target user that
talks to the notification server on that user's session bus.

Notifications come in three kinds: ``ACTIVITY`` (a passkey was saved, used or
deleted), ``PROBLEM`` (a request was refused or could not be answered) and
``ERROR`` (something went wrong inside LocalPasskey).
"""

from __future__ import annotations

import html
import logging
import os
import pwd
import subprocess
import sys
import threading

log = logging.getLogger(__name__)

ACTIVITY = "activity"
PROBLEM = "problem"
ERROR = "error"

# kind: (icon, urgency, transient). Activity notes are transient so that a
# day of sign-ins doesn't pile up in the notification history.
_STYLES = {
    ACTIVITY: ("dialog-password", 0, True),
    PROBLEM: ("dialog-warning", 1, False),
    ERROR: ("dialog-error", 1, False),
}

_HELPER = """
import sys
from gi.repository import Gio, GLib
summary, body, icon, urgency, transient = sys.argv[1:6]
hints = {
    "urgency": GLib.Variant("y", int(urgency)),
    "transient": GLib.Variant("b", transient == "1"),
    "desktop-entry": GLib.Variant("s", "org.localpasskey.Manager"),
}
bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
bus.call_sync(
    "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
    "org.freedesktop.Notifications", "Notify",
    GLib.Variant("(susssasa{sv}i)", ("LocalPasskey", 0, icon, summary, body, [], hints, 10000)),
    None, Gio.DBusCallFlags.NONE, 5000, None)
"""


def _reap(proc):
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


class DesktopNotifier:
    def __init__(self, activity: bool = True):
        """``activity=False`` shows only PROBLEM and ERROR notifications."""
        self.activity = activity

    def notify(self, requester, summary: str, body: str, kind: str = PROBLEM) -> None:
        if kind == ACTIVITY and not self.activity:
            return
        icon, urgency, transient = _STYLES[kind]
        runtime_dir = f"/run/user/{requester.uid}"
        bus = f"{runtime_dir}/bus"
        if not os.path.exists(bus):
            log.debug("uid %d has no session bus; not notifying", requester.uid)
            return
        account = pwd.getpwuid(requester.uid)
        env = {
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
            "XDG_RUNTIME_DIR": runtime_dir,
            "HOME": account.pw_dir,
            "PATH": "/usr/bin:/bin",
            "LANG": os.environ.get("LANG", "C.UTF-8"),
        }
        proc = subprocess.Popen(
            [
                sys.executable, "-I", "-c", _HELPER,
                summary, html.escape(body, quote=False), icon, str(urgency), "1" if transient else "0",
            ],
            user=account.pw_uid,
            group=account.pw_gid,
            extra_groups=[],
            env=env,
            cwd="/",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        threading.Thread(target=_reap, args=(proc,), daemon=True).start()
