"""Work out which local user, session and application sent a request.

The virtual device is shared by everyone, so for each request the daemon looks
for the processes that have its hidraw node open (normally exactly one
browser). Their owner decides whose passkeys are used, and polkit shows the
confirmation dialog in the session the browser process belongs to.
"""

from __future__ import annotations

import logging
import os
import pwd
from typing import Callable, List, Optional

from gi.repository import Gio, GLib

from .ctap2 import Requester

log = logging.getLogger(__name__)

LOGIND = "org.freedesktop.login1"
LOGIND_PATH = "/org/freedesktop/login1"

_APP_NAMES = {
    "brave": "Brave",
    "brave-browser": "Brave",
    "chrome": "Google Chrome",
    "chromium": "Chromium",
    "chromium-browser": "Chromium",
    "firefox": "Firefox",
    "firefox-bin": "Firefox",
    "firefox-esr": "Firefox",
    "librewolf": "LibreWolf",
    "msedge": "Microsoft Edge",
    "opera": "Opera",
    "thunderbird": "Thunderbird",
    "vivaldi-bin": "Vivaldi",
    "ssh": "SSH",
    "ssh-keygen": "ssh-keygen",
    "ssh-sk-helper": "SSH",
}


def processes_with_open(path: str) -> List[int]:
    """PIDs of the processes that currently have ``path`` open."""
    pids = []
    me = os.getpid()
    with os.scandir("/proc") as processes:
        for entry in processes:
            if not entry.name.isdigit() or int(entry.name) == me:
                continue
            try:
                with os.scandir(f"/proc/{entry.name}/fd") as fds:
                    for fd in fds:
                        try:
                            if os.readlink(fd.path) == path:
                                pids.append(int(entry.name))
                                break
                        except OSError:
                            continue
            except OSError:
                continue
    return pids


def process_uid(pid: int) -> Optional[int]:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def application_name(pid: int) -> Optional[str]:
    try:
        name = os.path.basename(os.readlink(f"/proc/{pid}/exe")).removesuffix(" (deleted)")
    except OSError:
        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
        except OSError:
            return None
    return _APP_NAMES.get(name, name or None)


class Logind:
    def __init__(self, bus: Gio.DBusConnection):
        self.bus = bus

    def _property(self, path, iface, name):
        result = self.bus.call_sync(
            LOGIND, path, "org.freedesktop.DBus.Properties", "Get",
            GLib.Variant("(ss)", (iface, name)), GLib.VariantType("(v)"),
            Gio.DBusCallFlags.NONE, 5000, None,
        )
        return result.unpack()[0]

    def active_session(self) -> Optional[int]:
        """uid of the session in the foreground on seat0."""
        try:
            session_id, path = self._property(
                f"{LOGIND_PATH}/seat/seat0", "org.freedesktop.login1.Seat", "ActiveSession"
            )
            if not session_id:
                return None
            uid, _ = self._property(path, "org.freedesktop.login1.Session", "User")
            return uid
        except GLib.Error:
            return None


class RequesterResolver:
    def __init__(self, device_path: Callable[[], Optional[str]], logind: Logind):
        self._device_path = device_path
        self._logind = logind

    def resolve(self) -> Optional[Requester]:
        path = self._device_path()
        openers = []
        if path:
            for pid in processes_with_open(path):
                uid = process_uid(pid)
                if uid is None:
                    log.warning("Could not identify a process with the authenticator open; denying the request")
                    return None
                openers.append((pid, uid))
        active = self._logind.active_session()

        user_openers = [(pid, uid) for pid, uid in openers if uid != 0]
        uids = {uid for _, uid in user_openers}
        if len(uids) == 1:
            uid = uids.pop()
        elif len(uids) > 1:
            log.warning("Several users have the authenticator open at once; denying the request")
            return None
        elif openers:
            log.warning("Only root processes have the authenticator open; root has no passkeys")
            return None
        else:
            return None
        if active != uid:
            log.warning("The authenticator's user is not in the active local session; denying the request")
            return None

        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            log.warning("uid %d has no passwd entry", uid)
            return None
        pids = [pid for pid, owner in user_openers if owner == uid]
        pid = pids[0]
        apps = {name for name in map(application_name, pids) if name}
        requester = Requester(
            uid=uid,
            username=username,
            pid=pid,
            app_name=apps.pop() if len(apps) == 1 else None,
        )
        log.debug(
            "Request from uid %d via the device's process %s", uid, pid,
        )
        return requester
