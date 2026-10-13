"""localpasskeyd: the system service behind the virtual security key."""

from __future__ import annotations

import argparse
import configparser
import logging
import os
import secrets
import select
import signal
import socket
import sys
import time

from . import __version__
from .config import DEFAULT_PATH, load_config

log = logging.getLogger("localpasskeyd")


class _JournalFormatter(logging.Formatter):
    """Prefix messages with their syslog priority, which journald understands."""

    _PRIORITIES = {logging.DEBUG: 7, logging.INFO: 6, logging.WARNING: 4, logging.ERROR: 3}

    def format(self, record):
        return f"<{self._PRIORITIES.get(record.levelno, 2)}>{super().format(record)}"


def _setup_logging(level):
    handler = logging.StreamHandler(sys.stderr)
    if os.environ.get("JOURNAL_STREAM"):
        handler.setFormatter(_JournalFormatter("%(message)s"))
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=getattr(logging, level.upper()), handlers=[handler])


def sd_notify(state):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
            sock.connect(address)
            sock.sendall(state.encode())
    except OSError as e:
        log.debug("sd_notify failed: %s", e)


def _wait_for_hidraw(device, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        path = device.hidraw_path()
        if path:
            return path
        time.sleep(0.05)
    return None


def run(config, state_dir, socket_path):
    from gi.repository import Gio

    from . import uhid
    from .clientpin import PinManager
    from .control import ControlServer
    from .ctap2 import Authenticator
    from .ctaphid import CtapHidTransport
    from .notify import DesktopNotifier
    from .polkit import PolkitVerifier
    from .session import Logind, RequesterResolver
    from .store import CredentialStore

    store = CredentialStore(state_dir)
    # One PinManager for both servers, so a PIN set from a browser and one set
    # from `localpasskey pin set` are the same PIN and the same tokens.
    pins = PinManager(store)
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    verifier = PolkitVerifier(bus)
    version = tuple(int(part) for part in __version__.split(".")[:3])
    device = uhid.UhidDevice(
        config.device_name,
        f"localpasskey-{secrets.token_hex(8)}",
        config.vendor_id,
        config.product_id,
        version=version[0] << 8 | version[1],
    )
    notifier = DesktopNotifier(config.activity_notifications) if config.notifications else None
    authenticator = Authenticator(
        store,
        RequesterResolver(device.hidraw_path, Logind(bus)),
        verifier,
        notifier,
        config.prompt_timeout,
        pins=pins,
    )
    transport = CtapHidTransport(device.send_input, authenticator, version)
    control = ControlServer(
        socket_path,
        store,
        verifier,
        lambda: {"version": __version__, "device": device.hidraw_path()},
        notifier,
        pins=pins,
    )

    wake_read, wake_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    previous_wakeup = signal.set_wakeup_fd(wake_write)
    stop = []
    previous_handlers = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.signal(signum, lambda signum, frame: stop.append(signum))

    try:
        control.start()
        hidraw = _wait_for_hidraw(device)
        if hidraw:
            log.info("LocalPasskey %s ready: virtual security key is %s", __version__, hidraw)
        else:
            log.warning("The kernel did not create a hidraw node for the virtual security key")
        sd_notify(f"READY=1\nSTATUS=Virtual security key {hidraw or 'missing'}")

        while not stop:
            readable, _, _ = select.select([device.fd, wake_read], [], [], transport.poll_timeout())
            if wake_read in readable:
                try:
                    os.read(wake_read, 64)
                except BlockingIOError:
                    pass
            if device.fd in readable:
                event, payload = device.read_event()
                if event == uhid.UHID_OUTPUT:
                    report = device.output_report(payload)
                    if report is not None:
                        transport.handle_report(report)
                elif event == uhid.UHID_CLOSE:
                    log.debug("All hosts closed the device")
                    transport.reset()
                elif event in (uhid.UHID_GET_REPORT, uhid.UHID_SET_REPORT):
                    device.reject_report_request(event, payload)
                else:
                    log.debug("uhid event %d", event)
            transport.tick()
    finally:
        sd_notify("STOPPING=1")
        control.stop()
        transport.reset()
        device.close()
        signal.set_wakeup_fd(previous_wakeup)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        os.close(wake_read)
        os.close(wake_write)
    log.info("Stopped")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="localpasskeyd",
        description="Software FIDO2/WebAuthn authenticator that stores passkeys on this computer.",
    )
    parser.add_argument("--config", default=DEFAULT_PATH, help="configuration file (default: %(default)s)")
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("STATE_DIRECTORY", "/var/lib/localpasskey"),
        help="where passkeys are stored (default: %(default)s)",
    )
    parser.add_argument(
        "--socket",
        default=os.path.join(os.environ.get("RUNTIME_DIRECTORY", "/run/localpasskey"), "control.sock"),
        help="control socket for the localpasskey command (default: %(default)s)",
    )
    parser.add_argument("--debug", action="store_true", help="verbose logging, including site names")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except (ValueError, configparser.Error) as e:
        print(f"localpasskeyd: invalid configuration in {args.config}: {e}", file=sys.stderr)
        return 2
    _setup_logging("debug" if args.debug else config.log_level)
    try:
        return run(config, args.state_dir, args.socket)
    except PermissionError as e:
        log.error("%s (localpasskeyd must run as root)", e)
        return 1
