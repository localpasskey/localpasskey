import contextlib
import fcntl
import io
import os
import signal
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from localpasskey import __version__, daemon, uhid
from localpasskey.config import Config


class DaemonTests(unittest.TestCase):
    def test_version_matches_debian_changelog(self):
        # The daemon reports __version__ to browsers (getInfo, CTAPHID INIT) and in `status`.
        changelog = Path(__file__).resolve().parent.parent / "debian" / "changelog"
        first_line = changelog.read_text().splitlines()[0]
        self.assertEqual(first_line.split("(", 1)[1].split(")", 1)[0], __version__)

    def test_systemd_notifications_use_real_filesystem_and_abstract_sockets(self):
        with tempfile.TemporaryDirectory() as directory:
            for address in (f"{directory}/notify", f"\0localpasskey-test-{os.getpid()}"):
                with self.subTest(address=address), socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
                    receiver.settimeout(1)
                    receiver.bind(address)
                    with patch.dict(os.environ, {"NOTIFY_SOCKET": address.replace("\0", "@", 1)}):
                        daemon.sd_notify("READY=1\nSTATUS=Testing")
                    self.assertEqual(receiver.recv(1024), b"READY=1\nSTATUS=Testing")

    def test_systemd_notification_failure_is_nonfatal(self):
        with patch.dict(os.environ, {"NOTIFY_SOCKET": "/missing/localpasskey/notify"}):
            daemon.sd_notify("READY=1")

    def test_invalid_configuration_stops_before_opening_device(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            config.write_text("[daemon]\nprompt_timeout = 0\n")
            with patch("localpasskey.daemon.run") as run, contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(daemon.main(["--config", str(config)]), 2)
            run.assert_not_called()
            self.assertIn("invalid configuration", error.getvalue())

    def test_daemon_dispatch_and_signal_descriptor_cleanup(self):
        previous_handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        previous_wakeup = signal.set_wakeup_fd(-1)
        signal.set_wakeup_fd(previous_wakeup)
        descriptors = []
        real_pipe2 = os.pipe2

        def pipe(flags):
            pair = real_pipe2(flags)
            descriptors.extend(pair)
            return pair

        def cleanup():
            signal.set_wakeup_fd(previous_wakeup)
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
            for fd in descriptors:
                try:
                    os.close(fd)
                except OSError:
                    pass

        self.addCleanup(cleanup)
        events = iter((uhid.UHID_OUTPUT, uhid.UHID_CLOSE, uhid.UHID_GET_REPORT, uhid.UHID_SET_REPORT, uhid.UHID_START))
        device = Mock(fd=42)
        device.output_report.return_value = bytes(64)

        def select(*_args):
            event = next(events)
            device.read_event.return_value = (event, b"payload")
            if event == uhid.UHID_START:
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return [42], [], []

        with (
            tempfile.TemporaryDirectory() as directory,
            patch("gi.repository.Gio.bus_get_sync"),
            patch("localpasskey.uhid.UhidDevice", return_value=device),
            patch("localpasskey.ctaphid.CtapHidTransport") as transport,
            patch("localpasskey.control.ControlServer") as control,
            patch("localpasskey.daemon.os.pipe2", side_effect=pipe),
            patch("localpasskey.daemon.select.select", side_effect=select),
            patch("localpasskey.daemon._wait_for_hidraw", return_value="/dev/hidraw42"),
            patch("localpasskey.daemon.sd_notify") as notify,
        ):
            self.assertEqual(daemon.run(Config(notifications=False), directory, str(Path(directory) / "socket")), 0)
        control.return_value.start.assert_called_once()
        control.return_value.stop.assert_called_once()
        transport.return_value.handle_report.assert_called_once_with(bytes(64))
        self.assertEqual(transport.return_value.reset.call_count, 2)
        self.assertEqual(transport.return_value.tick.call_count, 5)
        self.assertEqual(device.reject_report_request.call_count, 2)
        device.close.assert_called_once()
        self.assertEqual(notify.call_args.args, ("STOPPING=1",))
        for signum, handler in previous_handlers.items():
            self.assertEqual(signal.getsignal(signum), handler)
        self.assertEqual(signal.set_wakeup_fd(previous_wakeup), previous_wakeup)
        for fd in descriptors:
            with self.assertRaises(OSError):
                fcntl.fcntl(fd, fcntl.F_GETFD)
        descriptors.clear()


if __name__ == "__main__":
    unittest.main()
