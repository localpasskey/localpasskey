import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

from localpasskey.session import RequesterResolver, application_name, process_uid, processes_with_open


class SessionTests(unittest.TestCase):
    def test_real_process_open_file_and_identity(self):
        with tempfile.NamedTemporaryFile() as target:
            proc = subprocess.Popen(
                [sys.executable, "-c", "import sys; f=open(sys.argv[1]); print('ready', flush=True); sys.stdin.read(1)", target.name],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            )
            try:
                self.assertEqual(proc.stdout.readline(), "ready\n")
                self.assertIn(proc.pid, processes_with_open(target.name))
                self.assertEqual(process_uid(proc.pid), os.getuid())
                self.assertIsNotNone(application_name(proc.pid))
            finally:
                proc.communicate("x", timeout=5)
            self.assertNotIn(proc.pid, processes_with_open(target.name))
            self.assertIsNone(process_uid(proc.pid))
            self.assertIsNone(application_name(proc.pid))

    def resolve(self, owners, active=1000, app="Firefox"):
        logind = Mock()
        logind.active_session.return_value = active
        with (
            patch("localpasskey.session.processes_with_open", return_value=list(owners)),
            patch("localpasskey.session.process_uid", side_effect=owners.get),
            patch("localpasskey.session.pwd.getpwuid", return_value=SimpleNamespace(pw_name="alice")),
            patch("localpasskey.session.application_name", return_value=app),
        ):
            return RequesterResolver(lambda: "/dev/hidraw42", logind).resolve()

    def test_single_active_uid_is_attributed_to_real_opener(self):
        requester = self.resolve({41: 1000, 42: 1000})
        self.assertEqual((requester.uid, requester.username, requester.pid, requester.app_name), (1000, "alice", 41, "Firefox"))

    def test_ambiguous_absent_and_unreadable_openers_are_denied(self):
        for owners in ({41: 1000, 42: 1001}, {}, {41: None}, {41: 1000, 42: None}, {41: 0}):
            with self.subTest(owners=owners):
                self.assertIsNone(self.resolve(owners))

    def test_inactive_or_missing_session_is_denied(self):
        for active in (1001, None):
            with self.subTest(active=active):
                self.assertIsNone(self.resolve({41: 1000}, active))

    def test_executable_name_falls_back_when_process_exits(self):
        from unittest.mock import mock_open
        with patch("localpasskey.session.os.readlink", side_effect=FileNotFoundError), patch("builtins.open", mock_open(read_data="firefox\n")):
            self.assertEqual(application_name(41), "Firefox")

    def test_scanner_stops_at_match_and_closes_during_process_races(self):
        closed = []

        def descriptors(path):
            if path == "/proc/13/fd":
                raise FileNotFoundError(path)
            yield SimpleNamespace(path=f"{path}/gone")
            yield SimpleNamespace(path=f"{path}/device")
            self.fail("enumerated descriptors after a match")

        @contextmanager
        def scan(path):
            if path == "/proc/11/fd":
                raise PermissionError(path)
            try:
                yield (
                    (SimpleNamespace(name=n) for n in ("self", "10", "11", "12", "13"))
                    if path == "/proc" else descriptors(path)
                )
            finally:
                closed.append(path)

        def readlink(path):
            if path.endswith("/gone"):
                raise FileNotFoundError(path)
            return "/dev/hidraw42"

        with (
            patch("localpasskey.session.os.getpid", return_value=10),
            patch("localpasskey.session.os.scandir", side_effect=scan),
            patch("localpasskey.session.os.readlink", side_effect=readlink),
        ):
            self.assertEqual(processes_with_open("/dev/hidraw42"), [12])
        self.assertEqual(closed, ["/proc/12/fd", "/proc/13/fd", "/proc"])


if __name__ == "__main__":
    unittest.main()
