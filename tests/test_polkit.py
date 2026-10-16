import os
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, mock_open, patch

from gi.repository import GLib

from localpasskey.ctap2 import Verdict
from localpasskey.polkit import ACTION_AUTHENTICATE, PolkitVerifier, process_start_time, process_subject


class PolkitTests(unittest.TestCase):
    def test_process_subject_has_real_pid_uid_and_start_time(self):
        kind, fields = process_subject(os.getpid(), os.getuid())
        self.assertEqual(kind, "unix-process")
        self.assertEqual(fields["pid"].unpack(), os.getpid())
        self.assertEqual(fields["uid"].unpack(), os.getuid())
        self.assertGreater(fields["start-time"].unpack(), 0)
        self.assertEqual(fields["start-time"].unpack(), process_start_time(os.getpid()))

    def test_process_start_time_parses_spaces_and_parentheses_in_name(self):
        stat = "12 (tricky ) process name) " + " ".join(str(n) for n in range(3, 53))
        with patch("builtins.open", mock_open(read_data=stat)):
            self.assertEqual(process_start_time(12), 22)

    def test_reply_verdicts_and_sanitized_prompt(self):
        for authorized, challenge, details, expected in (
            (True, False, {}, Verdict.APPROVED),
            (False, False, {}, Verdict.DENIED),
            (False, True, {"polkit.dismissed": "true"}, Verdict.DENIED),
            (False, True, {}, Verdict.UNAVAILABLE),
        ):
            with self.subTest(expected=expected):
                bus = Mock()
                bus.call_sync.return_value = GLib.Variant("((bba{ss}))", ((authorized, challenge, details),))
                verdict = PolkitVerifier(bus).check(process_subject(os.getpid(), os.getuid()), ACTION_AUTHENTICATE, "one\n\x1b two\tthree")
                self.assertIs(verdict, expected)
                args = bus.call_sync.call_args.args[4].unpack()
                self.assertEqual(args[2]["polkit.message"], "one two three")
                self.assertEqual(args[1], ACTION_AUTHENTICATE)

    def test_missing_process_and_bus_errors_are_unavailable(self):
        bus = Mock()
        verifier = PolkitVerifier(bus)
        with patch("localpasskey.polkit.process_subject", side_effect=FileNotFoundError):
            self.assertIs(verifier.verify(SimpleNamespace(pid=41, uid=1000), "test", None, 1), Verdict.UNAVAILABLE)
        bus.call_sync.assert_not_called()
        bus.call_sync.side_effect = GLib.Error("system bus unavailable")
        self.assertIs(verifier.check(process_subject(os.getpid(), os.getuid()), ACTION_AUTHENTICATE, "test"), Verdict.UNAVAILABLE)

    def test_verify_asks_for_the_authenticate_action(self):
        bus = Mock()
        bus.call_sync.return_value = GLib.Variant("((bba{ss}))", ((True, False, {}),))
        requester = SimpleNamespace(pid=os.getpid(), uid=os.getuid())
        self.assertIs(PolkitVerifier(bus).verify(requester, "msg", threading.Event(), 5.0), Verdict.APPROVED)
        (kind, fields), action_id, details, _flags, _cancel_id = bus.call_sync.call_args.args[4].unpack()
        self.assertEqual((kind, fields["pid"], fields["uid"]), ("unix-process", os.getpid(), os.getuid()))
        self.assertEqual(action_id, ACTION_AUTHENTICATE)
        self.assertEqual(details["polkit.message"], "msg")

    def test_timeout_and_browser_cancellation_cancel_same_authorization(self):
        for expected in (Verdict.TIMED_OUT, Verdict.CANCELLED):
            with self.subTest(expected=expected):
                checked = []
                stopped = threading.Event()
                cancelled = threading.Event()
                if expected is Verdict.CANCELLED:
                    cancelled.set()

                def call(_destination, _path, _interface, method, args, *_rest):
                    if method == "CheckAuthorization":
                        checked.append(args.unpack()[-1])
                        if not stopped.wait(2):
                            raise AssertionError("authorization was never cancelled")
                        return GLib.Variant("((bba{ss}))", ((True, False, {}),))
                    self.assertEqual(method, "CancelCheckAuthorization")
                    self.assertEqual(args.unpack(), (checked[0],))
                    stopped.set()

                bus = Mock()
                bus.call_sync.side_effect = call
                result = PolkitVerifier(bus).check(process_subject(os.getpid(), os.getuid()), ACTION_AUTHENTICATE, "test", cancelled, 0.01)
                self.assertIs(result, expected)
                self.assertTrue(stopped.is_set())


if __name__ == "__main__":
    unittest.main()
