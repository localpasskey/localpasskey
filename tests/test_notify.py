import os
import pwd
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from localpasskey.notify import ACTIVITY, ERROR, PROBLEM, _HELPER, DesktopNotifier, _reap


class NotificationTests(unittest.TestCase):
    def test_missing_session_bus_does_not_launch_helper(self):
        with patch("localpasskey.notify.os.path.exists", return_value=False), patch("localpasskey.notify.subprocess.Popen") as popen:
            DesktopNotifier().notify(SimpleNamespace(uid=os.getuid()), "test", "body")
            popen.assert_not_called()

    def test_helper_drops_groups_and_escapes_untrusted_markup(self):
        account = pwd.getpwuid(os.getuid())
        with (
            patch("localpasskey.notify.os.path.exists", return_value=True),
            patch("localpasskey.notify.subprocess.Popen") as popen,
            patch("localpasskey.notify.threading.Thread") as thread,
        ):
            DesktopNotifier().notify(SimpleNamespace(uid=account.pw_uid), "Title", "<b>A&B</b>")
        args, kwargs = popen.call_args
        popen.return_value.stdin.write.assert_called_once_with("Title\0&lt;b&gt;A&amp;B&lt;/b&gt;".encode())
        self.assertEqual(kwargs["stdin"], subprocess.PIPE)
        self.assertNotIn("Title", args[0])
        self.assertEqual(args[0][1:3], ["-I", "-c"])
        self.assertEqual(kwargs["user"], account.pw_uid)
        self.assertEqual(kwargs["group"], account.pw_gid)
        self.assertEqual(kwargs["extra_groups"], [])
        self.assertEqual(kwargs["env"]["DBUS_SESSION_BUS_ADDRESS"], f"unix:path=/run/user/{account.pw_uid}/bus")
        self.assertEqual(kwargs["env"]["HOME"], account.pw_dir)
        self.assertEqual(kwargs["cwd"], "/")
        self.assertTrue(kwargs["start_new_session"])
        thread.return_value.start.assert_called_once()

    def notify(self, notifier, kind):
        with (
            patch("localpasskey.notify.os.path.exists", return_value=True),
            patch("localpasskey.notify.subprocess.Popen") as popen,
            patch("localpasskey.notify.threading.Thread"),
        ):
            notifier.notify(SimpleNamespace(uid=os.getuid()), "Title", "Body", kind)
        return popen.call_args.args[0][4:] if popen.called else None

    def test_kinds_choose_icon_urgency_and_transience(self):
        notifier = DesktopNotifier()
        self.assertEqual(self.notify(notifier, ACTIVITY), ["dialog-password", "0", "1"])
        self.assertEqual(self.notify(notifier, PROBLEM), ["dialog-warning", "1", "0"])
        self.assertEqual(self.notify(notifier, ERROR), ["dialog-error", "1", "0"])

    def test_activity_notifications_can_be_turned_off(self):
        notifier = DesktopNotifier(activity=False)
        self.assertIsNone(self.notify(notifier, ACTIVITY))
        self.assertIsNotNone(self.notify(notifier, PROBLEM))
        self.assertIsNotNone(self.notify(notifier, ERROR))

    def test_helper_script_compiles(self):
        compile(_HELPER, "<helper>", "exec")

    def test_hung_notification_helper_is_killed_and_reaped(self):
        proc = Mock()
        proc.wait.side_effect = [subprocess.TimeoutExpired("helper", 15), None]
        _reap(proc)
        proc.kill.assert_called_once()
        self.assertEqual(proc.wait.call_count, 2)


if __name__ == "__main__":
    unittest.main()
