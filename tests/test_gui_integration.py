import os
import pwd
import threading
import time
import unittest
from unittest.mock import patch

try:
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication, QMessageBox

    from localpasskey import gui
except ImportError:
    gui = None

from localpasskey.ctap2 import Verdict
from tests.gui_demo import start_backend
from tests.test_control import FakePolkit


@unittest.skipIf(gui is None, "PyQt6 and QDarkStyle are not installed")
class WindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {"QT_QPA_PLATFORM": "offscreen"}):
            cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.environment = patch.dict(os.environ)
        self.environment.start()
        self.server, self.tmp = start_backend()
        self.server.verifier = FakePolkit(Verdict.APPROVED)
        self.uid = os.getuid()
        self.username = pwd.getpwuid(self.uid).pw_name
        self.window = gui.Window()
        self.window._timer.stop()
        self.window.show()
        self.wait_for(lambda: not self.window._refreshing)
        self.assertEqual(self.window.model.rowCount(), 7)

    def tearDown(self):
        self.wait_for(lambda: not self.window._refreshing)
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()
        self.server.stop()
        self.tmp.cleanup()
        self.environment.stop()

    def wait_for(self, condition):
        deadline = time.monotonic() + 5
        while not condition() and time.monotonic() < deadline:
            QTest.qWait(10)
        self.assertTrue(condition(), "Qt/control-socket operation did not complete")

    def answer_delete(self, accept, inspect=None):
        def answer():
            box = self.app.activeModalWidget()
            if inspect is not None:
                inspect.append(box)
            button = next(
                button for button in box.buttons()
                if (box.buttonRole(button) == QMessageBox.ButtonRole.DestructiveRole) == accept
            )
            QTest.mouseClick(button, Qt.MouseButton.LeftButton)

        QTimer.singleShot(0, answer)

    def test_window_loads_over_socket_and_keyboard_search_selects_visible_result(self):
        self.assertEqual(self.window.count_label.text(), "7 passkeys")
        self.assertEqual(self.window.service_label.text(), "Service running")
        self.assertEqual(self.window.details.cred["site"], "amazon.com")
        QTest.keyClicks(self.window.search, "GIT octo-work")
        self.assertEqual(self.window.proxy.rowCount(), 1)
        self.assertEqual(self.window.details.username.text(), "octo-work")
        QTest.keyClick(self.window.search, Qt.Key.Key_Escape)
        self.assertEqual(self.window.proxy.rowCount(), 7)
        self.assertEqual(self.window.details.username.text(), "octo-work")

    def test_no_matches_disables_actions_and_clearing_recovers_selection(self):
        self.window.search.setText("nobody")
        self.assertEqual(self.window.message.title.text(), "No matching passkeys")
        for action in (self.window.copy_action, self.window.open_action, self.window.delete_action):
            self.assertFalse(action.isEnabled())
        self.window.search.clear()
        self.assertIs(self.window.side.currentWidget(), self.window.details)
        self.assertEqual(self.window.details.cred["site"], "amazon.com")

    def test_selection_survives_refresh_and_last_use_reorders_numerically(self):
        self.window.search.setText("github the octocat")
        selected = self.window.details.cred["id"]
        self.window.search.clear()
        self.server.store.record_use(self.uid, self.username, bytes.fromhex(selected))
        self.window.refresh()
        self.wait_for(lambda: not self.window._refreshing)
        self.assertEqual(self.window.details.cred["id"], selected)
        self.window.table.sortByColumn(2, Qt.SortOrder.DescendingOrder)
        self.assertEqual(self.window.proxy.index(0, 0).data(gui.CRED_ROLE)["id"], selected)

    def test_copy_and_open_use_the_selected_credential(self):
        self.window.search.setText("github the octocat")
        self.window.copy_action.trigger()
        self.assertEqual(self.app.clipboard().text(), "octocat")
        with patch.object(gui.QDesktopServices, "openUrl", return_value=False) as opened:
            self.window.open_action.trigger()
        self.assertEqual(opened.call_args.args[0].toString(), "https://github.com/")
        self.assertEqual(self.window.statusBar().currentMessage(), "Could not open the website")

    def test_cancel_delete_keeps_store_and_does_not_authenticate(self):
        self.answer_delete(False)
        self.window.delete_action.trigger()
        self.assertEqual(len(self.server.store.credentials(self.uid, self.username)), 7)
        self.assertEqual(self.server.verifier.checks, [])

    @unittest.skipIf(os.getuid() == 0, "root intentionally bypasses deletion authentication")
    def test_denied_delete_keeps_credential_and_restores_button(self):
        self.server.verifier.verdict = Verdict.DENIED
        self.answer_delete(True)
        self.window.delete_action.trigger()
        self.wait_for(lambda: "authentication denied" in self.window.statusBar().currentMessage())
        self.assertEqual(self.window.model.rowCount(), 7)
        self.assertTrue(self.window.details.delete_button.isEnabled())
        self.assertEqual(len(self.server.verifier.checks), 1)

    def test_approved_delete_updates_store_and_selection(self):
        deleted_id = self.window.details.cred["id"]
        self.answer_delete(True)
        QTest.mouseClick(self.window.details.delete_button, Qt.MouseButton.LeftButton)
        self.wait_for(lambda: self.window.model.rowCount() == 6 and not self.window._refreshing)
        self.assertNotEqual(self.window.details.cred["id"], deleted_id)
        self.assertEqual(self.window.count_label.text(), "6 passkeys")

    @unittest.skipIf(os.getuid() == 0, "root intentionally bypasses deletion authentication")
    def test_pending_delete_stays_disabled_across_selection_and_refresh(self):
        started, release = threading.Event(), threading.Event()

        def authorize(*args, **kwargs):
            started.set()
            if not release.wait(5):
                raise TimeoutError("test did not release authentication")
            return Verdict.APPROVED

        self.server.verifier.check = authorize
        self.answer_delete(True)
        self.window.delete_action.trigger()
        try:
            self.wait_for(started.is_set)
            self.assertFalse(self.window.delete_action.isEnabled())
            self.assertFalse(self.window.details.delete_button.isEnabled())
            self.window.search.setText("github the octocat")
            cred_id = bytes.fromhex(self.window.details.cred["id"])
            self.server.store.record_use(self.uid, self.username, cred_id)
            self.window.refresh()
            self.wait_for(lambda: not self.window._refreshing)
            self.assertFalse(self.window.delete_action.isEnabled())
            self.assertFalse(self.window.details.delete_button.isEnabled())
        finally:
            release.set()
            self.wait_for(lambda: self.window.model.rowCount() == 6 and not self.window._refreshing)
        self.assertTrue(self.window.delete_action.isEnabled())
        self.assertTrue(self.window.details.delete_button.isEnabled())

    def test_service_disconnect_and_reconnect(self):
        with patch.dict(os.environ, {"LOCALPASSKEY_SOCKET": os.path.join(self.tmp.name, "missing.sock")}):
            self.window.refresh()
            self.wait_for(lambda: not self.window._refreshing)
        self.assertEqual(self.window.service_label.text(), "Service not running")
        self.assertEqual(self.window.model.rowCount(), 0)
        self.assertFalse(self.window.delete_action.isEnabled())
        self.window.refresh()
        self.wait_for(lambda: not self.window._refreshing)
        self.assertEqual(self.window.model.rowCount(), 7)
        self.assertEqual(self.window.service_label.text(), "Service running")

    def test_credential_markup_is_displayed_as_plain_text(self):
        cred = {**self.window.details.cred, "site": "<b>example.com</b>",
                "site_name": "<b>Trusted bank</b>", "user_name": "<b>Alice</b>"}
        self.window._show(cred)
        self.assertEqual(self.window.details.site.textFormat(), Qt.TextFormat.PlainText)
        self.assertEqual(self.window.details.summary.textFormat(), Qt.TextFormat.PlainText)
        dialogs = []
        self.answer_delete(False, dialogs)
        self.window.confirm_delete(cred)
        self.assertEqual(dialogs[0].textFormat(), Qt.TextFormat.PlainText)

    def test_empty_store_shows_onboarding(self):
        self.server.store.remove(self.uid, self.username,
                                 [bytes.fromhex(cred["id"]) for cred in self.window._creds])
        self.window.refresh()
        self.wait_for(lambda: not self.window._refreshing)
        self.assertEqual(self.window.count_label.text(), "0 passkeys")
        self.assertEqual(self.window.message.title.text(), "No passkeys yet")

    def test_background_task_returns_success_and_error_on_gui_thread(self):
        task = gui.Tasks()
        received = []
        owner = threading.get_ident()

        def done(result, error):
            received.append((result, error, threading.get_ident()))

        task.run(threading.get_ident, done)
        self.wait_for(lambda: bool(received))
        self.assertNotEqual(received[0][0], owner)
        self.assertIsNone(received[0][1])
        self.assertEqual(received[0][2], owner)
        task.run(lambda: 1 / 0, done)
        self.wait_for(lambda: len(received) == 2)
        self.assertIsInstance(received[1][1], ZeroDivisionError)
        self.assertEqual(received[1][2], owner)


if __name__ == "__main__":
    unittest.main()
