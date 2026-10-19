import os
import pwd
import threading
import time
import unittest
from unittest.mock import patch

try:
    from PyQt6.QtCore import QEvent, QItemSelectionModel, Qt, QTimer
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication, QDialogButtonBox, QMessageBox

    from localpasskey import gui
except ImportError:
    gui = None

from localpasskey import cose, totp
from localpasskey.client import ServiceError, ServiceUnavailable
from localpasskey.clientpin import MAX_PIN_RETRIES, pin_hash
from localpasskey.ctap2 import Verdict
from localpasskey.store import Credential, PinState, TotpEntry
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
            if box is None:  # bulk actions open the box only after their dry run
                QTimer.singleShot(10, answer)
                return
            if inspect is not None:
                inspect.append(box)
            button = next(
                button for button in box.buttons()
                if (box.buttonRole(button) == QMessageBox.ButtonRole.DestructiveRole) == accept
            )
            QTest.mouseClick(button, Qt.MouseButton.LeftButton)

        QTimer.singleShot(0, answer)

    def answer_dialog(self, inspect):
        """Hand the next modal dialog to ``inspect`` once it has laid itself out."""
        def look():
            dialog = self.app.activeModalWidget()
            if dialog is None:
                QTimer.singleShot(10, look)
            else:
                inspect(dialog)

        QTimer.singleShot(0, look)

    @staticmethod
    def destructive(dialog):
        box = dialog.findChild(QDialogButtonBox)
        return next(b for b in box.buttons() if box.buttonRole(b) == QDialogButtonBox.ButtonRole.DestructiveRole)

    def set_trash_view(self, on):
        if self.window.trash_action.isChecked() != on:
            self.window.trash_action.toggle()
        self.wait_for(lambda: not self.window._refreshing and self.window._creds is not None)

    def select_rows(self, *titles):
        """Select these rows as a Shift-click would, replacing any earlier selection."""
        rows = [self.row_of(title) for title in titles]
        model = self.window.table.selectionModel()
        model.clearSelection()
        for row in rows:
            model.select(self.window.proxy.index(row, 0),
                         QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)

    def row_of(self, title):
        return next(r for r in range(self.window.proxy.rowCount())
                    if self.window.proxy.index(r, 0).data(Qt.ItemDataRole.DisplayRole) == title)

    def summaries(self):
        return sorted(cred["site"] for cred in self.window._creds)

    def test_status_bar_lock_shows_the_security_key_pin_state(self):
        button = self.window.pin_button
        self.assertFalse(button.isHidden())
        self.assertTrue(button.toolTip().startswith("No security key PIN is set."))
        self.assertIn("not your login password", button.toolTip())
        self.server.pins.set(self.uid, self.username, b"1234")
        self.window.refresh()
        self.wait_for(lambda: button.toolTip().startswith("A security key PIN is set."))
        self.assertEqual(button.accessibleName(), "A security key PIN is set.")
        state = self.server.store.pin(self.uid, self.username)
        self.server.store.set_pin(self.uid, self.username, PinState(hash=state.hash, retries=0))
        self.window.refresh()
        self.wait_for(lambda: "locked" in button.toolTip())
        self.server.stop()
        self.window.refresh()
        self.wait_for(lambda: button.isHidden())  # unknown state: no lock rather than a wrong one

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

    def test_columns_keep_their_sizing_after_a_load(self):
        header = self.window.table.header()
        modes = [header.sectionResizeMode(i) for i in range(3)]
        self.assertEqual(modes, [gui.QHeaderView.ResizeMode.Stretch, gui.QHeaderView.ResizeMode.Stretch,
                                 gui.QHeaderView.ResizeMode.ResizeToContents])

    def test_a_refresh_asked_for_during_a_load_runs_after_it(self):
        read, gate, real = threading.Event(), threading.Event(), gui.request

        def slow(payload):
            result = real(payload)
            if payload["command"] == "list" and not gate.is_set():
                read.set()
                gate.wait(5)  # this load has read the store before the change below
            return result

        with patch.object(gui, "request", slow):
            self.window.refresh()
            self.assertTrue(read.wait(5))
            doomed = self.window._creds[0]["id"]
            self.server.store.remove(self.uid, self.username, [bytes.fromhex(doomed)])
            self.window.refresh()
            gate.set()
            self.wait_for(lambda: not self.window._refreshing and len(self.window._creds) == 6)
        self.assertNotIn(doomed, [cred["id"] for cred in self.window._creds])

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
        self.assertTrue(self.window.delete_action.isEnabled())
        self.assertEqual(len(self.server.verifier.checks), 1)

    def test_approved_delete_moves_the_passkey_to_the_trash(self):
        doomed = self.window.details.cred
        self.answer_delete(True)
        QTest.mouseClick(self.window.details.delete_button, Qt.MouseButton.LeftButton)
        self.wait_for(lambda: self.window.model.rowCount() == 6 and not self.window._refreshing)
        self.assertNotEqual(self.window.details.cred["id"], doomed["id"])
        self.assertEqual(self.window.count_label.text(), "6 passkeys")
        self.assertIn(doomed["id"], [c.id.hex() for c in self.server.store.trash(self.uid, self.username)])
        self.assertEqual(self.window.statusBar().currentMessage(), "Passkey moved to the trash")

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

    def test_trash_view_lists_the_trash_and_renames_the_third_column(self):
        self.set_trash_view(True)
        self.assertEqual(self.window.model.headerData(2, Qt.Orientation.Horizontal), "Deleted")
        self.assertEqual(self.summaries(), ["github.com", "gitlab.com"])
        self.assertEqual(self.window.count_label.text(), "2 passkeys")
        self.assertIs(self.window.side.currentWidget(), self.window.details)
        for action in (self.window.restore_action, self.window.purge_action, self.window.all_restore_action):
            self.assertTrue(action.isVisible())
        for action in (self.window.delete_action, self.window.all_delete_action):
            self.assertFalse(action.isVisible())
        self.assertFalse(self.window.delete_action.isEnabled())
        self.set_trash_view(False)
        self.assertEqual(self.window.model.headerData(2, Qt.Orientation.Horizontal), "Last used")
        self.assertEqual(self.window.model.rowCount(), 7)

    def test_details_show_the_algorithm_and_the_deletion_time(self):
        self.assertEqual(self.window.details.algorithm.text(), "ES256")
        self.assertFalse(self.window.details.deleted.isVisible())
        self.set_trash_view(True)
        trashed = next(c for c in self.window._creds if c["site"] == "gitlab.com")
        self.window._restore(trashed["id"])
        self.wait_for(lambda: self.window.details.cred["id"] == trashed["id"])
        self.assertTrue(self.window.details.deleted.isVisible())
        self.assertNotEqual(self.window.details.deleted.text(), "Never")
        self.assertTrue(self.window.details.restore_button.isVisible())
        self.assertFalse(self.window.details.delete_button.isVisible())

    def test_empty_trash_says_so(self):
        for cred in self.server.store.trash(self.uid, self.username):
            self.server.store.purge(self.uid, self.username, [cred.id])
        self.set_trash_view(True)
        self.assertEqual(self.window.model.rowCount(), 0)
        self.assertEqual(self.window.message.title.text(), "The trash is empty")
        self.assertEqual(self.window.count_label.text(), "0 passkeys")

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

    def test_purge_dialog_is_plain_text_and_disabled_until_the_site_is_typed(self):
        self.set_trash_view(True)
        trashed = next(c for c in self.window._creds if c["site"] == "gitlab.com")
        self.window._restore(trashed["id"])
        seen = []

        def inspect(dialog):
            seen.append(dialog)
            labels = {label.text(): label for label in dialog.findChildren(gui.QLabel)}
            self.assertEqual(
                [label.textFormat() for label in labels.values()],
                [Qt.TextFormat.PlainText] * len(labels),
            )
            delete = self.destructive(dialog)
            cancel = dialog.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Cancel)
            self.assertFalse(delete.isEnabled())
            self.assertTrue(cancel.isDefault())
            field = dialog.findChild(gui.QLineEdit)
            for typed in ("git", "GITLAB.CO"):
                field.clear()
                QTest.keyClicks(field, typed)
                self.assertFalse(delete.isEnabled())
            QTest.keyClicks(field, "M")
            self.assertTrue(delete.isEnabled())
            QTest.mouseClick(cancel, Qt.MouseButton.LeftButton)

        self.answer_dialog(inspect)
        self.window.purge_action.trigger()
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].windowTitle(), "Delete Permanently")
        # Cancel must not contact the daemon: the passkey is still in the trash.
        self.wait_for(lambda: not self.window._refreshing)
        self.assertIn(trashed["id"], [c.id.hex() for c in self.server.store.trash(self.uid, self.username)])
        self.assertEqual(self.server.verifier.checks, [])

    def test_typed_confirmation_purges_for_good(self):
        self.set_trash_view(True)
        doomed = next(c for c in self.window._creds if c["site"] == "gitlab.com")
        self.window._restore(doomed["id"])

        def inspect(dialog):
            QTest.keyClicks(dialog.findChild(gui.QLineEdit), "  GitLab.com ")
            QTest.mouseClick(self.destructive(dialog),
                             Qt.MouseButton.LeftButton)

        self.answer_dialog(inspect)
        self.window.purge_action.trigger()
        self.wait_for(lambda: self.window.model.rowCount() == 1 and not self.window._refreshing)
        self.assertEqual(self.window.statusBar().currentMessage(), "Passkey permanently deleted")
        self.assertEqual(len(self.server.store.credentials(self.uid, self.username)), 7)
        self.assertNotIn(doomed["id"], [c.id.hex() for c in self.server.store.trash(self.uid, self.username)])
        self.assertEqual(len(self.server.verifier.checks), 1)

    def test_restore_returns_a_trashed_passkey_error_goes_to_the_status_bar(self):
        doomed = self.window.details.cred
        self.answer_delete(True)
        self.window.delete_action.trigger()
        self.wait_for(lambda: self.window.model.rowCount() == 6 and not self.window._refreshing)
        self.set_trash_view(True)
        self.window._restore(doomed["id"])
        self.wait_for(lambda: self.window.details.cred["id"] == doomed["id"])
        QTest.mouseClick(self.window.details.restore_button, Qt.MouseButton.LeftButton)
        self.wait_for(lambda: self.window.model.rowCount() == 2 and not self.window._refreshing)
        self.assertEqual(self.window.statusBar().currentMessage(), "Passkey restored")
        self.set_trash_view(False)
        self.assertEqual(self.window.model.rowCount(), 7)
        self.assertIn(doomed["id"], [c["id"] for c in self.window._creds])

    def test_restore_refused_by_a_newer_passkey_reports_the_conflict(self):
        doomed = self.window.details.cred  # amazon.com
        self.answer_delete(True)
        self.window.delete_action.trigger()
        self.wait_for(lambda: self.window.model.rowCount() == 6 and not self.window._refreshing)
        # A fresh passkey for the same account now lives, so restore must refuse.
        self.server.store.add(self.uid, self.username, Credential(
            id=os.urandom(32), rp_id=doomed["site"], user_id=b"alice@example.com", alg=cose.ES256,
            sealed_key=b"", user_name="alice@example.com", discoverable=True, created=time.time(),
        ))
        self.set_trash_view(True)
        self.window._restore(doomed["id"])
        self.wait_for(lambda: self.window.details.cred["id"] == doomed["id"])
        QTest.mouseClick(self.window.details.restore_button, Qt.MouseButton.LeftButton)
        self.wait_for(lambda: "exists" in self.window.statusBar().currentMessage())
        self.assertTrue(self.window.statusBar().currentMessage()[0].isupper())
        self.assertIn(doomed["id"], [c.id.hex() for c in self.server.store.trash(self.uid, self.username)])

    def test_bulk_delete_by_site_confirms_the_count_and_trashes_them_all(self):
        seen = []
        self.answer_delete(True, seen)
        self.window.search.setText("github")
        self.window.site_delete_action.trigger()
        self.wait_for(lambda: self.window.model.rowCount() == 5 and not self.window._refreshing)
        self.assertEqual(seen[0].text(), "Move 2 passkeys to the trash?")
        self.assertEqual(sorted(c.rp_id for c in self.server.store.trash(self.uid, self.username)),
                         ["github.com", "github.com", "github.com", "gitlab.com"])
        self.assertEqual(self.window.statusBar().currentMessage(), "Moved 2 passkeys to the trash")

    def test_bulk_delete_all_and_restore_all_round_trip(self):
        self.answer_delete(True)
        self.window.all_delete_action.trigger()
        self.wait_for(lambda: self.window.model.rowCount() == 0 and not self.window._refreshing)
        self.assertEqual(self.window.message.title.text(), "No passkeys yet")
        self.assertEqual(len(self.server.store.trash(self.uid, self.username)), 9)
        self.set_trash_view(True)
        seen = []
        self.answer_delete(True, seen)
        self.window.all_restore_action.trigger()
        self.wait_for(lambda: self.window.model.rowCount() == 0 and not self.window._refreshing)
        self.assertEqual(self.window.message.title.text(), "The trash is empty")
        self.assertEqual(seen[0].text(), "Restore 9 passkeys from the trash?")
        self.set_trash_view(False)
        self.assertEqual(self.window.model.rowCount(), 9)
        self.assertEqual(self.server.store.trash(self.uid, self.username), [])

    def test_several_rows_move_to_the_trash_in_one_request_and_come_back_together(self):
        self.select_rows("github.com", "proton.me")
        self.assertEqual(self.window.message.title.text(), "2 passkeys selected")
        self.assertTrue(self.window.delete_action.isEnabled())
        self.assertFalse(self.window.copy_action.isEnabled(), "there is no one username to copy")
        self.assertFalse(self.window.site_delete_action.isEnabled())
        self.assertFalse(self.window.purge_action.isEnabled(), "permanent deletion stays one passkey at a time")
        seen = []
        self.answer_delete(True, seen)
        QTest.keyClick(self.window.table, Qt.Key.Key_Delete)
        self.wait_for(lambda: self.window.model.rowCount() == 5 and not self.window._refreshing)
        self.assertEqual(seen[0].text(), "Move 2 passkeys to the trash?")
        self.assertEqual(self.window.statusBar().currentMessage(), "Moved 2 passkeys to the trash")
        trashed = sorted(c.rp_id for c in self.server.store.trash(self.uid, self.username))
        self.assertEqual(trashed, ["github.com", "github.com", "gitlab.com", "proton.me"])

        self.set_trash_view(True)
        self.select_rows("github.com", "proton.me")
        self.assertEqual(self.window.model.rowCount(), 4)
        seen = []
        self.answer_delete(True, seen)
        self.window.restore_action.trigger()  # Restore asks once, for the count
        self.wait_for(lambda: not self.window._busy and self.window.model.rowCount() == 2)
        self.assertEqual(seen[0].text(), "Restore 2 passkeys from the trash?")
        self.assertEqual(self.window.statusBar().currentMessage(), "Restored 2 passkeys")
        self.assertEqual(sorted(c["site"] for c in self.window._creds), ["github.com", "gitlab.com"])
        self.set_trash_view(False)
        self.assertEqual(self.window.model.rowCount(), 7)

    def test_bulk_action_cancelled_asks_the_daemon_nothing_but_the_dry_run(self):
        seen = []
        self.answer_delete(False, seen)
        self.window.all_delete_action.trigger()
        self.wait_for(lambda: bool(seen) and self.app.activeModalWidget() is None)
        self.assertEqual(seen[0].text(), "Move 7 passkeys to the trash?")
        self.assertTrue(self.window.all_delete_action.isEnabled())
        self.assertEqual(len(self.server.store.credentials(self.uid, self.username)), 7)
        self.assertEqual(self.server.verifier.checks, [])
        self.assertEqual(self.window.statusBar().currentMessage(), "")

    def test_pin_dialog_shows_status_and_sets_and_removes_the_pin(self):
        seen = []

        def inspect(dialog):
            seen.append(dialog)
            self.wait_for(lambda: "security key PIN" in dialog.status.text())
            self.assertEqual(dialog.status.text(), gui.pin_summary({"set": False, "retries": MAX_PIN_RETRIES}))
            self.assertFalse(dialog.remove_button.isEnabled())
            self.assertFalse(dialog.set_button.isEnabled())
            QTest.keyClicks(dialog.pin, "1234")
            self.assertFalse(dialog.set_button.isEnabled())
            QTest.keyClicks(dialog.repeat, "12345")
            self.assertFalse(dialog.set_button.isEnabled())
            QTest.keyClick(dialog.repeat, Qt.Key.Key_Backspace)
            self.assertTrue(dialog.set_button.isEnabled())
            QTest.mouseClick(dialog.set_button, Qt.MouseButton.LeftButton)
            self.wait_for(lambda: dialog.status.text() == "A security key PIN is set.")
            self.assertTrue(dialog.remove_button.isEnabled())
            self.assertEqual(dialog.pin.text(), "")
            self.assertEqual(dialog.repeat.text(), "")
            state = self.server.store.pin(self.uid, self.username)
            self.assertEqual(state.hash, pin_hash(b"1234"))
            self.assertEqual(state.retries, MAX_PIN_RETRIES)
            QTest.mouseClick(dialog.remove_button, Qt.MouseButton.LeftButton)
            self.wait_for(lambda: dialog.status.text() == gui.pin_summary({"set": False, "retries": MAX_PIN_RETRIES}))
            self.assertIsNone(self.server.store.pin(self.uid, self.username))
            dialog.reject()

        self.answer_dialog(inspect)
        self.window.show_pin_dialog()
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].windowTitle(), "Security Key PIN")
        self.assertEqual(len(self.server.verifier.checks), 2)
        self.assertEqual([m[2] for m in self.server.verifier.checks],
                         ["Set a new PIN for the passkeys stored on this computer?",
                          "Remove the PIN for the passkeys stored on this computer?"])

    def test_pin_dialog_does_not_invent_a_state_when_the_status_request_fails(self):
        # A daemon restart or socket timeout must not read as "no PIN is set",
        # which would offer to set one over the existing PIN and hide Remove.
        self.server.store.set_pin(self.uid, self.username, PinState(pin_hash(b"1234"), MAX_PIN_RETRIES))
        real_run = self.window.tasks.run

        def failing_run(work, done):
            if done.__name__ == "_on_loaded":
                done(None, ServiceUnavailable("the service is not running"))
            else:
                real_run(work, done)

        def inspect(dialog):
            self.wait_for(lambda: dialog.status.text() != "Checking…")
            self.assertEqual(dialog.status.text(), "Could not check whether a security key PIN is set.")
            for widget in (dialog.pin, dialog.repeat, dialog.set_button, dialog.remove_button):
                self.assertFalse(widget.isEnabled(), "the state is unknown, so nothing is offered")
            self.assertIn("not running", self.window.statusBar().currentMessage())
            dialog.reject()

        with patch.object(self.window.tasks, "run", failing_run):
            self.answer_dialog(inspect)
            self.window.show_pin_dialog()
        self.assertIsNotNone(self.server.store.pin(self.uid, self.username))

    def test_pin_dialog_reports_a_too_short_pin(self):
        def inspect(dialog):
            self.wait_for(lambda: dialog.status.text() == gui.pin_summary({"set": False, "retries": MAX_PIN_RETRIES}))
            QTest.keyClicks(dialog.pin, "123")
            QTest.keyClicks(dialog.repeat, "123")
            self.assertEqual(dialog.feedback.text(), "At least 4 characters")
            self.assertFalse(dialog.set_button.isEnabled())
            QTest.mouseClick(dialog.set_button, Qt.MouseButton.LeftButton)
            self.assertEqual(dialog.status.text(), gui.pin_summary({"set": False, "retries": MAX_PIN_RETRIES}))
            dialog.reject()

        self.answer_dialog(inspect)
        self.window.show_pin_dialog()
        self.assertIsNone(self.server.store.pin(self.uid, self.username))

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


@unittest.skipIf(gui is None, "PyQt6 and QDarkStyle are not installed")
class CodesTabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {"QT_QPA_PLATFORM": "offscreen"}):
            cls.app = QApplication.instance() or QApplication([])

    wait_for = WindowTests.wait_for
    answer_dialog = WindowTests.answer_dialog
    answer_delete = WindowTests.answer_delete
    select_rows = WindowTests.select_rows
    row_of = WindowTests.row_of
    destructive = staticmethod(WindowTests.destructive)

    def setUp(self):
        self.environment = patch.dict(os.environ)
        self.environment.start()
        self.server, self.tmp = start_backend()
        self.server.verifier = FakePolkit(Verdict.APPROVED)
        self.uid = os.getuid()
        self.username = pwd.getpwuid(self.uid).pw_name
        # A fixed clock 10.5 s into a 30 s period: the code the window fetched is the code expected() computes.
        clock = patch("time.time", return_value=time.time() // 300 * 300 + 10.5)
        clock.start()
        self.addCleanup(clock.stop)
        self.window = gui.Window()
        self.window._timer.stop()
        self.window.show()
        self.wait_for(lambda: not self.window._refreshing)
        self.add_entry("steamcommunity.com", "Steam", "alice", "JBSWY3DPEHPK3PXP", "steam")
        self.hotp_secret = totp.decode_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        self.hotp_id = self.add_entry("bank.example", "Bank", "alice", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                                      "hotp", counter=7)

    tearDown = WindowTests.tearDown

    def add_entry(self, site, issuer, account, key, kind, counter=0):
        entry_id = os.urandom(16)
        self.server.store.totp_add(self.uid, self.username, TotpEntry(
            id=entry_id, sealed_secret=self.server.store.seal(self.uid, b"totp\0" + entry_id,
                                                             totp.decode_secret(key)),
            site=site, issuer=issuer, account=account, algorithm="SHA1",
            digits=totp.STEAM_DIGITS if kind == "steam" else 6, period=30, kind=kind, counter=counter,
        ))
        return entry_id

    def open_codes(self):
        self.window.tabs.setCurrentIndex(1)
        self.wait_for(lambda: not self.window._unlocking and not self.window._refreshing
                      and not self.window._fetching)

    def expected(self, site):
        entry = next(e for e in self.server.store.totp_entries(self.uid, self.username) if e.site == site)
        return totp.code(self.server.store.totp_unseal(self.uid, entry), entry.algorithm, entry.digits,
                         entry.period)[0]

    def code_cell(self, site):
        row = next(r for r in range(self.window.model.rowCount()) if self.window.model.item(r, 0).text() == site)
        return self.window.model.item(row, 2).text()

    def select(self, title):
        row = next(r for r in range(self.window.proxy.rowCount())
                   if self.window.proxy.index(r, 0).data(Qt.ItemDataRole.DisplayRole) == title)
        self.window.table.clearSelection()
        self.window.table.setCurrentIndex(self.window.proxy.index(row, 0))

    @unittest.skipIf(os.getuid() == 0, "root is always unlocked")
    def test_the_tab_unlocks_shows_the_codes_and_leaving_locks_them(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.assertEqual([m[1:] for m in self.server.verifier.checks],
                         [("org.localpasskey.totp", "Show the authenticator codes stored on this computer?")])
        self.assertEqual([self.window.model.headerData(i, Qt.Orientation.Horizontal) for i in range(3)],
                         list(gui.CODE_COLUMNS))
        self.assertEqual(self.window.count_label.text(), "5 authenticator codes")
        self.assertEqual(self.code_cell("github.com"), gui.grouped(self.expected("github.com")))
        self.assertEqual(self.code_cell("Example Bank"), gui.grouped(self.expected("")))  # issuer stands in
        self.assertEqual(len(self.code_cell("Example Bank")), 9, "8 digits, grouped")
        self.select("github.com")
        self.assertIs(self.window.side.currentWidget(), self.window.code_details)
        self.assertEqual(self.window.code_details.code.text(), gui.grouped(self.expected("github.com")))
        self.assertEqual(self.window.code_details.kind.text(), "SHA1 · 6 digits · every 30 s")
        self.assertRegex(self.window.code_details.countdown.text(), r"^Changes in \d+ s$")
        self.assertTrue(self.window.code_menu.menuAction().isVisible())
        self.assertFalse(self.window.passkey_menu.menuAction().isVisible())
        self.assertFalse(self.window.copy_action.isEnabled(), "Ctrl+C belongs to Copy Code here")
        self.assertTrue(self.server._unlocks)

        self.window.tabs.setCurrentIndex(0)
        self.wait_for(lambda: not self.server._unlocks and not self.window._refreshing)
        self.assertEqual(self.window._values, {})
        self.assertEqual(self.window.model.rowCount(), 7)
        self.assertEqual(self.window.count_label.text(), "7 passkeys")
        self.assertTrue(self.window.passkey_menu.menuAction().isVisible())
        self.assertFalse(self.window.copy_code_action.isEnabled())
        self.assertTrue(self.window.copy_action.isEnabled())

    @unittest.skipIf(os.getuid() == 0, "root is always unlocked")
    def test_a_refused_unlock_stays_locked_quietly_until_unlock_is_clicked(self):
        self.server.verifier.verdict = Verdict.DENIED
        self.open_codes()
        self.assertFalse(self.window._unlocked)
        self.assertEqual(self.window.model.rowCount(), 0)
        self.assertEqual(self.window.message.title.text(), "Authenticator codes are locked")
        self.assertEqual(self.window.message.text.text(), "Your password is needed to show them.")
        self.assertTrue(self.window.message.button.isVisible())
        self.assertEqual(self.window.statusBar().currentMessage(), "")
        self.assertEqual(self.window.count_label.text(), "5 authenticator codes · locked")
        self.server.verifier.verdict = Verdict.APPROVED
        QTest.mouseClick(self.window.message.button, Qt.MouseButton.LeftButton)
        self.wait_for(lambda: len(self.window._values) == 4)
        self.assertEqual(self.window.model.rowCount(), 5)
        self.assertEqual(self.window.count_label.text(), "5 authenticator codes")
        self.assertFalse(self.window.message.button.isVisible())

    @unittest.skipIf(os.getuid() == 0, "root is always unlocked")
    def test_the_service_locking_the_codes_shows_the_locked_state(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        with self.server._unlocks_lock:
            self.server._unlocks.clear()  # the idle relock, or a restarted service
        self.window._show_values({})
        self.window._fetch_codes()
        self.wait_for(lambda: not self.window._unlocked)
        self.assertEqual(self.window.model.rowCount(), 0)
        self.assertEqual(self.window.message.title.text(), "Authenticator codes are locked")
        self.assertEqual(self.window.statusBar().currentMessage(), "")
        self.assertEqual(self.window.count_label.text(), "5 authenticator codes · locked")

    @unittest.skipIf(os.getuid() == 0, "root is always unlocked")
    def test_the_trash_view_relocks_when_the_service_drops_the_unlock(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.window.trash_action.setChecked(True)
        self.assertEqual(self.window._values, {}, "no old codes kept for the way back")
        self.wait_for(lambda: not self.window._refreshing)
        with self.server._unlocks_lock:
            self.server._unlocks.clear()  # the idle relock while in the trash
        self.window.refresh()
        self.wait_for(lambda: not self.window._unlocked and not self.window._refreshing)
        self.assertEqual(self.window.message.title.text(), "Authenticator codes are locked")
        self.assertTrue(self.window.message.button.isVisible())

    def test_leaving_the_trash_fetches_the_codes_again(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.window._values = {k: ("000000", until, p) for k, (_, until, p) in self.window._values.items()}
        self.window.trash_action.setChecked(True)
        self.wait_for(lambda: not self.window._refreshing)
        self.window.trash_action.setChecked(False)
        self.wait_for(lambda: self.window.model.rowCount() == 5 and len(self.window._values) == 4
                      and not self.window._refreshing and not self.window._fetching)
        self.assertEqual(self.code_cell("github.com"), gui.grouped(self.expected("github.com")))

    def test_a_failed_refresh_forgets_the_codes(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        with patch.object(gui, "request", side_effect=ServiceUnavailable("gone")):
            self.window.refresh()
            self.wait_for(lambda: not self.window._refreshing)
        self.assertEqual(self.window._values, {})

    def test_countdown_ticks_and_a_finished_code_is_fetched_again(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.select("github.com")
        code, _, period = self.window._values[self.window._selected_id]
        self.window._values[self.window._selected_id] = (code, time.monotonic() + 12.2, period)
        with patch.object(self.window, "_fetch_codes") as fetch:
            self.window._on_tick()
        self.assertEqual(self.window.code_details.countdown.text(), "Changes in 13 s", "rounded up, as the CLI")
        fetch.assert_not_called()
        self.window._values[self.window._selected_id] = ("000000", time.monotonic() - 0.1, period)
        self.window._on_tick()
        self.wait_for(lambda: self.window._values[self.window._selected_id][1] > time.monotonic())
        self.assertEqual(self.window._values[self.window._selected_id][0], self.expected("github.com"))

    def test_a_code_is_fetched_again_right_when_it_runs_out_not_at_the_next_tick(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.window._tick.stop()
        with patch.object(self.window, "_fetch_codes") as fetch:
            self.window._show_values({k: (c, time.monotonic() + 0.2, p) for k, (c, _, p) in self.window._values.items()})
            QTest.qWait(100)
            fetch.assert_not_called()
            self.wait_for(lambda: fetch.called)

    def test_long_periods_still_fetch_every_minute_to_keep_the_unlock(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.window._show_values({k: (c, time.monotonic() + 290, 300) for k, (c, _, _) in self.window._values.items()})
        with patch.object(self.window, "_fetch_codes") as fetch:
            self.window._on_tick()
            fetch.assert_not_called()
            self.window._fetched_at -= gui.KEEP_UNLOCKED_S  # a minute without a fetch: the service would idle out
            self.window._on_tick()
            fetch.assert_called_once()

    def test_a_failed_fetch_is_tried_again_a_minute_later_not_every_tick(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.window._tick.stop()
        self.window._values, self.window._fetched_at = {}, 0.0  # as if the first fetch failed
        self.window._on_codes(None, ServiceError("secret of authenticator code 0123 cannot be decrypted"))
        with patch.object(self.window, "_fetch_codes") as fetch:
            self.window._on_tick()
            fetch.assert_not_called()  # no request, and no new error, every second
            self.window._fetched_at -= gui.KEEP_UNLOCKED_S
            self.window._on_tick()
            fetch.assert_called_once()

    def test_an_inactive_window_blanks_the_codes_and_fetches_none(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.select("github.com")
        with patch.object(self.window, "isActiveWindow", return_value=False):
            self.window.changeEvent(QEvent(QEvent.Type.ActivationChange))
            self.assertEqual(self.window._values, {})
            self.assertEqual(self.code_cell("github.com"), gui.HIDDEN_CODE)
            self.assertEqual(self.window.code_details.code.text(), gui.HIDDEN_CODE)
            self.assertFalse(self.window.code_details.copy_button.isEnabled())
            with patch.object(gui, "request") as asked:
                self.window._fetch_codes()
            asked.assert_not_called()
        self.window.changeEvent(QEvent(QEvent.Type.ActivationChange))
        self.wait_for(lambda: len(self.window._values) == 4)

    def test_copy_code_is_marked_secret_and_cleared_only_if_still_there(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.select("github.com")
        QTest.keyClick(self.window.table, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
        clipboard = self.app.clipboard()
        code = self.expected("github.com")
        self.assertEqual(clipboard.text(), code)
        self.assertEqual(bytes(clipboard.mimeData().data("x-kde-passwordManagerHint")), b"secret")
        self.assertEqual(self.window.statusBar().currentMessage(), "Code copied; the clipboard is cleared in 30 s")
        self.assertTrue(self.window._clipboard_timer.isActive())
        focus_in = QEvent(QEvent.Type.ActivationChange)
        with patch.object(self.window, "isActiveWindow", return_value=True):
            self.window.changeEvent(focus_in)  # focus-in before the 30 s are up
            self.assertEqual(clipboard.text(), code)
            self.window._copied_until = time.monotonic() - 1  # as after a sleep past the timer
            self.window.changeEvent(focus_in)
        self.assertEqual(clipboard.text(), "")
        self.window.copy_code()
        clipboard.setText("something else")
        self.window._copied_until = time.monotonic()
        self.window._expire_copied()
        self.assertEqual(clipboard.text(), "something else")
        self.window.copy_code()
        self.window.shutdown()  # aboutToQuit: no waiting for the 30 s
        self.assertEqual(clipboard.text(), "")
        self.assertFalse(self.server._unlocks)

    def test_the_clipboard_timer_clears_the_code_by_itself(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.select("github.com")
        self.assertEqual(self.window._clipboard_timer.timerType(), Qt.TimerType.PreciseTimer)
        clipboard = self.app.clipboard()
        with patch.object(gui, "COPY_CLEAR_MS", 150):
            self.window.copy_code()
            self.assertEqual(clipboard.text(), self.expected("github.com"))
            self.wait_for(lambda: clipboard.text() == "")
        self.assertIsNone(self.window._copied)

    def test_the_clipboard_timer_fired_early_waits_for_the_time_left(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.select("github.com")
        clipboard = self.app.clipboard()
        with patch.object(gui, "COPY_CLEAR_MS", 50):
            self.window.copy_code()
            self.window._copied_until = time.monotonic() + 0.4  # as if the timer ran fast
            QTest.qWait(150)
            self.assertEqual(clipboard.text(), self.expected("github.com"))
            self.assertTrue(self.window._clipboard_timer.isActive(), "re-armed for the rest")
            self.wait_for(lambda: clipboard.text() == "")

    def test_closing_the_window_locks_the_codes(self):
        self.open_codes()
        self.wait_for(lambda: self.window._unlocked)
        self.window.close()
        self.assertFalse(self.window._unlocked)
        self.assertFalse(self.server._unlocks)

    def test_add_code_from_a_pasted_link_then_clears_the_clipboard(self):
        link = "otpauth://totp/example.com:bob?secret=KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU&issuer=example.com&digits=8"
        self.app.clipboard().setText(link)
        seen = []

        def fill(dialog):
            seen.append(dialog.windowTitle())
            self.assertEqual(dialog.key.echoMode(), gui.QLineEdit.EchoMode.Password)
            self.assertFalse(dialog.save_button.isEnabled())
            dialog.key.setText("not a key 0")
            self.assertEqual(dialog.feedback.text(), "This is not a valid setup key")
            self.assertFalse(dialog.save_button.isEnabled())
            next(b for b in dialog.findChildren(gui.QPushButton) if b.text() == "Paste").click()
            self.assertEqual(dialog.feedback.text(), "Setup key is valid")
            self.assertEqual((dialog.site.text(), dialog.issuer.text(), dialog.account.text()),
                             ("example.com", "example.com", "bob"))
            self.assertIn("8 digits", dialog.note.text())
            dialog.site.setText("not a site")
            self.assertFalse(dialog.save_button.isEnabled())
            dialog.site.setText("example.com")
            dialog.save_button.click()

        self.open_codes()
        self.answer_dialog(fill)
        self.window.add_code_action.trigger()
        self.wait_for(lambda: not self.window._busy and not self.window._refreshing)
        self.assertEqual(seen, ["Add Authenticator Code"])
        added = [e for e in self.server.store.totp_entries(self.uid, self.username) if e.site == "example.com"]
        self.assertEqual([(e.account, e.digits) for e in added], [("bob", 8)])
        self.assertEqual(self.app.clipboard().text(), "")
        self.assertEqual(self.window.statusBar().currentMessage(), "Authenticator code added")
        self.window.activateWindow()  # the offscreen platform does not hand activation back by itself
        self.wait_for(lambda: len(self.window._values) == 5)

    def test_add_code_keeps_a_clipboard_that_no_longer_holds_the_pasted_link(self):
        self.app.clipboard().setText("otpauth://totp/example.com:bob?secret=KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU")

        def fill(dialog):
            next(b for b in dialog.findChildren(gui.QPushButton) if b.text() == "Paste").click()
            self.assertEqual(dialog.feedback.text(), "Setup key is valid")
            self.app.clipboard().setText("copied after pasting")
            dialog.save_button.click()

        self.open_codes()
        self.answer_dialog(fill)
        self.window.add_code_action.trigger()
        self.wait_for(lambda: not self.window._busy and not self.window._refreshing)
        self.assertEqual(self.window.statusBar().currentMessage(), "Authenticator code added")
        self.assertEqual(self.app.clipboard().text(), "copied after pasting")

    def test_the_setup_key_and_the_copied_code_are_never_shown_as_text(self):
        key = "QZ7XKW3MVB5TNRYJ2PLDH6GCFE4SAUOI"  # distinctive: any 12 characters of it would stand out
        link = f"otpauth://totp/Leak%20Check:eve?secret={key}&issuer=leak.example&period=60&digits=8"

        def leaks(root, skip=()):
            from PyQt6.QtWidgets import QLabel, QLineEdit, QWidget
            texts = [w.toolTip() for w in [root, *root.findChildren(QWidget)]]
            texts += [w.text() for w in root.findChildren(QLabel)]
            texts += [w.text() for w in root.findChildren(QLineEdit) if w not in skip]
            if hasattr(root, "statusBar"):
                texts.append(root.statusBar().currentMessage())
            flat = [t.replace(" ", "").upper() for t in texts]
            return [t for t in flat if any(key[i:i + 12] in t for i in range(len(key) - 11))]

        def fill(dialog):
            for typed in (key[:-1] + "1", key[:8], link.replace("digits=8", "digits=7"), link):
                dialog.key.setText(typed)
                self.assertEqual(leaks(dialog, skip=(dialog.key,)), [], typed)
            self.assertTrue(dialog.note.isVisible())
            dialog.save_button.click()

        self.open_codes()
        self.answer_dialog(fill)
        self.window.add_code_action.trigger()
        self.wait_for(lambda: not self.window._busy and not self.window._refreshing)
        self.assertEqual(self.window.findChildren(gui.CodeDialog), [], "the closed dialog still holds the key")
        self.window.activateWindow()
        self.wait_for(lambda: len(self.window._values) == 5)
        self.select("leak.example")
        self.assertEqual(self.window.code_details.issuer.text(), "leak.example")
        self.assertEqual(leaks(self.window), [])
        self.window.copy_code()
        code = self.window._values[self.window._selected_id][0]
        self.assertEqual(self.app.clipboard().text(), code)
        self.assertNotIn(code, self.window.statusBar().currentMessage())
        self.assertNotIn(gui.grouped(code), self.window.statusBar().currentMessage())
        self.assertEqual(leaks(self.window), [])

    def test_edit_changes_the_labels(self):
        self.open_codes()
        self.select("github.com")

        def edit(dialog):
            self.assertEqual(dialog.windowTitle(), "Edit Authenticator Code")
            self.assertFalse(dialog.key.isVisibleTo(dialog))
            dialog.account.setText("octo-new")
            dialog.save_button.click()

        self.answer_dialog(edit)
        self.window.edit_code_action.trigger()
        self.wait_for(lambda: not self.window._busy and not self.window._refreshing)
        self.assertIn("octo-new", [e.account for e in self.server.store.totp_entries(self.uid, self.username)])

    def test_a_request_started_while_the_dialog_was_open_is_not_overrun(self):
        self.open_codes()
        self.select("github.com")

        def accept_while_busy(dialog):
            self.window._busy = True  # another request began meanwhile
            return gui.QDialog.DialogCode.Accepted

        for trigger in (self.window.add_code, lambda: self.window.edit_code(self.window.code_details.entry)):
            with self.subTest(trigger=trigger), patch.object(gui.CodeDialog, "exec", accept_while_busy), \
                    patch.object(self.window.tasks, "run") as run:
                self.window._busy = False
                trigger()
                run.assert_not_called()
                self.assertEqual(self.window.statusBar().currentMessage(),
                                 "Not saved: another request is still running. Try again when it finishes.")
        self.window._busy = False

    def test_several_code_rows_move_to_the_trash_in_one_request(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.select_rows("github.com", "google.com")
        self.assertEqual(self.window.message.title.text(), "2 authenticator codes selected")
        self.assertFalse(self.window.code_details.code.isVisible(), "no one code to show")
        seen = []
        self.answer_delete(True, seen)
        QTest.keyClick(self.window.table, Qt.Key.Key_Delete)
        self.wait_for(lambda: not self.window._busy and self.window.model.rowCount() == 3)
        self.assertEqual(seen[0].text(), "Move 2 authenticator codes to the trash?")
        self.assertEqual(self.window.statusBar().currentMessage(), "Moved 2 authenticator codes to the trash")
        self.assertEqual(len(self.server.store.totp_entries(self.uid, self.username)), 3)
        self.assertEqual(sorted(e.issuer for e in self.server.store.totp_trash(self.uid, self.username)),
                         ["GitHub", "GitLab", "Google"])

    def test_ctrl_n_adds_a_code_on_the_codes_tab_and_does_nothing_on_the_passkeys_tab(self):
        def accepted(dialog):
            dialog.key.setText("JBSWY3DPEHPK3PXP")
            dialog.save_button.click()
            return gui.QDialog.DialogCode.Accepted

        self.window.tabs.setCurrentIndex(0)
        self.wait_for(lambda: not self.window._refreshing)
        with patch.object(gui.CodeDialog, "exec", accepted):
            QTest.keyClick(self.window, Qt.Key.Key_N, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(self.window.findChildren(gui.CodeDialog), [], "the dialog never opened")
        self.open_codes()
        with patch.object(gui.CodeDialog, "exec", accepted):
            QTest.keyClick(self.window, Qt.Key.Key_N, Qt.KeyboardModifier.ControlModifier)
        self.wait_for(lambda: not self.window._busy and not self.window._refreshing)
        self.assertEqual(self.window.statusBar().currentMessage(), "Authenticator code added")

    def test_double_click_copies_that_row_s_code(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        index = self.window.proxy.index(self.row_of("google.com"), 0)
        self.select("github.com")
        self.window._on_double_click(index)  # what the table's doubleClicked signal calls
        clipboard = self.app.clipboard()
        self.assertEqual(clipboard.text(), self.expected("google.com"), "the double-clicked row, not the selection")
        self.assertEqual(bytes(clipboard.mimeData().data("x-kde-passwordManagerHint")), b"secret")
        self.assertEqual(self.window.statusBar().currentMessage(), "Code copied; the clipboard is cleared in 30 s")

    def test_double_click_does_nothing_while_the_code_is_not_known(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        index = self.window.proxy.index(self.row_of("github.com"), 0)
        self.window._values = {}
        QApplication.clipboard().clear()
        before = self.window.statusBar().currentMessage()
        self.window._on_double_click(index)
        self.assertEqual(self.app.clipboard().text(), "", "no code to copy")
        self.assertEqual(self.window.statusBar().currentMessage(), before, "and no error either")

    def test_double_click_on_the_big_code_copies_it_too(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.select("github.com")
        self.window.code_details.code.mouseDoubleClickEvent(None)
        self.assertEqual(self.app.clipboard().text(), self.expected("github.com"))

    def counter(self):
        return next(e.counter for e in self.server.store.totp_entries(self.uid, self.username)
                    if e.id == self.hotp_id)

    def test_a_steam_code_shows_its_5_characters_ungrouped(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        expected = totp.steam_code(totp.decode_secret("JBSWY3DPEHPK3PXP"), int(time.time()) // 30)
        self.assertEqual(self.code_cell("steamcommunity.com"), expected)
        self.select("steamcommunity.com")
        self.assertEqual(self.window.code_details.code.text(), expected)
        self.assertEqual(self.window.code_details.kind.text(), "Steam · 5 characters · every 30 s")
        self.assertRegex(self.window.code_details.countdown.text(), r"^Changes in \d+ s$")
        self.assertFalse(self.window.code_details.next_button.isVisible())
        self.assertFalse(self.window.next_code_action.isEnabled())

    def test_an_hotp_code_moves_on_only_on_next_code(self):
        self.open_codes()
        self.wait_for(lambda: len(self.window._values) == 4)
        self.assertEqual(self.code_cell("bank.example"), gui.HIDDEN_CODE, "showing every code uses no counter")
        self.assertEqual(self.counter(), 7)
        self.select("bank.example")
        details = self.window.code_details
        self.assertEqual(details.countdown.text(), "Counter 7")
        self.assertTrue(details.next_button.isVisible())
        self.assertFalse(details.copy_button.isEnabled())
        self.assertTrue(self.window.next_code_action.isEnabled())
        self.assertFalse(self.window.copy_code_action.isEnabled())
        self.window.next_code_action.trigger()
        self.wait_for(lambda: not self.window._busy and not self.window._refreshing)
        expected = totp.hotp(self.hotp_secret, 7)
        self.assertEqual(self.counter(), 8, "written before the code was shown")
        self.assertEqual(details.code.text(), gui.grouped(expected))
        self.assertEqual(details.countdown.text(), "Counter 7", "the counter of the code shown")
        self.assertEqual(self.code_cell("bank.example"), gui.grouped(expected))
        self.assertEqual(details.kind.text(), "SHA1 · 6 digits · a new code each time you ask")
        self.window._fetch_codes()  # the background fetch keeps the shown code and uses no counter
        self.wait_for(lambda: not self.window._fetching)
        self.assertEqual(self.window._values[self.hotp_id.hex()][0], expected)
        self.window._on_tick()
        self.assertEqual(details.countdown.text(), "Counter 7")
        self.window._on_double_click(self.window.proxy.index(self.row_of("bank.example"), 0))
        self.assertEqual(self.app.clipboard().text(), expected)
        self.assertEqual(self.counter(), 8, "copying copies the code shown, it makes no new one")
        details.next_button.click()
        self.wait_for(lambda: not self.window._busy and not self.window._refreshing)
        self.assertEqual(details.code.text(), gui.grouped(totp.hotp(self.hotp_secret, 8)))
        self.assertEqual(self.counter(), 9)

    def test_add_code_imports_every_code_in_a_migration_link(self):
        from tests.test_totp import migration, migration_link, otp_parameters
        link = migration_link(migration([
            otp_parameters(name="Example:bob", issuer="example.com", type=2),
            otp_parameters(name="Bank:me", issuer="Bank", type=1, counter=3),
            otp_parameters(name="Old:me", algorithm=4, type=2),
        ]))
        self.app.clipboard().setText(link)

        def fill(dialog):
            next(b for b in dialog.findChildren(gui.QPushButton) if b.text() == "Paste").click()
            self.assertIn("This link holds 3 authenticator codes.", dialog.note.text())
            dialog.save_button.click()

        self.open_codes()
        checks = len(self.server.verifier.checks)
        for done in ("Imported 2 authenticator codes", "Imported 0 authenticator codes; 2 could not be imported"):
            self.app.clipboard().setText(link)
            self.answer_dialog(fill)
            self.window.add_code_action.trigger()
            self.wait_for(lambda: not self.window._busy and not self.window._refreshing)
            self.assertEqual(self.window.statusBar().currentMessage(), done)
        self.assertEqual(len(self.server.verifier.checks), checks + 1, "one prompt; a re-import has nothing to ask")
        entries = {e.issuer: e for e in self.server.store.totp_entries(self.uid, self.username)}
        self.assertEqual((entries["example.com"].site, entries["example.com"].kind), ("example.com", "totp"))
        self.assertEqual((entries["Bank"].kind, entries["Bank"].counter), ("hotp", 3))
        self.assertNotIn("Old", entries)
        self.assertEqual(self.app.clipboard().text(), "", "the link has done its job")

    def test_trash_lists_deleted_codes_and_purge_needs_the_site_typed(self):
        self.open_codes()
        self.select("github.com")
        self.answer_delete(True)
        self.window.delete_code_action.trigger()
        self.wait_for(lambda: not self.window._busy and self.window.model.rowCount() == 4)
        self.window.trash_action.toggle()
        self.wait_for(lambda: not self.window._refreshing and self.window.model.rowCount() == 2)
        self.assertEqual(self.window.model.headerData(2, Qt.Orientation.Horizontal), "Deleted")
        self.assertEqual(self.window.count_label.text(), "2 authenticator codes")
        self.select("github.com")
        self.assertTrue(self.window.code_details.restore_button.isVisible())
        self.assertFalse(self.window.code_details.code.isVisible())
        self.window.restore_code_action.trigger()
        self.wait_for(lambda: not self.window._busy and self.window.model.rowCount() == 1)
        self.select("gitlab.com")

        def purge(dialog):
            delete = self.destructive(dialog)
            QTest.keyClicks(dialog.findChild(gui.QLineEdit), "gitlab")
            self.assertFalse(delete.isEnabled())
            QTest.keyClicks(dialog.findChild(gui.QLineEdit), ".com")
            QTest.mouseClick(delete, Qt.MouseButton.LeftButton)

        self.answer_dialog(purge)
        self.window.purge_code_action.trigger()
        self.wait_for(lambda: not self.window._busy and self.window.model.rowCount() == 0)
        self.assertEqual(self.window.message.title.text(), "The trash is empty")
        self.assertEqual(self.server.store.totp_trash(self.uid, self.username), [])
        self.assertEqual(len(self.server.store.totp_entries(self.uid, self.username)), 5)

    @unittest.skipIf(os.getuid() == 0, "root is never asked for a password")
    def test_settings_turning_the_password_off_asks_and_a_refusal_puts_it_back(self):
        def flip(dialog):
            self.wait_for(dialog.ask.isEnabled)
            self.assertTrue(dialog.ask.isChecked())
            self.server.verifier.verdict = Verdict.DENIED
            dialog.ask.click()
            self.wait_for(lambda: dialog.ask.isEnabled() and dialog.ask.isChecked())
            self.server.verifier.verdict = Verdict.APPROVED
            dialog.ask.click()
            self.wait_for(lambda: dialog.ask.isEnabled() and not dialog.ask.isChecked())
            self.assertFalse(self.server.store.totp_require_auth(self.uid, self.username))
            checks = len(self.server.verifier.checks)
            dialog.ask.click()  # turning it back on never asks
            self.wait_for(lambda: dialog.ask.isEnabled() and dialog.ask.isChecked())
            self.assertEqual(len(self.server.verifier.checks), checks)
            dialog.reject()

        self.answer_dialog(flip)
        SettingsDialog = gui.SettingsDialog(self.window)
        SettingsDialog.exec()
        self.assertTrue(self.server.store.totp_require_auth(self.uid, self.username))
        self.assertEqual([m[2] for m in self.server.verifier.checks],
                         ["Show authenticator codes without asking for your password?"] * 2)


    @unittest.skipIf(os.getuid() == 0, "root is never asked for a password")
    def test_turning_the_password_off_unlocks_a_locked_codes_tab_without_asking(self):
        self.server.verifier.verdict = Verdict.DENIED
        self.open_codes()
        self.assertFalse(self.window._unlocked)
        self.server.verifier.verdict = Verdict.APPROVED
        asked = []

        def flip(dialog):
            self.wait_for(dialog.ask.isEnabled)
            dialog.ask.click()
            self.wait_for(lambda: dialog.ask.isEnabled() and not dialog.ask.isChecked())
            asked.append(len(self.server.verifier.checks))
            dialog.reject()

        self.answer_dialog(flip)
        gui.SettingsDialog(self.window).exec()
        self.wait_for(lambda: self.window._unlocked)
        self.window.activateWindow()  # the offscreen platform does not hand activation back by itself
        self.wait_for(lambda: len(self.window._values) == 4)
        self.assertEqual(self.window.model.rowCount(), 5)
        self.assertEqual(len(self.server.verifier.checks), asked[0], "the unlock asked nothing")

if __name__ == "__main__":
    unittest.main()
