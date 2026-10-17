import os
import pwd
import stat
import time
import unittest
from unittest.mock import patch

try:
    from PyQt6.QtCore import QTimer
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication, QWidget

    from localpasskey import gui
except ImportError:  # PyQt6 or QDarkStyle not installed
    gui = None

from localpasskey import transfer
from localpasskey.ctap2 import Verdict
from tests.gui_demo import start_backend
from tests import test_control
from tests.test_control import FakePolkit
from tests.test_transfer import fast_kdf

PASSPHRASE = "correct horse"


@unittest.skipIf(gui is None, "PyQt6 and QDarkStyle are not installed")
class ExportDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {"QT_QPA_PLATFORM": "offscreen"}):
            cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.parent = QWidget()
        self.addCleanup(self.parent.deleteLater)

    def test_export_stays_disabled_until_the_passphrase_is_valid(self):
        dialog = gui.ExportDialog(self.parent)
        red, green = gui.Feedback.BAD, gui.Feedback.GOOD
        cases = [
            ("", "", "Enter a passphrase to encrypt your export.", red),
            ("short", "", "At least 8 characters", red),
            ("long enough", "", "Confirm the passphrase", red),
            ("long enough", "long", "The passphrases do not match", red),
            ("long enough", "long enough", "Passphrase is valid", green),
        ]
        for passphrase, repeat, text, colour in cases:
            with self.subTest(passphrase=passphrase, repeat=repeat):
                dialog.passphrase.setText(passphrase)
                dialog.repeat.setText(repeat)
                self.assertEqual(dialog.feedback.text(), text)
                self.assertIn(colour, dialog.feedback.styleSheet())
                self.assertEqual(dialog.export_button.isEnabled(), colour == green)

    def test_says_the_passphrase_is_not_the_login_password(self):
        dialog = gui.ExportDialog(self.parent)
        self.assertIn("not your login password", dialog.intro.text())
        self.assertIn("login password", dialog.next_step.text())

    def test_scope_is_the_selected_site_or_everything(self):
        dialog = gui.ExportDialog(self.parent, "github.com")
        self.assertEqual(dialog.selector(), {"site": "github.com"})
        dialog.all.setChecked(True)
        self.assertEqual(dialog.selector(), {"all": True})
        dialog = gui.ExportDialog(self.parent)
        self.assertFalse(dialog.site.isEnabled())
        self.assertEqual(dialog.selector(), {"all": True})

    def test_codes_are_included_by_default_when_there_are_any(self):
        dialog = gui.ExportDialog(self.parent, "github.com", codes=3)
        self.assertEqual(dialog.codes.text(), "Include this website's authenticator codes",
                         "the count is for all websites, not this one")
        self.assertTrue(dialog.codes.isEnabled() and dialog.codes.isChecked())
        dialog.all.setChecked(True)
        self.assertEqual(dialog.codes.text(), "Include authenticator codes (3)")
        self.assertEqual(dialog.selector(), {"all": True, "codes": True})
        dialog.site.setChecked(True)
        self.assertEqual(dialog.codes.text(), "Include this website's authenticator codes")
        self.assertEqual(dialog.selector(), {"site": "github.com", "codes": True})
        dialog.codes.setChecked(False)
        self.assertEqual(dialog.selector(), {"site": "github.com"})
        for none in (0, None):  # None: the service did not say
            dialog = gui.ExportDialog(self.parent, codes=none)
            self.assertEqual(dialog.codes.text(), "Include authenticator codes (0)")
            self.assertFalse(dialog.codes.isEnabled() or dialog.codes.isChecked())
            self.assertEqual(dialog.selector(), {"all": True})

    def test_the_plan_lists_codes_too(self):
        codes = [{"site": "", "issuer": "Bank", "account": "a\nb"}]
        skipped = [{"code": {"site": "github.com", "issuer": "GitHub", "account": "octocat"},
                    "reason": "already on this computer"}]
        dialog = gui.ImportDialog(self.parent, [], [], codes, skipped)
        self.assertEqual(dialog.findChild(gui.QLabel).text(), "Import 1 authenticator code?")
        self.assertTrue(dialog.import_button.isEnabled())
        self.assertEqual(dialog.plan.toPlainText().split("\n\n")[1:], [
            "Authenticator codes to import (1):\n  Bank  a b",
            "Skipped authenticator codes (1):\n  github.com  octocat: already on this computer",
        ])
        self.assertNotIn("authenticator", gui.plan_text([], []))

    def test_the_plan_is_plain_text_with_a_reason_per_skip(self):
        imported = [{"site": "a.example", "user_name": "<b>alice</b>"}]
        skipped = [{"credential": {"site": "b.example", "user_name": "bob"}, "reason": "duplicate in the file"}]
        dialog = gui.ImportDialog(self.parent, imported, skipped)
        text = dialog.plan.toPlainText()
        self.assertIn("<b>alice</b>", text)
        self.assertIn("b.example  bob: duplicate in the file", text)
        self.assertTrue(dialog.import_button.isEnabled())
        self.assertFalse(gui.ImportDialog(self.parent, [], skipped).import_button.isEnabled())
        forged = gui.plan_text([{"site": "a.example", "user_name": "a\nb.example  x"}], skipped)
        self.assertEqual(forged.split("\n\n")[0].splitlines(), ["Will be imported (1):", "  a.example  a b.example  x"])


@unittest.skipIf(gui is None, "PyQt6 and QDarkStyle are not installed")
@fast_kdf
class WindowTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {"QT_QPA_PLATFORM": "offscreen"}):
            cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        self.server, self.tmp = start_backend()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.server.stop)
        self.polkit = self.server.verifier = FakePolkit(Verdict.APPROVED)
        self.window = gui.Window()
        self.window._timer.stop()
        self.window.show()
        self.addCleanup(self.close)
        self.wait_for(lambda: not self.window._refreshing)
        self.path = os.path.join(self.tmp.name, "keys.lpkbackup")

    def close(self):
        self.wait_for(lambda: not self.window._refreshing and not self.window._busy)
        self.window.close()
        # Closing changes the activation, which starts one more refresh.
        self.app.processEvents()
        self.wait_for(lambda: not self.window._refreshing)
        self.window.deleteLater()
        self.app.processEvents()

    def wait_for(self, condition, seconds=10):
        deadline = time.monotonic() + seconds
        while not condition() and time.monotonic() < deadline:
            QTest.qWait(10)
        self.assertTrue(condition(), "Qt/control-socket operation did not complete")

    def on_dialog(self, handle):
        """Hand the next modal dialog to ``handle``."""
        def look():
            dialog = self.app.activeModalWidget()
            if dialog is None:
                QTimer.singleShot(10, look)
            else:
                handle(dialog)

        QTimer.singleShot(0, look)

    def export(self, scope_all=True):
        def fill(dialog):
            if scope_all:
                dialog.all.setChecked(True)
            dialog.passphrase.setText(PASSPHRASE)
            dialog.repeat.setText(PASSPHRASE)
            dialog.export_button.click()

        self.on_dialog(fill)
        with patch.object(gui.QFileDialog, "getSaveFileName", return_value=(self.path, "")):
            self.window.export_passkeys()
        self.wait_for(lambda: not self.window._busy)

    def import_file(self, passphrases, accept=True):
        shown = []

        def answer(dialog):
            shown.append(dialog)
            (dialog.accept if accept else dialog.reject)()

        self.on_dialog(answer)
        with (
            patch.object(gui.QFileDialog, "getOpenFileName", return_value=(self.path, "")),
            patch.object(gui.QInputDialog, "getText", side_effect=[(p, True) for p in passphrases]) as asked,
        ):
            self.window.import_passkeys()
            self.wait_for(lambda: shown and not self.window._busy)
        return shown[0], asked

    def live(self):
        return self.window._creds

    def test_a_transfer_in_progress_disables_the_other_actions(self):
        self.window._show(self.live()[0])
        self.assertTrue(self.window._start("Waiting…"))
        for act in (self.window.import_action, self.window.export_action):
            self.assertFalse(act.isEnabled())
        self.assertFalse(self.window.details.delete_button.isEnabled())
        self.assertEqual(self.window.details.delete_button.text(), "Move to Trash…")
        self.window._show(self.live()[1])  # no passkey is moving, whatever is selected
        self.assertEqual(self.window.details.delete_button.text(), "Move to Trash…")
        self.window._finish()
        self.wait_for(lambda: not self.window._refreshing)
        for act in (self.window.import_action, self.window.export_action):
            self.assertTrue(act.isEnabled())
        self.assertTrue(self.window.details.delete_button.isEnabled())

    def test_export_writes_an_encrypted_owner_only_backup(self):
        self.export()
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(self.polkit.checks[-1][1], "org.localpasskey.export")
        with open(self.path, "rb") as stream:
            records = transfer.load(stream.read(), lambda: PASSPHRASE)
        self.assertEqual(len(records), 7)  # the trash is never exported
        self.assertIn("Exported 7 passkeys", self.window.statusBar().currentMessage())

    def test_export_takes_the_codes_along_unless_unticked_and_import_brings_them_back(self):
        self.export()
        with open(self.path, "rb") as stream:
            records = transfer.load(stream.read(), lambda: PASSPHRASE)
        self.assertEqual(sorted(c["issuer"] for c in records.codes), ["Example Bank", "GitHub", "Google"])
        self.assertEqual(self.window.statusBar().currentMessage(), "Exported 7 passkeys and 3 authenticator codes")
        store, uid_user = self.server.store, (os.getuid(), pwd.getpwuid(os.getuid()).pw_name)
        live = store.totp_entries(*uid_user)
        store.totp_remove(*uid_user, [e.id for e in live])
        store.totp_purge(*uid_user, [e.id for e in live])
        dialog, _ = self.import_file([PASSPHRASE])
        self.assertIn("Authenticator codes to import (3):", dialog.plan.toPlainText())
        self.wait_for(lambda: not self.window._busy and "Imported" in self.window.statusBar().currentMessage())
        self.assertEqual(self.window.statusBar().currentMessage(), "Imported 3 authenticator codes")
        self.assertEqual(len(store.totp_entries(*uid_user)), 3)

        os.unlink(self.path)

        def fill(dialog):
            dialog.all.setChecked(True)
            dialog.codes.setChecked(False)
            dialog.passphrase.setText(PASSPHRASE)
            dialog.repeat.setText(PASSPHRASE)
            dialog.export_button.click()

        self.on_dialog(fill)
        with patch.object(gui.QFileDialog, "getSaveFileName", return_value=(self.path, "")):
            self.window.export_passkeys()
        self.wait_for(lambda: not self.window._busy)
        with open(self.path, "rb") as stream:
            self.assertEqual(transfer.load(stream.read(), lambda: PASSPHRASE).codes, [])
        self.assertEqual(self.window.statusBar().currentMessage(), "Exported 7 passkeys")

    def test_export_write_error_names_the_chosen_file(self):
        hidden = os.path.join(self.tmp.name, ".keys.lpkbackup.1.tmp")
        with patch.object(gui, "write_private_file", side_effect=PermissionError(13, "Permission denied", hidden)):
            self.export()
        self.assertEqual(self.window.statusBar().currentMessage(), f"Cannot write {self.path}: Permission denied")

    def test_export_to_a_missing_folder_stops_before_the_password_is_asked(self):
        self.path = os.path.join(self.tmp.name, "missing", "keys" + transfer.BACKUP_SUFFIX)
        checks = len(self.polkit.checks)
        self.export()
        self.assertIn("does not exist or is not writable", self.window.statusBar().currentMessage())
        self.assertEqual(len(self.polkit.checks), checks)

    def test_export_adds_the_suffix_and_never_replaces_what_was_not_confirmed(self):
        with open(self.path, "wb") as stream:
            stream.write(b"old")
        self.path = self.path[:-len(transfer.BACKUP_SUFFIX)]
        checks = len(self.polkit.checks)
        self.export()
        self.assertIn("already exists", self.window.statusBar().currentMessage())
        self.assertEqual(len(self.polkit.checks), checks)  # refused before the password is asked for
        with open(self.path + transfer.BACKUP_SUFFIX, "rb") as stream:
            self.assertEqual(stream.read(), b"old")
        os.unlink(self.path + transfer.BACKUP_SUFFIX)
        self.export()
        self.assertTrue(os.path.exists(self.path + transfer.BACKUP_SUFFIX))
        self.assertFalse(os.path.exists(self.path))

    def test_export_of_the_selected_site_only(self):
        github = next(row for row in range(self.window.proxy.rowCount())
                      if self.window.proxy.index(row, 0).data(gui.CRED_ROLE)["site"] == "github.com")
        self.window.table.setCurrentIndex(self.window.proxy.index(github, 0))
        self.export(scope_all=False)
        with open(self.path, "rb") as stream:
            records = transfer.load(stream.read(), lambda: PASSPHRASE)
        self.assertEqual({r["rp_id"] for r in records}, {"github.com"})

    def test_import_skips_what_is_here_and_adds_the_rest_after_a_wrong_passphrase(self):
        self.export()
        dialog, asked = self.import_file([PASSPHRASE], accept=False)
        self.assertEqual(asked.call_count, 1)
        self.assertFalse(dialog.import_button.isEnabled())
        # 7 passkeys and the 3 live authenticator codes the export took along.
        self.assertEqual(dialog.plan.toPlainText().count("already on this computer"), 10)

        fresh = test_control.ControlTests.normalized(None)
        with open(self.path, "wb") as stream:
            stream.write(transfer.export_backup([fresh, dict(fresh)], PASSPHRASE))
        checks = len(self.polkit.checks)
        dialog, asked = self.import_file(["wrong one", PASSPHRASE])
        self.assertEqual(asked.call_count, 2)
        self.assertIn("duplicate in the file", dialog.plan.toPlainText())
        self.wait_for(lambda: not self.window._busy and "Imported" in self.window.statusBar().currentMessage())
        self.assertIn("Imported 1 passkey", self.window.statusBar().currentMessage())
        self.assertEqual(len(self.polkit.checks), checks + 1)
        self.wait_for(lambda: not self.window._refreshing and len(self.live()) == 8)

    def test_cancelled_import_adds_nothing(self):
        with open(self.path, "wb") as stream:
            stream.write(transfer.export_cxf([test_control.ControlTests.normalized(None)]))
        dialog, asked = self.import_file([], accept=False)
        asked.assert_not_called()  # CXF is not encrypted
        self.assertTrue(dialog.import_button.isEnabled())
        self.assertEqual(self.polkit.checks, [])
        self.window.refresh()
        self.wait_for(lambda: not self.window._refreshing)
        self.assertEqual(len(self.live()), 7)

    def test_unsupported_file_goes_to_the_status_bar(self):
        with open(self.path, "w") as stream:
            stream.write("[]")
        with patch.object(gui.QFileDialog, "getOpenFileName", return_value=(self.path, "")):
            self.window.import_passkeys()
        self.assertIn("not a LocalPasskey backup", self.window.statusBar().currentMessage())
        self.assertFalse(self.window._busy)


if __name__ == "__main__":
    unittest.main()
