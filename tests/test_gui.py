import os
import unittest
from datetime import date, datetime
from types import SimpleNamespace
from unittest.mock import patch

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QStandardItemModel
    from PyQt6.QtWidgets import QApplication, QWidget

    from localpasskey import gui
except ImportError:  # PyQt6 or QDarkStyle not installed
    gui = None


@unittest.skipIf(gui is None, "PyQt6 and QDarkStyle are not installed")
class HelperTests(unittest.TestCase):
    def test_brand_is_the_recognisable_part_of_the_domain(self):
        cases = {
            "github.com": "github",
            "login.microsoft.com": "microsoft",
            "www.bbc.co.uk": "bbc",
            "localhost": "localhost",
            "ssh:": "ssh:",
        }
        for site, expected in cases.items():
            self.assertEqual(gui.brand(site), expected, site)

    def test_when(self):
        today = date(2026, 10, 8)

        def at(*args):
            return datetime(*args).timestamp()

        month = datetime(2026, 3, 2).strftime("%B")
        december = datetime(2025, 12, 31).strftime("%B")
        self.assertEqual(gui.when(None, today), "Never")
        self.assertEqual(gui.when(at(2026, 10, 8, 6, 5), today), "Today at 06:05")
        self.assertEqual(gui.when(at(2026, 10, 7, 23, 0), today), "Yesterday at 23:00")
        self.assertEqual(gui.when(at(2026, 3, 2, 12), today), f"2 {month}")
        self.assertEqual(gui.when(at(2025, 12, 31, 12), today), f"31 {december} 2025")

    def test_search_matches_every_word_anywhere(self):
        cred = {"site": "github.com", "site_name": "GitHub", "user_name": "octocat", "display_name": "The Octocat"}
        self.assertTrue(gui.matches(cred, ""))
        self.assertTrue(gui.matches(cred, "GIT octo"))
        self.assertFalse(gui.matches(cred, "gitlab"))

    def test_only_domains_get_an_open_website_button(self):
        self.assertTrue(gui.is_website("github.com"))
        self.assertFalse(gui.is_website("localhost"))
        self.assertFalse(gui.is_website("ssh:"))
        self.assertTrue(gui.is_website("bücher.example"))
        for site in ("accounts.google.com@evil.example", "evil.example#.github.com", "evil.example?github.com",
                     "github.com\\@evil.example", "a b.com", "host:80"):
            self.assertFalse(gui.is_website(site), site)

    def test_list_is_sorted_by_brand_then_account(self):
        creds = [
            {"site": "proton.me", "user_name": "a"},
            {"site": "login.microsoft.com", "user_name": "a"},
            {"site": "github.com", "user_name": "zed"},
            {"site": "github.com", "user_name": "amy"},
        ]
        ordered = [(c["site"], c["user_name"]) for c in sorted(creds, key=gui.sort_key)]
        self.assertEqual(ordered, [("github.com", "amy"), ("github.com", "zed"),
                                   ("login.microsoft.com", "a"), ("proton.me", "a")])

    def test_trash_rows_show_and_sort_by_the_deletion_time(self):
        cred = {"id": "a", "site": "github.com", "user_name": "a", "last_used": None, "deleted": 20.0}
        self.assertEqual(gui.passkey_row(cred)[2].data(gui.SORT_ROLE), 0.0)
        self.assertEqual(gui.passkey_row(cred, trashed=True)[2].data(gui.SORT_ROLE), 20.0)
        self.assertEqual(gui.passkey_row(cred, trashed=True)[2].text(), gui.when(20.0))

    def test_first_visible_row_follows_display_order(self):
        model = QStandardItemModel(0, len(gui.COLUMNS))
        for site, user, used in (("proton.me", "a", 30.0), ("github.com", "zed", 10.0), ("github.com", "amy", 20.0)):
            model.appendRow(gui.passkey_row({"id": user, "site": site, "user_name": user, "last_used": used}))
        proxy = gui.PasskeyFilter()
        proxy.setSourceModel(model)

        def first():
            return proxy.index(0, 0).data(gui.CRED_ROLE)["user_name"] if proxy.rowCount() else None

        proxy.sort(0, Qt.SortOrder.AscendingOrder)
        self.assertEqual(first(), "amy")
        proxy.sort(2, Qt.SortOrder.DescendingOrder)
        self.assertEqual(first(), "a", "most recently used first")
        proxy.set_query("zed")
        self.assertEqual(first(), "zed")
        proxy.set_query("nobody")
        self.assertIsNone(first())


@unittest.skipIf(gui is None, "PyQt6 and QDarkStyle are not installed")
class PinDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {"QT_QPA_PLATFORM": "offscreen"}):
            cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = QWidget()
        self.window.tasks = SimpleNamespace(run=lambda work, done: None)  # the daemon never answers
        self.dialog = gui.PinDialog(self.window)

    def tearDown(self):
        self.window.deleteLater()

    def type(self, pin, repeat):
        self.dialog.pin.setText(pin)
        self.dialog.repeat.setText(repeat)
        return self.dialog.feedback.text(), self.dialog.feedback.styleSheet(), self.dialog.set_button.isEnabled()

    def test_set_pin_stays_dark_until_the_daemon_answers(self):
        self.assertEqual(self.dialog.status.text(), "Checking…")
        self.type("1234", "1234")
        self.assertFalse(self.dialog.set_button.isEnabled())
        self.dialog.show_state(True, 5)
        self.assertEqual(self.dialog.status.text(), "A security key PIN is set. 5 wrong attempts left before it locks.")
        self.assertEqual(self.dialog.set_button.text(), "Change PIN")
        self.assertTrue(self.dialog.set_button.isEnabled())

    def test_feedback_names_the_first_problem_on_every_keystroke(self):
        self.dialog.show_state(False, 8)
        red, green = gui.Feedback.BAD, gui.Feedback.GOOD
        cases = [
            ("", "", "Enter a PIN", red),
            ("123", "", "At least 4 characters", red),
            ("123", "999", "At least 4 characters", red),
            ("a" * 64, "", "At most 63 bytes", red),
            ("12\x0034", "", "No NUL characters", red),
            ("1234", "", "Confirm the PIN", red),
            ("1234", "12", "The PINs do not match", red),
            ("1234", "1234", "PIN is valid", green),
            ("äöüß", "äöüß", "PIN is valid", green),
        ]
        for pin, repeat, text, colour in cases:
            with self.subTest(pin=pin, repeat=repeat):
                shown, style, enabled = self.type(pin, repeat)
                self.assertEqual(shown, text)
                self.assertIn(colour, style)
                self.assertEqual(enabled, colour == green)

    def test_busy_dialog_keeps_set_pin_disabled(self):
        self.dialog.show_state(False, 8)
        self.type("1234", "1234")
        self.dialog._request("set")
        self.assertFalse(self.dialog.set_button.isEnabled())
        self.assertEqual(self.dialog.feedback.text(), "PIN is valid")


@unittest.skipIf(gui is None, "PyQt6 and QDarkStyle are not installed")
class CodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {"QT_QPA_PLATFORM": "offscreen"}):
            cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.parent = QWidget()
        self.addCleanup(self.parent.deleteLater)

    def test_codes_are_grouped_and_hidden_until_known(self):
        self.assertEqual(gui.grouped("123456"), "123 456")
        self.assertEqual(gui.grouped("12345678"), "1234 5678")
        entry = {"id": "ab", "site": "", "issuer": "Bank", "account": "Alice", "deleted": 5.0}
        self.assertEqual([c.text() for c in gui.code_row(entry)], ["Bank", "Alice", gui.HIDDEN_CODE])
        self.assertEqual(gui.code_row(entry, code="070818")[2].text(), "070 818")
        self.assertEqual(gui.code_row(entry, trashed=True)[2].text(), gui.when(5.0))
        self.assertEqual(gui.code_title({"site": "", "issuer": ""}), "Unknown website")
        self.assertTrue(gui.matches(entry, "bank ali"))

    def test_add_dialog_feedback_and_the_entry_it_sends(self):
        dialog = gui.CodeDialog(self.parent)
        cases = [
            ("", "Paste the setup key or link the website shows"),
            ("JBSW", "The setup key is too short"),
            ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", "The link has no counter parameter"),
            ("jbsw y3dp ehpk 3pxp", "Setup key is valid"),
        ]
        for text, shown in cases:
            with self.subTest(text=text):
                dialog.key.setText(text)
                self.assertEqual(dialog.feedback.text(), shown)
                self.assertEqual(dialog.save_button.isEnabled(), shown == "Setup key is valid")
        self.assertFalse(dialog.note.isVisibleTo(dialog))
        self.assertEqual(dialog.entry(), {"secret": "JBSWY3DPEHPK3PXP", "site": "", "issuer": "", "account": "",
                                          "algorithm": "SHA1", "digits": 6, "period": 30})
        dialog.key.setText("otpauth://totp/Big%20Corp:al?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&period=60")
        self.assertEqual((dialog.site.text(), dialog.issuer.text(), dialog.account.text()), ("", "Big Corp", "al"))
        self.assertTrue(dialog.note.isVisibleTo(dialog))
        self.assertIn("SHA256 · 6 digits · every 60 s", dialog.note.text())
        dialog.site.setText("a b")
        self.assertFalse(dialog.save_button.isEnabled())

    def test_edit_dialog_has_no_setup_key(self):
        dialog = gui.CodeDialog(self.parent, {"site": "github.com", "issuer": "GitHub", "account": "octocat"})
        self.assertFalse(dialog.key.isVisibleTo(dialog))
        self.assertTrue(dialog.save_button.isEnabled())
        self.assertEqual(dialog.feedback.text(), "")
        dialog.account.setText(" octo ")
        self.assertEqual(dialog.labels(), {"site": "github.com", "issuer": "GitHub", "account": "octo"})

    def test_each_parse_refills_the_labels_the_user_has_not_edited(self):
        from PyQt6.QtTest import QTest
        dialog = gui.CodeDialog(self.parent)

        def labels():
            return dialog.site.text(), dialog.issuer.text(), dialog.account.text()

        dialog.key.setText("otpauth://totp/example.com:bob?secret=JBSWY3DPEHPK3PXP&issuer=example.com")
        self.assertEqual(labels(), ("example.com", "example.com", "bob"))
        dialog.key.setText("otpauth://totp/Big%20Corp:carol?secret=JBSWY3DPEHPK3PXP&issuer=Big%20Corp")
        self.assertEqual(labels(), ("", "Big Corp", "carol"), "a second link replaces the first one's labels")
        dialog.key.setText("JBSWY3DPEHPK3PXP")
        self.assertEqual(labels(), ("", "", ""))
        QTest.keyClicks(dialog.account, "me")
        QTest.keyClicks(dialog.site, "mine.example")
        dialog.key.setText("otpauth://totp/example.com:bob?secret=JBSWY3DPEHPK3PXP&issuer=example.com")
        self.assertEqual(labels(), ("mine.example", "example.com", "me"), "typed fields are kept")

    def test_a_typed_website_is_reduced_to_its_host_name(self):
        dialog = gui.CodeDialog(self.parent, {"site": "", "issuer": " GitHub ", "account": " octocat "})
        dialog.site.setText(" https://GitHub.com/login ")
        self.assertTrue(dialog.save_button.isEnabled())
        self.assertEqual(dialog.labels(), {"site": "github.com", "issuer": "GitHub", "account": "octocat"})
        dialog.site.setText("https://not a site/")
        self.assertFalse(dialog.save_button.isEnabled())

    def test_purge_asks_for_the_stripped_site_else_issuer_else_delete(self):
        cases = [({"site": " github.com ", "issuer": "GitHub"}, "github.com"),
                 ({"site": "", "issuer": " Example Bank "}, "Example Bank"),
                 ({"site": " ", "issuer": "  "}, "delete")]
        for labels, expected in cases:
            with self.subTest(labels=labels):
                asked = []
                window = SimpleNamespace(_busy=False, _send=lambda *a, **k: None,
                                         _confirm_typed=lambda question, typed: asked.append(typed))
                gui.Window.confirm_purge_code(window, {"id": "ab", "account": "", **labels})
                self.assertEqual(asked, [expected])

    def test_typed_confirmation_ignores_case_and_surrounding_spaces(self):
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QDialogButtonBox, QLineEdit
        seen = []

        def answer():
            dialog = self.app.activeModalWidget()
            box = dialog.findChild(QDialogButtonBox)
            delete = next(b for b in box.buttons()
                          if box.buttonRole(b) == QDialogButtonBox.ButtonRole.DestructiveRole)
            dialog.findChild(QLineEdit).setText("  example BANK ")
            seen.append(delete.isEnabled())
            dialog.reject()

        QTimer.singleShot(0, answer)
        gui.Window._confirm_typed(self.parent, "Delete?", " Example Bank ")
        self.assertEqual(seen, [True])


if __name__ == "__main__":
    unittest.main()
