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
        self.assertEqual(self.dialog.status.text(), "A PIN is set (5 attempts left).")
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
            ("1234", "", "Repeat the PIN", red),
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


if __name__ == "__main__":
    unittest.main()
