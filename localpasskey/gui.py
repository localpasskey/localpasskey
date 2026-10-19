"""LocalPasskey's window: see, search and remove the passkeys on this computer.

Qt 6 with QDarkStyle, the dark theme Electrum and Feather Wallet use.
Everything goes through localpasskeyd's control socket, so the window only
sees the current user's passkeys, and deleting one makes the service ask for
the user's password first. Deleted passkeys wait in the trash view until they
are restored or permanently deleted, and the PIN browsers ask for can be set
or removed here too. Passkeys can be exported to an encrypted backup and
imported from one (or from CXF and Bitwarden files); the files are read,
written and encrypted here, never by the service.

The Authenticator Codes tab shows the codes the service keeps for the user:
time-based (TOTP), Steam, and counter-based (HOTP) ones. Opening it asks the
service for the user's password once; the window then asks for the current
codes while it is active, and only the codes: the setup keys never leave the
service except in an export. An HOTP code is only made on Next Code, since
each one uses up its counter.
"""

from __future__ import annotations

import math
import os
import sys
import threading
import time
from datetime import date, datetime, timedelta

import qdarkstyle
from PyQt6.QtCore import (
    QEvent, QItemSelectionModel, QMimeData, QObject, QRectF, QSortFilterProxyModel, Qt, QTimer, QUrl, pyqtSignal,
)
from PyQt6.QtGui import (
    QAction, QColor, QDesktopServices, QFontDatabase, QGuiApplication, QIcon, QKeySequence, QPainter,
    QPainterPath, QPen, QPixmap, QStandardItem, QStandardItemModel,
)
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QButtonGroup, QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QFrame, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QRadioButton, QSplitter, QStackedWidget, QStyle, QTabBar, QToolButton, QTreeView,
    QVBoxLayout, QWidget,
)

from . import __version__, totp, transfer
from .cli import (
    join_counts, migration_records, planned_records, plural, plural_codes, unwritable, write_private_file,
)
from .client import ServiceUnavailable, request
from .clientpin import MAX_PIN_RETRIES, pin_problem
from .ctap2 import valid_rp_id

APP_ID = "org.localpasskey.Manager"
REFRESH_MS = 5000
PALETTE = qdarkstyle.DarkPalette
# One sticky-note yellow for every tooltip; QDarkStyle's are blue, and a darker blue in the status bar.
TOOLTIP_STYLE = (
    "QToolTip, QStatusBar QToolTip { background-color: #FFF475; color: #000000;"
    " border: 1px solid #000000; padding: 4px; opacity: 255; }"
)
CRED_ROLE = Qt.ItemDataRole.UserRole
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
COLUMNS = ("Website", "Account", "Last used")
TRASH_COLUMNS = ("Website", "Account", "Deleted")
CODE_COLUMNS = ("Website", "Account", "Code")
TICK_MS = 1000  # the countdown, and the check whether the codes need fetching again
KEEP_UNLOCKED_S = 60  # fetch at least this often: long periods must not let the service's 5 min unlock run out
COPY_CLEAR_MS = 30000
HIDDEN_CODE = "••••••"
LOCKED = "authenticator codes are locked"  # the service's error once an unlock has gone
_SECOND_LEVEL = {"ac", "co", "com", "edu", "gov", "net", "org"}
# Bulk confirmations: window title, button, question, what the items do meanwhile.
BULK = {
    "delete": ("Move to Trash", "Move to Trash", "Move {n} passkey{s} to the trash?",
               "They stop working until you restore them."),
    "restore": ("Restore Passkeys", "Restore", "Restore {n} passkey{s} from the trash?",
                "They sign you in again right away."),
    "delete_codes": ("Move to Trash", "Move to Trash", "Move {n} authenticator code{s} to the trash?",
                     "Their codes are not shown until you restore them."),
    "restore_codes": ("Restore Codes", "Restore", "Restore {n} authenticator code{s} from the trash?",
                      "They show codes again right away."),
}


def brand(site: str) -> str:
    """The part of a domain people recognise: login.microsoft.com -> microsoft."""
    labels = [label for label in site.split(".") if label]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return labels[-3]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else site


def account_label(cred: dict) -> str:
    return cred.get("user_name") or cred.get("display_name") or "Unnamed account"


def is_website(site: str) -> bool:
    url = QUrl()
    url.setHost(site, QUrl.ParsingMode.StrictMode)  # strict: '@', '#', '?' or '\\' would make the URL open another host
    return "." in site and bool(url.host())


def matches(cred: dict, query: str) -> bool:
    keys = ("site", "site_name", "user_name", "display_name", "issuer", "account")  # passkeys and codes
    haystack = " ".join(cred.get(key) or "" for key in keys).lower()
    return all(word in haystack for word in query.lower().split())


def sort_key(cred: dict):
    return brand(cred["site"]).lower(), cred["site"], account_label(cred).lower()


def when(timestamp, today=None) -> str:
    if not timestamp:
        return "Never"
    moment = datetime.fromtimestamp(timestamp)
    today = today or date.today()
    clock = moment.strftime("%H:%M")
    if moment.date() == today:
        return f"Today at {clock}"
    if moment.date() == today - timedelta(days=1):
        return f"Yesterday at {clock}"
    day = f"{moment.day} {moment:%B}"
    return day if moment.year == today.year else f"{day} {moment.year}"


def passkey_row(cred: dict, trashed: bool = False) -> list:
    """The table cells for one passkey, carrying the values the columns sort by."""
    website = QStandardItem(cred["site"])
    website.setData(cred, CRED_ROLE)
    website.setData("\0".join(sort_key(cred)), SORT_ROLE)
    account = QStandardItem(account_label(cred))
    account.setData(account_label(cred).lower(), SORT_ROLE)
    moment = cred.get("deleted") if trashed else cred.get("last_used")
    when_item = QStandardItem(when(moment))
    when_item.setData(moment or 0.0, SORT_ROLE)
    return [website, account, when_item]


def code_title(entry: dict) -> str:
    """What the Website column says for a code: the site, else the issuer."""
    return entry.get("site") or entry.get("issuer") or "Unknown website"


def grouped(code: str) -> str:
    """123456 -> "123 456", 12345678 -> "1234 5678": easier to read and type.
    A Steam code's 5 characters stay as they are."""
    if len(code) % 2:
        return code
    half = len(code) // 2
    return f"{code[:half]} {code[half:]}"


def code_type(entry: dict) -> str:
    if entry.get("kind") == "steam":
        return f"Steam · 5 characters · every {entry['period']} s"
    if entry.get("kind") == "hotp":
        return f"{entry['algorithm']} · {entry['digits']} digits · a new code each time you ask"
    return f"{entry['algorithm']} · {entry['digits']} digits · every {entry['period']} s"


def code_row(entry: dict, trashed: bool = False, code=None) -> list:
    """The table cells for one authenticator code; ``code`` is the current one, if known."""
    title = code_title(entry)
    website = QStandardItem(title)
    website.setData(entry, CRED_ROLE)
    website.setData("\0".join((brand(title).lower(), title, entry["account"].lower())), SORT_ROLE)
    account = QStandardItem(entry["account"])
    account.setData(entry["account"].lower(), SORT_ROLE)
    if trashed:
        third = QStandardItem(when(entry.get("deleted")))
        third.setData(entry.get("deleted") or 0.0, SORT_ROLE)
    else:
        third = QStandardItem(grouped(code) if code else HIDDEN_CODE)
        third.setData("", SORT_ROLE)  # sorting by a code that changes every 30 s means nothing
        third.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    return [website, account, third]


def monogram(text: str, size: int, ratio: float) -> QPixmap:
    pixmap = QPixmap(round(size * ratio), round(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(PALETTE.COLOR_BACKGROUND_4))
    painter.drawEllipse(QRectF(0, 0, size, size))
    font = painter.font()
    font.setBold(True)
    font.setPixelSize(round(size * 0.45))
    painter.setFont(font)
    painter.setPen(QColor(PALETTE.COLOR_TEXT_1))
    painter.drawText(QRectF(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, text[:1].upper())
    painter.end()
    return pixmap


PIN_PURPOSE = (
    "Browsers ask for the security key PIN before they list or delete these passkeys in their "
    "security-key settings, such as chrome://settings/securityKeys. It stays on this computer, "
    "is never sent to websites, and is not your login password."
)


def pin_summary(pin) -> str:
    """One sentence on the PIN state from a ``pin status`` reply, or None if unknown."""
    if pin is None:
        return None
    if not pin["set"]:
        return "No security key PIN is set. Browsers need one before they can list or delete these passkeys."
    if pin["retries"] == 0:
        return "The security key PIN is locked after too many wrong attempts. Set a new PIN to unlock it."
    if pin["retries"] < MAX_PIN_RETRIES:
        left = pin["retries"]
        return f"A security key PIN is set. {left} wrong attempt{'s' if left != 1 else ''} left before it locks."
    return "A security key PIN is set."


def lock_pixmap(closed: bool, color: str, size: int, ratio: float) -> QPixmap:
    """A padlock, closed or with its shackle open; no icon theme ships one that suits the dark style."""
    pixmap = QPixmap(round(size * ratio), round(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(color), size * 0.12)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    left, right = size * 0.3, size * 0.7
    top = size * (0.16 if closed else 0.06)  # an open shackle sits higher, free on the right
    middle = top + (right - left) / 2
    shackle = QPainterPath()
    shackle.moveTo(left, size * 0.48)
    shackle.lineTo(left, middle)
    shackle.arcTo(QRectF(left, top, right - left, right - left), 180, -180)
    if closed:
        shackle.lineTo(right, size * 0.48)
    painter.drawPath(shackle)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(color))
    painter.drawRoundedRect(QRectF(size * 0.16, size * 0.45, size * 0.68, size * 0.5), size * 0.08, size * 0.08)
    painter.end()
    return pixmap


def app_icon() -> QIcon:
    source = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "data", "icons",
                          "hicolor", "scalable", "apps", f"{APP_ID}.svg")
    if os.path.isfile(source):  # running from a source checkout
        return QIcon(source)
    return QIcon.fromTheme(APP_ID)


class Tasks(QObject):
    """Runs blocking control-socket requests off the GUI thread."""

    _finished = pyqtSignal(object, object, object)

    def __init__(self):
        super().__init__()
        self._finished.connect(lambda done, result, error: done(result, error))

    def run(self, work, done):
        """Call ``work()`` on a thread, then ``done(result, error)`` here."""

        def thread():
            try:
                outcome = (work(), None)
            except Exception as e:
                outcome = (None, e)
            self._finished.emit(done, *outcome)

        threading.Thread(target=thread, daemon=True).start()


class PasskeyFilter(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.query = ""
        self.setSortRole(SORT_ROLE)

    def set_query(self, query):
        self.query = query
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        return not self.query or matches(self.sourceModel().index(row, 0, parent).data(CRED_ROLE), self.query)


class Details(QFrame):
    def __init__(self, window):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.cred = None
        heading = self._heading()

        self.form = QFormLayout()
        self._form_rows = {}
        self.form.setHorizontalSpacing(18)
        self.form.setVerticalSpacing(10)
        self.form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.username = self._row("Username", copy=lambda: window.copy(self.cred["user_name"], "Username"))
        self.display_name = self._row("Display name")
        self.algorithm = self._row("Algorithm")
        self.created = self._row("Created")
        self.last_used = self._row("Last used")
        self.deleted = self._row("Deleted")
        self.ident = self._row("ID", copy=lambda: window.copy(self.cred["id"], "ID"))

        self.open_button = QPushButton("Open Website")
        self.open_button.clicked.connect(lambda: window.open_site(self.cred))
        self.delete_button = QPushButton("Move to Trash…")
        self.delete_button.clicked.connect(lambda: window.confirm_delete(self.cred))
        buttons = QHBoxLayout()
        buttons.addWidget(self.open_button)
        buttons.addWidget(self.delete_button)
        buttons.addStretch(1)

        self.trash_buttons = QHBoxLayout()
        self.restore_button = QPushButton("Restore")
        self.restore_button.clicked.connect(lambda: window._send(
            {"command": "restore", "ids": [self.cred["id"]]}, "Restoring…", "Passkey restored"))
        self.purge_button = QPushButton("Delete Permanently…")
        self.purge_button.clicked.connect(lambda: window.confirm_purge(self.cred))
        self.trash_buttons.addWidget(self.restore_button)
        self.trash_buttons.addWidget(self.purge_button)
        self.trash_buttons.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        layout.addLayout(heading)
        layout.addLayout(self.form)
        layout.addLayout(buttons)
        layout.addLayout(self.trash_buttons)
        layout.addStretch(1)

    def _heading(self):
        """The monogram, the big site name and the summary line under it."""
        self.monogram = QLabel()
        self.site = QLabel()
        self.site.setTextFormat(Qt.TextFormat.PlainText)
        self.site.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        font = self.site.font()
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() * 1.5)
        self.site.setFont(font)
        self.summary = QLabel()
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setStyleSheet(f"color: {PALETTE.COLOR_TEXT_3};")
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(self.site)
        titles.addWidget(self.summary)
        heading = QHBoxLayout()
        heading.setSpacing(14)
        heading.addWidget(self.monogram)
        heading.addLayout(titles, 1)
        return heading

    def _row(self, title, copy=None):
        value = QLabel()
        value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        value.setTextFormat(Qt.TextFormat.PlainText)
        field = QHBoxLayout()
        field.setSpacing(8)
        field.addWidget(value, 1)
        if copy:
            button = QPushButton("Copy")
            button.setToolTip(f"Copy the {title.lower()}")
            button.clicked.connect(copy)
            field.addWidget(button)
        self._form_rows[value] = self.form.rowCount()
        self.form.addRow(title, field)
        return value

    def _show_row(self, value, visible):
        self.form.setRowVisible(self._form_rows[value], visible)

    def show_cred(self, cred):
        self.cred = cred
        site = cred["site"]
        self.monogram.setPixmap(monogram(brand(site), 48, self.devicePixelRatioF()))
        self.site.setText(site)
        site_name = cred.get("site_name") or ""
        kind = "Passkey" if cred["discoverable"] else "Security key"
        if cred.get("deleted") is not None:
            kind = f"In the trash · {kind}"
        self.summary.setText(f"{site_name} · {kind}" if site_name and site_name.lower() != site.lower() else kind)
        self.summary.setToolTip(
            "Signs you in without a username" if cred["discoverable"]
            else "A second sign-in step after your password"
        )
        user_name, display_name = cred.get("user_name") or "", cred.get("display_name") or ""
        self.username.setText(user_name)
        self.display_name.setText(display_name)
        self._show_row(self.username, bool(user_name))
        self._show_row(self.display_name, bool(display_name) and display_name != user_name)
        trashed = cred.get("deleted") is not None
        self.algorithm.setText(cred.get("algorithm") or "")
        self.created.setText(when(cred.get("created")))
        self.last_used.setText(when(cred.get("last_used")))
        self.deleted.setText(when(cred.get("deleted")))
        self._show_row(self.deleted, trashed)
        self.ident.setText(cred["id"][:12])
        self.open_button.setVisible(is_website(site) and not trashed)
        self.delete_button.setVisible(not trashed)
        self.restore_button.setVisible(trashed)
        self.purge_button.setVisible(trashed)

    def set_busy(self, busy, moving=True):
        self.delete_button.setEnabled(not busy)
        self.delete_button.setText("Moving…" if busy and moving else "Move to Trash…")
        self.restore_button.setEnabled(not busy)
        self.purge_button.setEnabled(not busy)


class CodeLabel(QLabel):
    """The large code in the details panel: a double-click copies it, as the button does."""

    def __init__(self, window):
        super().__init__(HIDDEN_CODE)
        self.window = window

    def mouseDoubleClickEvent(self, event):
        self.window.copy_code()


class CodeDetails(QFrame):
    """One authenticator code: its current value, a countdown (an HOTP code: its counter) and its labels."""

    _heading, _row, _show_row = Details._heading, Details._row, Details._show_row

    def __init__(self, window):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.entry = None
        heading = self._heading()

        self.code = CodeLabel(window)
        self.code.setTextFormat(Qt.TextFormat.PlainText)
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setBold(True)
        font.setPointSizeF(self.font().pointSizeF() * 2)
        self.code.setFont(font)
        self.countdown = QLabel()
        self.countdown.setStyleSheet(f"color: {PALETTE.COLOR_TEXT_3};")
        self.copy_button = QPushButton("Copy Code")
        self.copy_button.clicked.connect(lambda: window.copy_code())
        self.next_button = QPushButton("Next Code")
        self.next_button.clicked.connect(lambda: window.next_code(self.entry))
        value = QHBoxLayout()
        value.setSpacing(14)
        value.addWidget(self.code)
        value.addWidget(self.countdown, 1)
        value.addWidget(self.next_button)
        value.addWidget(self.copy_button)

        self.form = QFormLayout()
        self._form_rows = {}
        self.form.setHorizontalSpacing(18)
        self.form.setVerticalSpacing(10)
        self.form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.issuer = self._row("Issuer")
        self.account = self._row("Account")
        self.kind = self._row("Type")
        self.created = self._row("Created")
        self.deleted = self._row("Deleted")
        self.ident = self._row("ID")

        self.edit_button = QPushButton("Edit…")
        self.edit_button.clicked.connect(lambda: window.edit_code(self.entry))
        self.delete_button = QPushButton("Move to Trash…")
        self.delete_button.clicked.connect(lambda: window.confirm_delete_code(self.entry))
        self.restore_button = QPushButton("Restore")
        self.restore_button.clicked.connect(lambda: window.restore_code(self.entry))
        self.purge_button = QPushButton("Delete Permanently…")
        self.purge_button.clicked.connect(lambda: window.confirm_purge_code(self.entry))
        buttons = QHBoxLayout()
        for button in (self.edit_button, self.delete_button, self.restore_button, self.purge_button):
            buttons.addWidget(button)
        buttons.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        layout.addLayout(heading)
        layout.addLayout(value)
        layout.addLayout(self.form)
        layout.addLayout(buttons)
        layout.addStretch(1)

    def show_entry(self, entry, value=None):
        self.entry = entry
        title = code_title(entry)
        trashed = entry.get("deleted") is not None
        self.monogram.setPixmap(monogram(brand(title), 48, self.devicePixelRatioF()))
        self.site.setText(title)
        kind = "In the trash · Authenticator code" if trashed else "Authenticator code"
        issuer = entry["issuer"]
        self.summary.setText(f"{issuer} · {kind}" if issuer and issuer.lower() != title.lower() else kind)
        self.issuer.setText(issuer)
        self.account.setText(entry["account"])
        self._show_row(self.issuer, bool(issuer))
        self._show_row(self.account, bool(entry["account"]))
        self.kind.setText(code_type(entry))
        self.created.setText(when(entry.get("created")))
        self.deleted.setText(when(entry.get("deleted")))
        self._show_row(self.deleted, trashed)
        self.ident.setText(entry["id"][:12])
        for widget in (self.code, self.countdown, self.copy_button, self.edit_button, self.delete_button):
            widget.setVisible(not trashed)
        self.next_button.setVisible(not trashed and entry.get("kind") == "hotp")
        self.restore_button.setVisible(trashed)
        self.purge_button.setVisible(trashed)
        self.show_value(value)

    def show_value(self, value):
        """``value`` is (code, monotonic time it runs out, period), or None while unknown;
        an HOTP code does not run out: (code, None, its counter)."""
        self.code.setText(grouped(value[0]) if value else HIDDEN_CODE)
        if self.entry.get("kind") == "hotp":  # before Next Code: the counter the next code uses
            self.countdown.setText(f"Counter {value[2] if value else self.entry['counter']}")
        elif value is None:
            self.countdown.setText("")
        else:
            left = max(0, math.ceil(value[1] - time.monotonic()))
            self.countdown.setText(f"Changes in {left} s")
        self.copy_button.setEnabled(value is not None)

    def set_busy(self, busy, moving=True):
        for button in (self.edit_button, self.delete_button, self.restore_button, self.purge_button,
                       self.next_button):
            button.setEnabled(not busy)
        self.delete_button.setText("Moving…" if busy and moving else "Move to Trash…")


class Message(QWidget):
    """A centred icon, title and explanation for the empty states."""

    def __init__(self):
        super().__init__()
        self.icon = QLabel(alignment=Qt.AlignmentFlag.AlignCenter)
        self.icon.setPixmap(app_icon().pixmap(72, 72))
        self.title = QLabel(alignment=Qt.AlignmentFlag.AlignCenter)
        font = self.title.font()
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() * 1.3)
        self.title.setFont(font)
        self.text = QLabel(alignment=Qt.AlignmentFlag.AlignCenter, wordWrap=True)
        self.text.setStyleSheet(f"color: {PALETTE.COLOR_TEXT_3};")
        self.button = QPushButton(visible=False)  # the locked codes' Unlock
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addStretch(1)
        for widget in (self.icon, self.title, self.text):
            layout.addWidget(widget)
        layout.addWidget(self.button, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(2)

    def set_message(self, title, text="", button=None):
        self.title.setText(title)
        self.text.setText(text)
        self.text.setVisible(bool(text))
        self.button.setText(button or "")
        self.button.setVisible(bool(button))


class Feedback(QLabel):
    """A plain-text line that says what is wrong with a field as the user types."""

    BAD = "#e06c75"  # QDarkStyle has no red or green; these read well on its background
    GOOD = "#98c379"

    def __init__(self):
        super().__init__()
        self.setTextFormat(Qt.TextFormat.PlainText)

    def show_problem(self, problem, fine):
        """Show ``problem`` in red, or ``fine`` in green if there is none."""
        self.setText(problem or fine)
        self.setStyleSheet(f"color: {self.BAD if problem else self.GOOD};")


class PinDialog(QDialog):
    """Set, change or remove the security key PIN browsers ask for before they
    list or delete passkeys."""

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.setWindowTitle("Security Key PIN")
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.why = QLabel(
            PIN_PURPOSE + " Signing in to websites still uses the usual confirmation dialog. "
            "If you forget the PIN, set a new one here: your passkeys are kept."
        )
        self.why.setTextFormat(Qt.TextFormat.PlainText)
        self.why.setWordWrap(True)
        self.why.setStyleSheet(f"color: {PALETTE.COLOR_TEXT_3};")
        self.pin = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.repeat = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        form = QFormLayout()
        form.addRow("New PIN", self.pin)
        form.addRow("Confirm", self.repeat)
        self.feedback = Feedback()
        self.set_button = QPushButton("Set PIN")
        self.set_button.clicked.connect(lambda: self._request("set"))
        self.remove_button = QPushButton("Remove PIN")
        self.remove_button.clicked.connect(lambda: self._request("remove"))
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addWidget(self.set_button)
        buttons.addWidget(self.remove_button)
        buttons.addStretch(1)
        buttons.addWidget(close)
        layout = QVBoxLayout(self)
        layout.addWidget(self.status)
        layout.addWidget(self.why)
        layout.addLayout(form)
        layout.addWidget(self.feedback)
        layout.addLayout(buttons)
        for field in (self.pin, self.repeat):
            field.textChanged.connect(self._sync)
        # Nothing is known until the daemon answers; keep the controls dark so no
        # click can race the status request.
        self.busy = True
        self.status.setText("Checking…")
        for widget in (self.pin, self.repeat, self.set_button, self.remove_button):
            widget.setEnabled(False)
        self.window.tasks.run(lambda: request({"command": "pin", "action": "status"}), self._on_loaded)

    def _sync(self, *_):
        problem = pin_problem(self.pin.text(), self.repeat.text())
        if problem is None and not self.repeat.text():
            problem = "Confirm the PIN"  # never green while Set PIN is still greyed out
        self.feedback.show_problem(problem, "PIN is valid")
        self.set_button.setEnabled(problem is None and not self.busy)

    def show_state(self, is_set, retries):
        self.busy = False
        self.status.setText(pin_summary({"set": is_set, "retries": retries}))
        self.set_button.setText("Change PIN" if is_set else "Set PIN")
        for widget in (self.pin, self.repeat):
            widget.setEnabled(True)
        self.remove_button.setEnabled(is_set)
        self._sync()

    def _on_loaded(self, result, error):
        if error is not None:
            # The state is unknown, not "no PIN set": inventing one would offer
            # to set a PIN over an existing one and hide Remove PIN.
            self.status.setText("Could not check whether a security key PIN is set.")
            self.window._error(error)
            return
        self.show_state(result["set"], result["retries"])

    def _request(self, action):
        payload = {"command": "pin", "action": action}
        if action == "set":
            if self.pin.text() != self.repeat.text():
                self.status.setText("The PINs do not match.")
                return
            payload["pin"] = self.pin.text()
        self.busy = True
        self.remove_button.setEnabled(False)
        self._sync()
        self.window.tasks.run(lambda: request(payload), self._sent)

    def _sent(self, result, error):
        if error is not None:
            self.window._error(error)
        else:
            self.pin.clear()
            self.repeat.clear()
        # Re-read the state either way: a refused PIN may still have burned a retry.
        self.window.tasks.run(lambda: request({"command": "pin", "action": "status"}), self._on_loaded)


class ExportDialog(QDialog):
    """Choose what to export and the passphrase that encrypts the backup."""

    def __init__(self, window, site=None, codes=0):
        super().__init__(window)
        self.setWindowTitle("Export Passkeys")
        intro = QLabel(
            "Choose a new passphrase to encrypt the exported file. This is not your login "
            "password: you will need this passphrase to import the file again, and nobody can "
            "recover it if you forget it. Anyone with the file and the passphrase can sign in "
            "as you."
        )
        intro.setTextFormat(Qt.TextFormat.PlainText)
        intro.setWordWrap(True)
        self.next_step = QLabel("After you choose where to save the file, your login password is asked for to allow the export.")
        self.next_step.setTextFormat(Qt.TextFormat.PlainText)
        self.next_step.setWordWrap(True)
        self.next_step.setStyleSheet(f"color: {PALETTE.COLOR_TEXT_3};")
        self.intro = intro
        self.all = QRadioButton("All passkeys")
        self.site = QRadioButton(f"Passkeys for {site}" if site else "Passkeys for the selected website")
        self.site.setEnabled(bool(site))
        (self.site if site else self.all).setChecked(True)
        self._site = site
        scope = QButtonGroup(self)
        scope.addButton(self.all)
        scope.addButton(self.site)
        # With a site chosen, only the codes saved for that website go along: their number is not known here.
        self.codes = QCheckBox(checked=bool(codes), enabled=bool(codes))
        def label(site_chosen):
            self.codes.setText("Include this website's authenticator codes" if site_chosen
                               else f"Include authenticator codes ({codes or 0})")

        label(self.site.isChecked())
        self.site.toggled.connect(label)
        self.passphrase = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.repeat = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        form = QFormLayout()
        form.addRow("Backup passphrase", self.passphrase)
        form.addRow("Confirm", self.repeat)
        self.feedback = Feedback()
        buttons = QDialogButtonBox()
        self.export_button = buttons.addButton("Export…", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self.all)
        layout.addWidget(self.site)
        layout.addWidget(self.codes)
        layout.addLayout(form)
        layout.addWidget(self.feedback)
        layout.addWidget(self.next_step)
        layout.addWidget(buttons)
        for field in (self.passphrase, self.repeat):
            field.textChanged.connect(self._sync)
        self._sync()

    def _sync(self, *_):
        problem = transfer.passphrase_problem(self.passphrase.text(), self.repeat.text())
        if problem is None and not self.repeat.text():
            problem = "Confirm the passphrase"
        self.feedback.show_problem(problem, "Passphrase is valid")
        self.export_button.setEnabled(problem is None)

    def selector(self):
        chosen = {"site": self._site} if self.site.isChecked() else {"all": True}
        return {**chosen, "codes": True} if self.codes.isChecked() else chosen


def plan_text(imported, skipped, codes=(), skipped_codes=()) -> str:
    """The import plan as plain text: one line per passkey or authenticator code."""
    def clean(text):  # names come from the import file: keep each passkey on one line
        return "".join(ch if ch.isprintable() else " " for ch in text)

    def line(cred):
        return clean(f"{cred.get('site') or '?'}  {account_label(cred)}")

    lines = [f"Will be imported ({len(imported)}):", *(f"  {line(c)}" for c in imported)]
    if skipped:
        lines += ["", f"Skipped ({len(skipped)}):"]
        lines += [f"  {line(s['credential'])}: {clean(s['reason'])}" for s in skipped]
    if codes or skipped_codes:
        def code_line(entry):
            return clean(f"{code_title(entry)}  {entry.get('account') or ''}".rstrip())

        lines += ["", f"Authenticator codes to import ({len(codes)}):", *(f"  {code_line(c)}" for c in codes)]
        if skipped_codes:
            lines += ["", f"Skipped authenticator codes ({len(skipped_codes)}):"]
            lines += [f"  {code_line(s['code'])}: {clean(s['reason'])}" for s in skipped_codes]
    return "\n".join(lines)


class ImportDialog(QDialog):
    """What an import will add and what it skips, before anything is asked."""

    def __init__(self, window, imported, skipped, codes=(), skipped_codes=()):
        super().__init__(window)
        self.setWindowTitle("Import Passkeys")
        n = len(imported) + len(codes)
        heading = QLabel(f"Import {join_counts(len(imported), len(codes))}?" if n else "Nothing to import.")
        heading.setTextFormat(Qt.TextFormat.PlainText)
        self.plan = QPlainTextEdit(plan_text(imported, skipped, codes, skipped_codes), readOnly=True)
        self.plan.setMinimumSize(480, 240)
        buttons = QDialogButtonBox()
        self.import_button = buttons.addButton("Import", QDialogButtonBox.ButtonRole.AcceptRole)
        self.import_button.setEnabled(bool(n))
        buttons.addButton(QDialogButtonBox.StandardButton.Cancel if n else QDialogButtonBox.StandardButton.Close)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(self.plan)
        layout.addWidget(buttons)


class CodeDialog(QDialog):
    """Add an authenticator code from a pasted setup key or otpauth:// link (or every code in a
    Google Authenticator export link), or, given ``entry``, change the website, issuer and account of one."""

    def __init__(self, window, entry=None):
        super().__init__(window)
        self.setWindowTitle("Edit Authenticator Code" if entry else "Add Authenticator Code")
        self.adding = entry is None
        self.parsed = None
        self.migration = None  # parse_migration's (entries, skipped) for an export link
        self.pasted = None  # what Paste took from the clipboard, to clear it after saving
        self.key = QLineEdit(echoMode=QLineEdit.EchoMode.Password, maxLength=totp.MAX_INPUT)
        show = QPushButton("Show", checkable=True)
        show.toggled.connect(lambda on: self.key.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        paste = QPushButton("Paste")
        paste.clicked.connect(self._paste)
        key = QHBoxLayout()
        key.addWidget(self.key, 1)
        key.addWidget(show)
        key.addWidget(paste)
        self.site = QLineEdit(placeholderText="github.com", maxLength=totp.MAX_LABEL)
        self.issuer = QLineEdit(maxLength=totp.MAX_LABEL)
        self.account = QLineEdit(maxLength=totp.MAX_LABEL)
        form = QFormLayout()
        if self.adding:
            form.addRow("Setup key or link", key)
        form.addRow("Website", self.site)
        form.addRow("Issuer", self.issuer)
        form.addRow("Account", self.account)
        self.note = QLabel(visible=False, wordWrap=True)
        self.note.setTextFormat(Qt.TextFormat.PlainText)
        self.note.setStyleSheet(f"color: {PALETTE.COLOR_TEXT_3};")
        self.feedback = Feedback()
        buttons = QDialogButtonBox()
        self.save_button = buttons.addButton("Save", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.note)
        layout.addWidget(self.feedback)
        layout.addWidget(buttons)
        self.setMinimumWidth(480)
        if entry is not None:
            self.site.setText(entry["site"])
            self.issuer.setText(entry["issuer"])
            self.account.setText(entry["account"])
        self.edited = set()  # the label fields the user has typed in
        for field in (self.site, self.issuer, self.account):
            field.textEdited.connect(lambda _, field=field: self.edited.add(field))
        self.key.textChanged.connect(self._parse)
        self.site.textChanged.connect(self._sync)
        self._parse(self.key.text())

    def _paste(self):
        """Read the clipboard only when asked to; nothing watches it."""
        self.pasted = QGuiApplication.clipboard().text()
        self.key.setText(self.pasted)

    def _parse(self, text):
        self.parsed, self.migration, self.problem = None, None, None
        if self.adding:
            try:
                if text.strip().lower().startswith("otpauth-migration://"):
                    self.migration = totp.parse_migration(text)
                else:
                    self.parsed = totp.parse(text) if text.strip() else None
            except totp.OtpError as e:
                self.problem = str(e)[:1].upper() + str(e)[1:]
            else:
                if self.migration is not None and not self.migration[0]:
                    self.problem = "None of the codes in this link can be imported"
                elif self.parsed is None and self.migration is None:
                    self.problem = "Paste the setup key or link the website shows"
        for field in (self.site, self.issuer, self.account):
            field.setEnabled(self.migration is None)  # each code in the link keeps its own labels
        if self.migration is not None:
            entries, skipped = self.migration
            lines = [f"This link holds {plural_codes(len(entries) + len(skipped))}."]
            if skipped:  # labels come from the link: keep each on one line
                lines.append(f"{len(skipped)} cannot be imported:")
                lines += ["  " + "".join(ch if ch.isprintable() else " " for ch in f"{label}: {reason}")
                          for label, reason in skipped]
            self.note.setText("\n".join(lines))
            self.note.setVisible(True)
        elif self.parsed:
            suggestion = totp.site_from_issuer(self.parsed["issuer"])
            for field, value in ((self.issuer, self.parsed["issuer"]), (self.account, self.parsed["account"]),
                                 (self.site, suggestion)):
                if field not in self.edited:  # what the user typed wins over any link
                    field.setText(value)
            usual = (totp.DEFAULT_ALGORITHM, totp.DEFAULT_DIGITS, totp.DEFAULT_PERIOD)
            unusual = self.parsed["kind"] != "steam" and (
                self.parsed["algorithm"], self.parsed["digits"], self.parsed["period"]) != usual
            self.note.setText(f"This code is unusual: {code_type(self.parsed)}." if unusual else "")
            self.note.setVisible(unusual)
        else:
            self.note.setVisible(False)
        self._sync()

    def _sync(self, *_):
        site = totp.normalize_site(self.site.text()) if self.migration is None else ""
        problem = self.problem
        if problem is None and site and not valid_rp_id(site):
            problem = "The website must be a name such as github.com"
        fine = "Link is valid" if self.migration else "Setup key is valid" if self.adding else ""
        self.feedback.show_problem(problem, fine)
        self.save_button.setEnabled(problem is None)

    def labels(self):
        return {"site": totp.normalize_site(self.site.text()), "issuer": self.issuer.text().strip(),
                "account": self.account.text().strip()}

    def entry(self):
        """The ``add`` request's entry; the secret goes to the service and nowhere else."""
        return {"secret": totp.encode_secret(self.parsed["secret"]), **self.labels(),
                "algorithm": self.parsed["algorithm"], "digits": self.parsed["digits"],
                "period": self.parsed["period"], "kind": self.parsed["kind"], "counter": self.parsed["counter"]}


class SettingsDialog(QDialog):
    """The one setting: whether showing authenticator codes asks for the password."""

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.setWindowTitle("Settings")
        self.ask = QCheckBox("Ask for my password before showing authenticator codes", enabled=False)
        self.ask.clicked.connect(self._changed)
        why = QLabel("Without it, anyone who can use this computer while you are logged in can see your codes.")
        why.setTextFormat(Qt.TextFormat.PlainText)
        why.setWordWrap(True)
        why.setStyleSheet(f"color: {PALETTE.COLOR_TEXT_3};")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(self.ask)
        layout.addWidget(why)
        layout.addWidget(buttons)
        self._load()

    def _load(self):
        self.ask.setEnabled(False)  # until the service says what is set
        self.window.tasks.run(lambda: request({"command": "totp", "action": "status"}), self._loaded)

    def _loaded(self, result, error):
        if error is not None:
            self.window._error(error)
            return
        self.ask.setChecked(result["require_auth"])
        self.ask.setEnabled(True)

    def _changed(self, checked):
        self.ask.setEnabled(False)
        payload = {"command": "totp", "action": "settings", "require_auth": checked}

        def sent(result, error):
            if error is not None:
                self.window._error(error)
            elif not checked and self.window._codes_tab:
                self.window.unlock_codes()  # no password now, so this asks nothing; no-op if unlocked
            self._load()  # a refusal puts the box back as the service has it

        self.window.tasks.run(lambda: request(payload), sent)


class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LocalPasskey")
        self.setMinimumSize(640, 400)
        self.resize(900, 560)
        self.tasks = Tasks()
        self._creds = None
        self._selected_id = None
        self._chosen = []  # every selected entry; the table keeps one selection across both tabs
        self._refreshing = False
        self._refresh_again = False
        self._busy = False
        self._moving = True  # what set_busy says while busy: "Moving…" unless an import or export runs
        self._trash = False
        self._codes_tab = False  # the Authenticator Codes tab is showing
        self._unlocked = False  # the service shows this window the codes without asking
        self._unlocking = False
        self._fetching = False
        self._fetch_again = False
        self._values = {}  # code ID -> (code, monotonic time it runs out, period); HOTP: (code, None, counter)
        self._fetched_at = 0.0  # monotonic time of the last successful code fetch
        self._code_count = None  # live codes, for the export checkbox
        self._copied = None  # the code Copy Code put on the clipboard
        self._copied_until = 0.0

        self.model = QStandardItemModel(0, len(COLUMNS))
        self.model.setHorizontalHeaderLabels(COLUMNS)
        self.proxy = PasskeyFilter()
        self.proxy.setSourceModel(self.model)

        self.search = QLineEdit(placeholderText="Search passkeys", clearButtonEnabled=True)
        self.search.textChanged.connect(self._on_search)
        clear = QAction(self.search)
        clear.setShortcut(QKeySequence(Qt.Key.Key_Escape))
        clear.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        clear.triggered.connect(self.search.clear)
        self.search.addAction(clear)

        self.table = QTreeView()
        self.table.setStyleSheet("QTreeView::item { padding: 4px 2px; }")
        self.table.setModel(self.proxy)
        self.table.setRootIsDecorated(False)
        self.table.setUniformRowHeights(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.selectionModel().selectionChanged.connect(self._on_selection)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.header().setStretchLastSection(False)
        self._size_columns()

        self.details = Details(self)
        self.code_details = CodeDetails(self)
        self.message = Message()
        self.message.button.clicked.connect(self.unlock_codes)
        self.side = QStackedWidget()
        self.side.addWidget(self.message)
        self.side.addWidget(self.details)
        self.side.addWidget(self.code_details)

        self.tabs = QTabBar(expanding=False, drawBase=False)
        self.tabs.addTab("Passkeys")
        self.tabs.addTab("Authenticator Codes")
        self.tabs.currentChanged.connect(self._on_tab)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.side)
        splitter.setChildrenCollapsible(False)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([520, 380])

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 4)
        layout.setSpacing(8)
        layout.addWidget(self.tabs)
        layout.addWidget(self.search)
        layout.addWidget(splitter, 1)
        self.setCentralWidget(central)

        self.count_label = QLabel()
        self.service_label = QLabel()
        self.pin_button = QToolButton(autoRaise=True, visible=False)
        self.pin_button.clicked.connect(self.show_pin_dialog)
        self.statusBar().addWidget(self.count_label)
        self.statusBar().addPermanentWidget(self.pin_button)
        self.statusBar().addPermanentWidget(self.service_label)

        self._build_menus()
        self._timer = QTimer(self, interval=REFRESH_MS, timeout=self.refresh)
        self._timer.start()
        self._tick = QTimer(self, interval=TICK_MS, timeout=self._on_tick)
        # Fires when the first code runs out, so an old code is not shown until the next tick.
        self._rollover = QTimer(self, singleShot=True, timerType=Qt.TimerType.PreciseTimer, timeout=self._on_tick)
        self._clipboard_timer = QTimer(self, singleShot=True, timerType=Qt.TimerType.PreciseTimer,
                                       timeout=self._expire_copied)
        self._show(None)
        self.search.setFocus()  # typing searches at once, as before the tab bar came first
        self.refresh()

    def _build_menus(self):
        def action(menu, text, slot, shortcut=None):
            act = QAction(text, self)
            if shortcut:
                act.setShortcut(QKeySequence(shortcut))
            act.triggered.connect(slot)
            menu.addAction(act)
            return act

        file_menu = self.menuBar().addMenu("&File")
        action(file_menu, "&Refresh", self.refresh, QKeySequence.StandardKey.Refresh)
        file_menu.addSeparator()
        self.import_action = action(file_menu, "&Import Passkeys…", self.import_passkeys)
        self.export_action = action(file_menu, "&Export Passkeys…", self.export_passkeys)
        file_menu.addSeparator()
        action(file_menu, "Security Key &PIN…", self.show_pin_dialog)
        action(file_menu, "&Settings…", lambda: SettingsDialog(self).exec())
        file_menu.addSeparator()
        action(file_menu, "&Quit", self.close, QKeySequence.StandardKey.Quit)
        view_menu = self.menuBar().addMenu("&View")
        self.trash_action = QAction("Show &Trash", self, checkable=True)
        self.trash_action.setShortcut(QKeySequence("Ctrl+T"))
        self.trash_action.toggled.connect(self.set_trash)
        view_menu.addAction(self.trash_action)
        self.passkey_menu = self.menuBar().addMenu("&Passkey")
        self.copy_action = action(self.passkey_menu, "&Copy Username",
                                  lambda: self.copy(self.details.cred["user_name"], "Username"),
                                  QKeySequence.StandardKey.Copy)
        self.open_action = action(self.passkey_menu, "&Open Website", lambda: self.open_site(self.details.cred))
        self.passkey_menu.addSeparator()
        self.delete_action = action(self.passkey_menu, "Move to &Trash…", lambda: self.trash_chosen(delete=True),
                                    QKeySequence.StandardKey.Delete)
        self.site_delete_action = action(self.passkey_menu, "Move All for This &Website to Trash…",
                                         lambda: self._bulk("delete", {"site": self.details.cred["site"]}))
        self.all_delete_action = action(self.passkey_menu, "Move All Passkeys to Trash…",
                                        lambda: self._bulk("delete", {"all": True}))
        self.passkey_menu.addSeparator()
        self.restore_action = action(self.passkey_menu, "&Restore", lambda: self.trash_chosen(delete=False))
        self.site_restore_action = action(self.passkey_menu, "Restore All for This We&bsite",
                                          lambda: self._bulk("restore", {"site": self.details.cred["site"]}))
        self.all_restore_action = action(self.passkey_menu, "Restore All",
                                         lambda: self._bulk("restore", {"all": True}))
        self.purge_action = action(self.passkey_menu, "Delete &Permanently…",
                                   lambda: self.confirm_purge(self.details.cred))
        self.trash_actions = (self.restore_action, self.site_restore_action, self.all_restore_action,
                              self.purge_action)
        self.code_menu = self.menuBar().addMenu("&Code")
        self.code_menu.menuAction().setVisible(False)
        self.add_code_action = action(self.code_menu, "&Add Code…", self.add_code, QKeySequence.StandardKey.New)
        self.copy_code_action = action(self.code_menu, "&Copy Code", self.copy_code, QKeySequence.StandardKey.Copy)
        self.next_code_action = action(self.code_menu, "&Next Code", lambda: self.next_code(self.code_details.entry))
        self.edit_code_action = action(self.code_menu, "&Edit…", lambda: self.edit_code(self.code_details.entry))
        self.code_menu.addSeparator()
        self.delete_code_action = action(self.code_menu, "Move to &Trash…", lambda: self.trash_chosen(delete=True),
                                         QKeySequence.StandardKey.Delete)
        self.restore_code_action = action(self.code_menu, "&Restore", lambda: self.trash_chosen(delete=False))
        self.purge_code_action = action(self.code_menu, "Delete &Permanently…",
                                        lambda: self.confirm_purge_code(self.code_details.entry))
        search = QAction(self)
        search.setShortcut(QKeySequence.StandardKey.Find)
        search.triggered.connect(lambda: (self.search.setFocus(), self.search.selectAll()))
        self.addAction(search)
        help_menu = self.menuBar().addMenu("&Help")
        action(help_menu, "&About LocalPasskey", self._about)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.ActivationChange and self.isActiveWindow():
            self.refresh()
            self._expire_copied()
            self._fetch_codes()
        elif event.type() == QEvent.Type.ActivationChange and self._values:
            self._show_values({})  # nobody is looking: no codes on screen, none fetched

    def closeEvent(self, event):
        self._lock_codes(wait=True)
        super().closeEvent(event)

    def shutdown(self):
        """aboutToQuit: lock the codes and take a copied one off the clipboard."""
        self._lock_codes(wait=True)
        self._expire_copied(now=True)

    def _on_tab(self, index):
        self._codes_tab = index == 1
        self.search.setPlaceholderText("Search authenticator codes" if self._codes_tab else "Search passkeys")
        self.passkey_menu.menuAction().setVisible(not self._codes_tab)
        self.code_menu.menuAction().setVisible(self._codes_tab)
        if self._codes_tab:
            self.unlock_codes()
        else:
            self._lock_codes()
        self.refresh()
        self._creds = None  # the other tab's rows must not stay under this tab's details
        self._selected_id = None
        self._chosen = []
        self._rebuild()

    def unlock_codes(self):
        """Ask the service to show this window the codes; it asks for the password if set to."""
        if self._unlocking or self._unlocked:
            return
        self._unlocking = True
        self.message.button.setEnabled(False)
        self.tasks.run(lambda: request({"command": "totp", "action": "unlock"}), self._on_unlock)

    def _on_unlock(self, result, error):
        self._unlocking = False
        self.message.button.setEnabled(True)
        if not self._codes_tab:  # left the tab while the dialog was open
            if error is None:
                self._send_lock()
            return
        if error is not None:
            if not str(error).startswith("not unlocked"):  # a cancelled dialog needs no message
                self._error(error)
            return
        self._unlocked = True
        self._tick.start()
        self._rebuild()
        self._fetch_codes()

    def _lock_codes(self, wait=False, tell=True):
        """Forget the codes; ``tell`` the service unless it locked them itself."""
        held = self._unlocked or self._unlocking
        self._unlocked = False
        self._tick.stop()
        self._rollover.stop()
        self._values = {}
        if held and tell:
            self._send_lock(wait)

    def _send_lock(self, wait=False):
        payload = {"command": "totp", "action": "lock"}
        if not wait:
            self.tasks.run(lambda: request(payload), lambda result, error: None)
            return
        try:  # closing or quitting: a thread might not get to run, so ask now, briefly
            request(payload, timeout=1)
        except Exception:
            pass  # the service forgets every unlock when it stops, and this process's when it exits

    def _fetch_codes(self):
        """Ask for every live code, if the codes are showing and someone can see them."""
        if self._fetching:
            self._fetch_again = True  # the running request may predate a new code
            return
        if not self._unlocked or not self._codes_tab or self._trash or not self._creds or not self.isActiveWindow():
            return
        self._fetching = True
        self.tasks.run(lambda: request({"command": "totp", "action": "code", "all": True})["codes"],
                       self._on_codes)

    def _on_codes(self, codes, error):
        self._fetching = False
        if self._fetch_again:
            self._fetch_again = False
            self._fetch_codes()
            return
        if not self._unlocked or not self._codes_tab or self._trash or not self.isActiveWindow():
            return  # locked, left or hidden while asking: show nothing
        if error is not None:
            if str(error) == LOCKED:  # idle for too long, or the service restarted
                self._lock_codes(tell=False)
                self._rebuild()
            else:
                # Try again with the keep-alive, a minute on, not on every tick.
                self._fetched_at = time.monotonic()
                if not str(error).startswith("no matching"):  # the last code was just deleted
                    self._error(error)
            return
        now = self._fetched_at = time.monotonic()
        kept = {i: value for i, value in self._values.items() if value[1] is None}  # "all" has no HOTP codes
        self._show_values({**kept, **{c["id"]: (c["code"], now + c["remaining"], c["period"]) for c in codes}})

    def _show_values(self, values):
        self._values = values
        ends = [until for _, until, _ in values.values() if until is not None]
        if ends:  # a few ms late, so the tick sees the code as run out
            left = min(ends) - time.monotonic()
            self._rollover.start(max(0, math.ceil(left * 1000)) + 5)
        else:
            self._rollover.stop()
        if self._codes_tab and not self._trash:
            for row in range(self.model.rowCount()):
                entry = self.model.item(row, 0).data(CRED_ROLE)
                value = values.get(entry["id"])
                self.model.item(row, 2).setText(grouped(value[0]) if value else HIDDEN_CODE)
        if self.side.currentWidget() is self.code_details:
            self.code_details.show_value(values.get(self.code_details.entry["id"]))
        self._resync()

    def _on_tick(self):
        if self.side.currentWidget() is self.code_details:
            self.code_details.show_value(self._values.get(self.code_details.entry["id"]))
        now = time.monotonic()
        if now - self._fetched_at >= KEEP_UNLOCKED_S or any(
                until is not None and until <= now for _, until, _ in self._values.values()):
            self._fetch_codes()

    def set_trash(self, on):
        """Show the trash instead of the live passkeys or codes."""
        self._trash = bool(on)
        self._values = {}  # leaving the trash fetches them again, not minutes-old ones
        self._creds = None  # forces a rebuild when the new list arrives, even if both are empty
        self._selected_id = None
        self._chosen = []
        self.refresh()

    def refresh(self):
        if self._refreshing:
            self._refresh_again = True  # the running load may have read the store before a change
            return
        self._refreshing = True
        trashed, codes, unlocked = self._trash, self._codes_tab, self._unlocked

        def load():
            status = request({"command": "status"})
            if codes:  # the codes' labels only; the codes themselves come from _fetch_codes
                payload = {"command": "totp", "action": "list"}
            else:
                payload = {"command": "list"}
            if trashed:
                payload["trash"] = True
            creds = request(payload)["codes" if codes else "credentials"]
            try:
                pin = request({"command": "pin", "action": "status"})
            except Exception:
                pin = None  # the lock just stays hidden; the list is what matters
            try:
                codes_status = request({"command": "totp", "action": "status"})
            except Exception:
                codes_status = None  # export then offers no codes
            return status, creds, pin, codes_status

        self.tasks.run(load, lambda result, error: self._on_loaded(result, error, trashed, codes, unlocked))

    def _on_loaded(self, result, error, trashed=False, codes=False, unlocked=False):
        self._refreshing = False
        # A change, or a switch of view or tab, came in while loading.
        if self._refresh_again or trashed != self._trash or codes != self._codes_tab:
            self._refresh_again = False
            self.refresh()
            return
        if error is not None:
            self._values = {}
            self.count_label.setText("")
            self.service_label.setText("Service not running" if isinstance(error, ServiceUnavailable) else str(error))
            self.service_label.setToolTip(str(error))
            self.show_pin_state(None)
            if self._creds is not None or self.side.currentWidget() is self.message:
                self._creds = None
                self._rebuild()
            return
        status, creds, pin, codes_status = result
        self._code_count = codes_status and codes_status["count"]
        # Unlocked when the load began, and the service says no more: idle in the trash, or restarted.
        if unlocked and self._unlocked and codes_status and not codes_status["unlocked"]:
            self._lock_codes(tell=False)
            self._creds = None  # rebuilds below into the locked state
        self.show_pin_state(pin)
        self.service_label.setText("Service running")
        self.service_label.setToolTip(
            f"localpasskeyd {status['version']} · virtual security key {status.get('device') or 'missing'}"
        )
        if creds != self._creds:
            self._creds = creds
            self._rebuild()
            if any(entry["id"] not in self._values for entry in creds if codes and entry.get("kind") != "hotp"):
                self._fetch_codes()  # a new code has no value yet
        self._show_count()

    def _show_count(self):
        if self._creds is None:
            return
        if not self._codes_tab:
            self.count_label.setText(plural(len(self._creds)))
        else:  # locked, the list is empty but the count still says what is there
            self.count_label.setText(plural_codes(len(self._creds)) + ("" if self._unlocked else " · locked"))

    def show_pin_state(self, pin):
        """The lock in the status bar: closed when a PIN is set, red when it is locked."""
        summary = pin_summary(pin)
        self.pin_button.setVisible(summary is not None)
        if summary is None:
            return
        if not pin["set"]:
            closed, color = False, PALETTE.COLOR_TEXT_3
        else:
            closed, color = True, Feedback.BAD if pin["retries"] == 0 else Feedback.GOOD
        self.pin_button.setIcon(QIcon(lock_pixmap(closed, color, 16, self.devicePixelRatioF())))
        self.pin_button.setToolTip(f"{summary}\n\n{PIN_PURPOSE}\n\nClick to set, change or remove it.")
        self.pin_button.setAccessibleName(summary)

    def _rebuild(self):
        chosen = list(self._chosen)  # the rows below are new; _restore selects these again
        if self.table.model() is not None:
            self.table.clearSelection()  # before the model goes: clearing after it does nothing
        self.model.setHorizontalHeaderLabels(
            TRASH_COLUMNS if self._trash else CODE_COLUMNS if self._codes_tab else COLUMNS)
        self.proxy.setSourceModel(None)  # one sort and filter pass, not one per row
        self.model.removeRows(0, self.model.rowCount())
        if not self._codes_tab:
            for cred in self._creds or []:
                self.model.appendRow(passkey_row(cred, trashed=self._trash))
        elif self._unlocked:  # locked codes list nothing, not even their labels
            for entry in self._creds or []:
                value = self._values.get(entry["id"])
                self.model.appendRow(code_row(entry, self._trash, value and value[0]))
        self.proxy.setSourceModel(self.model)
        self._size_columns()  # reattaching the model reset the header's sections
        self._restore(self._selected_id, chosen)
        self._show_count()  # an unlock or lock rebuilds without a reload

    def _size_columns(self):
        header = self.table.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)

    def _proxy_row_of(self, cred_id):
        for row in range(self.proxy.rowCount()):
            if self.proxy.index(row, 0).data(CRED_ROLE)["id"] == cred_id:
                return row
        return None

    def _restore(self, cred_id=None, chosen=None):
        """Select the rows still visible, else the first row, else show the empty state."""
        chosen = chosen or ([{"id": cred_id}] if cred_id else [])
        rows = [row for row in (self._proxy_row_of(cred["id"]) for cred in chosen) if row is not None]
        model = self.table.selectionModel()
        if not rows:
            self.table.clearSelection()
            rows = [0] if self.proxy.rowCount() else []
        if len(rows) == 1 and not model.isRowSelected(rows[0]):
            self.table.setCurrentIndex(self.proxy.index(rows[0], 0))
        elif len(rows) > 1:  # a refresh must not throw away a shift-click selection
            model.select(self.proxy.index(rows[0], 0),
                         QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
            for row in rows[1:]:
                model.select(self.proxy.index(row, 0), QItemSelectionModel.SelectionFlag.Select
                             | QItemSelectionModel.SelectionFlag.Rows)
        if not model.hasSelection():
            self._show(None)

    def _on_search(self, text):
        self.proxy.set_query(text)
        self._restore(self._selected_id, self._chosen)

    def _on_selection(self, *_):
        self._chosen = [index.data(CRED_ROLE) for index in self.table.selectionModel().selectedRows()]
        self._show(self._chosen[0] if len(self._chosen) == 1 else None)

    def _resync(self):
        """Re-enable the actions for whatever is selected now."""
        current = self.code_details.entry if self._codes_tab else self.details.cred
        self._sync_actions(current if self._selected_id else None, len(self._chosen) > 1)

    def _sync_actions(self, cred, many=False):
        """Enable exactly the actions the current view and selection allow."""
        for act in self.trash_actions:
            act.setVisible(self._trash)
        for act in (self.delete_action, self.site_delete_action, self.all_delete_action):
            act.setVisible(not self._trash)
        self.all_delete_action.setEnabled(not self._trash and not self._busy)
        self.all_restore_action.setEnabled(self._trash and not self._busy)
        self.import_action.setEnabled(not self._busy)
        self.export_action.setEnabled(not self._busy)
        for act in (self.copy_action, self.open_action, self.site_delete_action, self.site_restore_action,
                    self.purge_action):
            act.setEnabled(cred is not None and not self._busy)
        for act in (self.delete_action, self.restore_action):  # these two take every selected row
            act.setEnabled(not self._busy and (cred is not None or many))
        if cred is not None:
            self.open_action.setEnabled(is_website(cred["site"]) and not self._trash and not self._busy)
            self.copy_action.setEnabled(bool(cred.get("user_name")) and not self._busy)
        codes = self._codes_tab
        if codes:  # one menu at a time: Ctrl+C and Delete mean the code here
            for act in self.passkey_menu.actions():
                act.setEnabled(False)
        live, trashed = codes and cred is not None and not self._trash, codes and cred is not None and self._trash
        some = codes and (cred is not None or many) and not self._busy  # Move to Trash and Restore take several
        self.add_code_action.setEnabled(codes and not self._busy)
        self.copy_code_action.setEnabled(live and cred["id"] in self._values)
        self.next_code_action.setVisible(not self._trash)
        self.next_code_action.setEnabled(live and cred.get("kind") == "hotp" and not self._busy)
        self.edit_code_action.setVisible(not self._trash)
        self.edit_code_action.setEnabled(live and not self._busy)
        self.delete_code_action.setVisible(not self._trash)
        self.delete_code_action.setEnabled(some and not self._trash)
        self.restore_code_action.setVisible(self._trash)
        self.restore_code_action.setEnabled(some and self._trash)
        self.purge_code_action.setVisible(self._trash)
        self.purge_code_action.setEnabled(trashed and not self._busy)

    def _show(self, cred):
        self._sync_actions(cred, len(self._chosen) > 1)
        if len(self._chosen) > 1:
            self._selected_id = None
            self.message.set_message((plural_codes if self._codes_tab else plural)(len(self._chosen)) + " selected")
            self.side.setCurrentWidget(self.message)
            return
        if self._codes_tab:
            self._show_code(cred)
            return
        if cred is not None:
            self._selected_id = cred["id"]
            self.details.show_cred(cred)
            self.details.set_busy(self._busy, self._moving)
            self.side.setCurrentWidget(self.details)
            return
        self._selected_id = None
        if self._creds is None and self._refreshing:
            self.message.set_message("Loading…")
        elif self._creds is None:
            self.message.set_message(
                "LocalPasskey isn't running",
                "Start the service with “sudo systemctl start localpasskey”. "
                "This window reconnects by itself.",
            )
        elif self._trash and not self._creds:
            self.message.set_message(
                "The trash is empty",
                "Passkeys you move to the trash wait here until you restore them.",
            )
        elif not self._creds:
            self.message.set_message(
                "No passkeys yet",
                "When a website offers to create a passkey, pick the security key option. "
                "LocalPasskey keeps the passkey on this computer, and it shows up here.",
            )
        elif self.proxy.rowCount() == 0:
            self.message.set_message("No matching passkeys")
        else:
            self.message.set_message("Select a passkey")
        self.side.setCurrentWidget(self.message)

    def _show_code(self, entry):
        if entry is not None:
            self._selected_id = entry["id"]
            self.code_details.show_entry(entry, self._values.get(entry["id"]))
            self.code_details.set_busy(self._busy, self._moving)
            self.side.setCurrentWidget(self.code_details)
            return
        self._selected_id = None
        if not self._unlocked:
            self.message.set_message("Authenticator codes are locked", "Your password is needed to show them.",
                                     "Unlock")
        elif self._creds is None:
            self.message.set_message("Loading…" if self._refreshing else "LocalPasskey isn't running")
        elif self._trash and not self._creds:
            self.message.set_message(
                "The trash is empty",
                "Authenticator codes you move to the trash wait here until you restore them.",
            )
        elif not self._creds:
            self.message.set_message(
                "No authenticator codes yet",
                "When a website offers two-step sign-in with an authenticator app, choose Code → Add Code… "
                "and paste the setup key or link it shows.",
            )
        elif self.proxy.rowCount() == 0:
            self.message.set_message("No matching authenticator codes")
        else:
            self.message.set_message("Select an authenticator code")
        self.side.setCurrentWidget(self.message)

    def _context_menu(self, position):
        if not self._codes_tab:  # passkeys are added from a browser, so only a row has a menu
            if self.table.indexAt(position).isValid():
                self.passkey_menu.exec(self.table.viewport().mapToGlobal(position))
            return
        if not self.table.indexAt(position).isValid():  # empty space: Add Code is the only action
            self.table.clearSelection()
        self.code_menu.exec(self.table.viewport().mapToGlobal(position))

    def _on_double_click(self, index):
        """A double-click copies that row's code, as Copy Code does; nothing when it is not known yet."""
        if self._codes_tab and not self._trash and index.isValid():
            self.copy_code(index.data(CRED_ROLE)["id"])

    def copy(self, text, what):
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage(f"{what} copied", 3000)

    def copy_code(self, entry_id=None):
        """Copy a code, marked secret for clipboard managers, for 30 seconds."""
        entry_id = entry_id or (self.code_details.entry["id"] if self._codes_tab and self._selected_id else None)
        value = self._values.get(entry_id)
        if value is None:
            return
        data = QMimeData()
        data.setText(value[0])
        data.setData("x-kde-passwordManagerHint", b"secret")  # Klipper and others keep it out of their history
        QGuiApplication.clipboard().setMimeData(data)
        self._copied, self._copied_until = value[0], time.monotonic() + COPY_CLEAR_MS / 1000
        self._clipboard_timer.start(COPY_CLEAR_MS)
        self.statusBar().showMessage(f"Code copied; the clipboard is cleared in {COPY_CLEAR_MS // 1000} s", 4000)

    def _expire_copied(self, now=False):
        """Clear a copied code once its time is up, unless something else was copied since."""
        if self._copied is None:
            return
        left = self._copied_until - time.monotonic()
        if not now and left > 0:
            if not self._clipboard_timer.isActive():  # it fired early: wait out the rest
                self._clipboard_timer.start(max(1, round(left * 1000 + 0.5)))
            return
        self._clipboard_timer.stop()
        clipboard = QGuiApplication.clipboard()
        if clipboard.text() == self._copied:
            clipboard.clear()
        self._copied = None

    def open_site(self, cred):
        if not QDesktopServices.openUrl(QUrl(f"https://{cred['site']}/")):
            self.statusBar().showMessage("Could not open the website", 4000)

    def confirm_delete(self, cred):
        if self._busy:
            return
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Move to Trash")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(f"Move the passkey for “{account_label(cred)}” on {cred['site']} to the trash?")
        box.setInformativeText(
            "It stops working until you restore it. Remove it from your account settings "
            "on the website too."
        )
        move = box.addButton("Move to Trash", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        if box.clickedButton() is not move:
            return
        self._send({"command": "delete", "ids": [cred["id"]]}, "Waiting for you to authenticate…",
                   "Passkey moved to the trash", cred["id"])

    def _bulk(self, command, selector):
        """The site/all forms: confirm the count the daemon reports first."""
        if self._busy:
            return
        title, button_text, question, note = BULK[command]
        self._busy = True

        def loaded(doomed, error):
            self._busy = False
            if error is not None:
                self._error(error)
                self._resync()
                return
            # Send exactly the IDs the daemon counted and the user approved.
            self._confirm_doomed(command, doomed, title, button_text, question, note)

        self.tasks.run(lambda: request({"command": command, **selector, "dry_run": True})["deleted"], loaded)

    def trash_chosen(self, delete):
        """Move to Trash or Restore for every selected row: one confirmation, one request."""
        if self._busy or not self._chosen:
            return
        one = self._chosen[0]
        if len(self._chosen) == 1:  # the single row's own wording and confirmation
            if self._codes_tab:
                if delete:
                    self.confirm_delete_code(one)
                else:
                    self.restore_code(one)
            elif delete:
                self.confirm_delete(one)
            else:
                self._send({"command": "restore", "ids": [one["id"]]}, "Restoring…", "Passkey restored")
            return
        command = ("delete" if delete else "restore") + ("_codes" if self._codes_tab else "")
        title, button_text, question, note = BULK[command]
        self._confirm_doomed(command, self._chosen, title, button_text, question, note)

    def _confirm_doomed(self, command, doomed, title, button_text, question, note):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(question.format(n=len(doomed), s="s" if len(doomed) != 1 else ""))
        box.setInformativeText(note)
        go = box.addButton(button_text, QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        if box.clickedButton() is not go:
            self._resync()
            return
        codes = command.endswith("_codes")
        command = command.removesuffix("_codes")
        noun = "authenticator code{s}" if codes else "passkey{s}"
        done = f"Moved {{n}} {noun} to the trash" if command == "delete" else f"Restored {{n}} {noun}"
        payload = {"command": "totp", "action": command} if codes else {"command": command}
        self._send({**payload, "ids": [cred["id"] for cred in doomed]},
                   "Waiting for you to authenticate…",
                   done.format(n=len(doomed), s="s" if len(doomed) != 1 else ""))

    def confirm_purge(self, cred):
        if self._busy:
            return
        if self._confirm_typed(f"Permanently delete the passkey for “{account_label(cred)}” on {cred['site']}?",
                               cred["site"]):
            self._send({"command": "purge", "ids": [cred["id"]]}, "Waiting for you to authenticate…",
                       "Passkey permanently deleted", cred["id"])

    def _confirm_typed(self, question, expected):
        """Delete Permanently: True once the user has typed ``expected`` and confirmed."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Delete Permanently")
        warning = QLabel()
        warning.setTextFormat(Qt.TextFormat.PlainText)
        warning.setPixmap(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning).pixmap(48, 48))
        text = QLabel(question)
        text.setTextFormat(Qt.TextFormat.PlainText)
        text.setWordWrap(True)
        expected = expected.strip()
        instruction = QLabel(f'Type "{expected}" to confirm. This cannot be undone.')
        instruction.setTextFormat(Qt.TextFormat.PlainText)
        typed = QLineEdit()
        buttons = QDialogButtonBox()
        delete = buttons.addButton("Delete Permanently", QDialogButtonBox.ButtonRole.DestructiveRole)
        cancel = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        delete.setEnabled(False)
        typed.textChanged.connect(
            lambda value: delete.setEnabled(value.strip().casefold() == expected.casefold())
        )
        buttons.rejected.connect(dialog.reject)
        buttons.accepted.connect(dialog.accept)
        delete.clicked.connect(dialog.accept)
        layout = QVBoxLayout(dialog)
        row = QHBoxLayout()
        row.addWidget(warning, 0, Qt.AlignmentFlag.AlignTop)
        row.addWidget(text, 1)
        layout.addLayout(row)
        layout.addWidget(instruction)
        layout.addWidget(typed)
        layout.addWidget(buttons)
        cancel.setDefault(True)  # only takes once the button belongs to the dialog
        return dialog.exec() == QDialog.DialogCode.Accepted

    def _send(self, payload, note, done, forget_id=None, moving=True):
        """Run one delete/restore/purge request, with the same busy handling for all three."""
        if not self._start(note, moving=moving):
            return

        def finished(result, error):
            if error is None and forget_id is not None and self._selected_id == forget_id:
                self._selected_id = None
            self._finish(error, done)

        self.tasks.run(lambda: request(payload), finished)

    def add_code(self):
        if self._busy:
            return
        dialog = CodeDialog(self)
        send = dialog.exec() == QDialog.DialogCode.Accepted and not self._still_busy()
        if send and dialog.migration:  # one import request; the dialog's plan was the one prompt
            payload = {"command": "import", "credentials": [], "codes": migration_records(dialog.migration[0])}
        elif send:
            payload = {"command": "totp", "action": "add", "entry": dialog.entry()}
        pasted = dialog.pasted
        dialog.key.clear()  # a closed dialog stays the window's child until deleted: keep no key in it
        dialog.deleteLater()
        if not send:
            return
        self._start("Waiting for you to authenticate…")

        def finished(result, error):
            clipboard = QGuiApplication.clipboard()
            if error is None and pasted and clipboard.text() == pasted:
                clipboard.clear()  # the setup key has done its job
            if result and "imported_codes" in result:
                done = (f"Imported {plural_codes(len(result['imported_codes']))}" if result["imported_codes"]
                        else "Nothing to import")
                if result["skipped_codes"]:
                    done += f"; {plural_codes(len(result['skipped_codes']))} could not be imported"
            else:
                done = "Authenticator code added"
            self._finish(error, done)

        self.tasks.run(lambda: request(payload), finished)

    def next_code(self, entry):
        """Show an HOTP code's next code: only on request, since each one uses up its counter."""
        if not self._start("Getting the next code…"):
            return
        payload = {"command": "totp", "action": "next", "ids": [entry["id"]]}

        def finished(result, error):
            if error is None and self._unlocked:  # before _finish: its refresh rebuilds the rows from _values
                code = result["code"]
                self._show_values({**self._values, code["id"]: (code["code"], None, code["counter"])})
            self._finish(error)

        self.tasks.run(lambda: request(payload), finished)

    def _still_busy(self):
        """After a dialog: True, and say so, if another request started while it was open."""
        if self._busy:
            self.statusBar().showMessage("Not saved: another request is still running. Try again when it finishes.",
                                         6000)
        return self._busy

    def edit_code(self, entry):
        if self._busy:
            return
        dialog = CodeDialog(self, entry)
        send = dialog.exec() == QDialog.DialogCode.Accepted and not self._still_busy()
        labels = dialog.labels()
        dialog.deleteLater()
        if not send:
            return
        self._send({"command": "totp", "action": "update", "id": entry["id"], **labels},
                   "Waiting for you to authenticate…", "Authenticator code changed", moving=False)

    def confirm_delete_code(self, entry):
        if self._busy:
            return
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Move to Trash")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(f"Move the authenticator code for {code_title(entry)} to the trash?")
        box.setInformativeText("Its codes are not shown until you restore it.")
        move = box.addButton("Move to Trash", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        if box.clickedButton() is move:
            self._send({"command": "totp", "action": "delete", "ids": [entry["id"]]},
                       "Waiting for you to authenticate…", "Authenticator code moved to the trash", entry["id"])

    def restore_code(self, entry):
        self._send({"command": "totp", "action": "restore", "ids": [entry["id"]]}, "Restoring…",
                   "Authenticator code restored")

    def confirm_purge_code(self, entry):
        if self._busy:
            return
        expected = entry["site"].strip() or entry["issuer"].strip() or "delete"
        question = (f"Permanently delete the authenticator code for {code_title(entry)}? "
                    "You may lose access to that account.")
        if self._confirm_typed(question, expected):
            self._send({"command": "totp", "action": "purge", "ids": [entry["id"]]},
                       "Waiting for you to authenticate…", "Authenticator code permanently deleted", entry["id"])

    def _error(self, error):
        message = str(error)
        self.statusBar().showMessage(message[:1].upper() + message[1:], 6000)

    def _start(self, note, moving=False):
        """Mark the window busy for a request; False if it already is."""
        if self._busy:
            return False
        self._busy = True
        self._moving = moving
        self.statusBar().showMessage(note)
        self._resync()
        if self.side.currentWidget() in (self.details, self.code_details):
            self.side.currentWidget().set_busy(True, moving)
        return True

    def _finish(self, error=None, done=None):
        self._busy = False
        self._moving = True
        self.details.set_busy(False)
        self.code_details.set_busy(False)
        self._resync()
        if error is not None:
            self._error(error)
        elif done:
            self.statusBar().showMessage(done, 4000)
        self.refresh()

    def export_passkeys(self):
        if self._busy:
            return
        cred = self.details.cred if self._selected_id and not self._trash and not self._codes_tab else None
        dialog = ExportDialog(self, cred["site"] if cred else None, self._code_count)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        default = os.path.join(os.path.expanduser("~"), f"localpasskey-{date.today():%Y-%m-%d}{transfer.BACKUP_SUFFIX}")
        # The save dialog has already asked before replacing an existing file.
        path, _ = QFileDialog.getSaveFileName(self, "Export Passkeys", default,
                                              f"LocalPasskey backup (*{transfer.BACKUP_SUFFIX})")
        if not path:
            return
        confirmed = path.endswith(transfer.BACKUP_SUFFIX)  # the dialog asked about `path`, not path + suffix
        if not confirmed:
            path += transfer.BACKUP_SUFFIX
        problem = unwritable(path) or ("it already exists" if not confirmed and os.path.lexists(path) else None)
        if problem:
            self._error(f"cannot write {path}: {problem}")
            return
        if not self._start("Waiting for you to authenticate…"):
            return
        selector, passphrase = dialog.selector(), dialog.passphrase.text()

        def work():
            reply = request({"command": "export", **selector})
            records, codes = reply["credentials"], reply.get("codes") or []
            try:
                write_private_file(path, transfer.export_backup(records, passphrase, codes), overwrite=confirmed)
            except OSError as e:  # not str(e): that names the hidden temporary file
                raise OSError(f"cannot write {path}: {e.strerror or e}") from None
            return len(records), len(codes)

        self.tasks.run(work, lambda counts, error: self._finish(
            error, f"Exported {join_counts(*(counts or (0, 0)))}"))

    def import_passkeys(self):
        if self._busy:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Passkeys", os.path.expanduser("~"),
            f"LocalPasskey backup (*{transfer.BACKUP_SUFFIX});;CXF or Bitwarden JSON (*.json);;All files (*)",
        )
        if not path:
            return
        try:
            with open(path, "rb") as stream:
                data = stream.read()
            encrypted = transfer.detect_format(data) == "localpasskey"
        except (OSError, transfer.TransferError) as e:
            self._error(e.strerror if isinstance(e, OSError) and e.strerror else e)
            return
        self._load_import(data, encrypted)

    def _load_import(self, data, encrypted, retry=False):
        passphrase = ""
        if encrypted:
            label = "The passphrase this file was exported with (not your login password):"
            if retry:
                label = "Wrong passphrase. " + label
            passphrase, ok = QInputDialog.getText(self, "Import Passkeys", label, QLineEdit.EchoMode.Password)
            if not ok:
                return
        if not self._start("Reading the file…"):
            return

        def work():
            records = transfer.load(data, lambda: passphrase)
            payload = {"command": "import", "credentials": records, "dry_run": True}
            if records.codes:
                payload["codes"] = records.codes
            return records, request(payload)

        def loaded(result, error):
            if isinstance(error, transfer.WrongPassphrase):
                self._finish()
                self._load_import(data, encrypted, retry=True)
                return
            if error is not None:
                self._finish(error)
                return
            self._finish()
            records, plan = result
            codes = plan.get("imported_codes", [])
            dialog = ImportDialog(self, plan["imported"], records.skipped + plan["skipped"],
                                  codes, records.skipped_codes + plan.get("skipped_codes", []))
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            self._send_import(records, plan["imported"], codes)

        self.tasks.run(work, loaded)

    def _send_import(self, records, planned, planned_codes=()):
        chosen = planned_records(records, planned)
        payload = {"command": "import", "credentials": chosen}
        wanted = {entry["id"] for entry in planned_codes}
        codes = []
        for record in records.codes:  # each planned code once, as with the passkeys
            if transfer.describe_code(record)["id"] in wanted:
                wanted.discard(transfer.describe_code(record)["id"])
                codes.append(record)
        if codes:
            payload["codes"] = codes
        if not self._start("Waiting for you to authenticate…"):
            return

        def done(result, error):
            counts = (len(result["imported"]), len(result.get("imported_codes", []))) if result else (0, 0)
            self._finish(error, f"Imported {join_counts(*counts)}")

        self.tasks.run(lambda: request(payload), done)

    def show_pin_dialog(self):
        PinDialog(self).exec()
        self.refresh()  # the lock in the status bar follows a change at once

    def _about(self):
        QMessageBox.about(
            self, "About LocalPasskey",
            f"<b>LocalPasskey {__version__}</b>"
            "<p>Passkeys kept on this computer and confirmed with your own password.</p>",
        )


def main(argv=None):
    QApplication.setApplicationName("LocalPasskey")
    QGuiApplication.setDesktopFileName(APP_ID)
    app = QApplication(sys.argv if argv is None else argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet(qt_api="pyqt6") + TOOLTIP_STYLE)
    app.setWindowIcon(app_icon())
    window = Window()
    app.aboutToQuit.connect(window.shutdown)
    window.show()
    return app.exec()
