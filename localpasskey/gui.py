"""LocalPasskey's window: see, search and remove the passkeys on this computer.

Qt 6 with QDarkStyle, the dark theme Electrum and Feather Wallet use.
Everything goes through localpasskeyd's control socket, so the window only
sees the current user's passkeys, and deleting one makes the service ask for
the user's password first. Deleted passkeys wait in the trash view until they
are restored or permanently deleted, and the PIN browsers ask for can be set
or removed here too. Passkeys can be exported to an encrypted backup and
imported from one (or from CXF and Bitwarden files); the files are read,
written and encrypted here, never by the service.
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import date, datetime, timedelta

import qdarkstyle
from PyQt6.QtCore import QEvent, QObject, QRectF, QSortFilterProxyModel, Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import (
    QAction, QColor, QDesktopServices, QGuiApplication, QIcon, QKeySequence, QPainter, QPixmap,
    QStandardItem, QStandardItemModel,
)
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QButtonGroup, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QFrame, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QRadioButton, QSplitter, QStackedWidget, QStyle, QTreeView, QVBoxLayout,
    QWidget,
)

from . import __version__, transfer
from .cli import planned_records, write_private_file
from .client import ServiceUnavailable, request
from .clientpin import pin_problem

APP_ID = "org.localpasskey.Manager"
REFRESH_MS = 5000
PALETTE = qdarkstyle.DarkPalette
CRED_ROLE = Qt.ItemDataRole.UserRole
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
COLUMNS = ("Website", "Account", "Last used")
TRASH_COLUMNS = ("Website", "Account", "Deleted")
_SECOND_LEVEL = {"ac", "co", "com", "edu", "gov", "net", "org"}
# Bulk confirmations: window title, button, question, what the passkeys do meanwhile.
BULK = {
    "delete": ("Move to Trash", "Move to Trash", "Move {n} passkey{s} to the trash?",
               "They stop working until you restore them."),
    "restore": ("Restore Passkeys", "Restore", "Restore {n} passkey{s} from the trash?",
                "They sign you in again right away."),
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
    return "." in site and not any(ch in site for ch in ":/ ")


def matches(cred: dict, query: str) -> bool:
    keys = ("site", "site_name", "user_name", "display_name")
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
        return matches(self.sourceModel().index(row, 0, parent).data(CRED_ROLE), self.query)


class Details(QFrame):
    def __init__(self, window):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.cred = None

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
        self.restore_button.clicked.connect(self._restore_clicked)
        self.purge_button = QPushButton("Delete Permanently…")
        self.purge_button.clicked.connect(self._purge_clicked)
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

    @property
    def window(self):
        return self.parentWidget().window()

    def _restore_clicked(self):  # the button belongs to this pane, the request to the window
        self.window._send({"command": "restore", "ids": [self.cred["id"]]}, "Restoring…", "Passkey restored")

    def _purge_clicked(self):
        self.window.confirm_purge(self.cred)

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
        self.set_busy(False)

    def set_busy(self, busy):
        self.delete_button.setEnabled(not busy)
        self.delete_button.setText("Moving…" if busy else "Move to Trash…")
        self.restore_button.setEnabled(not busy)
        self.purge_button.setEnabled(not busy)


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
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addStretch(1)
        for widget in (self.icon, self.title, self.text):
            layout.addWidget(widget)
        layout.addStretch(2)

    def set_message(self, title, text=""):
        self.title.setText(title)
        self.text.setText(text)
        self.text.setVisible(bool(text))


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
    """Set or remove the PIN browsers ask for before they list or delete passkeys."""

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.setWindowTitle("Security Key PIN")
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.why = QLabel(
            "Browsers ask for this PIN in their security-key settings to list or delete "
            "the passkeys stored on this computer."
        )
        self.why.setTextFormat(Qt.TextFormat.PlainText)
        self.why.setWordWrap(True)
        self.why.setStyleSheet(f"color: {PALETTE.COLOR_TEXT_3};")
        self.pin = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.repeat = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        form = QFormLayout()
        form.addRow("New PIN", self.pin)
        form.addRow("Repeat", self.repeat)
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
            problem = "Repeat the PIN"  # never green while Set PIN is still greyed out
        self.feedback.show_problem(problem, "PIN is valid")
        self.set_button.setEnabled(problem is None and not self.busy)

    def show_state(self, is_set, retries):
        self.busy = False
        self.set = is_set
        self.retries = retries
        self.status.setText(
            f"A PIN is set ({retries} attempts left)." if is_set else "No PIN is set."
        )
        for widget in (self.pin, self.repeat):
            widget.setEnabled(True)
        self.remove_button.setEnabled(is_set)
        self._sync()

    def _on_loaded(self, result, error):
        if error is not None:
            # The state is unknown, not "no PIN set": inventing one would offer
            # to set a PIN over an existing one and hide Remove PIN.
            self.status.setText("Could not read the PIN state.")
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

    def __init__(self, window, site=None):
        super().__init__(window)
        self.setWindowTitle("Export Passkeys")
        intro = QLabel(
            "The backup holds the private keys of your passkeys, encrypted with this passphrase. "
            "Whoever has the file and the passphrase can sign in as you."
        )
        intro.setTextFormat(Qt.TextFormat.PlainText)
        intro.setWordWrap(True)
        self.all = QRadioButton("All passkeys")
        self.site = QRadioButton(f"Passkeys for {site}" if site else "Passkeys for the selected website")
        self.site.setEnabled(bool(site))
        (self.site if site else self.all).setChecked(True)
        self._site = site
        scope = QButtonGroup(self)
        scope.addButton(self.all)
        scope.addButton(self.site)
        self.passphrase = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.repeat = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        form = QFormLayout()
        form.addRow("Passphrase", self.passphrase)
        form.addRow("Repeat", self.repeat)
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
        layout.addLayout(form)
        layout.addWidget(self.feedback)
        layout.addWidget(buttons)
        for field in (self.passphrase, self.repeat):
            field.textChanged.connect(self._sync)
        self._sync()

    def _sync(self, *_):
        problem = transfer.passphrase_problem(self.passphrase.text(), self.repeat.text())
        if problem is None and not self.repeat.text():
            problem = "Repeat the passphrase"
        self.feedback.show_problem(problem, "Passphrase is valid")
        self.export_button.setEnabled(problem is None)

    def selector(self):
        return {"site": self._site} if self.site.isChecked() else {"all": True}


def plan_text(imported, skipped) -> str:
    """The import plan as plain text: one line per passkey."""
    def line(cred):
        return f"{cred.get('site') or '?'}  {account_label(cred)}"

    lines = [f"Will be imported ({len(imported)}):", *(f"  {line(c)}" for c in imported)]
    if skipped:
        lines += ["", f"Skipped ({len(skipped)}):"]
        lines += [f"  {line(s['credential'])}: {s['reason']}" for s in skipped]
    return "\n".join(lines)


class ImportDialog(QDialog):
    """What an import will add and what it skips, before anything is asked."""

    def __init__(self, window, imported, skipped):
        super().__init__(window)
        self.setWindowTitle("Import Passkeys")
        n = len(imported)
        heading = QLabel(f"Import {n} passkey{'s' if n != 1 else ''}?" if n else "Nothing to import.")
        heading.setTextFormat(Qt.TextFormat.PlainText)
        self.plan = QPlainTextEdit(plan_text(imported, skipped), readOnly=True)
        self.plan.setMinimumSize(480, 240)
        buttons = QDialogButtonBox()
        self.import_button = buttons.addButton("Import", QDialogButtonBox.ButtonRole.AcceptRole)
        self.import_button.setEnabled(bool(imported))
        buttons.addButton(QDialogButtonBox.StandardButton.Cancel if n else QDialogButtonBox.StandardButton.Close)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(self.plan)
        layout.addWidget(buttons)


class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LocalPasskey")
        self.setMinimumSize(640, 400)
        self.resize(900, 560)
        self.tasks = Tasks()
        self._creds = None
        self._selected_id = None
        self._refreshing = False
        self._busy = False
        self._trash = False

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
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.selectionModel().selectionChanged.connect(self._on_selection)
        header = self.table.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(False)

        self.details = Details(self)
        self.message = Message()
        self.side = QStackedWidget()
        self.side.addWidget(self.message)
        self.side.addWidget(self.details)

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
        layout.addWidget(self.search)
        layout.addWidget(splitter, 1)
        self.setCentralWidget(central)

        self.count_label = QLabel()
        self.service_label = QLabel()
        self.statusBar().addWidget(self.count_label)
        self.statusBar().addPermanentWidget(self.service_label)

        self._build_menus()
        self._timer = QTimer(self, interval=REFRESH_MS, timeout=self.refresh)
        self._timer.start()
        self._show(None)
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
        action(file_menu, "&Import Passkeys…", self.import_passkeys)
        self.export_action = action(file_menu, "&Export Passkeys…", self.export_passkeys)
        file_menu.addSeparator()
        action(file_menu, "Security Key &PIN…", self.show_pin_dialog)
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
        self.delete_action = action(self.passkey_menu, "Move to &Trash…",
                                    lambda: self.confirm_delete(self.details.cred),
                                    QKeySequence.StandardKey.Delete)
        self.site_delete_action = action(self.passkey_menu, "Move All for This &Website to Trash…",
                                         lambda: self._bulk("delete", {"site": self.details.cred["site"]}))
        self.all_delete_action = action(self.passkey_menu, "Move All Passkeys to Trash…",
                                        lambda: self._bulk("delete", {"all": True}))
        self.passkey_menu.addSeparator()
        self.restore_action = action(self.passkey_menu, "&Restore",
                                     lambda: self._send({"command": "restore", "ids": [self.details.cred["id"]]},
                                                        "Restoring…", "Passkey restored"))
        self.site_restore_action = action(self.passkey_menu, "Restore All for This We&bsite",
                                          lambda: self._bulk("restore", {"site": self.details.cred["site"]}))
        self.all_restore_action = action(self.passkey_menu, "Restore All",
                                         lambda: self._bulk("restore", {"all": True}))
        self.purge_action = action(self.passkey_menu, "Delete &Permanently…",
                                   lambda: self.confirm_purge(self.details.cred))
        self.trash_actions = (self.restore_action, self.site_restore_action, self.all_restore_action,
                              self.purge_action)
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

    def set_trash(self, on):
        """Show the trash instead of the live passkeys."""
        self._trash = bool(on)
        self._creds = None  # forces a rebuild when the new list arrives, even if both are empty
        self._selected_id = None
        self.refresh()

    def refresh(self):
        if self._refreshing:
            return
        self._refreshing = True
        trashed = self._trash

        def load():
            status = request({"command": "status"})
            payload = {"command": "list"}
            if trashed:
                payload["trash"] = True
            return status, request(payload)["credentials"]

        self.tasks.run(load, lambda result, error: self._on_loaded(result, error, trashed))

    def _on_loaded(self, result, error, trashed=False):
        self._refreshing = False
        if trashed != self._trash:  # the view changed while the request was in flight
            self.refresh()
            return
        if error is not None:
            self.count_label.setText("")
            self.service_label.setText("Service not running" if isinstance(error, ServiceUnavailable) else str(error))
            self.service_label.setToolTip(str(error))
            if self._creds is not None or self.side.currentWidget() is self.message:
                self._creds = None
                self._rebuild()
            return
        status, creds = result
        self.count_label.setText(f"{len(creds)} passkey{'s' if len(creds) != 1 else ''}")
        self.service_label.setText("Service running")
        self.service_label.setToolTip(
            f"localpasskeyd {status['version']} · virtual security key {status.get('device') or 'missing'}"
        )
        if (trashed, creds) != (self._trash, self._creds):
            self._trash = trashed
            self._creds = creds
            self._rebuild()

    def _rebuild(self):
        selected = self._selected_id
        self.model.setHorizontalHeaderLabels(TRASH_COLUMNS if self._trash else COLUMNS)
        self.model.removeRows(0, self.model.rowCount())
        for cred in self._creds or []:
            self.model.appendRow(passkey_row(cred, trashed=self._trash))
        self._restore(selected)

    def _proxy_row_of(self, cred_id):
        for row in range(self.proxy.rowCount()):
            if self.proxy.index(row, 0).data(CRED_ROLE)["id"] == cred_id:
                return row
        return None

    def _restore(self, cred_id):
        """Keep cred_id selected if visible, else select the first row, else show the empty state."""
        row = self._proxy_row_of(cred_id) if cred_id else None
        if row is None:
            self.table.clearSelection()
            row = 0 if self.proxy.rowCount() else None
        if row is not None and not self.table.selectionModel().isRowSelected(row):
            self.table.setCurrentIndex(self.proxy.index(row, 0))
        if not self.table.selectionModel().hasSelection():
            self._show(None)

    def _on_search(self, text):
        self.proxy.set_query(text)
        self._restore(self._selected_id)

    def _on_selection(self, *_):
        rows = self.table.selectionModel().selectedRows()
        self._show(rows[0].data(CRED_ROLE) if rows else None)

    def _resync(self):
        """Re-enable the actions for whatever is selected now."""
        self._sync_actions(self.details.cred if self._selected_id else None)

    def _sync_actions(self, cred):
        """Enable exactly the actions the current view and selection allow."""
        for act in self.trash_actions:
            act.setVisible(self._trash)
        for act in (self.delete_action, self.site_delete_action, self.all_delete_action):
            act.setVisible(not self._trash)
        self.all_delete_action.setEnabled(not self._trash and not self._busy)
        self.all_restore_action.setEnabled(self._trash and not self._busy)
        chosen = cred is not None
        for act in (self.copy_action, self.open_action, self.delete_action, self.site_delete_action,
                    self.restore_action, self.site_restore_action, self.purge_action):
            act.setEnabled(chosen and not self._busy)
        if chosen:
            self.open_action.setEnabled(is_website(cred["site"]) and not self._trash and not self._busy)
            self.copy_action.setEnabled(bool(cred.get("user_name")) and not self._busy)

    def _show(self, cred):
        self._sync_actions(cred)
        if cred is not None:
            self._selected_id = cred["id"]
            self.details.show_cred(cred)
            self.details.set_busy(self._busy)
            self.side.setCurrentWidget(self.details)
            return
        self._selected_id = None
        if self._creds is None:
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

    def _context_menu(self, position):
        if self.table.indexAt(position).isValid():
            self.passkey_menu.exec(self.table.viewport().mapToGlobal(position))

    def copy(self, text, what):
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage(f"{what} copied", 3000)

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
        done = "Moved {n} passkey{s} to the trash" if command == "delete" else "Restored {n} passkey{s}"
        self._send({"command": command, "ids": [cred["id"] for cred in doomed]},
                   "Waiting for you to authenticate…",
                   done.format(n=len(doomed), s="s" if len(doomed) != 1 else ""))

    def confirm_purge(self, cred):
        if self._busy:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Delete Permanently")
        warning = QLabel()
        warning.setTextFormat(Qt.TextFormat.PlainText)
        warning.setPixmap(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning).pixmap(48, 48))
        text = QLabel(f"Permanently delete the passkey for “{account_label(cred)}” on {cred['site']}?")
        text.setTextFormat(Qt.TextFormat.PlainText)
        text.setWordWrap(True)
        instruction = QLabel(f'Type "{cred["site"]}" to confirm. This cannot be undone.')
        instruction.setTextFormat(Qt.TextFormat.PlainText)
        typed = QLineEdit()
        buttons = QDialogButtonBox()
        delete = buttons.addButton("Delete Permanently", QDialogButtonBox.ButtonRole.DestructiveRole)
        cancel = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        delete.setEnabled(False)
        typed.textChanged.connect(
            lambda value: delete.setEnabled(value.strip().casefold() == cred["site"].casefold())
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
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self._send({"command": "purge", "ids": [cred["id"]]}, "Waiting for you to authenticate…",
                   "Passkey permanently deleted", cred["id"])

    def _send(self, payload, note, done, forget_id=None):
        """Run one delete/restore/purge request, with the same busy handling for all three."""
        if self._busy:
            return
        self._busy = True
        self.statusBar().showMessage(note)
        self._resync()
        if self.side.currentWidget() is self.details:
            self.details.set_busy(True)

        def finished(result, error):
            self._busy = False
            self.details.set_busy(False)
            self._resync()
            if error is not None:
                self._error(error)
            else:
                self.statusBar().showMessage(done, 4000)
                if forget_id is not None and self._selected_id == forget_id:
                    self._selected_id = None
            self.refresh()

        self.tasks.run(lambda: request(payload), finished)

    def _error(self, error):
        message = str(error)
        self.statusBar().showMessage(message[:1].upper() + message[1:], 6000)

    def _start(self, note):
        """Mark the window busy for an import or export; False if it already is."""
        if self._busy:
            return False
        self._busy = True
        self.statusBar().showMessage(note)
        self._resync()
        return True

    def _finish(self, error=None, done=None):
        self._busy = False
        self._resync()
        if error is not None:
            self._error(error)
        elif done:
            self.statusBar().showMessage(done, 4000)
        self.refresh()

    def export_passkeys(self):
        if self._busy:
            return
        cred = self.details.cred if self._selected_id and not self._trash else None
        dialog = ExportDialog(self, cred["site"] if cred else None)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        default = os.path.join(os.path.expanduser("~"), f"localpasskey-{date.today():%Y-%m-%d}{transfer.BACKUP_SUFFIX}")
        # The save dialog has already asked before replacing an existing file.
        path, _ = QFileDialog.getSaveFileName(self, "Export Passkeys", default,
                                              f"LocalPasskey backup (*{transfer.BACKUP_SUFFIX})")
        if not path or not self._start("Waiting for you to authenticate…"):
            return
        selector, passphrase = dialog.selector(), dialog.passphrase.text()

        def work():
            records = request({"command": "export", **selector})["credentials"]
            write_private_file(path, transfer.export_backup(records, passphrase), overwrite=True)
            return len(records)

        self.tasks.run(work, lambda count, error: self._finish(
            error, f"Exported {count} passkey{'s' if count != 1 else ''}"))

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
            label = "Wrong passphrase. Try again:" if retry else "Passphrase of the backup:"
            passphrase, ok = QInputDialog.getText(self, "Import Passkeys", label, QLineEdit.EchoMode.Password)
            if not ok:
                return
        if not self._start("Reading the file…"):
            return

        def work():
            records = transfer.load(data, lambda: passphrase)
            plan = request({"command": "import", "credentials": records, "dry_run": True})
            return records, plan

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
            dialog = ImportDialog(self, plan["imported"], records.skipped + plan["skipped"])
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            self._send_import(records, plan["imported"])

        self.tasks.run(work, loaded)

    def _send_import(self, records, planned):
        chosen = planned_records(records, planned)
        if not self._start("Waiting for you to authenticate…"):
            return

        def done(result, error):
            n = len(result["imported"]) if result else 0
            self._finish(error, f"Imported {n} passkey{'s' if n != 1 else ''}")

        self.tasks.run(lambda: request({"command": "import", "credentials": chosen}), done)

    def show_pin_dialog(self):
        PinDialog(self).exec()

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
    app.setStyleSheet(qdarkstyle.load_stylesheet(qt_api="pyqt6"))
    app.setWindowIcon(app_icon())
    window = Window()
    window.show()
    return app.exec()
