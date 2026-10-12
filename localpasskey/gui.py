"""LocalPasskey's window: see, search and remove the passkeys on this computer.

Qt 6 with QDarkStyle, the dark theme Electrum and Feather Wallet use.
Everything goes through localpasskeyd's control socket, so the window only
sees the current user's passkeys, and deleting one makes the service ask for
the user's password first.
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
    QAbstractItemView, QApplication, QFormLayout, QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMenu, QMessageBox, QPushButton, QSplitter, QStackedWidget, QTreeView, QVBoxLayout,
    QWidget,
)

from . import __version__
from .client import ServiceUnavailable, request

APP_ID = "org.localpasskey.Manager"
REFRESH_MS = 5000
PALETTE = qdarkstyle.DarkPalette
CRED_ROLE = Qt.ItemDataRole.UserRole
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
COLUMNS = ("Website", "Account", "Last used")
_SECOND_LEVEL = {"ac", "co", "com", "edu", "gov", "net", "org"}


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


def passkey_row(cred: dict) -> list:
    """The table cells for one passkey, carrying the values the columns sort by."""
    website = QStandardItem(cred["site"])
    website.setData(cred, CRED_ROLE)
    website.setData("\0".join(sort_key(cred)), SORT_ROLE)
    account = QStandardItem(account_label(cred))
    account.setData(account_label(cred).lower(), SORT_ROLE)
    used = QStandardItem(when(cred.get("last_used")))
    used.setData(cred.get("last_used") or 0.0, SORT_ROLE)
    return [website, account, used]


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
        self.created = self._row("Created")
        self.last_used = self._row("Last used")
        self.ident = self._row("ID", copy=lambda: window.copy(self.cred["id"], "ID"))

        self.open_button = QPushButton("Open Website")
        self.open_button.clicked.connect(lambda: window.open_site(self.cred))
        self.delete_button = QPushButton("Delete Passkey…")
        self.delete_button.clicked.connect(lambda: window.confirm_delete(self.cred))
        buttons = QHBoxLayout()
        buttons.addWidget(self.open_button)
        buttons.addWidget(self.delete_button)
        buttons.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        layout.addLayout(heading)
        layout.addLayout(self.form)
        layout.addLayout(buttons)
        layout.addStretch(1)

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
        self.created.setText(when(cred.get("created")))
        self.last_used.setText(when(cred.get("last_used")))
        self.ident.setText(cred["id"][:12])
        self.open_button.setVisible(is_website(site))
        self.set_busy(False)

    def set_busy(self, busy):
        self.delete_button.setEnabled(not busy)
        self.delete_button.setText("Deleting…" if busy else "Delete Passkey…")


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
        self._deleting = False

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
        action(file_menu, "&Quit", self.close, QKeySequence.StandardKey.Quit)
        self.passkey_menu = self.menuBar().addMenu("&Passkey")
        self.copy_action = action(self.passkey_menu, "&Copy Username",
                                  lambda: self.copy(self.details.cred["user_name"], "Username"),
                                  QKeySequence.StandardKey.Copy)
        self.open_action = action(self.passkey_menu, "&Open Website", lambda: self.open_site(self.details.cred))
        self.passkey_menu.addSeparator()
        self.delete_action = action(self.passkey_menu, "&Delete…", lambda: self.confirm_delete(self.details.cred),
                                    QKeySequence.StandardKey.Delete)
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

    def refresh(self):
        if self._refreshing:
            return
        self._refreshing = True
        self.tasks.run(
            lambda: (request({"command": "status"}), request({"command": "list"})["credentials"]),
            self._on_loaded,
        )

    def _on_loaded(self, result, error):
        self._refreshing = False
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
        if creds != self._creds:
            self._creds = creds
            self._rebuild()

    def _rebuild(self):
        selected = self._selected_id
        self.model.removeRows(0, self.model.rowCount())
        for cred in self._creds or []:
            self.model.appendRow(passkey_row(cred))
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

    def _show(self, cred):
        for act in (self.copy_action, self.open_action, self.delete_action):
            act.setEnabled(cred is not None)
        if cred is not None:
            self._selected_id = cred["id"]
            self.details.show_cred(cred)
            self.details.set_busy(self._deleting)
            self.delete_action.setEnabled(not self._deleting)
            self.open_action.setEnabled(is_website(cred["site"]))
            self.copy_action.setEnabled(bool(cred.get("user_name")))
            self.side.setCurrentWidget(self.details)
            return
        self._selected_id = None
        if self._creds is None:
            self.message.set_message(
                "LocalPasskey isn't running",
                "Start the service with “sudo systemctl start localpasskey”. "
                "This window reconnects by itself.",
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
        if self._deleting:
            return
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Delete Passkey")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(f"Delete the passkey for “{account_label(cred)}” on {cred['site']}?")
        box.setInformativeText(
            "You won't be able to sign in with it anymore. "
            "Remove it from your account settings on the website too."
        )
        delete = box.addButton("Delete", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        if box.clickedButton() is not delete:
            return
        self._deleting = True
        self.delete_action.setEnabled(False)
        self.details.set_busy(True)
        self.statusBar().showMessage("Waiting for you to authenticate…")
        self.tasks.run(lambda: request({"command": "delete", "ids": [cred["id"]]}),
                       lambda result, error: self._on_deleted(cred, error))

    def _on_deleted(self, cred, error):
        self._deleting = False
        self.delete_action.setEnabled(self._selected_id is not None)
        self.details.set_busy(False)
        if error is not None:
            message = str(error)
            self.statusBar().showMessage(message[:1].upper() + message[1:], 6000)
            return
        self.statusBar().showMessage("Passkey deleted", 4000)
        if self._selected_id == cred["id"]:
            self._selected_id = None
        self.refresh()

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
