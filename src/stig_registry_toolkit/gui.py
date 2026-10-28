"""PyQt6 graphical interface.

The GUI is a thin view over the same engine the CLI uses: verification
is always computed live, fixes always record a prior-value backup
first, and fixes always ask for confirmation. No WebEngine, no
JavaScript bridge, no sys.path tricks. Requires the ``gui`` extra
(``pip install stig-registry-toolkit[gui]``) and Windows for registry operations;
on other platforms the check data is still viewable.
"""

from __future__ import annotations

import html
import os
import sys
from pathlib import Path
from typing import Any

from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import QObject, QThread, pyqtSignal

from .backup import BackupError, BackupStore, backup_all_hives
from .checks import APPS, Check, load_checks
from .cli import DEFAULT_BACKUP_DIR
from .engine import CheckResult, FixOutcome, fix_all, fix_check, verify_all
from .registry import RegistryBackend, RegistryUnavailableError, create_backend


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes  # noqa: PLC0415

        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return False
        return bool(windll.shell32.IsUserAnAdmin() != 0)
    except Exception:
        return False


def _details_html(check: Check, result: CheckResult | None) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value)).replace("\n", "<br>")

    rows: list[tuple[str, Any]] = [
        ("ID", check.id),
        ("Title", check.title),
        ("Severity", check.severity),
        ("Test type", check.test_type),
        ("Status", result.status if result else "Not verified"),
    ]
    if result is not None:
        rows.append(("Detail", result.detail))
    if check.rule_id:
        rows.append(("Rule ID", check.rule_id))
    if check.is_automated:
        rows.append(("Hive", check.hive))
        rows.append(("Path", check.path))
        rows.append(("Value name", check.value_name))
        rows.append(("Type", check.reg_type))
        rows.append(
            (
                "Expected",
                check.pattern if check.pattern is not None else repr(check.expected),
            )
        )
    if check.reference:
        ref = "<br>".join(
            f"{html.escape(str(k))}: {html.escape(str(v))}"
            for k, v in check.reference.items()
        )
        rows.append(("Reference", ref))
    body = "".join(
        f"<tr><td><b>{html.escape(k)}</b></td><td>{esc(v)}</td></tr>" for k, v in rows
    )
    return (
        f"<h3>{html.escape(check.title)}</h3>"
        f"<table>{body}</table>"
        f"<h4>Description</h4><p>{esc(check.description)}</p>"
        f"<h4>Fix text</h4><p>{esc(check.fix_text)}</p>"
    )


class CheckPanel(QtWidgets.QWidget):
    """One app's checks: table, details, verify/fix/restore."""

    def __init__(
        self,
        app: str,
        backend: RegistryBackend | None,
        backup_dir: Path,
        data_dir: Path | None = None,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.app = app
        self.backend = backend
        self.backup_dir = backup_dir
        self.checks: list[Check] = load_checks(app, data_dir)
        self.results: dict[str, CheckResult] = {}

        layout = QtWidgets.QVBoxLayout(self)

        self.warning_label = QtWidgets.QLabel()
        self.warning_label.setVisible(False)
        layout.addWidget(self.warning_label)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["ID", "Title", "Severity", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self.table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.itemSelectionChanged.connect(self._show_details)
        layout.addWidget(self.table)

        self.details = QtWidgets.QTextBrowser()
        layout.addWidget(self.details)

        buttons = QtWidgets.QHBoxLayout()
        self.verify_btn = QtWidgets.QPushButton("Verify All")
        self.verify_btn.clicked.connect(self.verify)
        self.fix_btn = QtWidgets.QPushButton("Fix Selected Issue")
        self.fix_btn.clicked.connect(self.fix_selected)
        self.fix_all_btn = QtWidgets.QPushButton("Fix All Issues")
        self.fix_all_btn.clicked.connect(self.fix_all_issues)
        self.restore_btn = QtWidgets.QPushButton("Restore Selected")
        self.restore_btn.clicked.connect(self.restore_selected)
        for btn in (self.verify_btn, self.fix_btn, self.fix_all_btn, self.restore_btn):
            buttons.addWidget(btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self._populate_table()
        if backend is None:
            self.warning_label.setText(
                "Registry unavailable on this platform. "
                "Check data is view-only; run on Windows to verify or fix."
            )
            self.warning_label.setVisible(True)
            for btn in (
                self.verify_btn,
                self.fix_btn,
                self.fix_all_btn,
                self.restore_btn,
            ):
                btn.setEnabled(False)
        else:
            self.verify()

    def _populate_table(self) -> None:
        self.table.setRowCount(len(self.checks))
        for row, check in enumerate(self.checks):
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(check.id))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(check.title))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(check.severity))
            status = self.results.get(check.id)
            self.table.setItem(
                row,
                3,
                QtWidgets.QTableWidgetItem(status.status if status else "Not verified"),
            )
        if self.checks:
            self.table.selectRow(0)

    def _refresh_statuses(self) -> None:
        for row, check in enumerate(self.checks):
            status = self.results.get(check.id)
            item = self.table.item(row, 3)
            if item is not None:
                item.setText(status.status if status else "Not verified")
        self._show_details()

    def _selected_check(self) -> Check | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.checks):
            return None
        return self.checks[row]

    def _show_details(self) -> None:
        check = self._selected_check()
        if check is None:
            self.details.clear()
            return
        self.details.setHtml(_details_html(check, self.results.get(check.id)))

    def _store(self) -> BackupStore:
        return BackupStore(self.backup_dir)

    def verify(self) -> None:
        assert self.backend is not None
        self.results = {r.check.id: r for r in verify_all(self.checks, self.backend)}
        self._refresh_statuses()

    def _confirm(self, title: str, text: str) -> bool:
        reply = QtWidgets.QMessageBox.question(
            self,
            title,
            text,
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No,
        )
        return reply == QtWidgets.QMessageBox.StandardButton.Yes

    def _apply_outcome(self, outcome: FixOutcome) -> None:
        self.results[outcome.result.check.id] = outcome.result
        self._refresh_statuses()
        QtWidgets.QMessageBox.information(self, "Fix result", outcome.detail)

    def fix_selected(self) -> None:
        assert self.backend is not None
        check = self._selected_check()
        if check is None:
            return
        if not self._confirm(
            "Fix selected issue",
            f"Apply the fix for {check.id}?\n\nThe current value is "
            "backed up first and can be restored.",
        ):
            return
        outcome = fix_check(
            check, self.backend, app=self.app, backup_store=self._store()
        )
        self._apply_outcome(outcome)

    def fix_all_issues(self) -> None:
        assert self.backend is not None
        failing = [
            c
            for c in self.checks
            if self.results.get(c.id) is not None
            and self.results[c.id].status == "fail"
        ]
        if not failing:
            QtWidgets.QMessageBox.information(
                self, "Fix all", "No failing checks to fix."
            )
            return
        if not self._confirm(
            "Fix all issues",
            f"Apply fixes for {len(failing)} failing check(s)?\n\n"
            "Current values are backed up first and can be restored.",
        ):
            return
        outcomes = fix_all(
            failing, self.backend, app=self.app, backup_store=self._store()
        )
        for outcome in outcomes:
            self.results[outcome.result.check.id] = outcome.result
        self._refresh_statuses()
        fixed = sum(1 for o in outcomes if o.changed)
        failed = sum(
            1
            for o in outcomes
            if o.result.status in ("fail", "error") and not o.changed
        )
        skipped = len(outcomes) - fixed - failed
        QtWidgets.QMessageBox.information(
            self,
            "Fix all summary",
            f"Fixed: {fixed}\nFailed: {failed}\nSkipped: {skipped}",
        )

    def restore_selected(self) -> None:
        assert self.backend is not None
        check = self._selected_check()
        if check is None:
            return
        store = self._store()
        record = store.latest(self.app, check.id)
        if record is None:
            QtWidgets.QMessageBox.information(
                self, "Restore", f"No backup recorded for {check.id}."
            )
            return
        if not self._confirm(
            "Restore selected issue",
            f"Restore the backed-up value for {check.id} "
            f"(recorded {record.timestamp})?",
        ):
            return
        from .backup import restore_record  # noqa: PLC0415

        try:
            detail = restore_record(self.backend, record)
        except Exception as exc:  # noqa: BLE001 - show the error to the user
            QtWidgets.QMessageBox.critical(self, "Restore failed", str(exc))
            return
        QtWidgets.QMessageBox.information(self, "Restore", detail)
        self.verify()


class HiveBackupWorker(QObject):
    finished = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, directory: Path) -> None:
        super().__init__()
        self.directory = directory

    @QtCore.pyqtSlot()
    def run(self) -> None:
        try:
            paths = backup_all_hives(self.directory)
        except BackupError as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit("\n".join(str(p) for p in paths))


class BackupTab(QtWidgets.QWidget):
    """Hive backup controls. Per-value backups happen automatically on fix."""

    def __init__(
        self,
        backup_dir: Path,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.backup_dir = backup_dir
        layout = QtWidgets.QVBoxLayout(self)

        row = QtWidgets.QHBoxLayout()
        row.addWidget(QtWidgets.QLabel("Backup directory:"))
        self.dir_edit = QtWidgets.QLineEdit(str(backup_dir))
        self.dir_edit.setReadOnly(True)
        browse = QtWidgets.QPushButton("Browse...")
        browse.clicked.connect(self._browse)
        row.addWidget(self.dir_edit)
        row.addWidget(browse)
        layout.addLayout(row)

        self.log = QtWidgets.QTextBrowser()
        self.log.setPlaceholderText(
            "Hive backups (.hiv) and per-value backups (backups.json) "
            "are stored here. Hive backup restores a whole hive with "
            "'reg restore' from an elevated prompt; per-value restore "
            "is available from each check panel."
        )
        layout.addWidget(self.log)

        self.backup_btn = QtWidgets.QPushButton("Back Up Registry Hives")
        self.backup_btn.clicked.connect(self._start_backup)
        layout.addWidget(self.backup_btn)
        self._thread: QThread | None = None

    def _browse(self) -> None:
        chosen = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select Backup Directory", str(self.backup_dir)
        )
        if chosen:
            self.backup_dir = Path(chosen)
            self.dir_edit.setText(chosen)

    def _start_backup(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            QtWidgets.QMessageBox.information(
                self, "Backup in progress", "A hive backup is already running."
            )
            return
        self.backup_btn.setEnabled(False)
        self.log.append("Starting hive backup...")
        self._thread = QThread(self)
        worker = HiveBackupWorker(self.backup_dir)
        worker.moveToThread(self._thread)
        self._thread.started.connect(worker.run)
        worker.finished.connect(self._on_finished)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(self._thread.quit)
        worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    @QtCore.pyqtSlot(str)
    def _on_finished(self, text: str) -> None:
        self.log.append(f"Backup complete:\n{text}")
        self.backup_btn.setEnabled(True)

    @QtCore.pyqtSlot(str)
    def _on_failed(self, text: str) -> None:
        self.log.append(f"Backup failed: {text}")
        QtWidgets.QMessageBox.critical(self, "Backup failed", text)
        self.backup_btn.setEnabled(True)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(
        self,
        backend: RegistryBackend | None,
        backup_dir: Path,
        data_dir: Path | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle("STIG Registry Toolkit")
        self.setGeometry(100, 100, 1100, 800)

        if os.name == "nt" and not _is_admin():
            QtWidgets.QMessageBox.warning(
                self,
                "Not running as administrator",
                "Registry verification works without elevation, but "
                "fixes and hive backups will likely be denied. "
                "Restart as administrator to apply changes.",
            )

        tabs = QtWidgets.QTabWidget()
        tabs.addTab(BackupTab(backup_dir), "Backup & Restore")
        for app in APPS:
            tabs.addTab(CheckPanel(app, backend, backup_dir, data_dir), APPS[app])
        self.setCentralWidget(tabs)
        self.statusBar().showMessage(
            "Verify first. Fixes ask for confirmation and back up the prior value."
        )


def run_gui(
    data_dir: Path | None = None,
    backup_dir: Path | None = None,
    view: str = "64",
) -> int:
    """Create the application and show the main window."""
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    if hasattr(QtCore.Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
        QtWidgets.QApplication.setAttribute(
            QtCore.Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True
        )
    try:
        backend: RegistryBackend | None = create_backend(view=view)
    except RegistryUnavailableError:
        backend = None
    window = MainWindow(backend, backup_dir or DEFAULT_BACKUP_DIR, data_dir)
    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(run_gui())
