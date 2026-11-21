"""Janela principal: aba Varredura."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, QStandardPaths, QUrl, Signal
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QFontMetrics
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QMainWindow, QMessageBox, QProgressBar,
    QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from mandacaru.events import Severity
from mandacaru_win.quarantine import Quarantine, QuarantineError
from mandacaru_win.scan import Finding, ScanSummary, make_scanner
from mandacaru_win.store import History, TrustList
from mandacaru_win.worker import ScanThread

SEV_LABEL = {
    Severity.CRITICAL: "Crítica", Severity.HIGH: "Alta",
    Severity.MEDIUM: "Média", Severity.LOW: "Baixa", Severity.INFO: "Info",
}
SEV_COLOR = {
    Severity.CRITICAL: "#b71c1c", Severity.HIGH: "#e65100",
    Severity.MEDIUM: "#f9a825", Severity.LOW: "#1565c0", Severity.INFO: "#616161",
}


def _default_confirm(text: str) -> bool:
    return QMessageBox.question(None, "Mandacaru", text) == QMessageBox.StandardButton.Yes


def _default_notify(text: str) -> None:
    QMessageBox.warning(None, "Mandacaru", text)


class MainWindow(QMainWindow):
    scan_finished = Signal(object)

    def __init__(self, data: Path, scanner=None):
        super().__init__()
        self.setWindowTitle("Mandacaru")
        self.resize(1040, 560)
        self.setAcceptDrops(True)
        self.confirm: Callable[[str], bool] = _default_confirm
        self.notify: Callable[[str], None] = _default_notify
        self.findings: dict[Path, Finding] = {}
        self._items: dict[Path, QTreeWidgetItem] = {}
        self._thread: ScanThread | None = None
        self._files = 0
        self._data = Path(data)
        self._scanner = scanner if scanner is not None else make_scanner()
        self._history = History(self._data / "history.jsonl")
        self._quarantine = Quarantine(self._data / "quarantine")
        self._trust: TrustList | None = None
        self._trust_error: str | None = None
        try:
            self._trust = TrustList(self._data / "trust.json")
        except OSError as e:
            # Arquivo existe mas não pôde ser lido: não criamos uma lista vazia
            # (um add/remove depois sobrescreveria a real). "Ignorar sempre"
            # fica desativado nesta sessão.
            self._trust_error = (
                "Não foi possível ler a lista de confiança "
                f"({e}). A opção \"Ignorar sempre\" fica desativada nesta sessão.")
        self._build_ui()
        if self._trust_error:
            self.statusBar().showMessage(self._trust_error)

    # ---------- interface ----------
    def _build_ui(self) -> None:
        scan_tab = QWidget()
        lay = QVBoxLayout(scan_tab)
        row = QHBoxLayout()
        self.btn_downloads = QPushButton("Downloads")
        self.btn_desktop = QPushButton("Área de Trabalho")
        self.btn_folder = QPushButton("Pasta…")
        self.btn_stop = QPushButton("Parar")
        self.btn_downloads.clicked.connect(lambda: self._scan_standard(
            QStandardPaths.StandardLocation.DownloadLocation))
        self.btn_desktop.clicked.connect(lambda: self._scan_standard(
            QStandardPaths.StandardLocation.DesktopLocation))
        self.btn_folder.clicked.connect(self._pick_folder)
        self.btn_stop.clicked.connect(self.stop_scan)
        for b in (self.btn_downloads, self.btn_desktop, self.btn_folder, self.btn_stop):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.lbl_file = QLabel("Arraste uma pasta ou arquivo para cá, ou escolha acima.")
        self.lbl_count = QLabel("0 arquivos · 0 achados")
        lay.addWidget(self.progress)
        lay.addWidget(self.lbl_file)
        lay.addWidget(self.lbl_count)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Severidade", "Arquivo", "Motivo", "Ações"])
        self.tree.setRootIsDecorated(True)
        self.tree.header().setStretchLastSection(False)
        self.tree.setColumnWidth(0, 90)
        self.tree.setColumnWidth(1, 270)
        self.tree.setColumnWidth(2, 200)
        self.tree.setColumnWidth(3, 340)
        lay.addWidget(self.tree, 1)

        tabs = QTabWidget()
        tabs.addTab(scan_tab, "Varredura")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage("Pronto")
        self._set_scanning(False)

    def _set_scanning(self, on: bool) -> None:
        for b in (self.btn_downloads, self.btn_desktop, self.btn_folder):
            b.setEnabled(not on)
        self.btn_stop.setEnabled(on)

    def _scan_standard(self, loc) -> None:
        p = QStandardPaths.writableLocation(loc)
        if p:
            self.start_scan([Path(p)])

    def _pick_folder(self) -> None:
        p = QFileDialog.getExistingDirectory(self, "Escolher pasta")
        if p:
            self.start_scan([Path(p)])

    # ---------- arrastar e soltar ----------
    def dragEnterEvent(self, e) -> None:
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e) -> None:
        if self._thread is not None:
            return
        paths = [Path(u.toLocalFile()) for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.start_scan(paths)

    # ---------- varredura ----------
    def start_scan(self, paths: list[Path]) -> None:
        if self._thread is not None:
            return
        self.tree.clear()
        self.findings.clear()
        self._items.clear()
        self._files = 0
        self.progress.setRange(0, 0)  # indeterminado até saber o total
        self.lbl_count.setText("0 arquivos · 0 achados")
        self.statusBar().showMessage("Varrendo…")
        self._set_scanning(True)
        trusted = self._trust.hashes() if self._trust else set()
        t = ScanThread([Path(p) for p in paths], self._scanner, trusted)
        t.progress.connect(self._on_progress)
        t.found.connect(self._on_found)
        t.done.connect(self._on_done)
        t.failed.connect(self._on_failed)
        self._thread = t
        t.start()

    def stop_scan(self) -> None:
        if self._thread is not None:
            self._thread.stop()
            self.statusBar().showMessage("Interrompendo…")

    def _on_progress(self, path: Path, i: int, total: int) -> None:
        self._files = i
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(i)
        fm = QFontMetrics(self.lbl_file.font())
        self.lbl_file.setText(fm.elidedText(str(path), Qt.TextElideMode.ElideMiddle,
                                            max(self.lbl_file.width(), 300)))
        self._update_count()

    def _update_count(self) -> None:
        self.lbl_count.setText(f"{self._files} arquivos · {len(self.findings)} achados")

    def _on_found(self, f: Finding) -> None:
        self.findings[f.path] = f
        item = QTreeWidgetItem([SEV_LABEL.get(f.severity, str(f.severity)),
                                str(f.path), f.alerts[0].summary if f.alerts else ""])
        item.setData(0, Qt.ItemDataRole.UserRole, int(f.severity))
        item.setForeground(0, QBrush(QColor(SEV_COLOR.get(f.severity, "#616161"))))
        for a in f.alerts:
            mitre = f" ({', '.join(a.mitre)})" if a.mitre else ""
            item.addChild(QTreeWidgetItem(["", "", a.summary + mitre]))
        # Insere já na posição certa (severidade decrescente, estável).
        idx = self.tree.topLevelItemCount()
        sev = int(f.severity)
        while idx > 0 and self.tree.topLevelItem(idx - 1).data(
                0, Qt.ItemDataRole.UserRole) < sev:
            idx -= 1
        self.tree.insertTopLevelItem(idx, item)
        self._items[f.path] = item
        self.tree.setItemWidget(item, 3, self._actions_widget(f.path))
        self._update_count()

    def _actions_widget(self, path: Path) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(2, 0, 2, 0)
        for label, fn in (("Abrir local", self.open_location),
                          ("Ignorar sempre", self.ignore_finding),
                          ("Quarentena", self.quarantine_finding)):
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, p=path, fn=fn: fn(p))
            if fn == self.ignore_finding and self._trust is None:
                b.setEnabled(False)
                b.setToolTip(self._trust_error or "")
            h.addWidget(b)
        return w

    def _on_done(self, summary: ScanSummary) -> None:
        t, self._thread = self._thread, None
        if t is not None:
            t.wait()
            t.deleteLater()
        try:
            self._history.append(summary)
        except OSError as e:
            self.notify(f"Não foi possível gravar o histórico: {e}")
        self._set_scanning(False)
        self.progress.setRange(0, max(summary.files, 1))
        self.progress.setValue(summary.files if summary.completed else self.progress.value())
        self.statusBar().showMessage("Concluída" if summary.completed else "Interrompida")
        self.scan_finished.emit(summary)

    def _on_failed(self, msg: str) -> None:
        t, self._thread = self._thread, None
        if t is not None:
            t.wait()
            t.deleteLater()
        self._set_scanning(False)
        self.statusBar().showMessage("Falhou")
        self.notify(f"A varredura falhou: {msg}")
        self.scan_finished.emit(ScanSummary(0.0, [], self._files, len(self.findings),
                                            0.0, False))

    def closeEvent(self, e) -> None:
        if self._thread is not None:
            self._thread.stop()
            self._thread.wait()
        super().closeEvent(e)

    # ---------- ações por achado ----------
    def _remove_row(self, path: Path) -> None:
        self.findings.pop(path, None)
        item = self._items.pop(path, None)
        if item is not None:
            idx = self.tree.indexOfTopLevelItem(item)
            if idx >= 0:
                self.tree.takeTopLevelItem(idx)
        self._update_count()

    def open_location(self, path: Path) -> None:
        if sys.platform == "win32":
            subprocess.Popen(f'explorer /select,"{path}"')
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).parent)))

    def ignore_finding(self, path: Path) -> None:
        f = self.findings.get(path)
        if f is None:
            return
        if self._trust is None:
            self.notify(self._trust_error or "Lista de confiança indisponível.")
            return
        try:
            self._trust.add(f.sha256, path)
        except OSError as e:
            self.notify(f"Não foi possível salvar a lista de confiança: {e}")
            return
        self._remove_row(path)

    def quarantine_finding(self, path: Path) -> None:
        f = self.findings.get(path)
        if f is None:
            return
        if not self.confirm(f"Mover para a quarentena?\n{path}"):
            return
        try:
            self._quarantine.add(f)
        except QuarantineError as e:
            self.notify(str(e))
            return
        self._remove_row(path)
