"""Janela principal: aba Varredura."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QEvent, QFileSystemWatcher, QStandardPaths, Qt, QUrl, Signal
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QFontMetrics
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mandacaru.analysis import AnalysisResult
from mandacaru.events import Severity
from mandacaru_win.quarantine import Quarantine, QuarantineError
from mandacaru_win.scan import Finding, ScanSummary, make_scanner
from mandacaru_win.shred import ShredSummary
from mandacaru_win.store import UPDATE_KIND, ExcludeList, History, TrustList
from mandacaru_win.theme import build_stylesheet, is_dark_palette, style_button
from mandacaru_win.update_ui import UpdateBar
from mandacaru_win.updates import (
    APP_INSTALLER_URI,
    WINDOWS_UPDATE_URI,
    ApplyResult,
    Assessment,
    CheckResult,
    UpdateService,
    WingetUnavailable,
)
from mandacaru_win.widgets import BadgeDelegate, MandacaruProgressBar
from mandacaru_win.worker import (
    HashAnalysisThread,
    ScanThread,
    ShredThread,
    UpdateApplyThread,
    UpdateCheckThread,
)

SEV_LABEL = {
    Severity.CRITICAL: "Crítica", Severity.HIGH: "Alta",
    Severity.MEDIUM: "Média", Severity.LOW: "Baixa", Severity.INFO: "Info",
}
SEV_COLOR = {
    Severity.CRITICAL: "#b71c1c", Severity.HIGH: "#e65100",
    Severity.MEDIUM: "#f9a825", Severity.LOW: "#1565c0", Severity.INFO: "#616161",
}
RISK_COLOR = {"Explorada": "#b71c1c", "Explorada (produto)": "#b71c1c", "Alta": "#e65100",
              "Média": "#f9a825", "Suspeita": "#6a1b9a", "Baixa": "#1565c0"}
APPLY_LABEL = {"ok": "Atualizado", "reiniciar": "Atualizado (reinicie)", "ja_atualizado": "Já estava em dia",
               "fechar": "Feche o programa", "ocupado": "Tente de novo", "cancelado": "Cancelado",
               "falhou": "Falhou", "invalido": "Inválido"}


def _default_confirm(text: str, parent=None) -> bool:
    return QMessageBox.question(parent, "Mandacaru", text) == QMessageBox.StandardButton.Yes


def _default_notify(text: str, parent=None) -> None:
    QMessageBox.warning(parent, "Mandacaru", text)


def _default_info(text: str, parent=None) -> None:
    QMessageBox.information(parent, "Mandacaru — Análise de hash", text)


_SOURCE_NAMES = {"cymru": "Team Cymru MHR", "circl": "CIRCL hashlookup",
                 "malwarebazaar": "MalwareBazaar", "virustotal": "VirusTotal"}
_STATUS_LABEL = {"achou": "encontrado", "nao_achou": "não encontrado", "erro": "erro"}


def format_analysis_result(label: str, sha256: str, res: AnalysisResult) -> str:
    """Formata o veredito da análise de hash em português para exibir na interface."""
    lines = [
        f"Arquivo: {label}",
        f"SHA-256: {sha256[:16]}…",
        "",
        res.summary,
        "",
        "Fontes consultadas:",
    ]
    for name, src in res.sources.items():
        if src.status == "desligada":
            continue
        title = _SOURCE_NAMES.get(name, name)
        st = _STATUS_LABEL.get(src.status, src.status)
        detail = f" ({src.detail})" if src.detail else ""
        lines.append(f"• {title}: {st}{detail}")
    lines.append("")
    lines.append("Apenas o hash SHA-256 foi consultado; o conteúdo do arquivo não saiu do computador.")
    return "\n".join(lines)


class MainWindow(QMainWindow):
    scan_finished = Signal(object)
    hash_analysis_finished = Signal(str, object)
    shred_finished = Signal(object)

    def __init__(self, data: Path, scanner=None):
        super().__init__()
        self.setWindowTitle("Mandacaru")
        self.resize(1100, 580)
        self.setAcceptDrops(True)
        self.confirm: Callable[[str], bool] = lambda t: _default_confirm(t, self)
        self.notify: Callable[[str], None] = lambda t: _default_notify(t, self)
        self.info: Callable[[str], None] = lambda t: _default_info(t, self)
        self.hash_analyzer: Callable[[str], AnalysisResult] | None = None
        self.findings: dict[Path, Finding] = {}
        self._items: dict[Path, QTreeWidgetItem] = {}
        self._thread: ScanThread | None = None
        self._shred_thread: ShredThread | None = None
        self._analysis_threads: list[HashAnalysisThread] = []
        self._analyzing_hashes: set[str] = set()
        self._req_watcher: QFileSystemWatcher | None = None
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
        self._excludes: ExcludeList | None = None
        self._excludes_error: str | None = None
        try:
            self._excludes = ExcludeList(self._data / "excludes.json")
        except OSError as e:
            self._excludes_error = (
                "Não foi possível ler a lista de pastas excluídas "
                f"({e}). A edição de exclusões fica desativada nesta sessão.")
        self._dark_theme: bool | None = None
        self._build_ui()
        self._build_update_ui()
        self._apply_theme()
        if self._trust_error:
            self.statusBar().showMessage(self._trust_error)
        elif self._excludes_error:
            self.statusBar().showMessage(self._excludes_error)

    def _apply_theme(self) -> None:
        dark = is_dark_palette(self)
        if dark == self._dark_theme:
            return
        self._dark_theme = dark
        self.setStyleSheet(build_stylesheet(dark))

    def changeEvent(self, event) -> None:  # noqa: N802 - API Qt
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.ApplicationPaletteChange):
            self._apply_theme()

    # ---------- interface ----------
    def _build_ui(self) -> None:
        scan_tab = QWidget()
        lay = QVBoxLayout(scan_tab)
        row = QHBoxLayout()
        self.btn_downloads = style_button(QPushButton("Downloads"), "scan")
        self.btn_desktop = style_button(QPushButton("Área de Trabalho"), "scan")
        self.btn_folder = style_button(QPushButton("Pasta…"), "scan")
        self.btn_stop = style_button(QPushButton("Parar"), "danger")
        self.btn_shred = style_button(QPushButton("Destruir pasta…"), "danger")
        self.btn_shred.setToolTip(
            "Sobrescreve os arquivos com dados aleatórios e apaga definitivamente (sem possibilidade de restauração).")
        self.btn_downloads.clicked.connect(lambda: self._scan_standard(
            QStandardPaths.StandardLocation.DownloadLocation))
        self.btn_desktop.clicked.connect(lambda: self._scan_standard(
            QStandardPaths.StandardLocation.DesktopLocation))
        self.btn_folder.clicked.connect(self._pick_folder)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_shred.clicked.connect(self._pick_shred_folder)
        for b in (self.btn_downloads, self.btn_desktop, self.btn_folder, self.btn_stop):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(self.btn_shred)
        lay.addLayout(row)

        self.progress = MandacaruProgressBar()
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
        self.tree.setColumnWidth(0, 100)
        self.tree.setColumnWidth(1, 250)
        self.tree.setColumnWidth(2, 200)
        self.tree.setColumnWidth(3, 430)
        self.tree.setItemDelegateForColumn(0, BadgeDelegate(self.tree))
        lay.addWidget(self.tree, 1)

        tabs = QTabWidget()
        self.tabs = tabs
        tabs.addTab(scan_tab, "Varredura")
        self.tbl_quarantine = self._make_table(
            ["Data", "Caminho original", "Severidade", "Regras", "Ações"], stretch=1)
        self.tbl_quarantine.setItemDelegateForColumn(2, BadgeDelegate(self.tbl_quarantine))
        tabs.addTab(self.tbl_quarantine, "Quarentena")
        trust_tab = QWidget()
        tl = QVBoxLayout(trust_tab)
        tl.addWidget(QLabel("Arquivos confiáveis (ignorados por hash SHA-256)"))
        self.lbl_trust = QLabel("")
        self.lbl_trust.setWordWrap(True)
        self.lbl_trust.setVisible(False)
        self.tbl_trust = self._make_table(
            ["Caminho quando confiado", "Data", "SHA-256", "Ações"], stretch=0)
        tl.addWidget(self.lbl_trust)
        tl.addWidget(self.tbl_trust, 1)

        excl_hdr = QHBoxLayout()
        excl_hdr.addWidget(QLabel("Pastas ignoradas na varredura"))
        excl_hdr.addStretch(1)
        self.btn_add_exclude = QPushButton("Adicionar pasta…")
        self.btn_add_exclude.clicked.connect(self._pick_exclude_folder)
        if self._excludes is None:
            self.btn_add_exclude.setEnabled(False)
            self.btn_add_exclude.setToolTip(self._excludes_error or "")
        excl_hdr.addWidget(self.btn_add_exclude)
        tl.addLayout(excl_hdr)
        self.lbl_excludes = QLabel("")
        self.lbl_excludes.setWordWrap(True)
        self.lbl_excludes.setVisible(False)
        self.tbl_excludes = self._make_table(["Pasta ignorada", "Data", "Ações"], stretch=0)
        tl.addWidget(self.lbl_excludes)
        tl.addWidget(self.tbl_excludes, 1)
        tabs.addTab(trust_tab, "Confiáveis")
        self.tbl_history = self._make_table(
            ["Data", "Pastas", "Arquivos", "Achados", "Duração", "Situação"], stretch=1)
        tabs.addTab(self.tbl_history, "Histórico")
        tabs.addTab(self._build_updates_tab(), "Atualizações")
        self.setCentralWidget(tabs)
        self.refresh_tabs()
        self.statusBar().showMessage("Pronto")
        self._set_scanning(False)

    @staticmethod
    def _make_table(headers: list[str], stretch: int = 1) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.verticalHeader().setDefaultSectionSize(34)
        t.setWordWrap(False)
        hh = t.horizontalHeader()
        hh.setStretchLastSection(False)
        for c in range(len(headers)):
            hh.setSectionResizeMode(
                c, QHeaderView.ResizeMode.Stretch if c == stretch
                else QHeaderView.ResizeMode.ResizeToContents)
        return t

    @staticmethod
    def _fmt_date(value) -> str:
        try:
            d = (datetime.fromtimestamp(value) if isinstance(value, (int, float))
                 else datetime.fromisoformat(str(value)))
            return d.strftime("%d/%m/%Y %H:%M")
        except (ValueError, OverflowError, OSError):
            return str(value)

    @staticmethod
    def _button_cell(table: QTableWidget, row: int, col: int,
                     buttons: list[tuple]) -> None:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(4, 2, 4, 2)
        h.setSpacing(6)
        for item in buttons:
            label, fn = item[0], item[1]
            role = item[2] if len(item) > 2 else "neutral"
            b = style_button(QPushButton(label), role, compact=True)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            h.addWidget(b)
        table.setCellWidget(row, col, w)

    @staticmethod
    def _reset_table(t: QTableWidget, rows: int) -> None:
        # Esconde widgets de células antigos já (deleteLater só roda depois),
        # senão eles aparecem soltos no canto da tabela.
        for r in range(t.rowCount()):
            for c in range(t.columnCount()):
                w = t.cellWidget(r, c)
                if w is not None:
                    w.hide()
        t.setRowCount(0)
        t.setRowCount(rows)

    def refresh_tabs(self) -> None:
        """Reconstrói as tabelas pequenas de quarentena, confiáveis e histórico.

        Cada linha é montada em try/except: dado malformado pula a linha em vez
        de impedir a janela de abrir.
        """
        qrows = []
        for m in self._quarantine.items():
            try:
                sev = m.get("severidade", "")
                sev = SEV_LABEL.get(Severity[sev], sev) if sev in Severity.__members__ else sev
                orig = str(m["caminho_original"])
                vals = (self._fmt_date(m["data"]), orig, str(sev),
                        ", ".join(str(r) for r in m.get("regras", [])))
                qrows.append((vals, str(m["id"]), str(m["sha256"]), Path(orig).name or orig))
            except (TypeError, ValueError, KeyError):
                continue
        t = self.tbl_quarantine
        self._reset_table(t, len(qrows))
        for r, (vals, qid, sha, name) in enumerate(qrows):
            for c, v in enumerate(vals):
                t.setItem(r, c, QTableWidgetItem(v))
            self._button_cell(t, r, 4, [
                ("Analisar", lambda h=sha, n=name: self.analyze_hash(h, n), "analyze"),
                ("Restaurar", lambda q=qid: self.restore_item(q), "neutral"),
                ("Apagar", lambda q=qid: self.delete_item(q), "danger")])

        t = self.tbl_trust
        if self._trust is None:
            self.lbl_trust.setText(self._trust_error or "Lista de confiança indisponível.")
            self.lbl_trust.setVisible(True)
            entries = []
        else:
            self.lbl_trust.setVisible(False)
            entries = self._trust.entries()
        trows = []
        for e in entries:
            try:
                h = str(e["sha256"])
                trows.append(((str(e.get("caminho_quando_confiado", "")),
                               self._fmt_date(e.get("data", "")), h[:12]), h))
            except (TypeError, ValueError, KeyError):
                continue
        self._reset_table(t, len(trows))
        for r, (vals, h) in enumerate(trows):
            for c, v in enumerate(vals):
                t.setItem(r, c, QTableWidgetItem(v))
            t.item(r, 2).setToolTip(h)
            self._button_cell(t, r, 3, [("Remover", lambda x=h: self.remove_trusted(x))])

        t = self.tbl_excludes
        if self._excludes is None:
            self.lbl_excludes.setText(self._excludes_error or "Lista de exclusões indisponível.")
            self.lbl_excludes.setVisible(True)
            excl_entries = []
        else:
            self.lbl_excludes.setVisible(False)
            excl_entries = self._excludes.entries()
        erows = []
        for e in excl_entries:
            try:
                p = str(e["caminho"])
                erows.append(((p, self._fmt_date(e.get("data", ""))), p))
            except (TypeError, ValueError, KeyError):
                continue
        self._reset_table(t, len(erows))
        for r, (vals, p) in enumerate(erows):
            for c, v in enumerate(vals):
                t.setItem(r, c, QTableWidgetItem(v))
            self._button_cell(t, r, 2, [("Remover", lambda x=p: self.remove_excluded_folder(x))])

        hrows = []
        for e in self._history.recent(50):
            try:
                if e.get("tipo") == UPDATE_KIND:
                    hrows.append(self._update_history_row(e))
                    continue
                paths = e.get("paths") or []
                hrows.append((self._fmt_date(e.get("started", "")),
                              ", ".join(str(p) for p in paths), str(e.get("files", 0)),
                              str(e.get("findings", 0)),
                              f"{float(e.get('duration', 0) or 0):.1f} s",
                              "Concluída" if e.get("completed") else "Interrompida"))
            except (TypeError, ValueError):
                continue
        t = self.tbl_history
        self._reset_table(t, len(hrows))
        for r, vals in enumerate(hrows):
            for c, v in enumerate(vals):
                t.setItem(r, c, QTableWidgetItem(v))

    def _set_scanning(self, on: bool) -> None:
        for b in (self.btn_downloads, self.btn_desktop, self.btn_folder, self.btn_shred):
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

    # ---------- autoatualização ----------
    def _build_update_ui(self) -> None:
        """Faixa de versão nova acima das abas e menu Ajuda → Verificar atualizações."""
        self.update_bar = UpdateBar(self._data, notify=lambda t: self.notify(t),
                                    status=lambda t: self.statusBar().showMessage(t))
        self.update_bar.quit_requested.connect(self.close)
        tabs = self.takeCentralWidget()
        central = QWidget()
        v = QVBoxLayout(central)
        v.setContentsMargins(0, 0, 0, 0)
        v.addWidget(self.update_bar)
        v.addWidget(tabs, 1)
        self.setCentralWidget(central)
        self.act_check_updates = self.menuBar().addMenu("Ajuda").addAction("Verificar atualizações")
        self.act_check_updates.triggered.connect(lambda: self.check_updates(force=True))

    def check_updates(self, force: bool = False) -> bool:
        """Consulta em thread; sem ``force`` respeita o 1×/24 h e o "Depois"."""
        return self.update_bar.start_check(force)

    # ---------- arrastar e soltar ----------
    def dragEnterEvent(self, e) -> None:
        if self._thread is None and e.mimeData().hasUrls():
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
        self.progress.set_tone("normal")
        self.progress.setRange(0, 0)  # indeterminado até saber o total
        self.lbl_count.setText("0 arquivos · 0 achados")
        self.statusBar().showMessage("Varrendo…")
        self._set_scanning(True)
        trusted = self._trust.hashes() if self._trust else set()
        excluded = self._excludes.paths() if self._excludes else ()
        t = ScanThread([Path(p) for p in paths], self._scanner, trusted, exclude=excluded)
        t.listing.connect(self._on_listing)
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
        if self._shred_thread is not None:
            self._shred_thread.stop()
            self.statusBar().showMessage("Interrompendo destruição…")

    def _on_listing(self, count: int) -> None:
        self.lbl_file.setText(f"Listando… {count} arquivos")

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
        if f.path in self._items:
            self._remove_row(f.path)
        self.findings[f.path] = f
        # o nome do arquivo é o que a pessoa reconhece; o caminho inteiro cortado no fim escondia justamente o nome
        item = QTreeWidgetItem([SEV_LABEL.get(f.severity, str(f.severity)),
                                f.path.name, f.alerts[0].summary if f.alerts else ""])
        item.setToolTip(1, str(f.path))
        item.setData(0, Qt.ItemDataRole.UserRole, int(f.severity))
        item.addChild(QTreeWidgetItem(["", "Pasta", str(f.path.parent)]))
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
        h.setContentsMargins(4, 2, 4, 2)
        h.setSpacing(6)
        for label, fn, role in (("Analisar", self.analyze_finding, "analyze"),
                                ("Abrir local", self.open_location, "neutral"),
                                ("Ignorar sempre", self.ignore_finding, "neutral"),
                                ("Quarentena", self.quarantine_finding, "quarantine")):
            b = style_button(QPushButton(label), role, compact=True)
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
        self.refresh_tabs()
        if summary.completed:
            self.progress.set_tone("normal")
            self.progress.setRange(0, max(summary.files, 1))
            self.progress.setValue(summary.files)
        else:
            self.progress.set_tone("warning")
            if self.progress.maximum() == 0:  # parou ainda na listagem
                self.progress.setRange(0, 1)
                self.progress.setValue(0)
        self.statusBar().showMessage("Concluída" if summary.completed else "Interrompida")
        self.scan_finished.emit(summary)

    def _on_failed(self, msg: str) -> None:
        t, self._thread = self._thread, None
        if t is not None:
            t.wait()
            t.deleteLater()
        self._set_scanning(False)
        self.progress.set_tone("error")
        if self.progress.maximum() == 0:
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
        self.statusBar().showMessage("Falhou")
        self.notify(f"A varredura falhou: {msg}")
        self.scan_finished.emit(ScanSummary(0.0, [], self._files, len(self.findings),
                                            0.0, False))

    def closeEvent(self, e) -> None:
        if not self._updates_allow_close():
            e.ignore()
            return
        if self._thread is not None:
            self._thread.stop()
            self._thread.wait()
        if self._shred_thread is not None:
            self._shred_thread.stop()
            self._shred_thread.wait()
        for t in list(self._analysis_threads):
            t.wait()
        self._analysis_threads.clear()
        self._analyzing_hashes.clear()
        if self._req_watcher is not None:
            self._req_watcher.deleteLater()
            self._req_watcher = None
        self.update_bar.shutdown()
        super().closeEvent(e)

    def _pick_shred_folder(self) -> None:
        p = QFileDialog.getExistingDirectory(self, "Escolher pasta para destruir definitivamente")
        if p:
            self.shred_target(Path(p))

    def shred_target(self, target: Path) -> None:
        """Sobrescreve com dados aleatórios e apaga definitivamente um arquivo ou pasta."""
        if self._thread is not None or self._shred_thread is not None:
            return
        p = Path(target)
        if not self.confirm(
                f"Destruir definitivamente?\n{p}\n\n"
                "Todos os arquivos serão sobrescritos com dados aleatórios, renomeados e apagados "
                "sem passar pela Lixeira. Esta ação NÃO pode ser desfeita."):
            return
        self.progress.set_tone("shred")
        self.progress.setRange(0, 0)
        self.lbl_file.setText(f"Destruindo definitivamente: {p}")
        self.statusBar().showMessage("Destruindo arquivos…")
        self._set_scanning(True)
        t = ShredThread(p)
        t.progress.connect(self._on_shred_progress)
        t.done.connect(self._on_shred_done)
        t.failed.connect(self._on_shred_failed)
        self._shred_thread = t
        t.start()

    def _on_shred_progress(self, path: Path, i: int, total: int) -> None:
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(i)
        self.lbl_file.setText(f"Destruindo ({i}/{total}): {path.name}")

    def _finish_shred_thread(self) -> None:
        t, self._shred_thread = self._shred_thread, None
        if t is not None:
            t.wait()
            t.deleteLater()
        self._set_scanning(False)

    def _on_shred_done(self, summary: ShredSummary) -> None:
        self._finish_shred_thread()
        self.progress.set_tone("shred" if summary.completed and not summary.errors else "warning")
        self.progress.setRange(0, 1)
        self.progress.setValue(1 if summary.completed else 0)
        msg = (f"Destruição concluída: {summary.files_shredded} arquivo(s) sobrescrito(s) e apagado(s), "
               f"{summary.dirs_removed} pasta(s) removida(s).")
        if not summary.completed:
            msg = f"Destruição interrompida ({summary.files_shredded} arquivo(s) já destruído(s))."
        if summary.errors:
            msg += f"\n\nAvisos ({len(summary.errors)}):\n" + "\n".join(summary.errors[:10])
            self.notify(msg)
        else:
            self.info(msg)
        self.statusBar().showMessage("Destruição concluída" if summary.completed else "Destruição interrompida")
        self.lbl_file.setText("Arraste uma pasta ou arquivo para cá, ou escolha acima.")
        self.shred_finished.emit(summary)

    def _on_shred_failed(self, msg: str) -> None:
        self._finish_shred_thread()
        self.progress.set_tone("error")
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.statusBar().showMessage("Falha na destruição")
        self.notify(f"Não foi possível destruir: {msg}")
        self.shred_finished.emit(ShredSummary("", 0, 0, [msg], False))

    # ---------- análise de hash ----------
    def analyze_finding(self, path: Path) -> None:
        f = self.findings.get(path)
        if f is None:
            return
        self.analyze_hash(f.sha256, f.path.name)

    def analyze_hash(self, sha256: str, label: str) -> None:
        if sha256 in self._analyzing_hashes:
            return
        self._analyzing_hashes.add(sha256)
        self.statusBar().showMessage(f"Analisando hash de {label}…")
        t = HashAnalysisThread(sha256, label, analyzer=self.hash_analyzer)
        t.done.connect(lambda lbl, h, res, th=t: self._on_analysis_done(th, lbl, h, res))
        t.failed.connect(lambda lbl, msg, h=sha256, th=t: self._on_analysis_failed(th, lbl, h, msg))
        self._analysis_threads.append(t)
        t.start()

    def _finish_analysis_thread(self, t: HashAnalysisThread, sha256: str) -> None:
        self._analyzing_hashes.discard(sha256)
        if t in self._analysis_threads:
            self._analysis_threads.remove(t)
        t.wait()
        t.deleteLater()

    def _on_analysis_done(self, t: HashAnalysisThread, label: str, sha256: str, res: AnalysisResult) -> None:
        self._finish_analysis_thread(t, sha256)
        self.statusBar().showMessage(res.summary)
        self.info(format_analysis_result(label, sha256, res))
        self.hash_analysis_finished.emit(sha256, res)

    def _on_analysis_failed(self, t: HashAnalysisThread, label: str, sha256: str, msg: str) -> None:
        self._finish_analysis_thread(t, sha256)
        self.statusBar().showMessage("Falha na análise de hash")
        self.notify(f"Não foi possível analisar o hash de {label}: {msg}")
        self.hash_analysis_finished.emit(sha256, None)

    # ---------- requisições externas (--scan / menu de contexto) ----------
    def watch_scan_requests(self) -> None:
        """Observa arquivos scan-req-*.json gravados por uma segunda instância (--scan)."""
        self._data.mkdir(parents=True, exist_ok=True)
        if self._req_watcher is None:
            self._req_watcher = QFileSystemWatcher([str(self._data)], self)
            self._req_watcher.directoryChanged.connect(lambda _: self.consume_scan_requests())
        self.consume_scan_requests()

    def consume_scan_requests(self) -> list[Path]:
        """Lê e apaga requisições externas (`--scan` / `--shred`) e executa se a janela estiver livre."""
        scan_paths_req: list[Path] = []
        shred_paths_req: list[Path] = []
        if not self._data.is_dir():
            return []
        for req in sorted(self._data.glob("scan-req-*.json")):
            try:
                raw = json.loads(req.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raw = None
            try:
                req.unlink(missing_ok=True)
            except OSError:
                pass
            if isinstance(raw, dict) and isinstance(raw.get("paths"), list):
                action = raw.get("action", "scan")
                dest = shred_paths_req if action == "shred" else scan_paths_req
                for item in raw["paths"]:
                    if isinstance(item, str) and item.strip():
                        dest.append(Path(item))
        if not scan_paths_req and not shred_paths_req:
            return []
        self.tabs.setCurrentIndex(0)
        self.showNormal()
        self.raise_()
        self.activateWindow()
        if self._thread is not None or self._shred_thread is not None:
            self.statusBar().showMessage("Já há uma operação em andamento; aguarde terminar.")
        elif shred_paths_req:
            self.shred_target(shred_paths_req[0])
        else:
            self.start_scan(scan_paths_req)
        return shred_paths_req or scan_paths_req

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
            explorer = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "explorer.exe")
            try:
                subprocess.Popen([explorer, "/select,", str(path)])
            except OSError as e:
                self.notify(f"Não foi possível abrir o Explorer: {e}")
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
        for p in [p for p, x in self.findings.items() if x.sha256 == f.sha256]:
            self._remove_row(p)  # mesmo conteúdo em outros caminhos também some
        self.refresh_tabs()

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
        self.refresh_tabs()

    # ---------- ações das abas ----------
    def restore_item(self, qid: str) -> None:
        if not self.confirm("Este arquivo foi marcado como suspeito. Restaurar mesmo assim?"):
            return
        try:
            dest = self._quarantine.restore(qid)
        except QuarantineError as e:
            self.notify(str(e))
            return
        self.statusBar().showMessage(f"Restaurado em {dest}")
        self.refresh_tabs()

    def delete_item(self, qid: str) -> None:
        if not self.confirm("Apagar definitivamente?"):
            return
        try:
            self._quarantine.delete(qid)
        except QuarantineError as e:
            self.notify(str(e))
            return
        self.refresh_tabs()

    def remove_trusted(self, sha256: str) -> None:
        if self._trust is None:
            self.notify(self._trust_error or "Lista de confiança indisponível.")
            return
        try:
            self._trust.remove(sha256)
        except OSError as e:
            self.notify(f"Não foi possível salvar a lista de confiança: {e}")
            return
        self.refresh_tabs()

    def _pick_exclude_folder(self) -> None:
        p = QFileDialog.getExistingDirectory(self, "Escolher pasta para excluir da varredura")
        if p:
            self.add_excluded_folder(Path(p))

    def add_excluded_folder(self, path: Path) -> None:
        if self._excludes is None:
            self.notify(self._excludes_error or "Lista de exclusões indisponível.")
            return
        try:
            self._excludes.add(path)
        except OSError as e:
            self.notify(f"Não foi possível salvar as pastas excluídas: {e}")
            return
        self.refresh_tabs()

    def remove_excluded_folder(self, path: str) -> None:
        if self._excludes is None:
            self.notify(self._excludes_error or "Lista de exclusões indisponível.")
            return
        try:
            self._excludes.remove(path)
        except OSError as e:
            self.notify(f"Não foi possível salvar as pastas excluídas: {e}")
            return
        self.refresh_tabs()

    # ---------- aba Atualizações ----------
    def _build_updates_tab(self) -> QWidget:
        self.updates_service: UpdateService | None = None  # criado no primeiro uso (testes injetam)
        self._upd_thread: UpdateCheckThread | None = None
        self._apply_thread: UpdateApplyThread | None = None
        self._upd_items: list[Assessment] = []
        self._apply_rows: list[int] = []
        self._apply_started = 0.0
        tab = QWidget()
        lay = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.btn_upd_quick = style_button(QPushButton("Verificação rápida"), "scan")
        self.btn_upd_full = style_button(QPushButton("Verificação completa"), "scan")
        self.btn_upd_stop = style_button(QPushButton("Parar"), "danger")
        self.btn_open_wu = style_button(QPushButton("Abrir Windows Update"), "neutral")
        self.btn_upd_quick.setToolTip("Programas com versão nova e falhas já usadas em ataques (segundos).")
        self.btn_upd_full.setToolTip("Também consulta CVEs na NVD e as atualizações pendentes do Windows "
                                     "(minutos). Só o nome e a versão dos programas são enviados à NVD.")
        self.btn_upd_quick.clicked.connect(lambda: self.start_update_check(False))
        self.btn_upd_full.clicked.connect(lambda: self.start_update_check(True))
        self.btn_upd_stop.clicked.connect(self.stop_updates)
        self.btn_open_wu.clicked.connect(lambda: self._open_uri(WINDOWS_UPDATE_URI))
        for b in (self.btn_upd_quick, self.btn_upd_full, self.btn_upd_stop):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(self.btn_open_wu)
        lay.addLayout(row)

        self.upd_progress = MandacaruProgressBar()
        self.upd_progress.setRange(0, 1)
        self.upd_progress.setValue(0)
        self.lbl_upd = QLabel("Veja se os seus programas estão em dia. Nada é alterado sem você mandar.")
        self.lbl_upd.setWordWrap(True)
        lay.addWidget(self.upd_progress)
        lay.addWidget(self.lbl_upd)

        self.tbl_updates = self._make_table(["", "Programa", "Instalada → Disponível", "Risco", "Situação"],
                                            stretch=1)
        self.tbl_updates.setItemDelegateForColumn(3, BadgeDelegate(self.tbl_updates))
        self.tbl_updates.horizontalHeaderItem(0).setToolTip("Marcados serão atualizados")
        lay.addWidget(self.tbl_updates, 1)

        self.lbl_wu = QLabel("")
        self.lbl_wu.setWordWrap(True)
        self.lbl_wu.setVisible(False)
        lay.addWidget(self.lbl_wu)

        bottom = QHBoxLayout()
        self.lbl_uac = QLabel("Os programas com risco Explorada ou Alta já vêm marcados; desmarque o que não "
                              "quiser. Programas instalados para todos os usuários podem pedir permissão do "
                              "Windows (UAC).")
        self.lbl_uac.setWordWrap(True)
        self.btn_get_winget = style_button(QPushButton("Instalar o winget (Microsoft Store)"), "neutral")
        self.btn_get_winget.clicked.connect(lambda: self._open_uri(APP_INSTALLER_URI))
        self.btn_get_winget.setVisible(False)
        self.btn_upd_apply = style_button(QPushButton("Atualizar selecionados"), "scan")
        self.btn_upd_apply.clicked.connect(self.apply_selected_updates)
        bottom.addWidget(self.lbl_uac, 1)
        bottom.addWidget(self.btn_get_winget)
        bottom.addWidget(self.btn_upd_apply)
        lay.addLayout(bottom)
        self._set_updating(False)
        return tab

    def _service(self) -> UpdateService:
        if self.updates_service is None:
            self.updates_service = UpdateService(self._data / "cache")
        return self.updates_service

    @staticmethod
    def _open_uri(uri: str) -> None:
        QDesktopServices.openUrl(QUrl(uri))

    def _update_history_row(self, e: dict) -> tuple[str, ...]:
        progs = e.get("programas") or []
        ok = sum(1 for p in progs if p.get("resultado") in ("ok", "reiniciar", "ja_atualizado"))
        names = ", ".join(f"{p.get('nome', '')} ({APPLY_LABEL.get(p.get('resultado', ''), '?')})" for p in progs)
        return (self._fmt_date(e.get("started", "")), f"Atualização: {names}", "—", "—",
                f"{float(e.get('duration', 0) or 0):.1f} s", f"{ok} de {len(progs)} atualizado(s)")

    def _updates_allow_close(self) -> bool:
        if self._apply_thread is not None:  # não abandona um instalador no meio
            self.notify("Há uma atualização de programa em andamento. Aguarde terminar para fechar.")
            return False
        if self._upd_thread is not None:
            self._upd_thread.stop()
            self._upd_thread.wait()
        return True

    def _set_updating(self, on: bool) -> None:
        for b in (self.btn_upd_quick, self.btn_upd_full):
            b.setEnabled(not on)
        self.btn_upd_stop.setEnabled(on)
        self.btn_upd_apply.setEnabled(not on and bool(self._upd_items))

    def _upd_busy(self) -> bool:
        return self._upd_thread is not None or self._apply_thread is not None

    def start_update_check(self, complete: bool) -> None:
        if self._upd_busy():
            return
        self.btn_get_winget.setVisible(False)
        self.lbl_wu.setVisible(False)
        self.upd_progress.set_tone("normal")
        self.upd_progress.setRange(0, 0)
        self.lbl_upd.setText("Verificando…")
        self._upd_items = []
        self._reset_table(self.tbl_updates, 0)
        t = UpdateCheckThread(self._service(), complete)
        t.progress.connect(self._on_upd_progress)
        t.done.connect(self._on_upd_done)
        t.failed.connect(self._on_upd_failed)
        self._upd_thread = t
        self._set_updating(True)
        t.start()

    def stop_updates(self) -> None:
        for t in (self._upd_thread, self._apply_thread):
            if t is not None:
                t.stop()
        self.lbl_upd.setText("Interrompendo…")

    def _on_upd_progress(self, text: str, i: int, n: int) -> None:
        self.lbl_upd.setText(text)
        if n > 0:
            self.upd_progress.setRange(0, n)
            self.upd_progress.setValue(i)

    def _finish_upd_thread(self) -> None:
        t, self._upd_thread = self._upd_thread, None
        if t is not None:
            t.wait()
            t.deleteLater()
        self.upd_progress.setRange(0, 1)
        self.upd_progress.setValue(1)

    def _on_upd_done(self, result: CheckResult) -> None:
        self._finish_upd_thread()
        self._upd_items = list(result.items)
        self._fill_updates_table()
        n = len(result.items)
        marked = sum(1 for a in result.items if a.preselected)
        kind = "Verificação completa" if result.complete else "Verificação rápida"
        msg = (f"{kind}: {n} programa(s) com versão nova, {marked} já marcado(s) por risco."
               if n else f"{kind}: todos os programas que o winget conhece estão em dia.")
        self.lbl_upd.setText(" ".join([msg, *result.notes]))
        wu = result.windows
        if wu is not None:
            self.lbl_wu.setToolTip("")
            if not wu.available:
                text = f"Windows Update: {wu.reason}."
            elif wu.total == 0:
                text = "Windows Update: nenhuma atualização pendente."
            else:
                text = (f"Windows Update: {wu.total} atualização(ões) pendente(s), {wu.security} de segurança. "
                        "Instale pelo botão \"Abrir Windows Update\".")
                self.lbl_wu.setToolTip("\n".join(wu.titles[:20]))
            self.lbl_wu.setText(text)
            self.lbl_wu.setVisible(True)
        self._set_updating(False)
        self.statusBar().showMessage("Verificação de atualizações concluída")

    def _on_upd_failed(self, exc: object) -> None:
        self._finish_upd_thread()
        self.upd_progress.set_tone("error")
        self.upd_progress.setValue(0)
        if isinstance(exc, WingetUnavailable):
            self.lbl_upd.setText("Para listar e atualizar programas, o Mandacaru usa o winget, que vem com o "
                                 "\"Instalador de Aplicativo\" da Microsoft. Ele não foi encontrado neste "
                                 "computador: instale-o pela Microsoft Store e tente de novo.")
            self.btn_get_winget.setVisible(True)
        else:
            self.lbl_upd.setText(f"A verificação falhou: {exc}")
        self._set_updating(False)

    def _fill_updates_table(self) -> None:
        t = self.tbl_updates
        self._reset_table(t, len(self._upd_items))
        for r, a in enumerate(self._upd_items):
            p = a.program
            chk = QTableWidgetItem("")
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk.setCheckState(Qt.CheckState.Checked if a.preselected else Qt.CheckState.Unchecked)
            t.setItem(r, 0, chk)
            name = QTableWidgetItem(p.name)
            name.setToolTip(p.id)
            t.setItem(r, 1, name)
            t.setItem(r, 2, QTableWidgetItem(f"{p.installed} → {p.available}"))
            risk = QTableWidgetItem(a.risk)
            risk.setToolTip(a.detail)
            risk.setForeground(QBrush(QColor(RISK_COLOR.get(a.risk, "#616161"))))
            t.setItem(r, 3, risk)
            t.setItem(r, 4, QTableWidgetItem(""))

    def checked_updates(self) -> list[int]:
        t = self.tbl_updates
        return [r for r in range(min(t.rowCount(), len(self._upd_items)))
                if t.item(r, 0) is not None and t.item(r, 0).checkState() == Qt.CheckState.Checked]

    def apply_selected_updates(self) -> None:
        if self._upd_busy():
            return
        rows = self.checked_updates()
        if not rows:
            self.notify("Marque ao menos um programa para atualizar.")
            return
        names = "\n".join(f"• {self._upd_items[r].program.name}" for r in rows[:15])
        more = f"\n… e mais {len(rows) - 15}" if len(rows) > 15 else ""
        if not self.confirm(
                f"Atualizar {len(rows)} programa(s)?\n\n{names}{more}\n\n"
                "Cada um é baixado pelo winget e instalado em silêncio, um por vez. Salve o que estiver "
                "aberto e feche esses programas antes.\n\nProgramas instalados para todos os usuários podem "
                "abrir o aviso de permissão do Windows (UAC): confirme nele para continuar."):
            return
        self._apply_rows = rows
        self._apply_started = time.time()
        t = UpdateApplyThread(self._service(), [self._upd_items[r].program for r in rows])
        t.item_started.connect(self._on_apply_started)
        t.item_done.connect(self._on_apply_item)
        t.done.connect(self._on_apply_done)
        t.failed.connect(self._on_apply_failed)
        self._apply_thread = t
        self._set_updating(True)
        self.upd_progress.set_tone("normal")
        self.upd_progress.setRange(0, len(rows))
        self.upd_progress.setValue(0)
        t.start()

    def _row_of(self, pid: str) -> int:
        for r in self._apply_rows:
            if self._upd_items[r].program.id == pid:
                return r
        return -1

    def _on_apply_started(self, program) -> None:
        r = self._row_of(program.id)
        if r >= 0:
            self.tbl_updates.setItem(r, 4, QTableWidgetItem("Atualizando…"))
        self.lbl_upd.setText(f"Atualizando {program.name}…")

    def _on_apply_item(self, res: ApplyResult) -> None:
        r = self._row_of(res.id)
        if r >= 0:
            it = QTableWidgetItem(APPLY_LABEL.get(res.status, res.status))
            it.setToolTip(res.message)
            it.setForeground(QBrush(QColor("#2e7d32" if res.success else "#b71c1c")))
            self.tbl_updates.setItem(r, 4, it)
            if res.success:
                self.tbl_updates.item(r, 0).setCheckState(Qt.CheckState.Unchecked)
        self.upd_progress.setValue(self.upd_progress.value() + 1)

    def _finish_apply_thread(self) -> None:
        t, self._apply_thread = self._apply_thread, None
        if t is not None:
            t.wait()
            t.deleteLater()

    def _on_apply_done(self, results: list[ApplyResult]) -> None:
        self._finish_apply_thread()
        progs = {self._upd_items[r].program.id: self._upd_items[r].program for r in self._apply_rows}
        if results:
            try:
                self._history.append_update(self._apply_started, time.time() - self._apply_started, [
                    {"id": x.id, "nome": x.name, "de": progs[x.id].installed if x.id in progs else "",
                     "para": progs[x.id].available if x.id in progs else "", "resultado": x.status,
                     "mensagem": x.message} for x in results])
            except OSError as e:
                self.notify(f"Não foi possível gravar o histórico: {e}")
        ok = sum(1 for x in results if x.success)
        msg = f"{ok} de {len(results)} programa(s) atualizado(s)."
        if len(results) < len(self._apply_rows):
            msg += f" Interrompido: {len(self._apply_rows) - len(results)} não foram tentados."
        if any(x.status == "fechar" for x in results):
            msg += " Feche os programas indicados e tente de novo."
        self.lbl_upd.setText(msg)
        self._set_updating(False)
        self.refresh_tabs()
        self.statusBar().showMessage(msg)

    def _on_apply_failed(self, exc: object) -> None:
        self._finish_apply_thread()
        self.lbl_upd.setText(f"A atualização falhou: {exc}")
        self._set_updating(False)
