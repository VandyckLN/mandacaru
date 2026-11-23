"""Faixa "versão nova disponível" e as threads de consulta/download da autoatualização."""
from __future__ import annotations

import time
import urllib.request
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton

from mandacaru_win import __version__, updater
from mandacaru_win.theme import style_button
from mandacaru_win.widgets import MandacaruProgressBar


class UpdateCheckThread(QThread):
    done = Signal(object)  # updater.CheckResult

    def __init__(self, data: Path, http, now, force: bool):
        super().__init__()
        self._args = (data, http, now, force)

    def run(self) -> None:
        data, http, now, force = self._args
        try:
            res = updater.check(data, __version__, http=http, now=now, force=force)
        except Exception:  # noqa: BLE001 - consulta nunca derruba a janela
            res = updater.CheckResult(None, "falha")
        self.done.emit(res)


class UpdateDownloadThread(QThread):
    progress = Signal(int, int)  # baixados, total (0 = desconhecido)
    done = Signal(object)  # Path do setup conferido
    failed = Signal(str)

    def __init__(self, update: updater.Update, data: Path, http):
        super().__init__()
        self._update, self._data, self._http = update, data, http
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        try:
            path = updater.download(
                self._update, self._data, http=self._http,
                on_progress=lambda got, total: self.progress.emit(got, total or 0),
                should_stop=lambda: self._stop)
        except updater.UpdateError as e:
            self.failed.emit(str(e))
            return
        except Exception as e:  # noqa: BLE001 - qualquer falha deve liberar a faixa
            self.failed.emit(f"Não foi possível baixar a atualização: {type(e).__name__}: {e}")
            return
        self.done.emit(path)


class UpdateBar(QFrame):
    """Faixa no topo da janela; escondida até existir versão nova."""

    checked = Signal(object)  # CheckResult, depois de cada consulta
    quit_requested = Signal()  # setup iniciado: a janela deve fechar

    def __init__(self, data: Path, notify: Callable[[str], None],
                 status: Callable[[str], None], parent=None):
        super().__init__(parent)
        self._data = Path(data)
        self.notify = notify
        self.status = status
        # pontos de injeção para testes
        self.http = urllib.request.urlopen
        self.now: Callable[[], float] = time.time
        self.runner = updater._default_runner
        self.pending: updater.Update | None = None
        self._check: UpdateCheckThread | None = None
        self._download: UpdateDownloadThread | None = None
        self._manual = False

        self.setObjectName("faixaAtualizacao")
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 6, 10, 6)
        self.label = QLabel("")
        self.progress = MandacaruProgressBar(height=10, show_text=False)
        self.progress.setFixedWidth(140)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        self.btn_update = style_button(QPushButton("Atualizar agora"), "scan", compact=True)
        self.btn_later = style_button(QPushButton("Depois"), "neutral", compact=True)
        self.btn_update.clicked.connect(self.start_update)
        self.btn_later.clicked.connect(self.later)
        row.addWidget(self.label, 1)
        row.addWidget(self.progress)
        row.addWidget(self.btn_update)
        row.addWidget(self.btn_later)
        self.setVisible(False)

    # ---------- consulta ----------
    def start_check(self, force: bool = False) -> bool:
        """Consulta em thread. False se já há consulta ou download em andamento."""
        if self._check is not None or self._download is not None:
            return False
        self._manual = force
        if force:
            self.status("Verificando atualizações…")
        t = UpdateCheckThread(self._data, self.http, self.now, force)
        t.done.connect(self._on_checked)
        self._check = t
        t.start()
        return True

    def _on_checked(self, res: updater.CheckResult) -> None:
        t, self._check = self._check, None
        if t is not None:
            t.wait()
            t.deleteLater()
        if res.update is not None:
            self.show_update(res.update)
        elif self._manual:
            if res.reason == "falha":
                det = f" ({res.detail})" if res.detail else ". Verifique a conexão."
                self.status(f"Não foi possível verificar atualizações agora{det}")
            else:
                self.status(f"Você já tem a versão mais recente ({__version__}).")
        self.checked.emit(res)

    def show_update(self, update: updater.Update) -> None:
        self.pending = update
        self.label.setText(f"Mandacaru {update.version} disponível (você tem {update.current}).")
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        self._set_busy(False)
        self.setVisible(True)

    def later(self) -> None:
        if self.pending is not None:
            updater.snooze(self._data, self.pending.version, self.now)
        self.setVisible(False)

    # ---------- download e instalação ----------
    def _set_busy(self, on: bool) -> None:
        self.btn_update.setEnabled(not on)
        self.btn_later.setEnabled(not on)

    def start_update(self) -> None:
        if self.pending is None or self._download is not None:
            return
        self._set_busy(True)
        self.label.setText(f"Baixando Mandacaru {self.pending.version}…")
        self.progress.set_tone("normal")
        self.progress.setRange(0, 0)
        self.progress.setVisible(True)
        t = UpdateDownloadThread(self.pending, self._data, self.http)
        t.progress.connect(self._on_progress)
        t.done.connect(self._on_downloaded)
        t.failed.connect(self._on_failed)
        self._download = t
        t.start()

    def _release_download(self) -> None:
        t, self._download = self._download, None
        if t is not None:
            t.wait()
            t.deleteLater()

    def _on_progress(self, got: int, total: int) -> None:
        if self.pending is None:
            return
        if total > 0:
            self.progress.setRange(0, total)
            self.progress.setValue(min(got, total))
        pct = f" {got * 100 // total}%" if total else f" {got // (1024 * 1024)} MB"
        self.label.setText(f"Baixando Mandacaru {self.pending.version}…{pct}")

    def _on_failed(self, msg: str) -> None:
        self._release_download()
        if self.pending is not None:
            self.show_update(self.pending)
        self.notify(msg)

    def _on_downloaded(self, setup: Path) -> None:
        self._release_download()
        self.label.setText("Instalando… o Mandacaru vai reabrir sozinho.")
        try:
            updater.run_installer(setup, self.runner)
        except updater.UpdateError as e:
            self._on_failed(str(e))
            return
        self.quit_requested.emit()

    def shutdown(self) -> None:
        """Chamado ao fechar a janela: espera as threads (QThread viva ao destruir derruba o app)."""
        if self._download is not None:
            self._download.stop()
            self._download.wait()
        if self._check is not None:
            self._check.wait()
