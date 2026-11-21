"""Varredura em segundo plano (nunca na thread da interface)."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from mandacaru_win.scan import scan_paths


class ScanThread(QThread):
    progress = Signal(object, int, int)
    found = Signal(object)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, paths: list[Path], scanner, trusted: set[str]):
        super().__init__()
        self._paths = paths
        self._scanner = scanner
        self._trusted = trusted
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        try:
            summary = scan_paths(
                self._paths, self._scanner, self._trusted,
                on_progress=lambda p, i, n: self.progress.emit(p, i, n),
                on_finding=lambda f: self.found.emit(f),
                should_stop=lambda: self._stop,
            )
        except Exception as e:  # noqa: BLE001 - qualquer falha deve liberar a janela
            self.failed.emit(f"{type(e).__name__}: {e}")
            return
        self.done.emit(summary)
