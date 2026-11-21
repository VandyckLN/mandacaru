"""Varredura em segundo plano (nunca na thread da interface)."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from mandacaru_win.scan import scan_paths


class ScanThread(QThread):
    progress = Signal(object, int, int)
    found = Signal(object)
    done = Signal(object)

    def __init__(self, paths: list[Path], scanner, trusted: set[str]):
        super().__init__()
        self._paths = paths
        self._scanner = scanner
        self._trusted = trusted
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        summary = scan_paths(
            self._paths, self._scanner, self._trusted,
            on_progress=lambda p, i, n: self.progress.emit(p, i, n),
            on_finding=lambda f: self.found.emit(f),
            should_stop=lambda: self._stop,
        )
        self.done.emit(summary)
