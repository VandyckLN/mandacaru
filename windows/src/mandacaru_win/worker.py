"""Varredura em segundo plano (nunca na thread da interface)."""
from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from mandacaru_win.scan import scan_paths


class ScanThread(QThread):
    listing = Signal(int)
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
        self._last_progress = self._last_listing = 0.0

    def stop(self) -> None:
        self._stop = True

    def _emit_progress(self, p: Path, i: int, n: int) -> None:
        # No máximo ~20 sinais por segundo (o último sempre passa).
        now = time.monotonic()
        if i == n or now - self._last_progress >= 0.05:
            self._last_progress = now
            self.progress.emit(p, i, n)

    def _emit_listing(self, count: int) -> None:
        now = time.monotonic()
        if now - self._last_listing >= 0.05:
            self._last_listing = now
            self.listing.emit(count)

    def run(self) -> None:
        self._last_progress = self._last_listing = 0.0
        try:
            summary = scan_paths(
                self._paths, self._scanner, self._trusted,
                on_progress=self._emit_progress,
                on_finding=lambda f: self.found.emit(f),
                should_stop=lambda: self._stop,
                on_listing=self._emit_listing,
            )
        except Exception as e:  # noqa: BLE001 - qualquer falha deve liberar a janela
            self.failed.emit(f"{type(e).__name__}: {e}")
            return
        self.done.emit(summary)
