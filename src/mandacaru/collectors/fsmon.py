"""Coletor de arquivos (watchdog: inotify no Linux, ReadDirectoryChangesW no Windows)."""
from __future__ import annotations

import queue
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ..detectors.static import shannon_entropy
from ..events import Event

SAMPLE = 4096


def sample_entropy(path: str) -> float | None:
    try:
        with open(path, "rb") as fh:
            data = fh.read(SAMPLE)
        return shannon_entropy(data) if len(data) >= 512 else None
    except OSError:
        return None


class _Handler(FileSystemEventHandler):
    def __init__(self, out: queue.Queue):
        self.out = out

    def _emit(self, kind: str, path: str, **extra):
        self.out.put(Event(kind, {"path": path, "entropy": sample_entropy(extra.get("dest", path)), **extra},
                           source="fsmon"))

    def on_created(self, e: FileSystemEvent):
        if not e.is_directory:
            self._emit("file_create", e.src_path)

    def on_modified(self, e: FileSystemEvent):
        if not e.is_directory:
            self._emit("file_write", e.src_path)

    def on_moved(self, e: FileSystemEvent):
        if not e.is_directory:
            self._emit("file_rename", e.src_path, dest=e.dest_path)


class FileMonitor:
    def __init__(self, paths: list[str], out: queue.Queue):
        self.observer = Observer()
        handler = _Handler(out)
        for p in paths:
            if Path(p).exists():
                self.observer.schedule(handler, p, recursive=True)

    def start(self):
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=3)
