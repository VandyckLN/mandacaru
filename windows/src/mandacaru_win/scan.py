# Mandacaru - antivirus/EDR de codigo aberto contra ataques conduzidos por IA.
# Copyright (C) 2026  Vandyck Diniz
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version. See the LICENSE file.
"""Núcleo da varredura: lista arquivos, roda o StaticScanner e agrupa por arquivo."""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from mandacaru import ml
from mandacaru.detectors.static import StaticScanner
from mandacaru.events import Alert, Severity

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}
# RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE: arquivo só na nuvem
CLOUD_ATTRS = 0x00400000 | 0x00040000 | 0x00001000

_isjunction = getattr(os.path, "isjunction", lambda _: False)


@dataclass
class Finding:
    path: Path
    sha256: str
    severity: Severity
    alerts: list[Alert]


@dataclass
class ScanSummary:
    started: float
    paths: list[str]
    files: int
    findings: int
    duration: float
    completed: bool


def make_scanner() -> StaticScanner:
    return StaticScanner(classifier=ml.load_default("alert").classifier)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def is_cloud_only(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & CLOUD_ATTRS)


def _is_link(path: str) -> bool:
    return os.path.islink(path) or _isjunction(path)


def _own_dirs() -> tuple[str, ...]:
    """Pastas do próprio Mandacaru: as regras YARA contêm os textos que elas procuram e se acusariam."""
    import sys

    import mandacaru

    dirs = [Path(mandacaru.__file__).parent, Path(__file__).parent]
    if getattr(sys, "frozen", False):
        dirs.append(Path(sys.executable).parent)
    return tuple(os.path.normcase(os.path.abspath(d)) for d in dirs)


def _is_own(path: str | os.PathLike, own: tuple[str, ...]) -> bool:
    p = os.path.normcase(os.path.abspath(path))
    return any(p == d or p.startswith(d + os.sep) for d in own)


def list_files(
    paths: list[Path],
    scanner: StaticScanner,
    should_stop: Callable[[], bool] | None = None,
    on_listing: Callable[[int], None] | None = None,
) -> list[Path]:
    """Lista os arquivos a varrer. `should_stop` é checado a cada pasta."""
    stop = should_stop or (lambda: False)
    own = _own_dirs()
    found: list[Path] = []
    for p in paths:
        root = Path(os.path.abspath(p))
        if _is_own(root, own):
            continue
        if root.is_file():
            found.append(root)
            continue
        if not root.is_dir():
            continue
        stack = [str(root)]
        while stack:
            if stop():
                return list(dict.fromkeys(found))
            current = stack.pop()
            try:
                entries = list(os.scandir(current))
            except OSError:
                continue
            subdirs: list[str] = []
            for e in entries:
                try:
                    if e.is_dir():
                        if (e.name not in SKIP_DIRS
                                and not _is_own(e.path, own)
                                and not scanner.is_excluded(Path(e.path))
                                and not _is_link(e.path)):
                            subdirs.append(e.path)
                        continue
                    if is_cloud_only(e.stat()):
                        continue
                except OSError:
                    continue
                found.append(Path(e.path))
            stack.extend(reversed(subdirs))
            if on_listing is not None:
                on_listing(len(found))
    return list(dict.fromkeys(found))


def scan_paths(
    paths: list[Path],
    scanner: StaticScanner,
    trusted: set[str] | frozenset[str],
    on_progress: Callable[[Path, int, int], None],
    on_finding: Callable[[Finding], None],
    should_stop: Callable[[], bool],
    on_listing: Callable[[int], None] | None = None,
) -> ScanSummary:
    started = time.time()
    files = list_files(paths, scanner, should_stop, on_listing)
    total = len(files)
    scanned = findings = 0
    completed = not should_stop()  # parado durante a listagem
    for i, f in enumerate(files if completed else [], 1):
        if should_stop():
            completed = False
            break
        try:
            alerts = [a for a in scanner.scan_file(f) if a.severity > Severity.INFO]
        except Exception:  # noqa: BLE001 - um arquivo problemático não derruba a varredura
            alerts = []
        scanned += 1
        on_progress(f, i, total)
        if not alerts:
            continue
        try:
            digest = sha256_file(f)
        except OSError:
            continue
        if digest in trusted:
            continue
        findings += 1
        on_finding(Finding(f, digest, max(a.severity for a in alerts), alerts))
    return ScanSummary(started, [str(p) for p in paths], scanned, findings,
                       time.time() - started, completed)
