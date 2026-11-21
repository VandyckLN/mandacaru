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


def list_files(paths: list[Path], scanner: StaticScanner) -> list[Path]:
    found: list[Path] = []
    for p in paths:
        root = Path(os.path.abspath(p))
        if root.is_file():
            found.append(root)
            continue
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [
                d for d in dirnames
                if d not in SKIP_DIRS
                and not scanner.is_excluded(Path(dirpath) / d)
                and not _is_link(os.path.join(dirpath, d))
            ]
            for name in filenames:
                f = Path(dirpath) / name
                try:
                    if is_cloud_only(os.stat(f)):
                        continue
                except OSError:
                    continue
                found.append(f)
    return list(dict.fromkeys(found))


def scan_paths(
    paths: list[Path],
    scanner: StaticScanner,
    trusted: set[str],
    on_progress: Callable[[Path, int, int], None],
    on_finding: Callable[[Finding], None],
    should_stop: Callable[[], bool],
) -> ScanSummary:
    started = time.time()
    files = list_files(paths, scanner)
    total = len(files)
    scanned = findings = 0
    completed = True
    for i, f in enumerate(files, 1):
        if should_stop():
            completed = False
            break
        alerts = [a for a in scanner.scan_file(f) if a.severity > Severity.INFO]
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
