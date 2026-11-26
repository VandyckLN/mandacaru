"""Varredura e atualizações em segundo plano (nunca na thread da interface)."""
from __future__ import annotations

import hashlib
import os
import stat
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from mandacaru.analysis import AnalysisResult, analyze
from mandacaru.config import Config
from mandacaru.projeto import verificar_projeto
from mandacaru.vuln import KevCache, OsvClient
from mandacaru_win.scan import scan_paths
from mandacaru_win.shred import shred_path


class ScanThread(QThread):
    listing = Signal(int)
    progress = Signal(object, int, int)
    found = Signal(object)
    done = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        paths: list[Path],
        scanner,
        trusted: set[str],
        exclude: Iterable[str] = (),
        batch_size: int = 0,
        batch_pause_s: float = 0.0,
    ):
        super().__init__()
        self._paths = paths
        self._scanner = scanner
        self._trusted = trusted
        self._exclude = tuple(exclude)
        self._batch_size = batch_size
        self._batch_pause_s = batch_pause_s
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
                exclude=self._exclude,
                batch_size=self._batch_size,
                batch_pause_s=self._batch_pause_s,
            )
        except Exception as e:  # noqa: BLE001 - qualquer falha deve liberar a janela
            self.failed.emit(f"{type(e).__name__}: {e}")
            return
        self.done.emit(summary)


_CRIAR = object()  # osv/kev não injetados: o thread cria os clientes com cache em disco


def sha256_sem_seguir(caminho: Path) -> str | None:
    """SHA-256 de um arquivo regular sem seguir link; None se não der para ler."""
    try:
        if not hasattr(os, "O_NOFOLLOW") and Path(caminho).is_symlink():
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(caminho, flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            h = hashlib.sha256()
            while chunk := fh.read(1024 * 1024):
                h.update(chunk)
            return h.hexdigest()
    except OSError:
        return None


class ProjetoThread(QThread):
    """Verificar projeto fora da thread da interface.

    Depois de `done`, `hashes` tem o SHA-256 de cada arquivo com achado (caminho relativo -> sha ou None),
    calculado aqui para não travar a janela em projetos grandes.
    """

    progress = Signal(int, int)
    consultando = Signal(int)
    done = Signal(object)    # RelatorioProjeto
    failed = Signal(str)

    def __init__(self, raiz: Path, cache_dir: Path, excluir: Callable[[Path], bool],
                 osv=_CRIAR, kev=_CRIAR):
        super().__init__()
        self._raiz = Path(raiz)
        self._cache_dir = Path(cache_dir)
        self._excluir = excluir
        self._osv = osv
        self._kev = kev
        self._stop = False
        self._last_progress = 0.0
        self.hashes: dict[str, str | None] = {}

    def stop(self) -> None:
        self._stop = True

    def _emit_progress(self, i: int, n: int) -> None:
        # No máximo ~20 sinais por segundo (o último sempre passa), como ScanThread.
        now = time.monotonic()
        if i == n or now - self._last_progress >= 0.05:
            self._last_progress = now
            self.progress.emit(i, n)

    def run(self) -> None:
        self._last_progress = 0.0
        try:
            # Clientes criados aqui: as conexões SQLite do cache ficam na thread que as usa.
            osv = OsvClient(cache_db=self._cache_dir / "osv.db") if self._osv is _CRIAR else self._osv
            kev = KevCache(cache_db=self._cache_dir / "kev.db") if self._kev is _CRIAR else self._kev
            relatorio = verificar_projeto(
                self._raiz, osv=osv, kev=kev, excluir=self._excluir,
                ao_progresso=self._emit_progress,
                ao_consultar=lambda n: self.consultando.emit(n),
                deve_parar=lambda: self._stop,
            )
            for a in relatorio.achados:
                if a.caminho not in self.hashes:
                    self.hashes[a.caminho] = sha256_sem_seguir(self._raiz / a.caminho)
        except Exception as e:  # noqa: BLE001 - qualquer falha deve liberar a janela
            self.failed.emit(f"{type(e).__name__}: {e}")
            return
        self.done.emit(relatorio)


class HashAnalysisThread(QThread):
    """Consulta reputação de um SHA-256 fora da thread da interface (só o hash sai da máquina)."""

    done = Signal(str, str, object)  # (nome_arquivo, sha256, AnalysisResult)
    failed = Signal(str, str)        # (nome_arquivo, erro)

    def __init__(self, sha256: str, label: str, analyzer: Callable[[str], AnalysisResult] | None = None):
        super().__init__()
        self._sha256 = sha256
        self._label = label
        self._analyzer = analyzer

    def run(self) -> None:
        try:
            fn = self._analyzer or (lambda h: analyze(h[:12], h, Config()))
            result = fn(self._sha256)
        except Exception as e:  # noqa: BLE001 - falha na rede/consulta nunca trava a janela
            self.failed.emit(self._label, f"{type(e).__name__}: {e}")
            return
        self.done.emit(self._label, self._sha256, result)


class ShredThread(QThread):
    """Destruição segura de arquivo ou pasta fora da thread da interface."""

    progress = Signal(object, int, int)
    done = Signal(object)    # ShredSummary
    failed = Signal(str)

    def __init__(self, target: Path, passes: int = 1):
        super().__init__()
        self._target = Path(target)
        self._passes = passes
        self._stop = False
        self._last = 0.0

    def stop(self) -> None:
        self._stop = True

    def _emit_progress(self, p: Path, i: int, n: int) -> None:
        now = time.monotonic()
        if i == n or now - self._last >= 0.05:
            self._last = now
            self.progress.emit(p, i, n)

    def run(self) -> None:
        self._last = 0.0
        try:
            summary = shred_path(
                self._target,
                passes=self._passes,
                should_stop=lambda: self._stop,
                on_progress=self._emit_progress,
            )
        except Exception as e:  # noqa: BLE001
            self.failed.emit(str(e))
            return
        self.done.emit(summary)


class UpdateCheckThread(QThread):
    """Verificação rápida ou completa da aba Atualizações (winget/KEV/NVD)."""

    progress = Signal(str, int, int)
    done = Signal(object)    # CheckResult
    failed = Signal(object)  # a exceção (WingetUnavailable muda a mensagem)

    def __init__(self, service, complete: bool):
        super().__init__()
        self._service = service
        self._complete = complete
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        fn = self._service.complete if self._complete else self._service.quick
        try:
            result = fn(on_progress=lambda t, i, n: self.progress.emit(t, i, n), should_stop=lambda: self._stop)
        except Exception as e:  # noqa: BLE001 - qualquer falha deve liberar a aba
            self.failed.emit(e)
            return
        self.done.emit(result)


class UpdateApplyThread(QThread):
    """Roda `winget upgrade` para os programas marcados, um por vez."""

    item_started = Signal(object)  # Program
    item_done = Signal(object)     # ApplyResult
    done = Signal(object)          # list[ApplyResult]
    failed = Signal(object)

    def __init__(self, service, programs: list):
        super().__init__()
        self._service = service
        self._programs = programs
        self._stop = False

    def stop(self) -> None:
        self._stop = True  # para antes do próximo programa (o atual termina)

    def run(self) -> None:
        try:
            results = self._service.apply(self._programs, on_result=self.item_done.emit,
                                          should_stop=lambda: self._stop, on_start=self.item_started.emit)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(e)
            return
        self.done.emit(results)
