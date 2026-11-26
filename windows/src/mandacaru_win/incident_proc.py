"""Conter: encerrar um processo do usuário e os filhos dele, só depois de conferir quem ele é.

O número do processo (PID) pode ser reaproveitado pelo Windows. Por isso nada é encerrado sem
antes conferir que o PID ainda roda o mesmo executável, com o mesmo SHA-256 da detecção, e cada
filho só conta se nasceu depois do pai.
"""
from __future__ import annotations

import ntpath
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from mandacaru_win.incident import sha256_arquivo, sha256_valido


class ProcessoMudouError(OSError):
    """O PID já não pertence à mesma instância de processo inspecionada."""


@dataclass(frozen=True)
class ProcessoInfo:
    pid: int
    ppid: int
    exe: str | None
    criado: int | float | None  # ticks de 100 ns desde 1601 (FILETIME); só serve para comparar


class Processos(Protocol):
    def listar(self) -> list[ProcessoInfo]: ...
    def info(self, pid: int) -> ProcessoInfo | None: ...
    def encerrar(self, pid: int, criado: int | float | None) -> None:
        """Encerra o PID só se ele ainda é o processo criado em `criado`; levanta OSError se não der."""


@dataclass
class ResultadoEncerrar:
    encerrados: list[int] = field(default_factory=list)
    falhas: list[tuple[int, str]] = field(default_factory=list)
    recusa: str | None = None


def _mesmo_caminho(a: str | None, b: str | os.PathLike) -> bool:
    return a is not None and ntpath.normcase(a) == ntpath.normcase(os.fspath(b))


def _descendentes(raiz: ProcessoInfo, todos: list[ProcessoInfo]) -> list[ProcessoInfo]:
    """Filhos, netos… em largura. Um "filho" mais antigo que o pai é órfão de um PID reaproveitado."""
    atual_raiz = next((p for p in todos if p.pid == raiz.pid), None)
    if atual_raiz is None or atual_raiz.criado is None or atual_raiz.criado != raiz.criado:
        return []
    filhos: dict[int, list[ProcessoInfo]] = {}
    for p in todos:
        filhos.setdefault(p.ppid, []).append(p)
    vistos = {raiz.pid}
    fila, saida = [raiz], []
    while fila:
        pai = fila.pop(0)
        for f in filhos.get(pai.pid, []):
            if f.pid in vistos or f.criado is None or pai.criado is None or f.criado < pai.criado:
                continue
            vistos.add(f.pid)
            saida.append(f)
            fila.append(f)
    return saida


def encerrar_arvore(processos: Processos, pid: int, exe_esperado: str | os.PathLike, sha256: str, *,
                    hash_fn: Callable[[Path], str | None] = sha256_arquivo,
                    proprio_pid: int | None = None) -> ResultadoEncerrar:
    if not sha256_valido(sha256):
        return ResultadoEncerrar(recusa="SHA-256 inválido para confirmar o processo; nada foi encerrado.")
    proprio = os.getpid() if proprio_pid is None else proprio_pid
    if pid <= 4 or pid == proprio:
        return ResultadoEncerrar(recusa="Processo do sistema ou do próprio Mandacaru: não será encerrado.")
    # Um único snapshot para inspecionar o alvo e a árvore de filhos sem deriva entre duas listagens.
    todos = processos.listar()
    alvo = next((p for p in todos if p.pid == pid), None)
    if alvo is None:
        return ResultadoEncerrar(recusa="O processo já terminou.")
    if not _mesmo_caminho(alvo.exe, exe_esperado):
        return ResultadoEncerrar(
            recusa="O número do processo agora pertence a outro programa; nada foi encerrado.")
    atual_sha = hash_fn(Path(alvo.exe))
    if not isinstance(atual_sha, str) or atual_sha.lower() != sha256.lower():
        return ResultadoEncerrar(recusa="O executável mudou desde a detecção; nada foi encerrado.")
    # O alvo primeiro: assim ele não recria os filhos enquanto eles são encerrados.
    r = ResultadoEncerrar()
    for p in [alvo, *_descendentes(alvo, todos)]:
        if p.pid <= 4 or p.pid == proprio:
            continue
        try:
            processos.encerrar(p.pid, p.criado)
        except ProcessoMudouError as e:
            r.falhas.append((p.pid, str(e)))
            if p.pid == alvo.pid:
                break
        except OSError as e:
            r.falhas.append((p.pid, e.strerror or str(e)))
        else:
            r.encerrados.append(p.pid)
    return r


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _TH32CS_SNAPPROCESS = 0x2
    _PROCESS_TERMINATE = 0x0001
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _INVALIDO = wintypes.HANDLE(-1).value

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _k32.Process32FirstW.restype = wintypes.BOOL
    _k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _k32.Process32NextW.restype = wintypes.BOOL
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                ctypes.POINTER(wintypes.DWORD)]
    _k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    _k32.GetProcessTimes.restype = wintypes.BOOL
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateProcess.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL

    def _erro() -> OSError:
        n = ctypes.get_last_error()
        return OSError(n, ctypes.FormatError(n).strip())

    def _criado(h) -> int | None:
        c, x, k, u = (wintypes.FILETIME() for _ in range(4))
        if not _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(x), ctypes.byref(k), ctypes.byref(u)):
            return None
        return (c.dwHighDateTime << 32) | c.dwLowDateTime

    def _exe(h) -> str | None:
        buf = ctypes.create_unicode_buffer(32768)
        n = wintypes.DWORD(len(buf))
        if not _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
            return None
        return buf.value

    class ProcessosWindows:
        """Processos reais via kernel32 (sem psutil e sem privilégio de administrador)."""

        def listar(self) -> list[ProcessoInfo]:
            snap = _k32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
            if snap == _INVALIDO or not snap:
                raise _erro()
            pares: list[tuple[int, int]] = []
            try:
                e = _PROCESSENTRY32W()
                e.dwSize = ctypes.sizeof(e)
                ok = _k32.Process32FirstW(snap, ctypes.byref(e))
                while ok:
                    pares.append((e.th32ProcessID, e.th32ParentProcessID))
                    ok = _k32.Process32NextW(snap, ctypes.byref(e))
            finally:
                _k32.CloseHandle(snap)
            saida = []
            for pid, ppid in pares:
                exe = criado = None
                h = _k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if h:
                    try:
                        exe, criado = _exe(h), _criado(h)
                    finally:
                        _k32.CloseHandle(h)
                saida.append(ProcessoInfo(pid, ppid, exe, criado))
            return saida

        def info(self, pid: int) -> ProcessoInfo | None:
            return next((p for p in self.listar() if p.pid == pid), None)

        def encerrar(self, pid: int, criado: int | float | None) -> None:
            # Um único handle: confere a hora de criação e encerra o MESMO processo.
            h = _k32.OpenProcess(_PROCESS_TERMINATE | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                raise _erro()
            try:
                if criado is None or _criado(h) != criado:
                    raise ProcessoMudouError("O processo mudou desde a detecção; não foi encerrado.")
                if not _k32.TerminateProcess(h, 1):
                    raise _erro()
            finally:
                _k32.CloseHandle(h)
