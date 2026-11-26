"""Destruição segura (shred): sobrescreve com dados aleatórios, renomeia e apaga.

Impede a restauração pela Lixeira ou por ferramentas comuns de recuperação.
Em SSDs modernos (wear leveling), a sobrescrita ainda dificulta bastante a
recuperação, embora o controlador possa manter cópias antigas em blocos livres.
"""
from __future__ import annotations

import os
import secrets
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

CHUNK = 1024 * 1024
_isjunction = getattr(os.path, "isjunction", lambda _: False)


class ShredError(Exception):
    """Erro com mensagem em português pronta para exibir na interface."""


@dataclass
class ShredSummary:
    target: str
    files_shredded: int
    dirs_removed: int
    errors: list[str]
    completed: bool


def _is_link(path: str | os.PathLike) -> bool:
    p = str(path)
    return os.path.islink(p) or _isjunction(p)


def _protected_dirs() -> set[str]:
    """Diretórios críticos que nunca podem ser destruídos por acidente."""
    protected: set[str] = {
        os.path.normcase(os.path.abspath(os.sep)),
        os.path.normcase(os.path.abspath(Path.home())),
    }
    if sys.platform == "win32":
        for var in ("WINDIR", "SystemRoot", "ProgramFiles", "ProgramFiles(x86)",
                    "ProgramData", "USERPROFILE", "SystemDrive"):
            val = os.environ.get(var)
            if val:
                p = val + "\\" if len(val) == 2 and val[1] == ":" else val
                protected.add(os.path.normcase(os.path.abspath(p)))
    else:
        for p in ("/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/proc",
                  "/root", "/sbin", "/sys", "/usr", "/var"):
            protected.add(os.path.normcase(os.path.abspath(p)))
    return protected


def _assert_safe_target(target: Path) -> None:
    resolved = os.path.normcase(os.path.abspath(target))
    # Raiz de unidade (ex.: C:\ ou /)
    if Path(resolved).parent == Path(resolved):
        raise ShredError("Por segurança, não é permitido destruir a raiz de uma unidade.")
    if resolved in _protected_dirs():
        raise ShredError("Por segurança, não é permitido destruir esta pasta do sistema ou do usuário.")


def _make_writable(path: Path) -> None:
    try:
        mode = stat.S_IMODE(os.lstat(path).st_mode)
        if not (mode & stat.S_IWRITE):
            os.chmod(path, mode | stat.S_IWRITE)
    except OSError:
        pass


def _random_rename(path: Path) -> Path:
    """Renomeia para um nome aleatório no mesmo diretório para ofuscar o nome original."""
    for _ in range(5):
        candidate = path.with_name(f".{secrets.token_hex(12)}.del")
        if candidate.exists():
            continue
        try:
            os.replace(path, candidate)
            return candidate
        except OSError:
            return path
    return path


def shred_file(path: Path, passes: int = 1) -> None:
    """Sobrescreve o conteúdo do arquivo com bytes aleatórios, trunca, renomeia e remove."""
    p = Path(path)
    if _is_link(p):
        os.unlink(p)
        return
    if not p.exists():
        raise ShredError(f"Arquivo não encontrado: {p}")
    if not p.is_file():
        raise ShredError(f"Não é um arquivo comum: {p}")

    # Hard link: o mesmo conteúdo tem outro nome, possivelmente fora da pasta destruída. Sobrescrever
    # apagaria o arquivo do outro lado (ex.: um AGENTS.md ligado à tese do usuário). Só desvincula.
    try:
        outros_nomes = os.lstat(p).st_nlink > 1
    except OSError as exc:
        raise ShredError(f"Não foi possível examinar {p.name}: {exc}") from exc
    if outros_nomes:
        try:
            os.unlink(p)
        except OSError as exc:
            raise ShredError(f"Não foi possível remover {p.name}: {exc}") from exc
        return

    _make_writable(p)
    try:
        size = p.stat().st_size
        with open(p, "r+b", buffering=0) as fh:
            for step in range(max(1, passes)):
                fh.seek(0)
                remaining = size
                while remaining > 0:
                    n = min(CHUNK, remaining)
                    # último passo (quando passes > 1) zera; caso contrário, bytes aleatórios
                    buf = b"\x00" * n if (passes > 1 and step == passes - 1) else os.urandom(n)
                    fh.write(buf)
                    remaining -= n
                fh.flush()
                os.fsync(fh.fileno())
            fh.seek(0)
            fh.truncate(0)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise ShredError(f"Não foi possível sobrescrever {p.name}: {exc}") from exc

    renamed = _random_rename(p)
    try:
        os.unlink(renamed)
    except OSError as exc:
        raise ShredError(f"Não foi possível remover {p.name}: {exc}") from exc


def shred_path(
    target: Path,
    passes: int = 1,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[Path, int, int], None] | None = None,
) -> ShredSummary:
    """Destrói definitivamente um arquivo ou uma pasta inteira (sem seguir symlinks/junções)."""
    p = Path(os.path.abspath(target))
    stop = should_stop or (lambda: False)
    if not p.exists() and not _is_link(p):
        raise ShredError(f"Caminho não encontrado: {p}")
    _assert_safe_target(p)

    if _is_link(p) or p.is_file():
        if on_progress:
            on_progress(p, 0, 1)
        shred_file(p, passes=passes)
        if on_progress:
            on_progress(p, 1, 1)
        return ShredSummary(str(p), files_shredded=1, dirs_removed=0, errors=[], completed=True)

    if not p.is_dir():
        raise ShredError(f"Tipo de caminho não suportado: {p}")

    # 1) Coleta arquivos e subpastas de baixo para cima, sem seguir links/junções.
    files: list[Path] = []
    dirs: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(p, topdown=True, followlinks=False):
        # links/junções de pasta são removidos como link, sem entrar neles
        keep_dirs: list[str] = []
        for dname in dirnames:
            dpath = Path(dirpath) / dname
            if _is_link(dpath):
                files.append(dpath)
            else:
                keep_dirs.append(dname)
        dirnames[:] = keep_dirs
        for fname in filenames:
            files.append(Path(dirpath) / fname)
        dirs.append(Path(dirpath))

    total = len(files)
    shredded = 0
    errors: list[str] = []
    completed = True

    for i, f in enumerate(files, 1):
        if stop():
            completed = False
            break
        try:
            shred_file(f, passes=passes)
            shredded += 1
        except (ShredError, OSError) as exc:
            errors.append(str(exc))
        if on_progress:
            on_progress(f, i, total)

    removed_dirs = 0
    if completed:
        # Remove subpastas da mais profunda até a raiz alvo, renomeando antes.
        for d in sorted(dirs, key=lambda x: len(x.parts), reverse=True):
            if stop():
                completed = False
                break
            _make_writable(d)
            renamed = _random_rename(d)
            try:
                os.rmdir(renamed)
                removed_dirs += 1
            except OSError as exc:
                errors.append(f"Não foi possível remover pasta {d.name}: {exc}")

    return ShredSummary(str(p), files_shredded=shredded, dirs_removed=removed_dirs,
                        errors=errors, completed=completed)
