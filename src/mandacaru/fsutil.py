"""Escrita e leitura seguras em pastas que outro usuario pode controlar (troca entre root e _mandacaru-net)."""
from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path


def atomic_write_text(path: Path | str, text: str, mode: int = 0o644) -> None:
    """Grava via temporario exclusivo + rename. O rename troca o destino sem segui-lo: um symlink plantado
    no lugar do arquivo e substituido, nunca usado para escrever em outro lugar."""
    final = Path(path)
    tmp = final.with_name(f".{final.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        try:
            os.fchmod(fd, mode)
            data = text.encode("utf-8")
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, final)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_text_nofollow(path: Path | str, max_bytes: int = 1024 * 1024) -> str:
    """Le um arquivo regular sem seguir symlink e com limite de tamanho (ValueError se passar)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise ValueError(f"{path}: nao e um arquivo regular")
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{path}: maior que {max_bytes} bytes")
    return data.decode("utf-8")
