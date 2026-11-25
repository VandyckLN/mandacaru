"""Percurso de um projeto e leitura segura de arquivos de texto."""
from __future__ import annotations

import fnmatch
import os
import stat
from collections.abc import Callable, Iterable
from pathlib import Path

PULAR: frozenset[str] = frozenset({
    "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next", "site-packages",
})
MAX_BYTES = 2 * 1024 * 1024
MAX_ARQUIVOS = 20_000
_SONDA_BINARIO = 8 * 1024


def listar(
    raiz: Path,
    excluir: Callable[[Path], bool] = lambda p: False,
    limite: int = MAX_ARQUIVOS,
    deve_parar: Callable[[], bool] = lambda: False,
) -> tuple[list[str], bool]:
    """Lista arquivos regulares (caminhos relativos com `/`), sem seguir links.

    Devolve (rels ordenados, cortado); `cortado` indica que parou por limite ou cancelamento.
    """
    raiz = Path(raiz)
    rels: list[str] = []
    cortado = False
    ignorar = PULAR | {".git"}
    for dirpath, dirnames, filenames in os.walk(raiz, followlinks=False):
        if deve_parar():
            cortado = True
            break
        atual = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in ignorar and not excluir(atual / d))
        for nome in sorted(filenames):
            alvo = atual / nome
            if alvo.is_symlink() or excluir(alvo):
                continue
            if len(rels) >= limite:
                cortado = True
                break
            rels.append(alvo.relative_to(raiz).as_posix())
        if cortado:
            break
    return sorted(rels), cortado


def ler_texto(caminho: Path) -> str | None:
    """Le ate MAX_BYTES sem seguir link; None se link, nao-arquivo ou binario (NUL)."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        if not hasattr(os, "O_NOFOLLOW") and Path(caminho).is_symlink():
            return None
        fd = os.open(caminho, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, "rb", closefd=False) as fh:
                dados = fh.read(MAX_BYTES)
        finally:
            os.close(fd)
    except OSError:
        return None
    if b"\x00" in dados[:_SONDA_BINARIO]:
        return None
    return dados.decode("utf-8-sig", errors="replace")


def linha_de(texto: str, pos: int) -> int:
    """Linha 1-based da posicao `pos`; `\\r\\n` conta como uma quebra."""
    return texto.count("\n", 0, pos) + 1


def linha_do_trecho(texto: str, trecho: str) -> int | None:
    """Linha da primeira ocorrencia de `trecho`, ou None."""
    pos = texto.find(trecho)
    return None if pos < 0 else linha_de(texto, pos)


def excluir_por_globs(globs: Iterable[str]) -> Callable[[Path], bool]:
    """Mesma semantica de StaticScanner.is_excluded: o caminho absoluto ou uma pasta-mae casa."""
    padroes = [g.rstrip("/") or "/" for g in globs]

    def excluir(caminho: Path) -> bool:
        if not padroes:
            return False
        completo = Path(os.path.abspath(caminho))
        candidatos = [str(completo), *(str(p) for p in completo.parents)]
        return any(fnmatch.fnmatchcase(c, pat) for c in candidatos for pat in padroes)

    return excluir
