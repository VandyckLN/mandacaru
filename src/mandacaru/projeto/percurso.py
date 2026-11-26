"""Percurso de um projeto e leitura segura de arquivos de texto."""
from __future__ import annotations

import fnmatch
import os
import stat
from bisect import bisect_left
from collections.abc import Callable, Iterable
from pathlib import Path

PULAR: frozenset[str] = frozenset({
    "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
})
MAX_BYTES = 2 * 1024 * 1024
MAX_ARQUIVOS = 20_000
MAX_POR_PASTA_PRIORITARIA = 1_000
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
            try:
                if not stat.S_ISREG(os.lstat(alvo).st_mode) or excluir(alvo):
                    continue
            except OSError:
                continue
            if len(rels) >= limite:
                cortado = True
                break
            rels.append(alvo.relative_to(raiz).as_posix())
        if cortado:
            break
    return sorted(rels), cortado


def _pasta_real(raiz: Path, rel: str) -> bool:
    """Cada componente de `rel` (a partir de `raiz`) e pasta de verdade, nunca link."""
    atual = Path(raiz)
    for parte in rel.split("/"):
        if parte in ("", ".", ".."):
            return False
        atual = atual / parte
        try:
            if not stat.S_ISDIR(os.lstat(atual).st_mode):
                return False
        except OSError:
            return False
    return True


def _regular(caminho: Path, excluir: Callable[[Path], bool]) -> bool:
    try:
        return stat.S_ISREG(os.lstat(caminho).st_mode) and not excluir(caminho)
    except OSError:
        return False


def listar_prioritarios(
    raiz: Path,
    arquivos: Iterable[str],
    pastas: dict[str, bool],
    nome_na_raiz: Callable[[str], bool],
    excluir: Callable[[Path], bool] = lambda p: False,
    max_por_pasta: int = MAX_POR_PASTA_PRIORITARIA,
) -> tuple[list[str], bool]:
    """Alvos de caminho fixo, lidos fora do limite de MAX_ARQUIVOS (sem seguir links).

    `arquivos`: caminhos exatos; `pastas`: pasta -> recursiva?; `nome_na_raiz`: arquivos do
    primeiro nivel. Cada pasta (e a raiz) contribui com no maximo `max_por_pasta` arquivos;
    passar disso marca `cortado`.
    """
    raiz = Path(raiz)
    achados: set[str] = set()
    cortado = False
    for rel in arquivos:
        pai = rel.rpartition("/")[0]
        if (not pai or _pasta_real(raiz, pai)) and _regular(raiz / rel, excluir):
            achados.add(rel)
    n = 0
    try:
        with os.scandir(raiz) as it:
            for e in it:
                if nome_na_raiz(e.name) and _regular(raiz / e.name, excluir):
                    if n >= max_por_pasta:
                        cortado = True
                        break
                    n += 1
                    achados.add(e.name)
    except OSError:
        pass
    for pasta, recursiva in pastas.items():
        if not _pasta_real(raiz, pasta) or excluir(raiz / pasta):
            continue
        n = 0
        cheia = False
        for dirpath, dirnames, filenames in os.walk(raiz / pasta, followlinks=False):
            atual = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames if recursiva and not excluir(atual / d))
            for nome in sorted(filenames):
                if not _regular(atual / nome, excluir):
                    continue
                if n >= max_por_pasta:
                    cheia = True
                    break
                n += 1
                achados.add((atual / nome).relative_to(raiz).as_posix())
            if cheia:
                cortado = True
                break
    return sorted(achados), cortado


def ler_texto(caminho: Path) -> str | None:
    """Le ate MAX_BYTES sem seguir link; None se link, nao-arquivo ou binario (NUL)."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
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


class Linhas:
    """Numeracao de linhas de um texto: quebras pre-computadas (uma vez) e busca binaria.

    `do_trecho` faz no maximo MAX_BUSCAS buscas por texto; depois devolve None (sem linha),
    para que muitos achados num arquivo hostil nao virem tempo quadratico.
    """

    MAX_BUSCAS = 200

    def __init__(self, texto: str) -> None:
        self.texto = texto
        self._quebras: list[int] | None = None
        self._buscas = 0

    def de(self, pos: int) -> int:
        """Linha 1-based da posicao `pos`; `\\r\\n` conta como uma quebra."""
        if self._quebras is None:
            quebras, i = [], self.texto.find("\n")
            while i >= 0:
                quebras.append(i)
                i = self.texto.find("\n", i + 1)
            self._quebras = quebras
        return bisect_left(self._quebras, pos) + 1

    def do_trecho(self, trecho: str) -> int | None:
        """Linha da primeira ocorrencia de `trecho`, ou None."""
        if not trecho or self._buscas >= self.MAX_BUSCAS:
            return None
        self._buscas += 1
        pos = self.texto.find(trecho)
        return None if pos < 0 else self.de(pos)


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
