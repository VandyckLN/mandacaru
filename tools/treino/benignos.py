"""Ingestao de arquivos legitimos a partir de pacotes (.deb, wheels, sdists, npm), em streaming e so em memoria.

Os downloads ficam fora do codigo (apt-get download, PyPI, npm pack --ignore-scripts). Aqui so se le: o formato ar do
.deb e percorrido em streaming, o data.tar e descomprimido em fluxo, e so membros regulares com 0 < tamanho <
MAX_BYTES chegam a ser lidos. Symlinks, hardlinks e diretorios (no disco ou dentro dos pacotes) sao ignorados.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import lzma
import os
import re
import stat
import sys
import tarfile
import zipfile
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from typing import BinaryIO

from mandacaru.ml.kind import detect_kind

from .corpus import MAX_BYTES, Corpus, Entry

try:  # Python 3.14+
    from compression import zstd as _zstd
except ImportError:  # pragma: no cover - so em Python < 3.14
    _zstd = None

_AR_MAGIC = b"!<arch>\n"
_AR_HEADER = 60


def _aviso(msg: str) -> None:
    print(f"aviso: {msg}", file=sys.stderr)


class _Limitado(io.RawIOBase):
    """Visao de leitura de exatamente `n` bytes de um arquivo, sem copiar para a memoria."""

    def __init__(self, fh: BinaryIO, n: int) -> None:
        self.fh = fh
        self.restante = n

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        if self.restante <= 0:
            return 0
        n = min(len(b), self.restante)
        dados = self.fh.read(n)
        b[:len(dados)] = dados
        self.restante -= len(dados)
        return len(dados)


def _descomprimido(nome: str, raw: BinaryIO) -> BinaryIO:
    if nome.endswith(".xz"):
        return lzma.LZMAFile(raw)
    if nome.endswith(".gz"):
        return gzip.GzipFile(fileobj=raw)
    if nome.endswith(".zst"):
        if _zstd is not None:
            return _zstd.ZstdFile(raw)
        import zstandard  # noqa: PLC0415 - so em Python < 3.14 (extra "treino")
        return zstandard.ZstdDecompressor().stream_reader(raw)
    if nome.endswith(".tar"):
        return raw
    raise ValueError(f"compressao desconhecida: {nome}")


def _membros_tar(fileobj: BinaryIO, modo: str = "r|") -> Iterator[tuple[str, bytes]]:
    with tarfile.open(fileobj=fileobj, mode=modo) as tf:
        for m in tf:
            if not m.isreg() or not 0 < m.size < MAX_BYTES:
                continue
            fh = tf.extractfile(m)
            if fh is None:
                continue
            data = fh.read(MAX_BYTES)
            if len(data) < MAX_BYTES:
                yield m.name, data


def membros_deb_stream(fh: BinaryIO) -> Iterator[tuple[str, bytes]]:
    if fh.read(len(_AR_MAGIC)) != _AR_MAGIC:
        raise ValueError("nao e um arquivo ar (.deb)")
    while True:
        hdr = fh.read(_AR_HEADER)
        if len(hdr) < _AR_HEADER:
            return
        nome = hdr[:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            tamanho = int(hdr[48:58].decode("ascii").strip())
        except ValueError:
            raise ValueError("cabecalho ar invalido") from None
        pad = tamanho % 2                               # membro de tamanho impar tem 1 byte de enchimento
        if nome.startswith("data.tar"):
            limitado = _Limitado(fh, tamanho)
            yield from _membros_tar(_descomprimido(nome, io.BufferedReader(limitado)))
            fh.read(limitado.restante + pad)            # o que o tar nao consumiu
        else:
            fh.seek(tamanho + pad, os.SEEK_CUR)


def membros_deb(deb: bytes) -> Iterator[tuple[str, bytes]]:
    yield from membros_deb_stream(io.BytesIO(deb))


def _membros_zip(fh: BinaryIO) -> Iterator[tuple[str, bytes]]:
    with zipfile.ZipFile(fh) as zf:
        for info in zf.infolist():
            if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16) or not 0 < info.file_size < MAX_BYTES:
                continue
            with zf.open(info) as m:
                data = m.read(MAX_BYTES)
            if len(data) < MAX_BYTES:
                yield info.filename, data


def _membros_de(nome: str, fh: BinaryIO) -> Iterator[tuple[str, bytes]]:
    n = nome.lower()
    if n.endswith(".deb"):
        yield from membros_deb_stream(fh)
    elif n.endswith((".whl", ".zip")):
        yield from _membros_zip(fh)
    elif n.endswith((".tar.gz", ".tgz")):
        yield from _membros_tar(fh, "r|gz")
    else:
        data = fh.read(MAX_BYTES)
        if 0 < len(data) < MAX_BYTES:
            yield nome, data


def membros_arquivo(nome: str, data: bytes) -> Iterator[tuple[str, bytes]]:
    yield from _membros_de(nome, io.BytesIO(data))


def membros_caminho(path: Path) -> Iterator[tuple[str, bytes]]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return
        yield from _membros_de(path.name, fh)


_VERSAO = re.compile(r"^\d")


def nome_pacote(path: Path) -> str:
    """ola_1.0_all.deb -> ola; pkg-1.0-py3-none-any.whl -> pkg; pkg-1.0.0.tgz e pkg-1.0.tar.gz -> pkg."""
    nome = path.name
    if nome.endswith(".deb"):
        return nome.split("_", 1)[0]
    if nome.endswith(".whl"):
        return nome.split("-", 1)[0]
    for ext in (".tar.gz", ".tgz", ".zip"):
        if nome.endswith(ext):
            base = nome[: -len(ext)]
            partes = base.rsplit("-", 1)
            return partes[0] if len(partes) == 2 and _VERSAO.match(partes[1]) else base
    return path.stem


def ingerir(corpus: Corpus, pasta: Path, *, source: str, categoria: str = "geral", first_seen: str) -> int:
    entraram = 0
    for raiz, dirs, arquivos in os.walk(pasta, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(raiz) / d).is_symlink()]
        for nome in sorted(arquivos):
            p = Path(raiz) / nome
            if p.is_symlink():
                continue
            pacote = nome_pacote(p)
            try:
                for _caminho, data in membros_caminho(p):
                    if detect_kind(data) is None:
                        continue
                    entry = Entry(sha256=hashlib.sha256(data).hexdigest(), label=0, source=source, family="legitimo",
                                  first_seen=first_seen, reporter=source, categoria=categoria, package=pacote)
                    if corpus.add_bytes(entry, data):
                        entraram += 1
            except Exception as exc:  # noqa: BLE001 - pacote corrompido: pula so ele
                _aviso(f"{nome}: pacote ignorado ({exc})")
    return entraram


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.treino.benignos", description="ingere legitimos de pacotes")
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--pasta", required=True, type=Path)
    ap.add_argument("--source", required=True)
    ap.add_argument("--categoria", default="geral")
    ap.add_argument("--data", default=date.today().isoformat())
    args = ap.parse_args(argv)
    n = ingerir(Corpus(args.corpus), args.pasta, source=args.source, categoria=args.categoria, first_seen=args.data)
    print(f"legitimos ingeridos: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
