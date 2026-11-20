"""Ingestao de legitimos: pacotes montados em memoria, nada extraido no disco."""
import io
import os
import tarfile

import pytest

pytest.importorskip("pyzipper")
from tools.treino.benignos import ingerir, membros_arquivo
from tools.treino.corpus import Corpus


def _ar(membros: list[tuple[str, bytes]]) -> bytes:
    buf = bytearray(b"!<arch>\n")
    for nome, data in membros:
        hdr = f"{nome:<16}0           0     0     100644  {len(data):<10}`\n".encode("ascii")
        buf += hdr + data
        if len(data) % 2 == 1:
            buf += b"\n"                                   # padding de 1 byte em membro impar
    return bytes(buf)


def _tar_xz(arquivos: dict[str, bytes], symlink_nome: str | None = None) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:xz") as tf:
        for nome, data in arquivos.items():
            ti = tarfile.TarInfo(nome)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        if symlink_nome:
            si = tarfile.TarInfo(symlink_nome)
            si.type = tarfile.SYMTYPE
            si.linkname = "/etc/passwd"
            tf.addfile(si)
    return raw.getvalue()


def test_deb_em_streaming_com_membro_impar_e_symlink(tmp_path):
    pasta = tmp_path / "debs"
    pasta.mkdir()
    deb = _ar([
        ("debian-binary", b"2.0\n"),
        ("control.tar.xz", _tar_xz({}) + b"X"),             # membro anterior com tamanho impar
        ("data.tar.xz", _tar_xz({"usr/bin/ola": b"#!/bin/sh\necho ola\n",
                                 "usr/share/doc/x.txt": b"texto"}, symlink_nome="usr/bin/link")),
    ])
    (pasta / "ola_1.0_all.deb").write_bytes(deb)
    c = Corpus(tmp_path / "c")
    assert ingerir(c, pasta, source="ubuntu", first_seen="2026-11-20") == 1
    [e] = c.entries()
    assert e.label == 0 and e.categoria == "geral" and e.package == "ola"
    assert c.read(e) == b"#!/bin/sh\necho ola\n"
    assert not list((tmp_path / "c").rglob("ola"))


def test_npm_tgz_e_symlink_em_disco_ignorado(tmp_path):
    pasta = tmp_path / "npm"
    pasta.mkdir()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        data = b"const a = require('x');\nmodule.exports = a;\n"
        ti = tarfile.TarInfo("package/index.js")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    (pasta / "pkg-1.0.0.tgz").write_bytes(raw.getvalue())
    os.symlink("/etc/passwd", pasta / "link.sh")
    c = Corpus(tmp_path / "c")
    assert ingerir(c, pasta, source="npm", categoria="geral", first_seen="2026-11-20") == 1
    assert c.entries()[0].package == "pkg"


def test_membro_grande_e_ignorado():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        data = b"var a=1;\n" * 1_000_000
        ti = tarfile.TarInfo("package/g.js")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    assert dict(membros_arquivo("x.tgz", raw.getvalue())) == {}
