"""Indice local dos md5 do dpkg: arquivo identico a um de pacote instalado nao e isolado pelo modelo."""
import hashlib
import os
import time

from mandacaru.ml.knowngood import DpkgKnownGood


def test_reconhece_arquivo_de_pacote(tmp_path):
    conteudo = b"\x7fELF binario legitimo"
    (tmp_path / "coreutils.md5sums").write_text(f"{hashlib.md5(conteudo).hexdigest()}  usr/bin/ls\n")
    kg = DpkgKnownGood(tmp_path)
    assert kg.contains(conteudo) and not kg.contains(b"outro")


def test_recarrega_quando_o_dpkg_muda(tmp_path):
    kg = DpkgKnownGood(tmp_path)
    assert not kg.contains(b"novo")
    (tmp_path / "x.md5sums").write_text(f"{hashlib.md5(b'novo').hexdigest()}  usr/bin/x\n")
    os.utime(tmp_path, ns=(time.time_ns(), time.time_ns() + 10**9))
    assert kg.contains(b"novo")


def test_pasta_ausente_e_linhas_ruins(tmp_path):
    assert DpkgKnownGood(tmp_path / "nao-existe").contains(b"x") is False
    (tmp_path / "ruim.md5sums").write_text("lixo\nzz  a\n")
    assert DpkgKnownGood(tmp_path).contains(b"x") is False
