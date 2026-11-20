"""Corpus em zips AES: nada extraido no disco, validacao estrita e teto de disco."""
import hashlib

import pytest

pyzipper = pytest.importorskip("pyzipper")
from helpers import zip_aes

from tools.treino.corpus import MAX_BYTES, Corpus, Entry


def _e(sha, label=1, package=""):
    return Entry(sha, label, "teste", "Fam", "2026-11-01", "r", "geral", package=package)


def test_ida_e_volta_sem_extrair(tmp_path):
    c = Corpus(tmp_path / "c")
    data = b"#!/bin/sh\necho inofensivo\n"
    sha = hashlib.sha256(data).hexdigest()
    assert c.add_zip(_e(sha), zip_aes(sha, data))
    assert c.read(c.entries()[0]) == data
    arquivos = {p.name for p in (tmp_path / "c").rglob("*") if p.is_file()}
    assert arquivos == {f"{sha}.zip", "manifesto.jsonl"}          # nada extraido no disco
    assert (tmp_path / "c").stat().st_mode & 0o777 == 0o700


def test_entry_rejeita_path_traversal():
    with pytest.raises(ValueError):
        _e("../../etc/passwd")
    with pytest.raises(ValueError):
        _e("z" * 64)


def test_hash_errado_duplicado_e_legitimo(tmp_path):
    c = Corpus(tmp_path / "c")
    assert c.add_zip(_e("0" * 64), zip_aes("x", b"outro")) is False
    data = b"legitimo"
    sha = hashlib.sha256(data).hexdigest()
    assert c.add_bytes(_e(sha, label=0, package="pkg"), data)
    assert c.add_bytes(_e(sha, label=0, package="pkg"), data) is False
    assert c.read(c.entries()[0]) == data and c.entries()[0].package == "pkg"


def test_mesmo_sha_nos_dois_rotulos_vai_para_a_higiene(tmp_path):
    from tools.treino.higiene import remover_conflitos

    data = b"#!/bin/sh\necho instalador legitimo\n"
    sha = hashlib.sha256(data).hexdigest()
    c = Corpus(tmp_path / "c")
    assert c.add_zip(_e(sha), zip_aes(sha, data))
    assert c.add_bytes(_e(sha, label=0), data)                  # nao some em silencio: a higiene decide
    assert sorted(e.label for e in Corpus(tmp_path / "c").entries()) == [0, 1]
    assert remover_conflitos(Corpus(tmp_path / "c").entries()) == []


def test_zip_sem_criptografia_e_recusado(tmp_path):
    import io
    import zipfile

    data = b"amostra em claro"
    sha = hashlib.sha256(data).hexdigest()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(sha, data)
    c = Corpus(tmp_path / "c")
    assert c.add_zip(_e(sha), buf.getvalue()) is False
    assert not list((tmp_path / "c" / "malicioso").iterdir())


@pytest.mark.parametrize("zip_ruim", [
    lambda: b"nao e zip",
    lambda: zip_aes("x", b"a", senha=b"outra"),
    lambda: zip_aes("x", b"a", membros=2),
    lambda: zip_aes("x", b"/etc/passwd", symlink=True),
])
def test_zip_ruim_e_pulado(tmp_path, zip_ruim, capsys):
    c = Corpus(tmp_path / "c")
    sha = hashlib.sha256(b"a").hexdigest()
    (tmp_path / "c" / "malicioso").mkdir(parents=True, exist_ok=True)
    (tmp_path / "c" / "malicioso" / f"{sha}.zip").write_bytes(zip_ruim())
    assert c.read(_e(sha)) is None and "aviso" in capsys.readouterr().err


def test_limite_estrito_max_bytes_e_orcamento_disco(tmp_path):
    c = Corpus(tmp_path / "c")
    igual = b"\0" * MAX_BYTES
    sha = hashlib.sha256(igual).hexdigest()
    assert c.add_zip(_e(sha), zip_aes(sha, igual)) is False        # < MAX_BYTES (igual ao runtime)
    c_peq = Corpus(tmp_path / "c2", max_disk_bytes=600)
    d1 = b"A" * 200
    assert c_peq.add_bytes(_e(hashlib.sha256(d1).hexdigest(), label=0), d1)
    d2 = b"B" * 500
    assert c_peq.add_bytes(_e(hashlib.sha256(d2).hexdigest(), label=0), d2) is False
