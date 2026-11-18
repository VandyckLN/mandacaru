import errno
import hashlib
import json
import os

import pytest

from mandacaru import quarantine as qmod
from mandacaru.decisions import DecisionLog
from mandacaru.events import Alert, Severity
from mandacaru.quarantine import CaseNotFound, Quarantine, validate_id


@pytest.fixture
def q(tmp_path):
    (tmp_path / "q").mkdir()
    return Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"), now=lambda: 1000.0)


def alerta(f):
    return Alert("yara.X", Severity.HIGH, "s", {"path": str(f)})


def linhas(tmp_path):
    return [json.loads(x) for x in (tmp_path / "d.jsonl").read_text().splitlines()]


def test_isola_embaralha_e_remove_o_original(q, tmp_path):
    f = tmp_path / "mal.py"
    conteudo = b"print('oi')\n" * 10
    f.write_bytes(conteudo)
    r = q.isolate(str(f), alerta(f))
    assert r.status == "isolado"
    assert not f.exists()
    bin_ = tmp_path / "q" / f"{r.case.id}.bin"
    dado = bin_.read_bytes()
    assert dado != conteudo
    assert bytes(b ^ 0xA5 for b in dado) == conteudo
    assert (bin_.stat().st_mode & 0o777) == 0o600
    assert r.case.sha256 == hashlib.sha256(conteudo).hexdigest()
    assert r.case.expires_at == 1000.0 + 30 * 86400
    assert r.case.severity == "HIGH" and r.case.state == "isolado" and r.case.original_removido is True
    log = linhas(tmp_path)
    assert len(log) == 1 and log[0]["action"] == "isolar" and log[0]["id"] == r.case.id
    assert sorted(p.name for p in (tmp_path / "q").iterdir()) == [f"{r.case.id}.bin", f"{r.case.id}.json"]
    assert q.load(r.case.id) == r.case
    assert q.list() == [r.case]


def test_metadados_preservam_nome_com_bytes_invalidos(q, tmp_path):
    caminho = os.fsdecode(os.fsencode(str(tmp_path)) + b"/a\xff b\n.py")
    with open(caminho, "wb") as fh:
        fh.write(b"x")
    r = q.isolate(caminho, alerta(caminho))
    assert r.status == "isolado"
    assert q.load(r.case.id).original_path == caminho


def test_symlink_nao_e_seguido(q, tmp_path):
    alvo = tmp_path / "alvo"
    alvo.write_bytes(b"x")
    link = tmp_path / "link"
    link.symlink_to(alvo)
    r = q.isolate(str(link), alerta(link))
    assert r.status == "nao_isolado"
    assert alvo.read_bytes() == b"x" and link.is_symlink()


def test_falha_no_meio_da_copia_deixa_o_original(q, tmp_path, monkeypatch):
    f = tmp_path / "grande"
    f.write_bytes(b"a" * (3 * 1024 * 1024))
    real = os.write
    chamadas = []

    def falha(fd, dados):
        chamadas.append(1)
        if len(chamadas) == 2:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(fd, dados)

    monkeypatch.setattr(qmod.os, "write", falha)
    r = q.isolate(str(f), alerta(f))
    monkeypatch.undo()
    assert r.status == "nao_isolado"
    assert f.stat().st_size == 3 * 1024 * 1024
    assert list((tmp_path / "q").iterdir()) == []
    log = linhas(tmp_path)
    assert log[0]["action"] == "nao_isolado" and "space" in log[0]["detail"]["motivo"]


def test_arquivo_grande_demais_nao_e_isolado(tmp_path):
    (tmp_path / "q").mkdir()
    q = Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"), max_file_bytes=10)
    f = tmp_path / "f"
    f.write_bytes(b"x" * 11)
    r = q.isolate(str(f), alerta(f))
    assert (r.status, r.reason) == ("nao_isolado", "tamanho")
    assert f.exists()
    assert linhas(tmp_path)[0]["detail"]["motivo"] == "tamanho"


def test_quarentena_cheia(tmp_path):
    (tmp_path / "q").mkdir()
    q = Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"), max_total_bytes=15)
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"x" * 10)
    b.write_bytes(b"y" * 10)
    assert q.isolate(str(a), alerta(a)).status == "isolado"
    assert q.used_bytes() == 10
    r = q.isolate(str(b), alerta(b))
    assert (r.status, r.reason) == ("nao_isolado", "quarentena_cheia")
    assert b.exists()


def test_arquivo_que_sumiu(q, tmp_path):
    f = tmp_path / "nada"
    r = q.isolate(str(f), alerta(f))
    assert (r.status, r.reason) == ("nao_isolado", "sumiu")


def test_nao_regular(q, tmp_path):
    r = q.isolate(str(tmp_path), alerta(tmp_path))
    assert (r.status, r.reason) == ("nao_isolado", "nao_regular")


def test_raiz_inexistente_e_nao_isolado(tmp_path):
    q = Quarantine(tmp_path / "nao-existe", DecisionLog(tmp_path / "d.jsonl"))
    f = tmp_path / "f"
    f.write_bytes(b"x")
    r = q.isolate(str(f), alerta(f))
    assert r.status == "nao_isolado" and f.exists()


def test_falha_no_unlink_mantem_o_caso(q, tmp_path, monkeypatch):
    f = tmp_path / "f"
    f.write_bytes(b"x")
    real = os.unlink

    def falha(p, *a, **k):
        if os.fspath(p) == str(f):
            raise PermissionError(errno.EACCES, "Permission denied")
        return real(p, *a, **k)

    monkeypatch.setattr(qmod.os, "unlink", falha)
    r = q.isolate(str(f), alerta(f))
    monkeypatch.undo()
    assert r.status == "isolado" and r.case.original_removido is False
    assert f.exists()
    assert q.load(r.case.id).original_removido is False


def test_load_inexistente(q):
    with pytest.raises(CaseNotFound):
        q.load("a" * 32)


@pytest.mark.parametrize("ruim", ["../x", "A" * 32, "a" * 31])
def test_validate_id(ruim):
    with pytest.raises(CaseNotFound):
        validate_id(ruim)
