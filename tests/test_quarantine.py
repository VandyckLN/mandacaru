import errno
import hashlib
import json
import os

import pytest

from mandacaru import quarantine as qmod
from mandacaru.decisions import DecisionLog
from mandacaru.events import Alert, Severity
from mandacaru.quarantine import CaseNotFound, Quarantine, Tampered, TrustList, validate_id


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
        if os.fspath(p) == f.name and k.get("dir_fd") is not None:
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


def test_diretorio_pai_symlink_nao_e_seguido(q, tmp_path):
    fora = tmp_path / "fora"
    fora.mkdir()
    alvo = fora / "shadow"
    alvo.write_bytes(b"segredo")
    (tmp_path / "d").symlink_to(fora)
    caminho = str(tmp_path / "d" / "shadow")
    r = q.isolate(caminho, alerta(caminho))
    assert (r.status, r.reason) == ("nao_isolado", "caminho_com_symlink")
    assert alvo.read_bytes() == b"segredo"
    assert list((tmp_path / "q").iterdir()) == []


def test_symlink_em_nivel_intermediario(q, tmp_path):
    real = tmp_path / "real" / "b"
    real.mkdir(parents=True)
    alvo = real / "file"
    alvo.write_bytes(b"x")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "link").symlink_to(tmp_path / "real")
    caminho = str(tmp_path / "a" / "link" / "b" / "file")
    r = q.isolate(caminho, alerta(caminho))
    assert (r.status, r.reason) == ("nao_isolado", "caminho_com_symlink")
    assert alvo.exists()


def test_arquivo_que_cresce_alem_do_limite(tmp_path, monkeypatch):
    (tmp_path / "q").mkdir()
    q = Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"), max_file_bytes=10)
    f = tmp_path / "f"
    f.write_bytes(b"x" * 50)
    real = os.fstat

    def pequeno(fd):
        st = list(real(fd))
        st[6] = 5
        return os.stat_result(st)

    monkeypatch.setattr(qmod.os, "fstat", pequeno)
    r = q.isolate(str(f), alerta(f))
    monkeypatch.undo()
    assert (r.status, r.reason) == ("nao_isolado", "tamanho")
    assert f.exists() and list((tmp_path / "q").iterdir()) == []


def test_limite_total_ao_crescer(tmp_path, monkeypatch):
    (tmp_path / "q").mkdir()
    q = Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"), max_total_bytes=10)
    f = tmp_path / "f"
    f.write_bytes(b"x" * 50)
    real = os.fstat

    def pequeno(fd):
        st = list(real(fd))
        st[6] = 5
        return os.stat_result(st)

    monkeypatch.setattr(qmod.os, "fstat", pequeno)
    r = q.isolate(str(f), alerta(f))
    monkeypatch.undo()
    assert (r.status, r.reason) == ("nao_isolado", "quarentena_cheia")


def test_size_e_o_que_foi_copiado(q, tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"x" * 7)
    assert q.isolate(str(f), alerta(f)).case.size == 7


def test_falha_ao_reescrever_metadados_vai_para_o_log(q, tmp_path, monkeypatch):
    f = tmp_path / "f"
    f.write_bytes(b"x")
    real_unlink, real_write = os.unlink, Quarantine._write_json

    def sem_unlink(p, *a, **k):
        if k.get("dir_fd") is not None:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_unlink(p, *a, **k)

    chamadas = []

    def json_falha(self, case):
        chamadas.append(1)
        if len(chamadas) == 2:
            raise OSError(errno.EIO, "I/O error")
        return real_write(self, case)

    monkeypatch.setattr(qmod.os, "unlink", sem_unlink)
    monkeypatch.setattr(Quarantine, "_write_json", json_falha)
    r = q.isolate(str(f), alerta(f))
    monkeypatch.undo()
    assert r.status == "isolado" and r.case.original_removido is False
    d = linhas(tmp_path)[0]["detail"]
    assert d["metadados_desatualizados"] is True and d["original_removido"] is False


# --- Task 4: lista de confianca e restauracao ---
@pytest.fixture
def qt(tmp_path):
    (tmp_path / "q").mkdir()
    trust = TrustList(tmp_path / "trusted.json", recheck_seconds=0)
    return Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"), trust=trust, now=lambda: 1000.0)


def isolar(q, f, conteudo=b"print('x')\n"):
    f.write_bytes(conteudo)
    return q.isolate(str(f), alerta(f)).case


def test_restaurar_devolve_conteudo_modo_e_mtime(qt, tmp_path):
    f = tmp_path / "x.py"
    f.write_bytes(b"conteudo\n")
    os.chmod(f, 0o640)
    os.utime(f, (5000, 5000))
    case = qt.isolate(str(f), alerta(f)).case
    assert not f.exists()
    dest = qt.restore(case.id, "ana", 1000)
    assert dest == str(f)
    assert f.read_bytes() == b"conteudo\n"
    assert (f.stat().st_mode & 0o777) == 0o640
    assert f.stat().st_mtime == 5000
    assert qt.list() == []
    assert sorted(p.name for p in (tmp_path / "q").iterdir()) == []
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".mandacaru")] == []
    ult = linhas(tmp_path)[-1]
    assert ult["action"] == "confiar" and ult["by"] == "ana" and ult["detail"] == {"restaurado_em": str(f)}


def test_restaurar_nao_sobrescreve(qt, tmp_path):
    f = tmp_path / "x.py"
    case = isolar(qt, f)
    f.write_bytes(b"novo")
    dest = qt.restore(case.id, "ana", 1000)
    assert dest == str(f) + ".restaurado-1970-01-01"
    assert f.read_bytes() == b"novo"
    assert open(dest, "rb").read() == b"print('x')\n"


def test_restaurar_destino_alternativo_tambem_existe(qt, tmp_path):
    f = tmp_path / "x.py"
    case = isolar(qt, f)
    f.write_bytes(b"novo")
    alt = tmp_path / "x.py.restaurado-1970-01-01"
    alt.write_bytes(b"outro")
    with pytest.raises(FileExistsError):
        qt.restore(case.id, "ana", 1000)
    assert alt.read_bytes() == b"outro" and f.read_bytes() == b"novo"
    assert [c.id for c in qt.list()] == [case.id]
    assert not qt.trust.contains(case.sha256)
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".mandacaru")] == []


def test_restaurar_bin_adulterado_e_recusado(qt, tmp_path):
    f = tmp_path / "x.py"
    case = isolar(qt, f)
    b = tmp_path / "q" / f"{case.id}.bin"
    dado = bytearray(b.read_bytes())
    dado[0] ^= 1
    b.write_bytes(bytes(dado))
    with pytest.raises(Tampered):
        qt.restore(case.id, "ana", 1000)
    assert not f.exists()
    assert [c.id for c in qt.list()] == [case.id]
    assert linhas(tmp_path)[-1]["action"] == "restauracao_recusada"
    assert not qt.trust.contains(case.sha256)
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".mandacaru")] == []


def test_restaurar_poe_hash_na_lista_e_nao_isola_de_novo(qt, tmp_path):
    f = tmp_path / "x.py"
    case = isolar(qt, f)
    qt.restore(case.id, "ana", 1000)
    r = qt.isolate(str(f), alerta(f))
    assert r.status == "confiavel" and r.case is None
    assert f.read_bytes() == b"print('x')\n"
    assert qt.list() == []
    ult = linhas(tmp_path)[-1]
    assert ult["action"] == "ignorado_confiavel" and ult["sha256"] == case.sha256 and ult["path"] == str(f)


def test_restaurar_nome_com_bytes_invalidos(qt, tmp_path):
    caminho = os.fsdecode(os.fsencode(str(tmp_path)) + b"/a\xff b\n.py")
    case = isolar(qt, type("P", (), {"write_bytes": lambda self, d: open(caminho, "wb").write(d),
                                     "__str__": lambda self: caminho})())
    assert qt.restore(case.id, "ana", 1000) == caminho
    assert open(caminho, "rb").read() == b"print('x')\n"


def test_restaurar_id_inexistente(qt):
    with pytest.raises(CaseNotFound):
        qt.restore("0" * 32, "ana", 1000)


def test_restaurar_diretorio_original_ausente(qt, tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    case = isolar(qt, d / "x.py")
    d.rmdir()
    with pytest.raises(FileNotFoundError, match="diretorio original"):
        qt.restore(case.id, "ana", 1000)
    assert [c.id for c in qt.list()] == [case.id]
    assert not qt.trust.contains(case.sha256)


def test_restaurar_recusa_symlink_no_diretorio_pai(qt, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "d").mkdir()
    case = isolar(qt, tmp_path / "d" / "x.py")
    (tmp_path / "d").rmdir()
    (tmp_path / "d").symlink_to(real)
    with pytest.raises(qmod.UnsafePath):
        qt.restore(case.id, "ana", 1000)
    assert list(real.iterdir()) == []
    assert [c.id for c in qt.list()] == [case.id]
    ult = linhas(tmp_path)[-1]
    assert ult["action"] == "restauracao_recusada" and ult["detail"]["motivo"] == "caminho_com_symlink"


def test_confiavel_nao_move_nada(qt, tmp_path):
    f = tmp_path / "x.py"
    f.write_bytes(b"abc")
    qt.trust.add(hashlib.sha256(b"abc").hexdigest(), str(f), "ana")
    assert qt.isolate(str(f), alerta(f)).status == "confiavel"
    assert f.read_bytes() == b"abc" and list((tmp_path / "q").iterdir()) == []


def test_trustlist_rele_quando_outro_processo_altera(tmp_path):
    p = tmp_path / "t.json"
    a, b = TrustList(p, recheck_seconds=0), TrustList(p, recheck_seconds=0)
    assert not a.contains("aa")
    b.add("aa", "/x", "ana")
    assert a.contains("aa")
    assert (p.stat().st_mode & 0o777) == 0o644
    b.add("aa", "/x", "ana")  # no-op
    assert len(json.loads(p.read_text())) == 1
    assert b.remove("aa") is True and b.remove("aa") is False
    assert not a.contains("aa")


def test_trustlist_corrompida_ou_ausente_e_vazia(tmp_path):
    p = tmp_path / "t.json"
    t = TrustList(p, recheck_seconds=0)
    assert not t.contains("aa")
    p.write_text("{lixo")
    assert not t.contains("aa")
    p.write_text('{"nao": "lista"}')
    assert not t.contains("aa")


def test_trustlist_respeita_recheck_seconds(tmp_path):
    p = tmp_path / "t.json"
    agora = [0.0]
    a = TrustList(p, recheck_seconds=5, now=lambda: agora[0])
    assert not a.contains("aa")
    TrustList(p).add("aa", "/x", "ana")
    assert not a.contains("aa")
    agora[0] = 6
    assert a.contains("aa")


def test_restaurar_falha_no_fsync_do_destino_mantem_o_caso(qt, tmp_path, monkeypatch):
    import stat as _stat
    f = tmp_path / "x.py"
    case = isolar(qt, f)
    real = os.fsync

    def falha(fd):
        if _stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "Input/output error")
        return real(fd)

    monkeypatch.setattr(os, "fsync", falha)
    with pytest.raises(OSError):
        qt.restore(case.id, "ana", 1000)
    assert (tmp_path / "q" / f"{case.id}.bin").exists() and (tmp_path / "q" / f"{case.id}.json").exists()
    assert [c.id for c in qt.list()] == [case.id]
    assert not f.exists() and not qt.trust.contains(case.sha256)
    ult = linhas(tmp_path)[-1]
    assert ult["action"] == "restauracao_recusada" and ult["detail"]["motivo"] == "Input/output error"
    monkeypatch.undo()
    assert qt.restore(case.id, "ana", 1000) == str(f)


# --- Task 5: manter, apagar e expirar ---
class Relogio:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def qr(tmp_path):
    (tmp_path / "q").mkdir()
    rel = Relogio()
    qq = Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"), now=rel)
    qq.rel = rel
    return qq


def test_manter_registra_e_mantem_prazo(qr, tmp_path):
    c = isolar(qr, tmp_path / "a.py")
    out = qr.keep(c.id, "ana", 1000)
    assert out.expires_at == c.expires_at
    assert qr.load(c.id).expires_at == c.expires_at
    ult = linhas(tmp_path)[-1]
    assert (ult["action"], ult["id"], ult["by"], ult["uid"]) == ("manter", c.id, "ana", 1000)


def test_manter_id_inexistente(qr):
    with pytest.raises(CaseNotFound):
        qr.keep("0" * 32, "ana", 1000)
    with pytest.raises(CaseNotFound):
        qr.keep("../x", "ana", 1000)


def test_apagar_remove_os_dois_arquivos(qr, tmp_path):
    c = isolar(qr, tmp_path / "a.py")
    qr.delete(c.id, "ana", 1000)
    assert os.listdir(tmp_path / "q") == []
    ult = linhas(tmp_path)[-1]
    assert (ult["action"], ult["sha256"], ult["path"]) == ("apagar", c.sha256, str(tmp_path / "a.py"))
    with pytest.raises(CaseNotFound):
        qr.delete(c.id, "ana", 1000)


def test_purge_apaga_so_os_vencidos(qr, tmp_path):
    a = isolar(qr, tmp_path / "a.py")
    qr.rel.t += 10
    b = isolar(qr, tmp_path / "b.py", b"outro\n")
    qr.rel.t = a.expires_at + 1  # a venceu, b ainda nao (b vence 10 s depois)
    assert qr.purge_expired() == 1
    assert [c.id for c in qr.list()] == [b.id]
    ult = linhas(tmp_path)[-1]
    assert (ult["action"], ult["id"], ult["by"]) == ("expirado", a.id, "sistema")


def test_purge_ignora_json_corrompido_e_continua(qr, tmp_path):
    a = isolar(qr, tmp_path / "a.py")
    (tmp_path / "q" / ("f" * 32 + ".json")).write_text("{lixo")
    qr.rel.t = a.expires_at + 1
    assert qr.purge_expired() == 1
    assert (tmp_path / "q" / ("f" * 32 + ".json")).exists()


def test_purge_erro_em_um_caso_nao_para_os_outros(qr, tmp_path, monkeypatch):
    a = isolar(qr, tmp_path / "a.py")
    b = isolar(qr, tmp_path / "b.py", b"outro\n")
    qr.rel.t = b.expires_at + 1
    real = Quarantine.delete

    def falha(self, case_id, *args, **kw):
        if case_id == a.id:
            raise OSError(errno.EIO, "io")
        return real(self, case_id, *args, **kw)

    monkeypatch.setattr(Quarantine, "delete", falha)
    assert qr.purge_expired() == 1
    assert not (tmp_path / "q" / (b.id + ".json")).exists()


def test_purge_limpa_orfaos(qr, tmp_path):
    d = tmp_path / "q"
    (d / ("a" * 32 + ".bin")).write_bytes(b"x")
    velho = d / "x.json.tmp"
    velho.write_bytes(b"x")
    os.utime(velho, (qr.rel.t - 3601, qr.rel.t - 3601))
    novo = d / "y.json.tmp"
    novo.write_bytes(b"x")
    os.utime(novo, (qr.rel.t - 60, qr.rel.t - 60))
    c = isolar(qr, tmp_path / "a.py")
    n_log = len(linhas(tmp_path))
    assert qr.purge_expired() == 0
    assert sorted(os.listdir(d)) == sorted(["y.json.tmp", c.id + ".bin", c.id + ".json"])
    assert len(linhas(tmp_path)) == n_log


def test_set_analysis_persiste(qr, tmp_path):
    c = isolar(qr, tmp_path / "a.py")
    out = qr.set_analysis(c.id, {"cymru": "desconhecido"})
    assert out.analysis == {"cymru": "desconhecido"}
    assert qr.load(c.id).analysis == {"cymru": "desconhecido"}
    assert not [n for n in os.listdir(tmp_path / "q") if n.endswith(".tmp")]
    with pytest.raises(CaseNotFound):
        qr.set_analysis("0" * 32, {})


def test_list_ignora_json_corrompido(qr, tmp_path):
    c = isolar(qr, tmp_path / "a.py")
    (tmp_path / "q" / ("e" * 32 + ".json")).write_text("{lixo")
    assert [x.id for x in qr.list()] == [c.id]
