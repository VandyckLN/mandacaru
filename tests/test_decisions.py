import json
import multiprocessing
import os
import pwd
import stat

import pytest

from mandacaru.decisions import DecisionLog, actor_from_env


def _lines(p):
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()]


def test_grava_uma_linha_json_por_decisao(tmp_path):
    p = tmp_path / "d.jsonl"
    log = DecisionLog(p)
    log.record("isolar", case_id="c1", sha256="ab" * 32, path="/tmp/x", by="ana", uid=1000, detail={"k": 1})
    log.record("manter", case_id="c1")
    a, b = _lines(p)
    assert a["v"] == 1 and isinstance(a["ts"], float)
    assert (a["id"], a["sha256"], a["path"], a["action"]) == ("c1", "ab" * 32, "/tmp/x", "isolar")
    assert (a["by"], a["uid"], a["detail"]) == ("ana", 1000, {"k": 1})
    assert b["action"] == "manter" and b["by"] == "sistema" and b["uid"] is None


def test_acao_desconhecida_e_erro(tmp_path):
    with pytest.raises(ValueError):
        DecisionLog(tmp_path / "d.jsonl").record("explodir")
    assert not (tmp_path / "d.jsonl").exists()


def test_caminho_com_utf8_invalido_nao_perde_a_linha(tmp_path):
    p = tmp_path / "d.jsonl"
    DecisionLog(p).record("isolar", path="/tmp/\udcff.py")
    (linha,) = _lines(p)
    assert "\ufffd" in linha["path"] and linha["path"].endswith(".py")


def _escreve(path, n):
    log = DecisionLog(path)
    for i in range(n):
        log.record("isolar", case_id=str(os.getpid()), detail={"i": i, "pad": "x" * 500})


def test_dois_processos_escrevendo_nao_misturam_linhas(tmp_path):
    p = tmp_path / "d.jsonl"
    procs = [multiprocessing.Process(target=_escreve, args=(p, 200)) for _ in range(2)]
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join()
        assert pr.exitcode == 0
    assert len(_lines(p)) == 400


def test_actor_from_env():
    nome = pwd.getpwuid(os.getuid()).pw_name
    assert actor_from_env({"PKEXEC_UID": str(os.getuid())}) == (nome, os.getuid())
    assert actor_from_env({}) == ("sistema", None)
    assert actor_from_env({"SUDO_UID": "4242424"}) == ("4242424", 4242424)


def test_permissao_do_arquivo_novo_e_0640(tmp_path):
    p = tmp_path / "d.jsonl"
    old = os.umask(0)
    try:
        DecisionLog(p).record("manter")
    finally:
        os.umask(old)
    assert stat.S_IMODE(p.stat().st_mode) == 0o640


def test_diretorio_inexistente_levanta_oserror(tmp_path):
    with pytest.raises(OSError):
        DecisionLog(tmp_path / "nao" / "d.jsonl").record("manter")


def test_escrita_curta_continua_ate_gravar_a_linha_toda(tmp_path, monkeypatch):
    real = os.write

    def curta(fd, data):
        return real(fd, bytes(data)[:7])

    p = tmp_path / "d.jsonl"
    monkeypatch.setattr(os, "write", curta)
    DecisionLog(p).record("manter", case_id="c1")
    monkeypatch.undo()
    assert _lines(p)[0]["id"] == "c1"


def test_nao_segue_symlink_no_log(tmp_path):
    alvo = tmp_path / "alvo"
    alvo.write_text("")
    p = tmp_path / "d.jsonl"
    os.symlink(alvo, p)
    with pytest.raises(OSError):
        DecisionLog(p).record("manter", case_id="c1")
    assert alvo.read_text() == ""
