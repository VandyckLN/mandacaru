"""Registro de incidentes: incidents/<id>.json."""
import json
import os
import re

import pytest
from mandacaru_win.incident import Acao, IncidentError, IncidentStore, sha256_arquivo


def _achado(caminho="C:/x/a.exe"):
    return {"regra": "hash.malicioso", "severidade": "CRITICAL", "caminho": caminho, "sha256": "a" * 64}


def _acao(**kw):
    base = dict(tipo="remover_persistencia", fase="neutralizar", modo="guiada", resultado="concluida",
                detalhe="ok", alvo={"nome": "x"}, data="2026-11-26T10:00:00-03:00")
    base.update(kw)
    return Acao(**base)


def test_criar_grava_json_atomico(tmp_path):
    store = IncidentStore(tmp_path / "incidents")
    inc = store.criar(origem="varredura", ameaca="malware", achados=[_achado()])
    assert re.fullmatch(r"[0-9a-f]{32}", inc.id)
    arq = tmp_path / "incidents" / f"{inc.id}.json"
    assert arq.is_file()
    assert [p.name for p in arq.parent.iterdir()] == [arq.name]   # sem .tmp sobrando
    assert json.loads(arq.read_text(encoding="utf-8"))["origem"] == "varredura"
    assert store.carregar(inc.id) == inc
    assert inc.acoes == [] and inc.credenciais == {} and inc.pasta is None


@pytest.mark.parametrize("origem,ameaca", [("rede", "malware"), ("varredura", "virus")])
def test_origem_ou_ameaca_invalida(tmp_path, origem, ameaca):
    with pytest.raises(IncidentError):
        IncidentStore(tmp_path).criar(origem=origem, ameaca=ameaca, achados=[])


@pytest.mark.parametrize("ruim", ["../x", "A" * 32, "", "0" * 31])
def test_id_invalido_nao_vira_caminho(tmp_path, ruim):
    with pytest.raises(IncidentError):
        IncidentStore(tmp_path).carregar(ruim)


def test_registrar_acrescenta_e_persiste(tmp_path):
    store = IncidentStore(tmp_path)
    inc = store.criar(origem="projeto", ameaca="projeto", achados=[_achado()], pasta=r"C:\proj")
    assert store.registrar(inc, _acao()) == 0
    assert store.registrar(inc, _acao(backup={"tipo": "hkcu_run", "valor": "x"})) == 1
    de_novo = store.carregar(inc.id)
    assert len(de_novo.acoes) == 2
    assert de_novo.acoes[1].backup == {"tipo": "hkcu_run", "valor": "x"}
    assert de_novo.pasta == r"C:\proj"


def test_corrompido_nao_derruba_listar(tmp_path):
    store = IncidentStore(tmp_path)
    bom = store.criar(origem="varredura", ameaca="malware", achados=[_achado()])
    quebrado = "b" * 32
    (tmp_path / f"{quebrado}.json").write_text("{não é json", encoding="utf-8")
    tipo_errado = "c" * 32
    d = json.loads((tmp_path / f"{bom.id}.json").read_text(encoding="utf-8"))
    d["id"], d["acoes"] = tipo_errado, "nada"
    (tmp_path / f"{tipo_errado}.json").write_text(json.dumps(d), encoding="utf-8")
    assert [i.id for i in store.listar()] == [bom.id]
    with pytest.raises(IncidentError, match="O registro do incidente está corrompido."):
        store.carregar(quebrado)
    with pytest.raises(IncidentError):
        store.carregar(tipo_errado)


def test_listar_mais_novo_primeiro(tmp_path):
    store = IncidentStore(tmp_path)
    a = store.criar(origem="varredura", ameaca="malware", achados=[])
    b = store.criar(origem="varredura", ameaca="malware", achados=[])
    a.criado, b.criado = "2026-11-25T10:00:00-03:00", "2026-11-26T10:00:00-03:00"
    store.salvar(a)
    store.salvar(b)
    assert [i.id for i in store.listar()] == [b.id, a.id]
    assert IncidentStore(tmp_path / "nao-existe").listar() == []


def test_sha256_arquivo(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"abc")
    assert sha256_arquivo(f) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_arquivo(tmp_path / "nao.bin") is None
    assert sha256_arquivo(tmp_path) is None


def test_sha256_arquivo_nao_segue_link(tmp_path):
    alvo = tmp_path / "alvo.bin"
    alvo.write_bytes(b"abc")
    link = tmp_path / "link.bin"
    try:
        os.symlink(alvo, link)
    except (OSError, NotImplementedError):
        pytest.skip("sem permissão para criar link simbólico")
    assert sha256_arquivo(link) is None
