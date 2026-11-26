"""Relatório do incidente: HTML autocontido e JSON, com sanitização ligada por padrão."""
import json

import pytest
from mandacaru_win.incident import Acao, IncidentError, IncidentStore
from mandacaru_win.incident_cred import CATALOGO
from mandacaru_win.incident_report import Ambiente, exportar_html, exportar_json, salvar_relatorio, sanitizar

AMB = Ambiente(perfil=r"C:\Users\fulano", usuario="fulano", host="PC-FULANO")
SHA = "f" * 60 + "abcd"


def _inc(tmp_path, caminho=r"C:\Users\fulano\Downloads\mal.exe", regra="hash.malicioso", ameaca="malware"):
    store = IncidentStore(tmp_path / "incidents")
    inc = store.criar(origem="varredura", ameaca=ameaca, pasta=r"C:\Users\fulano\proj",
                      achados=[{"regra": regra, "severidade": "CRITICAL", "caminho": caminho,
                                "sha256": SHA, "mitre": ["T1547.001"]}])
    store.registrar(inc, Acao("remover_persistencia", "neutralizar", "guiada", "concluida",
                              "Removido do Run de fulano em PC-FULANO",
                              {"nome": "Atualizador", "comando": rf'"{caminho}" /s'},
                              "2026-11-26T10:00:00-03:00",
                              backup={"tipo": "hkcu_run", "valor": "SEGREDO-DO-BACKUP"}, desfeita=True))
    store.registrar(inc, Acao("encerrar_processo", "conter", "automatica", "concluida", "PID 4242",
                              {"pid": 4242, "exe": caminho}, "2026-11-26T10:01:00-03:00"))
    inc.credenciais = {"ssh": True}
    return inc


def test_sanitiza_perfil_e_outros_usuarios():
    t = sanitizar(r'"C:\Users\Fulano\AppData\x.exe" c:/users/fulano/y C:\Users\beltrano\z.txt', AMB)
    assert t == r'"%USERPROFILE%\AppData\x.exe" %USERPROFILE%/y %USERPROFILE%\z.txt'
    assert sanitizar(r"C:\Users\fulano2\a", AMB) == r"%USERPROFILE%\a"     # outro perfil também some
    assert sanitizar("Usuário fulano em PC-FULANO", AMB) == "Usuário <usuário> em <computador>"
    assert sanitizar("fulanos e ofulano ficam", AMB) == "fulanos e ofulano ficam"
    amb_acento = Ambiente(perfil=r"C:\Users\rio", usuario="rio", host="PC-CAO")
    assert sanitizar("Relatório do usuário rio em PC-CAO", amb_acento) == (
        "Relatório do usuário <usuário> em <computador>"
    )
    amb_colisao = Ambiente(perfil=r"C:\Users\computador", usuario="computador", host="MEU-HOST")
    assert sanitizar("Host MEU-HOST de computador", amb_colisao) == "Host <computador> de <usuário>"


def test_usuario_curto_preserva_regra_e_hash(tmp_path):
    amb = Ambiente(perfil=r"C:\Users\agente", usuario="agente", host="ab")
    inc = _inc(tmp_path, caminho=r"C:\Users\agente\x.exe", regra="projeto.agente.injecao")
    d = json.loads(exportar_json(inc, amb=amb))
    assert d["achados"][0]["regra"] == "projeto.agente.injecao"
    assert d["achados"][0]["sha256"] == SHA and d["achados"][0]["mitre"] == ["T1547.001"]
    assert d["achados"][0]["caminho"] == r"%USERPROFILE%\x.exe"
    assert sanitizar("ab", amb) == "ab"                                     # host curto demais: não mexe


def test_json_sem_backup_e_sanitizado_por_padrao(tmp_path):
    texto = exportar_json(_inc(tmp_path), amb=AMB)
    d = json.loads(texto)
    assert d["sanitizado"] is True and d["exportado"] and d["gerador"].startswith("Mandacaru ")
    assert "fulano" not in texto.lower() and "SEGREDO-DO-BACKUP" not in texto
    assert all("backup" not in a for a in d["acoes"])
    assert d["acoes"][0]["detalhe"] == "Removido do Run de <usuário> em <computador>"
    assert d["acoes"][0]["desfeita"] is True and d["acoes"][1]["alvo"]["pid"] == 4242
    assert d["credenciais"] == {"ssh": True} and d["pasta"] == r"%USERPROFILE%\proj"


def test_json_sem_ocultar_mantem_caminhos(tmp_path):
    d = json.loads(exportar_json(_inc(tmp_path), ocultar=False, amb=AMB))
    assert d["sanitizado"] is False
    assert d["achados"][0]["caminho"] == r"C:\Users\fulano\Downloads\mal.exe"
    assert all("backup" not in a for a in d["acoes"])                       # backup nunca sai


def test_html_autocontido(tmp_path):
    h = exportar_html(_inc(tmp_path), amb=AMB)
    assert h.startswith("<!DOCTYPE html>")
    assert "<title>Relatório de incidente — Mandacaru</title>" in h
    assert "default-src 'none'; style-src 'unsafe-inline'" in h
    assert "<script" not in h.lower() and "src=" not in h.lower() and "<link" not in h.lower()
    resto = h.replace('http-equiv="Content-Security-Policy"', "")
    for _texto, url in CATALOGO.values():
        if url:
            resto = resto.replace(url, "")
    assert "http" not in resto                                               # só os links da checklist, em texto
    assert "<a " not in h.lower()
    assert "fulano" not in h.lower() and "SEGREDO-DO-BACKUP" not in h
    assert "Remover persistência" in h and "(desfeita)" in h and "automática" in h
    assert "T1547.001" in h and SHA in h
    assert "[x] Gerar novas chaves SSH" in h and "[ ] Trocar a senha da Conta Google" in h


def test_html_escapa_texto_do_achado(tmp_path):
    inc = _inc(tmp_path, caminho=r'C:\x\<img src=x onerror=alert(1)>.exe')
    h = exportar_html(inc, amb=AMB)
    assert "<img" not in h and "&lt;img" in h


def test_ameaca_desconhecida_no_arquivo_nao_derruba(tmp_path):
    inc = _inc(tmp_path)
    inc.ameaca = "outra"
    assert "Credenciais" in exportar_html(inc, amb=AMB)


def test_salvar_relatorio_atomico(tmp_path):
    destino = tmp_path / "rel" / "incidente.html"
    salvar_relatorio(destino, "<p>olá</p>")
    assert destino.read_text(encoding="utf-8") == "<p>olá</p>"
    assert [p.name for p in destino.parent.iterdir()] == ["incidente.html"]
    with pytest.raises(IncidentError):
        salvar_relatorio(tmp_path / "rel", "x")                             # é uma pasta
