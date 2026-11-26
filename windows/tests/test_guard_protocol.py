"""Protocolo fechado do MandacaruGuard: uma linha JSON por pedido, esquema estrito."""
import json

import pytest
from mandacaru_win.guard_protocol import (
    MAX_MENSAGEM,
    GuardError,
    caminho_valido,
    codificar,
    decodificar,
    resposta_erro,
    resposta_ok,
    validar_pedido,
)

SHA = "a" * 64
EXE = r"C:\Program Files\Mal\mal.exe"


def test_ida_e_volta():
    linha = codificar({"acao": "ping"})
    assert linha.endswith(b"\n") and b"\n" not in linha[:-1]
    assert decodificar(linha) == {"acao": "ping"}
    assert decodificar(codificar({"t": "olá\nmundo"})) == {"t": "olá\nmundo"}


@pytest.mark.parametrize("ruim", [
    b"x" * (MAX_MENSAGEM + 1),
    b"\xff\xfe{}",
    b"[1, 2]",
    b"{nao json",
    b"",
])
def test_decodificar_recusa(ruim):
    with pytest.raises(GuardError):
        decodificar(ruim)


def test_codificar_grande_demais():
    with pytest.raises(GuardError):
        codificar({"x": "a" * MAX_MENSAGEM})


def test_respostas():
    assert resposta_ok(id="x") == {"ok": True, "id": "x"}
    assert resposta_erro("falhou") == {"ok": False, "erro": "falhou"}


def test_pedidos_validos():
    assert validar_pedido({"acao": "ping"}) == ("ping", {})
    assert validar_pedido({"acao": "terminate_process", "pid": 1234, "exe": EXE, "sha256": SHA}) == (
        "terminate_process", {"pid": 1234, "exe": EXE, "sha256": SHA})
    assert validar_pedido({"acao": "quarantine_file", "caminho": EXE, "sha256": SHA.upper()})[1]["sha256"] == SHA
    assert validar_pedido({"acao": "quarantine_restore", "id": "0" * 32})[0] == "quarantine_restore"
    assert validar_pedido({"acao": "firewall_block", "regra": "Mandacaru-0123abcd", "exe": EXE})[0] == "firewall_block"
    assert validar_pedido({"acao": "firewall_unblock", "regra": "Mandacaru-" + "f" * 32})[0] == "firewall_unblock"
    assert validar_pedido({"acao": "persistence_remove", "tipo": "hklm_run", "nome": "Upd",
                           "valor": f'"{EXE}"'})[1]["tipo"] == "hklm_run"
    assert validar_pedido({"acao": "persistence_restore", "backup": {"tipo": "service"}})[1] == {
        "backup": {"tipo": "service"}}


@pytest.mark.parametrize("pedido", [
    {"acao": "rodar_comando", "cmd": "whoami"},
    {"acao": "ping", "extra": 1},
    {},
    {"acao": 1},
    {"acao": "terminate_process", "pid": True, "exe": EXE, "sha256": SHA},
    {"acao": "terminate_process", "pid": 4, "exe": EXE, "sha256": SHA},
    {"acao": "terminate_process", "pid": "100", "exe": EXE, "sha256": SHA},
    {"acao": "terminate_process", "pid": 100, "exe": EXE},
    {"acao": "terminate_process", "pid": 100, "exe": EXE, "sha256": "x" * 64},
    {"acao": "quarantine_file", "caminho": "relativo\\mal.exe", "sha256": SHA},
    {"acao": "quarantine_file", "caminho": r"\\servidor\c$\mal.exe", "sha256": SHA},
    {"acao": "quarantine_file", "caminho": "\\\\?\\C:\\mal.exe", "sha256": SHA},
    {"acao": "quarantine_restore", "id": "../../x"},
    {"acao": "firewall_block", "regra": "Mandacaru-XYZ", "exe": EXE},
    {"acao": "firewall_block", "regra": "Outra-0123abcd", "exe": EXE},
    {"acao": "firewall_block", "regra": "Mandacaru-0123", "exe": EXE},
    {"acao": "firewall_unblock", "regra": "Mandacaru-0123abcd dir=in"},
    {"acao": "persistence_remove", "tipo": "hkcu_run", "nome": "x", "valor": "y"},
    {"acao": "persistence_remove", "tipo": "service", "nome": "", "valor": ""},
    {"acao": "persistence_remove", "tipo": "service", "nome": "a\nb", "valor": ""},
    {"acao": "persistence_restore", "backup": "nao é dict"},
])
def test_pedidos_invalidos(pedido):
    with pytest.raises(GuardError):
        validar_pedido(pedido)


@pytest.mark.parametrize("caminho,ok", [
    (EXE, True),
    ("C:/Users/ana/x.exe", True),
    ("c:\\x", True),
    ("x.exe", False),
    ("\\x.exe", False),
    ("C:", False),
    (r'C:\a"b.exe', False),
    ("C:\\a\x00b", False),
    ("C:\\a*b", False),
    ("C:\\" + "a" * 33000, False),
    (None, False),
])
def test_caminho_valido(caminho, ok):
    assert caminho_valido(caminho) is ok


def test_erro_traz_mensagem_legivel():
    with pytest.raises(GuardError, match="Ação desconhecida"):
        validar_pedido({"acao": "rodar_comando"})
    assert json.loads(codificar(resposta_erro("x")))["ok"] is False
