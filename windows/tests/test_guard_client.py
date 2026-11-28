"""Cliente IPC do MandacaruGuard (transporte falso; ida e volta real só no Windows)."""
import sys

import pytest
from mandacaru_win.guard_client import GuardClient
from mandacaru_win.guard_protocol import GuardError, codificar, decodificar

SHA = "a" * 64


class Transporte:
    def __init__(self, resposta=None, erro=None):
        self.resposta, self.erro = resposta, erro
        self.enviados: list[dict] = []

    def __call__(self, linha):
        self.enviados.append(decodificar(linha))
        if self.erro:
            raise self.erro
        return self.resposta


def test_chamar_ok():
    t = Transporte(codificar({"ok": True, "servico": "MandacaruGuard", "versao": "0.8.3"}))
    c = GuardClient(transporte=t)
    assert c.chamar("ping") == {"ok": True, "servico": "MandacaruGuard", "versao": "0.8.3"}
    assert t.enviados == [{"acao": "ping"}]
    assert c.disponivel() is True


def test_parametros_vao_no_pedido():
    t = Transporte(codificar({"ok": True, "id": "f" * 32}))
    GuardClient(transporte=t).chamar("quarantine_file", caminho=r"C:\x\mal.exe", sha256=SHA)
    assert t.enviados == [{"acao": "quarantine_file", "caminho": r"C:\x\mal.exe", "sha256": SHA}]


def test_erro_do_servico_vira_guarderror():
    t = Transporte(codificar({"ok": False, "erro": "Programa do sistema: o serviço não encerra este processo."}))
    with pytest.raises(GuardError, match="Programa do sistema"):
        GuardClient(transporte=t).chamar("terminate_process", pid=100, exe=r"C:\Windows\x.exe", sha256=SHA)


@pytest.mark.parametrize("resposta", [b"lixo\n", b"[1]\n", codificar({"ok": False})])
def test_resposta_malformada_ou_sem_motivo(resposta):
    with pytest.raises(GuardError):
        GuardClient(transporte=Transporte(resposta)).chamar("ping")


@pytest.mark.parametrize("acao,params", [
    ("rodar_comando", {"cmd": "whoami"}),
    ("terminate_process", {"pid": True, "exe": r"C:\x.exe", "sha256": SHA}),
    ("persistence_restore", {"backup": {"tipo": "schtask"}}),
])
def test_pedido_invalido_nem_sai(acao, params):
    t = Transporte(codificar({"ok": True}))
    with pytest.raises(GuardError):
        GuardClient(transporte=t).chamar(acao, **params)
    assert t.enviados == []


def test_servico_ausente():
    c = GuardClient(transporte=Transporte(erro=FileNotFoundError(2, "pipe")))
    assert c.disponivel() is False
    with pytest.raises(GuardError, match="não está instalada ou não está rodando"):
        c.chamar("ping")
    with pytest.raises(GuardError, match="Não foi possível falar"):
        GuardClient(transporte=Transporte(erro=OSError(231, "ocupado"))).chamar("ping")


@pytest.mark.skipif(sys.platform == "win32", reason="fora do Windows não há transporte")
def test_sem_windows_nao_ha_protecao():
    assert GuardClient().disponivel() is False


@pytest.mark.skipif(sys.platform != "win32", reason="só no Windows")
def test_cliente_real_contra_servidor_de_teste(tmp_path):
    import os
    import threading
    import uuid

    from mandacaru_win.guard_service import Despachante, ServidorPipe
    from test_guard_service import _acoes  # mesmos falsos do serviço

    nome = rf"\\.\pipe\MandacaruGuardTeste-{uuid.uuid4().hex}"
    srv = ServidorPipe(nome, Despachante(_acoes(tmp_path)[0]), lambda pid: pid == os.getpid())
    t = threading.Thread(target=srv.servir, daemon=True)
    t.start()
    try:
        c = GuardClient(nome=nome, verificar_servidor=lambda pid: pid == os.getpid())
        for _ in range(100):
            if c.disponivel():
                break
        assert c.chamar("ping")["servico"] == "MandacaruGuard"
        # Sem a verificação de teste: o servidor (este Python) não roda de Arquivos de Programas.
        with pytest.raises(GuardError, match="não é o serviço instalado"):
            GuardClient(nome=nome).chamar("ping")
    finally:
        srv.parar()
        t.join(10)
