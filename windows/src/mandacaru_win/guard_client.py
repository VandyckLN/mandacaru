"""Cliente da janela (sem privilégio) para o serviço MandacaruGuard.

Valida o pedido com o mesmo esquema do serviço antes de enviar, fala por uma linha JSON no named
pipe e, no Windows, só conversa com um servidor que rode de Arquivos de Programas: um programa
qualquer do usuário que tenha criado um pipe com o mesmo nome não se passa pela Proteção avançada.
"""
from __future__ import annotations

import sys
from collections.abc import Callable

from mandacaru_win.guard_protocol import MAX_MENSAGEM, GuardError, codificar, decodificar, validar_pedido

NOME_PIPE = r"\\.\pipe\MandacaruGuard"
Transporte = Callable[[bytes], bytes]


class GuardClient:
    def __init__(self, *, nome: str = NOME_PIPE, transporte: Transporte | None = None, timeout: float = 10.0,
                 verificar_servidor: Callable[[int], bool] | None = None):
        if transporte is None and sys.platform == "win32":
            transporte = _transporte_windows(nome, timeout, verificar_servidor or _servidor_instalado)
        self._transporte = transporte

    def chamar(self, acao: str, **params) -> dict:
        """Resposta do serviço (com `ok=True`); qualquer recusa ou falha vira `GuardError`."""
        pedido = {"acao": acao, **params}
        validar_pedido(pedido)  # pedido fora do esquema nem sai daqui
        if self._transporte is None:
            raise GuardError("A Proteção avançada não está instalada ou não está rodando.")
        try:
            linha = self._transporte(codificar(pedido))
        except FileNotFoundError as e:
            raise GuardError("A Proteção avançada não está instalada ou não está rodando.") from e
        except OSError as e:
            raise GuardError(f"Não foi possível falar com a Proteção avançada: {e}") from e
        resp = decodificar(linha)
        if resp.get("ok") is not True:
            raise GuardError(str(resp.get("erro") or "O serviço recusou o pedido."))
        return resp

    def disponivel(self) -> bool:
        try:
            self.chamar("ping")
        except GuardError:
            return False
        return True


def _servidor_instalado(pid: int) -> bool:
    from mandacaru_win.guard_service import Ambiente, exe_do_pid, pasta_protegida
    exe = exe_do_pid(pid)
    if not exe:
        return False
    pasta = exe.rsplit("\\", 1)[0]
    return pasta_protegida(pasta, Ambiente.atual(pasta))


def _transporte_windows(nome: str, timeout: float, verificar_servidor: Callable[[int], bool]) -> Transporte:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    k32.GetNamedPipeServerProcessId.restype = wintypes.BOOL
    k32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    k32.WaitNamedPipeW.restype = wintypes.BOOL

    def abrir():
        try:
            return open(nome, "r+b", buffering=0)
        except OSError as e:
            if getattr(e, "winerror", None) != 231:  # ERROR_PIPE_BUSY: espera uma instância livre
                raise
            k32.WaitNamedPipeW(nome, int(timeout * 1000))
            return open(nome, "r+b", buffering=0)

    def enviar(linha: bytes) -> bytes:
        with abrir() as p:
            pid = wintypes.ULONG()
            h = msvcrt.get_osfhandle(p.fileno())
            if not k32.GetNamedPipeServerProcessId(h, ctypes.byref(pid)) or not verificar_servidor(pid.value):
                raise GuardError("Quem respondeu no pipe não é o serviço instalado da Proteção avançada.")
            p.write(linha)
            resp = b""
            while not resp.endswith(b"\n"):
                bloco = p.read(4096)
                if not bloco:
                    break
                resp += bloco
                if len(resp) > MAX_MENSAGEM:
                    break
            return resp

    return enviar
