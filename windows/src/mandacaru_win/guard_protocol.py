"""Protocolo fechado entre a janela sem privilégio e o serviço MandacaruGuard (SYSTEM).

Uma linha JSON por pedido e por resposta, no máximo 64 KiB. Só as ações abaixo existem, cada uma
com as chaves exatas e os tipos conferidos aqui; qualquer outra coisa é recusada antes de chegar
perto do sistema. O cliente valida o mesmo esquema antes de enviar.
"""
from __future__ import annotations

import json
import re

MAX_MENSAGEM = 64 * 1024
REGRA_RE = re.compile(r"Mandacaru-[0-9a-f]{8,32}")
SHA_RE = re.compile(r"[0-9a-fA-F]{64}")
ID_RE = re.compile(r"[0-9a-f]{32}")
TIPOS_PERSISTENCIA = ("hklm_run", "hklm_runonce", "startup_all", "schtask", "service")
_UNIDADE = re.compile(r"[A-Za-z]:[\\/]")
_PROIBIDOS_CAMINHO = set('"*?<>|')
_MAX_CAMINHO = 32767


class GuardError(Exception):
    """Pedido ou resposta inválido; a mensagem pode ir direto para a pessoa."""


def codificar(obj: dict) -> bytes:
    dados = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(dados) > MAX_MENSAGEM:
        raise GuardError("Mensagem grande demais para o serviço.")
    return dados


def decodificar(linha: bytes) -> dict:
    if len(linha) > MAX_MENSAGEM:
        raise GuardError("Mensagem grande demais para o serviço.")
    try:
        obj = json.loads(linha.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise GuardError("Mensagem malformada.") from e
    if not isinstance(obj, dict):
        raise GuardError("Mensagem malformada.")
    return obj


def resposta_ok(**dados) -> dict:
    return {"ok": True, **dados}


def resposta_erro(msg: str) -> dict:
    return {"ok": False, "erro": msg}


def _sem_controle(s: str) -> bool:
    return not any(ord(c) < 32 or c == "\x7f" for c in s)


def caminho_valido(s: object) -> bool:
    """Caminho absoluto com letra de unidade; sem UNC, sem `\\\\?\\`, sem curingas nem aspas."""
    return (isinstance(s, str) and 3 < len(s) <= _MAX_CAMINHO
            and bool(_UNIDADE.match(s)) and _sem_controle(s)
            and not any(c in _PROIBIDOS_CAMINHO for c in s))


def _nome_valido(tipo: str, nome: object) -> bool:
    if not isinstance(nome, str) or not nome or not _sem_controle(nome) or len(nome) > 1024:
        return False
    if tipo == "schtask":
        return nome.startswith("\\") and len(nome) <= 260 and '"' not in nome
    if tipo == "service":
        return len(nome) <= 256 and not any(c in nome for c in '\\/"')
    if tipo == "startup_all":
        return nome not in (".", "..") and not any(c in nome for c in '\\/:"') and nome == nome.strip()
    return True  # hklm_run / hklm_runonce: nome do valor no registro


def _exigir(cond: bool, msg: str) -> None:
    if not cond:
        raise GuardError(msg)


def _sha(v: object) -> str:
    _exigir(isinstance(v, str) and bool(SHA_RE.fullmatch(v)), "SHA-256 inválido.")
    return v.lower()


def _caminho(v: object) -> str:
    _exigir(caminho_valido(v), "Caminho inválido: use um caminho completo com letra de unidade.")
    return v


def _regra(v: object) -> str:
    _exigir(isinstance(v, str) and bool(REGRA_RE.fullmatch(v)), "Nome de regra inválido (use Mandacaru-<hex>).")
    return v


_CHAVES = {
    "ping": set(),
    "terminate_process": {"pid", "exe", "sha256"},
    "quarantine_file": {"caminho", "sha256"},
    "quarantine_restore": {"id"},
    "firewall_block": {"regra", "exe"},
    "firewall_unblock": {"regra"},
    "persistence_remove": {"tipo", "nome", "valor"},
    "persistence_restore": {"backup"},
}


def validar_pedido(d: dict) -> tuple[str, dict]:
    """Confere o pedido contra o esquema fechado; devolve (ação, parâmetros normalizados)."""
    _exigir(isinstance(d, dict), "Mensagem malformada.")
    acao = d.get("acao")
    _exigir(isinstance(acao, str) and acao in _CHAVES, "Ação desconhecida.")
    p = {k: v for k, v in d.items() if k != "acao"}
    _exigir(set(p) == _CHAVES[acao], "Parâmetros inválidos para esta ação.")
    if acao == "terminate_process":
        pid = p["pid"]
        _exigir(type(pid) is int and 4 < pid < 2**32, "PID inválido.")
        return acao, {"pid": pid, "exe": _caminho(p["exe"]), "sha256": _sha(p["sha256"])}
    if acao == "quarantine_file":
        return acao, {"caminho": _caminho(p["caminho"]), "sha256": _sha(p["sha256"])}
    if acao == "quarantine_restore":
        _exigir(isinstance(p["id"], str) and bool(ID_RE.fullmatch(p["id"])), "Item de quarentena inválido.")
        return acao, {"id": p["id"]}
    if acao == "firewall_block":
        return acao, {"regra": _regra(p["regra"]), "exe": _caminho(p["exe"])}
    if acao == "firewall_unblock":
        return acao, {"regra": _regra(p["regra"])}
    if acao == "persistence_remove":
        tipo, nome, valor = p["tipo"], p["nome"], p["valor"]
        _exigir(tipo in TIPOS_PERSISTENCIA, "Tipo de persistência não aceito pelo serviço.")
        _exigir(_nome_valido(tipo, nome), "Nome de entrada inválido.")
        _exigir(isinstance(valor, str) and len(valor) <= _MAX_CAMINHO, "Valor de entrada inválido.")
        if tipo == "startup_all":
            valor = _sha(valor)
        elif tipo in ("schtask", "service"):
            _exigir(valor == "", "Valor de entrada inválido.")
        return acao, {"tipo": tipo, "nome": nome, "valor": valor}
    if acao == "persistence_restore":
        _exigir(isinstance(p["backup"], dict), "Backup inválido.")
        return acao, {"backup": p["backup"]}
    return acao, {}
