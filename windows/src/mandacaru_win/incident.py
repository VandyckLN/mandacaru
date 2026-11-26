"""Registro de incidentes: o que foi encontrado e cada ação tomada, em incidents/<id>.json.

Python puro (sem Qt): o painel "Resposta a incidente" (c.2) só lê e grava por aqui.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from mandacaru_win.store import _atomic_write_json

ORIGENS = ("varredura", "projeto", "atualizacoes")
AMEACAS = ("malware", "projeto", "vulnerabilidade")
FASES = ("conter", "neutralizar", "recuperar")
MODOS = ("automatica", "guiada")
RESULTADOS = ("em_andamento", "concluida", "parcial", "falhou")
_ID_RE = re.compile(r"[0-9a-f]{32}")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_CORROMPIDO = "O registro do incidente está corrompido."
_isjunction = getattr(os.path, "isjunction", lambda _: False)


class IncidentError(Exception):
    """Erro com mensagem pronta para mostrar à pessoa."""


def agora() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_valido(valor: object) -> bool:
    """Confere se `valor` é um resumo SHA-256 hexadecimal de 64 caracteres."""
    return isinstance(valor, str) and bool(_SHA256_RE.fullmatch(valor))


def sha256_arquivo(caminho: Path) -> str | None:
    """SHA-256 de um arquivo regular sem seguir link nem junção; None se não der para ler."""
    try:
        if _isjunction(caminho) or (not hasattr(os, "O_NOFOLLOW") and os.path.islink(caminho)):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(caminho, flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            h = hashlib.sha256()
            while chunk := fh.read(1024 * 1024):
                h.update(chunk)
            return h.hexdigest()
    except OSError:
        return None


@dataclass
class Acao:
    tipo: str
    fase: str
    modo: str
    resultado: str
    detalhe: str
    alvo: dict
    data: str
    backup: dict | None = None
    desfeita: bool = False


@dataclass
class Incidente:
    id: str
    criado: str
    origem: str
    ameaca: str
    achados: list[dict]
    pasta: str | None = None
    acoes: list[Acao] = field(default_factory=list)
    credenciais: dict[str, bool] = field(default_factory=dict)
    versao: int = 1


def _exigir(cond: bool) -> None:
    if not cond:
        raise IncidentError(_CORROMPIDO)


def _acao_de_dict(d: object) -> Acao:
    _exigir(isinstance(d, dict))
    for k in ("tipo", "fase", "modo", "resultado", "detalhe", "data"):
        _exigir(isinstance(d.get(k), str))
    _exigir(isinstance(d.get("alvo"), dict))
    _exigir(d.get("backup") is None or isinstance(d.get("backup"), dict))
    _exigir(isinstance(d.get("desfeita", False), bool))
    return Acao(d["tipo"], d["fase"], d["modo"], d["resultado"], d["detalhe"], d["alvo"], d["data"],
                d.get("backup"), d.get("desfeita", False))


def _de_dict(d: object, qid: str) -> Incidente:
    _exigir(isinstance(d, dict) and d.get("id") == qid)
    for k in ("criado", "origem", "ameaca"):
        _exigir(isinstance(d.get(k), str))
    achados, acoes, cred = d.get("achados"), d.get("acoes"), d.get("credenciais")
    _exigir(isinstance(achados, list) and all(isinstance(a, dict) for a in achados))
    _exigir(isinstance(acoes, list))
    _exigir(isinstance(cred, dict) and all(isinstance(k, str) and isinstance(v, bool) for k, v in cred.items()))
    _exigir(d.get("pasta") is None or isinstance(d.get("pasta"), str))
    versao = d.get("versao", 1)
    _exigir(isinstance(versao, int) and not isinstance(versao, bool))
    return Incidente(qid, d["criado"], d["origem"], d["ameaca"], achados, d.get("pasta"),
                     [_acao_de_dict(a) for a in acoes], cred, versao)


def _ordem_data(iso: str) -> float:
    try:
        dt = datetime.fromisoformat(iso)
        return dt.timestamp() if dt.tzinfo else dt.astimezone().timestamp()
    except ValueError:
        return float("-inf")


class IncidentStore:
    """Um arquivo JSON por incidente, sempre gravado de forma atômica (com fsync)."""

    def __init__(self, base: Path):
        self._base = Path(base)

    def _arquivo(self, qid: str) -> Path:
        if not isinstance(qid, str) or not _ID_RE.fullmatch(qid):
            raise IncidentError("Identificador de incidente inválido.")
        return self._base / f"{qid}.json"

    def criar(self, *, origem: str, ameaca: str, achados: list[dict], pasta: str | None = None) -> Incidente:
        if origem not in ORIGENS:
            raise IncidentError(f"Origem de incidente desconhecida: {origem}")
        if ameaca not in AMEACAS:
            raise IncidentError(f"Tipo de ameaça desconhecido: {ameaca}")
        inc = Incidente(uuid.uuid4().hex, agora(), origem, ameaca, [dict(a) for a in achados], pasta)
        self.salvar(inc)
        return inc

    def salvar(self, inc: Incidente) -> None:
        try:
            _atomic_write_json(self._arquivo(inc.id), asdict(inc))
        except OSError as e:
            raise IncidentError(f"Não foi possível gravar o registro do incidente: {e}") from e

    def carregar(self, qid: str) -> Incidente:
        arq = self._arquivo(qid)
        try:
            dados = json.loads(arq.read_text(encoding="utf-8"))
        except FileNotFoundError as e:
            raise IncidentError("Incidente não encontrado.") from e
        except (OSError, ValueError) as e:
            raise IncidentError(_CORROMPIDO) from e
        return _de_dict(dados, qid)

    def listar(self) -> list[Incidente]:
        if not self._base.is_dir():
            return []
        saida = []
        for p in self._base.glob("*.json"):
            if not _ID_RE.fullmatch(p.stem):
                continue
            try:
                saida.append(self.carregar(p.stem))
            except IncidentError:
                continue
        saida.sort(key=lambda i: _ordem_data(i.criado), reverse=True)
        return saida

    def registrar(self, inc: Incidente, acao: Acao) -> int:
        """Acrescenta a ação ao incidente e grava; devolve o índice dela."""
        inc.acoes.append(acao)
        self.salvar(inc)
        return len(inc.acoes) - 1
