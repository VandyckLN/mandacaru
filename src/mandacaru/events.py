"""Modelos de dados compartilhados entre coletores, detectores e o motor."""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


def safe_text(s: str) -> str:
    """Troca surrogates (bytes invalidos de nomes de arquivo lidos com surrogateescape) por U+FFFD.

    Sem isso, gravar ou enviar o alerta levanta UnicodeEncodeError e o alerta some:
    um malware escaparia so pelo nome do arquivo.
    """
    return s.encode("utf-8", "surrogatepass").decode("utf-8", "replace")


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Event:
    """Algo que aconteceu na maquina (processo, arquivo, rede)."""
    kind: str                      # process_start | file_write | file_rename | file_create
    data: dict[str, Any]
    ts: float = field(default_factory=time.time)
    source: str = "unknown"        # procmon | fsmon | ebpf | scan


@dataclass
class Alert:
    """Conclusao de um detector sobre um ou mais eventos."""
    rule: str
    severity: Severity
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    mitre: list[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)
    quarantine_id: str | None = None  # caso aberto quando o arquivo foi isolado

    def to_json(self) -> str:
        d = asdict(self)
        d["severity"] = self.severity.name
        return safe_text(json.dumps(d, ensure_ascii=False, default=str))
