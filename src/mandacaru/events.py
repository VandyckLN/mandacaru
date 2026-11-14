"""Modelos de dados compartilhados entre coletores, detectores e o motor."""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


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

    def to_json(self) -> str:
        d = asdict(self)
        d["severity"] = self.severity.name
        return json.dumps(d, ensure_ascii=False, default=str)
