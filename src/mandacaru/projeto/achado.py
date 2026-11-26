"""Achado: um indicio encontrado em um arquivo do projeto."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..events import Alert, Severity


@dataclass(frozen=True)
class Achado:
    regra: str
    severidade: Severity
    caminho: str  # relativo a raiz, com "/"
    explicacao: str
    linha: int | None = None
    trecho: str = ""
    mitre: tuple[str, ...] = ()

    def to_alert(self, raiz: Path) -> Alert:
        onde = self.caminho if self.linha is None else f"{self.caminho}:{self.linha}"
        return Alert(
            rule=self.regra,
            severity=self.severidade,
            summary=f"{onde}: {self.explicacao}",
            evidence={"path": str(raiz / self.caminho), "linha": self.linha, "trecho": self.trecho},
            mitre=list(self.mitre),
        )


class ArquivoIlegivel(Exception):
    """Arquivo-alvo com sintaxe invalida; o orquestrador conta e segue."""
