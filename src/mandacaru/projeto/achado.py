"""Achado: um indicio encontrado em um arquivo do projeto."""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path

from ..events import Alert, Severity, safe_text

LIMITE_TRECHO = 120
_ESCONDIDOS = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs"})


def exibivel(s: str, limite: int | None = LIMITE_TRECHO) -> str:
    """Texto do projeto pronto para terminal ou interface, sempre em UMA linha.

    Tabulação vira espaço; quebras de linha, controles, invisíveis (Cf), separadores de linha
    e parágrafo, uso privado e surrogates (bytes inválidos em nomes de arquivo) viram `<U+XXXX>`.
    Com `limite`, o resultado tem no máximo `limite` caracteres; se precisar cortar, termina em "…".
    Linear (para de ler ao passar do limite) e idempotente.
    """
    partes: list[str] = []
    tamanho = 0
    corte = 0  # quantas partes cabem junto com o "…"
    for c in s:
        if c == "\t":
            p = " "
        elif unicodedata.category(c) in _ESCONDIDOS:
            p = f"<U+{ord(c):04X}>"
        else:
            p = c
        tamanho += len(p)
        if limite is not None:
            if tamanho > limite:
                return safe_text("".join(partes[:corte]) + "…")
            if tamanho <= limite - 1:
                corte = len(partes) + 1
        partes.append(p)
    return safe_text("".join(partes))


@dataclass(frozen=True)
class Achado:
    regra: str
    severidade: Severity
    caminho: str  # relativo a raiz, com "/"
    explicacao: str
    linha: int | None = None
    trecho: str = ""
    mitre: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Mesmo formato em todas as famílias: uma linha, invisíveis à mostra, no máximo 120 caracteres.
        object.__setattr__(self, "trecho", exibivel(self.trecho))

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
